import logging
import re
import yaml

from nornir import InitNornir
from nornir.core.task import Task
from nornir.core.filter import F
from nornir_pyez.plugins.tasks import pyez_facts, pyez_rpc, pyez_scp, pyez_checksum


nr = InitNornir(config_file="config.yaml")
logger = logging.getLogger("nornir")

# Configuration constants
DEFAULT_STORAGE_THRESHOLD = 57  # Maximum storage usage percentage


def verify_freespace(
    task: Task, storage_threshold: int = DEFAULT_STORAGE_THRESHOLD
) -> None:
    """Verify that the storage usage on all FPC's is below
    threshold before copying the firmware file.

    Args:
        task: Nornir task object
        storage_threshold: Maximum allowed storage usage percentage (default: 57%)

    Raises:
        ValueError: If storage usage exceeds threshold
    """
    try:
        show_system_storage = task.run(
            task=pyez_rpc,
            func="get-system-storage",
        )

        if not show_system_storage.result:
            raise ValueError(
                f"{task.host.name}: Unable to retrieve storage information"
            )

        routing_engines = show_system_storage.result.get(
            "multi-routing-engine-results", {}
        ).get("multi-routing-engine-item")

        if not routing_engines:
            raise ValueError(f"{task.host.name}: No routing engine information found")

        # Handle both single and multiple routing engines
        if isinstance(routing_engines, list):
            engines_to_check = routing_engines
        else:
            engines_to_check = [routing_engines]

        for routing_engine in engines_to_check:
            re_name = routing_engine.get("re-name", "unknown")
            filesystems = routing_engine.get("system-storage-information", {}).get(
                "filesystem", []
            )

            if not isinstance(filesystems, list):
                filesystems = [filesystems]

            for file_system in filesystems:
                if file_system.get("filesystem-name") == "/dev/gpt/junos":
                    try:
                        used_percent = int(file_system.get("used-percent", 0))
                        if used_percent > storage_threshold:
                            raise ValueError(
                                f"{task.host.name}-{re_name}: storage usage {used_percent}% exceeds {storage_threshold}% threshold. "
                                "Upgrade might fail due to insufficient space. Firmware file will not be transferred."
                            )
                        logger.info(
                            "%s-%s: storage usage %d%% - OK",
                            task.host.name,
                            re_name,
                            used_percent,
                        )
                    except (ValueError, TypeError) as e:
                        if "storage usage" in str(e):
                            raise  # Re-raise our storage error
                        raise ValueError(
                            f"{task.host.name}-{re_name}: Invalid storage percentage data: {e}"
                        ) from e

    except Exception as e:
        if isinstance(e, ValueError):
            raise
        raise ValueError(f"{task.host.name}: Error checking storage: {e}") from e


def transfer_firmware(task: Task) -> None:
    """Transfer firmware file to the JUNOS switch.

    Args:
        task: Nornir task object

    Raises:
        ValueError: If firmware configuration is invalid or checksum doesn't match
        FileNotFoundError: If firmware.yaml configuration file not found
    """
    try:
        with open("firmware.yaml", "r", encoding="UTF-8") as firmware_definitions_raw:
            firmware_definitions = yaml.safe_load(firmware_definitions_raw)
    except FileNotFoundError as exc:
        raise FileNotFoundError("firmware.yaml configuration file not found") from exc
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML in firmware.yaml: {e}") from e

    try:
        base_path = firmware_definitions["general"]["base_path"]
        device_model = task.host.get("model")

        if not device_model:
            raise ValueError(
                f"{task.host.name}: Device model not found in host inventory"
            )

        if device_model not in firmware_definitions["device_types"]:
            raise ValueError(
                f"{task.host.name}: No firmware configuration found for model {device_model}"
            )

        firmware_config = firmware_definitions["device_types"][device_model]
        firmware_file = firmware_config["file"]
        expected_md5 = firmware_config["md5"]

    except KeyError as e:
        raise ValueError(
            f"Missing required configuration key in firmware.yaml: {e}"
        ) from e

    def log_transfer_progress(dev, report):
        """Log firmware transfer progress."""
        try:
            match = re.search(r"\((.*?)\)", report)
            if match:
                percentage = match.group(1)
                logger.info("%s: firmware transfer %s", dev.hostname, percentage)
            else:
                logger.debug("%s: transfer progress: %s", dev.hostname, report)
        except (AttributeError, re.error) as e:
            logger.warning("%s: Unable to parse transfer progress: %s", dev.hostname, e)

    try:
        scpargs = {"progress": log_transfer_progress}
        full_firmware_path = f"{base_path}{firmware_file}"

        logger.info(
            "%s: Starting firmware transfer of %s", task.host.name, firmware_file
        )
        task.run(
            task=pyez_scp,
            file=full_firmware_path,
            path="/var/tmp/",
            scpargs=scpargs,
        )

        logger.info("%s: Verifying firmware checksum", task.host.name)
        firmware_md5 = task.run(
            task=pyez_checksum, filepath=f"/var/tmp/{firmware_file}", calc="md5"
        )

        if firmware_md5.result != expected_md5:
            raise ValueError(
                f"{task.host.name}: Firmware checksum mismatch. "
                f"Expected: {expected_md5}, Got: {firmware_md5.result}"
            )

        logger.info(
            "%s: Firmware transfer and verification completed successfully",
            task.host.name,
        )

    except Exception as e:
        if isinstance(e, ValueError):
            raise
        raise ValueError(f"{task.host.name}: Firmware transfer failed: {e}") from e


def main():
    """
    Prepare a JUNOS switch for a firmware upgrade.
    This is done by:
    - Storage cleanup
    - Delete all snapshots (EX2300/EX3400/EX4100 only)
    - Verify that there is storage space available for the firmware upgrade (EX2300/EX3400 only)
    - Transfer the firmware file as defined in firmware.yaml
    """
    logger.info("Starting pre-upgrade preparation")

    try:
        # Gather facts and set device models
        logger.info("Gathering device facts")
        facts = nr.run(task=pyez_facts)

        for host in facts:
            if facts[host].failed:
                logger.error(
                    "Failed to gather facts for %s: %s", host, facts[host].exception
                )
                continue

            try:
                model = facts[host].result["model"].split("-")[0]
                nr.inventory.hosts[host]["model"] = model
                nr.inventory.hosts[host]["platform"] = "juniper"
                logger.info("%s: Detected model %s", host, model)
            except (KeyError, AttributeError, IndexError) as e:
                logger.error("%s: Unable to determine device model: %s", host, e)
                continue

        # Storage cleanup
        logger.info("Performing storage cleanup on all devices")
        cleanup_results = nr.run(task=pyez_rpc, func="request-system-storage-cleanup")
        for host, result in cleanup_results.items():
            if result.failed:
                logger.warning("%s: Storage cleanup failed: %s", host, result.exception)
            else:
                logger.info("%s: Storage cleanup completed", host)

        # Delete snapshots for specific models
        logger.info("Deleting snapshots for supported models")
        delete_extras = {"delete": "*"}
        snapshot_models = nr.filter(
            F(model="EX3400") | F(model="EX2300") | F(model="EX4100")
        )
        if snapshot_models.inventory.hosts:
            snapshot_results = snapshot_models.run(
                task=pyez_rpc, func="request-snapshot", extras=delete_extras
            )
            for host, result in snapshot_results.items():
                if result.failed:
                    logger.warning(
                        "%s: Snapshot deletion failed: %s", host, result.exception
                    )
                else:
                    logger.info("%s: Snapshots deleted", host)

        # Verify free space for specific models
        logger.info("Verifying storage space for models that require it")
        storage_check_models = nr.filter(F(model="EX3400") | F(model="EX2300"))
        if storage_check_models.inventory.hosts:
            storage_results = storage_check_models.run(task=verify_freespace)
            for host, result in storage_results.items():
                if result.failed:
                    logger.error(
                        "%s: Storage verification failed: %s", host, result.exception
                    )
                else:
                    logger.info("%s: Storage verification passed", host)

        # Transfer firmware
        logger.info("Starting firmware transfer to all devices")
        transfer_results = nr.run(task=transfer_firmware)

        failed_hosts = []
        successful_hosts = []

        for host, result in transfer_results.items():
            if result.failed:
                logger.error("%s: Firmware transfer failed: %s", host, result.exception)
                failed_hosts.append(host)
            else:
                logger.info("%s: Firmware transfer completed successfully", host)
                successful_hosts.append(host)

        # Summary
        logger.info("Pre-upgrade preparation completed")
        logger.info(
            "Successful: %d hosts - %s",
            len(successful_hosts),
            ", ".join(successful_hosts),
        )
        if failed_hosts:
            logger.error(
                "Failed: %d hosts - %s", len(failed_hosts), ", ".join(failed_hosts)
            )
            return 1  # Exit with error code

        return 0  # Success

    except (ValueError, FileNotFoundError, yaml.YAMLError) as e:
        logger.error("Pre-upgrade preparation failed: %s", e)
        return 1


if __name__ == "__main__":
    import sys

    exit_code = main()
    sys.exit(exit_code)
