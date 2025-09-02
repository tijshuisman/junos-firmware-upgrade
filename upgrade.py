import logging
import yaml

from nornir import InitNornir
from nornir.core.task import Task
from nornir_pyez.plugins.tasks import pyez_facts

from jnpr.junos import Device
from jnpr.junos.utils.sw import SW

nr = InitNornir(config_file="config.yaml")
logger = logging.getLogger("nornir")


def upgrade_junos(task: Task, firmware_definitions: dict) -> None:
    """Performs the firmware upgrade.

    Args:
        task: Nornir task object
        firmware_definitions: Dictionary containing firmware configuration

    Raises:
        ValueError: If upgrade configuration is invalid or upgrade fails
    """
    try:
        device_model = task.host.get("model")
        if not device_model:
            raise ValueError(f"{task.host.hostname}: Device model not found")

        if device_model not in firmware_definitions["device_types"]:
            raise ValueError(
                f"{task.host.hostname}: No firmware config for model {device_model}"
            )

        base_path = firmware_definitions["general"]["base_path"]
        firmware_file = firmware_definitions["device_types"][device_model]["file"]
        full_firmware_path = f"{base_path}{firmware_file}"

        logger.info(
            "%s: Starting firmware upgrade with %s", task.host.hostname, firmware_file
        )

        def log_upgrade_progress(dev, report):
            """Log upgrade progress."""
            logger.info("%s: %s", dev.hostname, report)

        try:
            with Device(
                host=task.host.hostname,
                username=task.host.username,
                password=task.host.password,
            ) as dev:
                sw = SW(dev)
                kwargs = {
                    "package": full_firmware_path,
                    "validate": False,
                    "progress": log_upgrade_progress,
                    "cleanfs": False,
                }
                if device_model == "EX4600":
                    kwargs["force_host"] = True
                    logger.info("%s: Using force_host for EX4600", task.host.hostname)

                ok, msg = sw.install(**kwargs)

            if ok:
                logger.info(
                    "%s: Upgrade installed successfully. Run reboot.py to complete.",
                    task.host.hostname,
                )
            else:
                raise ValueError(f"{task.host.hostname}: Upgrade failed - {msg}")

        except Exception as e:
            if isinstance(e, ValueError):
                raise
            raise ValueError(
                f"{task.host.hostname}: Device connection or upgrade error: {e}"
            ) from e

    except KeyError as e:
        raise ValueError(f"Missing firmware configuration key: {e}") from e


def main():
    """
    Upgrade firmware on JUNOS switch. The switch will not be automatically rebooted.
    """
    logger.info("Starting JUNOS firmware upgrade process")

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
                version = facts[host].result["version"]
                nr.inventory.hosts[host]["model"] = model
                nr.inventory.hosts[host]["platform"] = "juniper"
                nr.inventory.hosts[host]["version"] = version
                logger.info(
                    "%s: Detected model %s, current version %s", host, model, version
                )
            except (KeyError, AttributeError, IndexError) as e:
                logger.error("%s: Unable to determine device info: %s", host, e)
                continue

        # Load firmware definitions
        try:
            with open(
                "firmware.yaml", "r", encoding="UTF-8"
            ) as firmware_definitions_raw:
                firmware_definitions = yaml.safe_load(firmware_definitions_raw)
        except FileNotFoundError:
            logger.error("firmware.yaml configuration file not found")
            return 1
        except yaml.YAMLError as e:
            logger.error("Invalid YAML in firmware.yaml: %s", e)
            return 1

        # Display upgrade plan
        logger.info("Upgrade plan:")
        upgrade_plan = []
        for host in nr.inventory.hosts:
            try:
                current_version = nr.inventory.hosts[host].get("version", "unknown")
                device_model = nr.inventory.hosts[host].get("model")

                if not device_model:
                    logger.warning("%s: No device model found, skipping", host)
                    continue

                if device_model not in firmware_definitions["device_types"]:
                    logger.warning(
                        "%s: No firmware config for model %s, skipping",
                        host,
                        device_model,
                    )
                    continue

                target_version = firmware_definitions["device_types"][device_model][
                    "release"
                ]
                upgrade_plan.append((host, current_version, target_version))
                logger.info("  %s: %s → %s", host, current_version, target_version)

            except KeyError as e:
                logger.error("%s: Missing firmware configuration: %s", host, e)
                continue

        if not upgrade_plan:
            logger.error("No devices to upgrade")
            return 1

        # Confirm upgrade
        try:
            proceed = input("\nProceed with upgrade? (yes/no): ").strip().lower()
            if proceed not in ("yes", "y"):
                logger.info("Upgrade cancelled by user")
                return 0
        except (EOFError, KeyboardInterrupt):
            logger.info("\nUpgrade cancelled by user")
            return 0

        # Perform upgrades
        logger.info("Starting firmware upgrades")
        upgrade_results = nr.run(
            task=upgrade_junos, firmware_definitions=firmware_definitions
        )

        # Summary
        failed_hosts = []
        successful_hosts = []

        for host, result in upgrade_results.items():
            if result.failed:
                logger.error("%s: Upgrade failed: %s", host, result.exception)
                failed_hosts.append(host)
            else:
                logger.info("%s: Upgrade completed successfully", host)
                successful_hosts.append(host)

        logger.info("Upgrade process completed")
        logger.info(
            "Successful: %d hosts - %s",
            len(successful_hosts),
            ", ".join(successful_hosts),
        )
        if failed_hosts:
            logger.error(
                "Failed: %d hosts - %s", len(failed_hosts), ", ".join(failed_hosts)
            )
            return 1

        return 0

    except (ValueError, yaml.YAMLError) as e:
        logger.error("Upgrade process failed: %s", e)
        return 1


if __name__ == "__main__":
    import sys

    exit_code = main()
    sys.exit(exit_code)
