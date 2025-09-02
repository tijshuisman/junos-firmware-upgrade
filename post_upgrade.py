import logging

from nornir import InitNornir
from nornir.core.task import Task
from nornir.core.inventory import ConnectionOptions
from nornir.core.filter import F
from nornir_pyez.plugins.tasks import pyez_facts, pyez_rpc
from nornir_netmiko.tasks import netmiko_send_command


nr = InitNornir(config_file="config.yaml")
logger = logging.getLogger("nornir")


def cleanup_storage(task: Task) -> None:
    """Cleanup storage on device.

    Args:
        task: Nornir task object

    Raises:
        ValueError: If storage cleanup fails
    """
    try:
        logger.info("%s: Starting storage cleanup", task.host.hostname)
        extras_cleanup = {"all_members": True}
        result = task.run(
            task=pyez_rpc, func="request-system-storage-cleanup", extras=extras_cleanup
        )

        if result.failed:
            raise ValueError(
                f"{task.host.hostname}: Storage cleanup failed: {result.exception}"
            )

        logger.info("%s: Storage cleanup completed successfully", task.host.hostname)

    except Exception as e:
        if isinstance(e, ValueError):
            raise
        raise ValueError(
            f"{task.host.hostname}: Error during storage cleanup: {e}"
        ) from e


def create_snapshots(task: Task) -> None:
    """Create snapshots based on device model.

    Args:
        task: Nornir task object

    Raises:
        ValueError: If snapshot creation fails
    """
    try:
        device_model = task.host.get("model")
        if not device_model:
            raise ValueError(f"{task.host.hostname}: Device model not found")

        logger.info(
            "%s: Creating snapshots for model %s", task.host.hostname, device_model
        )

        # Create regular snapshot for specific models
        if device_model in ["EX3400", "EX2300", "EX4100"]:
            logger.info("%s: Creating regular snapshot", task.host.hostname)
            result = task.run(task=pyez_rpc, func="request-snapshot")
            if result.failed:
                raise ValueError(
                    f"{task.host.hostname}: Regular snapshot failed: {result.exception}"
                )

            # Create recovery snapshot
            logger.info("%s: Creating recovery snapshot", task.host.hostname)
            extras_recovery = {"recovery": True}
            result = task.run(
                task=pyez_rpc, func="request-snapshot", extras=extras_recovery
            )
            if result.failed:
                raise ValueError(
                    f"{task.host.hostname}: Recovery snapshot failed: {result.exception}"
                )

        elif device_model == "EX4200":
            logger.info("%s: Creating alternate slice snapshot", task.host.hostname)
            extras_alternate = {"slice": "alternate"}
            result = task.run(
                task=pyez_rpc, func="request-snapshot", extras=extras_alternate
            )
            if result.failed:
                raise ValueError(
                    f"{task.host.hostname}: Alternate snapshot failed: {result.exception}"
                )
        else:
            logger.info(
                "%s: No snapshots required for model %s",
                task.host.hostname,
                device_model,
            )

        logger.info("%s: Snapshot creation completed", task.host.hostname)

    except Exception as e:
        if isinstance(e, ValueError):
            raise
        raise ValueError(
            f"{task.host.hostname}: Error during snapshot creation: {e}"
        ) from e


def save_rescue_config(task: Task) -> None:
    """Save rescue configuration.

    Args:
        task: Nornir task object

    Raises:
        ValueError: If rescue config save fails
    """
    try:
        logger.info("%s: Saving rescue configuration", task.host.hostname)
        result = task.run(
            task=netmiko_send_command,
            command_string="request system configuration rescue save",
        )

        if result.failed:
            raise ValueError(
                f"{task.host.hostname}: Rescue config save failed: {result.exception}"
            )

        # Check if the output indicates success
        output = result.result.strip() if result.result else ""
        if "error" in output.lower() or "failed" in output.lower():
            raise ValueError(
                f"{task.host.hostname}: Rescue config save error: {output}"
            )

        logger.info("%s: Rescue configuration saved successfully", task.host.hostname)

    except Exception as e:
        if isinstance(e, ValueError):
            raise
        raise ValueError(
            f"{task.host.hostname}: Error saving rescue config: {e}"
        ) from e


def main():
    """
    Perform post upgrade actions.
    These actions include:
    - Cleanup storage
    - Create snapshots (model-specific)
    - Set rescue config
    """
    logger.info("Starting post-upgrade procedures")

    try:
        # Configure connection timeouts
        nr.inventory.defaults.connection_options["pyez"] = ConnectionOptions(
            extras={"rpc_timeout": 7200}
        )
        nr.inventory.defaults.connection_options["netmiko"] = ConnectionOptions(
            extras={"device_type": "juniper"}
        )

        # Gather facts and set device models
        logger.info("Gathering device facts")
        facts_result = nr.run(task=pyez_facts)

        for host in facts_result:
            if facts_result[host].failed:
                logger.error(
                    "Failed to gather facts for %s: %s",
                    host,
                    facts_result[host].exception,
                )
                continue

            try:
                model = facts_result[host].result["model"].split("-")[0]
                nr.inventory.hosts[host]["model"] = model
                nr.inventory.hosts[host]["platform"] = "juniper"
                logger.info("%s: Detected model %s", host, model)
            except (KeyError, AttributeError, IndexError) as e:
                logger.error("%s: Unable to determine device model: %s", host, e)
                continue

        # Step 1: Storage cleanup
        logger.info("Performing storage cleanup on all devices")
        cleanup_results = nr.run(task=cleanup_storage)
        cleanup_failed = []
        for host, result in cleanup_results.items():
            if result.failed:
                logger.error("%s: Storage cleanup failed: %s", host, result.exception)
                cleanup_failed.append(host)
            else:
                logger.info("%s: Storage cleanup completed", host)

        # Step 2: Create snapshots (model-specific)
        logger.info("Creating snapshots on supported devices")
        snapshot_models = nr.filter(
            F(model="EX3400")
            | F(model="EX2300")
            | F(model="EX4100")
            | F(model="EX4200")
        )
        snapshot_failed = []

        if snapshot_models.inventory.hosts:
            snapshot_results = snapshot_models.run(task=create_snapshots)
            for host, result in snapshot_results.items():
                if result.failed:
                    logger.error(
                        "%s: Snapshot creation failed: %s", host, result.exception
                    )
                    snapshot_failed.append(host)
                else:
                    logger.info("%s: Snapshots created successfully", host)
        else:
            logger.info("No devices require snapshots")

        # Step 3: Save rescue configuration
        logger.info("Saving rescue configurations on all devices")
        rescue_results = nr.run(task=save_rescue_config)
        rescue_failed = []
        for host, result in rescue_results.items():
            if result.failed:
                logger.error(
                    "%s: Rescue config save failed: %s", host, result.exception
                )
                rescue_failed.append(host)
            else:
                logger.info("%s: Rescue configuration saved", host)

        # Final summary
        total_hosts = len(nr.inventory.hosts)
        failed_hosts = set(cleanup_failed + snapshot_failed + rescue_failed)
        successful_hosts = [
            host for host in nr.inventory.hosts if host not in failed_hosts
        ]

        logger.info("Post-upgrade procedures completed")
        logger.info("Total devices: %d", total_hosts)
        logger.info(
            "Successful: %d hosts - %s",
            len(successful_hosts),
            ", ".join(successful_hosts),
        )

        if failed_hosts:
            logger.error(
                "Failed: %d hosts - %s", len(failed_hosts), ", ".join(failed_hosts)
            )
            logger.warning(
                "Some post-upgrade tasks failed. Please check failed devices manually."
            )
            return 1

        logger.info("All post-upgrade procedures completed successfully")
        return 0

    except (ValueError, KeyError, AttributeError, IndexError) as e:
        logger.error("Post-upgrade procedures failed: %s", e)
        return 1


if __name__ == "__main__":
    import sys

    exit_code = main()
    sys.exit(exit_code)
