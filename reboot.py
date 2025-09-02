import logging

from nornir import InitNornir
from nornir.core.task import Task
from nornir_pyez.plugins.tasks import pyez_rpc

nr = InitNornir(config_file="config.yaml")
logger = logging.getLogger("nornir")


def reboot_device(task: Task) -> None:
    """Reboot a single device to complete firmware upgrade.

    Args:
        task: Nornir task object

    Raises:
        ValueError: If reboot command fails
    """
    try:
        logger.info("%s: Initiating reboot", task.host.hostname)
        result = task.run(task=pyez_rpc, func="request-reboot")

        if result.failed:
            raise ValueError(
                f"{task.host.hostname}: Reboot command failed: {result.exception}"
            )

        logger.info("%s: Reboot command sent successfully", task.host.hostname)

    except Exception as e:
        if isinstance(e, ValueError):
            raise
        raise ValueError(f"{task.host.hostname}: Error during reboot: {e}") from e


def main():
    """Perform a reboot to finish the firmware upgrade process."""
    logger.info("Starting device reboot process")

    if not nr.inventory.hosts:
        logger.error("No devices found in inventory")
        return 1

    # Display devices that will be rebooted
    logger.info("Devices to be rebooted:")
    for host in nr.inventory.hosts:
        logger.info("  - %s", host)

    # Confirm reboot
    try:
        proceed = input("\nProceed with reboot? (yes/no): ").strip().lower()
        if proceed not in ("yes", "y"):
            logger.info("Reboot cancelled by user")
            return 0
    except (EOFError, KeyboardInterrupt):
        logger.info("\nReboot cancelled by user")
        return 0

    # Perform reboots
    logger.info("Sending reboot commands to all devices")
    reboot_results = nr.run(task=reboot_device)

    # Summary
    failed_hosts = []
    successful_hosts = []

    for host, result in reboot_results.items():
        if result.failed:
            logger.error("%s: Reboot failed: %s", host, result.exception)
            failed_hosts.append(host)
        else:
            logger.info("%s: Reboot command sent successfully", host)
            successful_hosts.append(host)

    # Final summary
    logger.info("Reboot process completed")
    logger.info(
        "Successful: %d hosts - %s", len(successful_hosts), ", ".join(successful_hosts)
    )
    if failed_hosts:
        logger.error(
            "Failed: %d hosts - %s", len(failed_hosts), ", ".join(failed_hosts)
        )
        logger.warning("Failed devices may need manual reboot")
        return 1

    logger.info("All devices will reboot in approximately 60 seconds")
    logger.info("Please wait for devices to come back online before proceeding")

    return 0


if __name__ == "__main__":
    import sys

    exit_code = main()
    sys.exit(exit_code)
