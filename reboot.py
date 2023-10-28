import logging
import sys

from nornir import InitNornir
from nornir_pyez.plugins.tasks import pyez_rpc

nr = InitNornir(config_file="config.yaml")
logger = logging.getLogger("nornir")


def main():
    """Perform a reboot to finish the firmware upgrade process."""
    for host in nr.inventory.hosts:
        logger.info("%s: preparing reboot", host)
    proceed = input("\nProceed? (yes/no): ")
    if proceed not in ("yes", "y"):
        sys.exit()

    nr.run(task=pyez_rpc, func="request-reboot")
    logger.info("Switches will reboot in 60 seconds.")

if __name__ == "__main__":
    main()
