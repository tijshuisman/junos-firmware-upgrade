import logging
import sys
import yaml

from nornir import InitNornir
from nornir.core.task import Task
from nornir_pyez.plugins.tasks import pyez_facts

from jnpr.junos import Device
from jnpr.junos.utils.sw import SW

nr = InitNornir(config_file="config.yaml")
logger = logging.getLogger("nornir")


def upgrade_junos(task: Task, firmware_definitions: dict) -> None:
    """Performs the firmware upgrade."""
    base_path = firmware_definitions["general"]["base_path"]
    firmware_file = firmware_definitions["device_types"][task.host["model"]]["file"]

    def log_upgrade_progress(dev, report):
        logger.info("%s: %s", dev.hostname, report)

    with Device(
        host=task.host.hostname,
        username=task.host.username,
        password=task.host.password
    ) as dev:
        sw = SW(dev)
        kwargs = {
            "package": f"{base_path}{firmware_file}",
            "validate": False,
            "progress": log_upgrade_progress,
            "cleanfs": False,
        }
        if task.host["model"] == "EX4600":
            kwargs["force_host"] = True
        ok, msg = sw.install(**kwargs)

    if ok:
        logger.info(
            "%s: upgrade installed, run reboot.py to complete.", task.host.hostname
        )
    else:
        logger.error("%s: upgrade failed, %s.", task.host.hostname, msg)


def main():
    """
    Upgrade firmware on JUNOS switch. The switch will not be automatically rebooted.
    """
    facts = nr.run(task=pyez_facts)
    for host in facts:
        model = facts[host].result["model"].split("-")[0]
        version = facts[host].result["version"]
        nr.inventory.hosts[host]["model"] = model
        nr.inventory.hosts[host]["platform"] = "juniper"
        nr.inventory.hosts[host]["version"] = version
    with open("firmware.yaml", "r", encoding="UTF-8") as firmware_definitions_raw:
        firmware_definitions = yaml.load(
            firmware_definitions_raw, Loader=yaml.FullLoader
        )
    for host in nr.inventory.hosts:
        current_version = nr.inventory.hosts[host]["version"]
        target_version = firmware_definitions["device_types"][
            nr.inventory.hosts[host].data["model"]
        ]["release"]
        logger.info("%s: Upgrade from %s to %s", host, current_version, target_version)
    proceed = input("\nProceed? (yes/no): ")
    if proceed not in ("yes", "y"):
        sys.exit()
    nr.run(task=upgrade_junos, firmware_definitions=firmware_definitions)


if __name__ == "__main__":
    main()
