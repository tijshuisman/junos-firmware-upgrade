import logging
import re
import yaml

from nornir import InitNornir
from nornir.core.task import Task
from nornir.core.filter import F
from nornir_pyez.plugins.tasks import pyez_facts, pyez_rpc, pyez_scp, pyez_checksum

nr = InitNornir(config_file="config.yaml")
logger = logging.getLogger('nornir')


def verify_freespace(task: Task) -> None:
    """Verify that the storage usage on all FPC's is <=57% before copying the firmware file."""
    show_system_storage = task.run(
        task=pyez_rpc,
        func="get-system-storage",
    )
    if isinstance(
        show_system_storage.result["multi-routing-engine-results"][
            "multi-routing-engine-item"
        ],
        list,
    ):
        for routing_engine in show_system_storage.result[
            "multi-routing-engine-results"
        ]["multi-routing-engine-item"]:
            for file_system in routing_engine["system-storage-information"][
                "filesystem"
            ]:
                if file_system["filesystem-name"] == "/dev/gpt/junos":
                    assert int(file_system["used-percent"]) <= 57, (
                        f"{task.host.name}-{routing_engine['re-name']}: storage usage over 57%. "
                        "Upgrade might fail because of too little space available! "
                        "Firmware file will not be transfered."
                    )
    else:
        for file_system in show_system_storage.result["multi-routing-engine-results"][
            "multi-routing-engine-item"
        ]["system-storage-information"]["filesystem"]:
            if file_system["filesystem-name"] == "/dev/gpt/junos":
                assert int(file_system["used-percent"]) <= 57, (
                    f"{task.host.name}-{routing_engine['re-name']}: storage usage over 57%. "
                    "Upgrade might fail because of too little space available! "
                    "Firmware file will not be transfered."
                )


def transfer_firmware(task: Task) -> None:
    """Transfer firmware file to the JUNOS switch."""
    with open("firmware.yaml", "r", encoding="UTF-8") as firmware_definitions_raw:
        firmware_definitions = yaml.load(
            firmware_definitions_raw, Loader=yaml.FullLoader
        )
    base_path = firmware_definitions["general"]["base_path"]
    firmware_file = firmware_definitions["device_types"][task.host["model"]]["file"]

    def log_transfer_progress(dev, report):
        percentage = re.search(r"\((.*)\)", report).groups(1)[0]
        logger.info("%s: firmware transfer %s", dev.hostname, percentage)

    scpargs = {"progress": log_transfer_progress}
    task.run(task=pyez_scp, file=f"{base_path}{firmware_file}", path="/var/tmp/", scpargs=scpargs)
    firmware_md5 = task.run(
        task=pyez_checksum, filepath=f"/var/tmp/{firmware_file}", calc="md5"
    )
    assert (
        firmware_md5.result == firmware_definitions["device_types"][task.host["model"]]["md5"]
    ), f"{task.host.name}: checksum of firmware file doesn't match original."


def main():
    """
    Prepare a JUNOS switch for a firmware upgrade.
    This is done by:
    - Storage cleanup
    - Delete all snapshots (EX2300/3400/EX4100 only)
    - Verify that there is storage space available for the firmware upgrade (EX2300/3400/EX4100 only)
    - Transfer the firmware file as defined in firmware.yaml
    """
    facts = nr.run(task=pyez_facts)
    for host in facts:
        model = facts[host].result["model"].split("-")[0]
        nr.inventory.hosts[host]["model"] = model
        nr.inventory.hosts[host]["platform"] = "juniper"
    nr.run(task=pyez_rpc, func="request-system-storage-cleanup")

    delete_extras = {"delete": "*"}
    nr.filter(F(model="EX3400") | F(model="EX2300")| F(model="EX4100")).run(
        task=pyez_rpc, func="request-snapshot", extras=delete_extras
    )
    nr.filter(F(model="EX3400") | F(model="EX2300")| F(model="EX4100")).run(task=verify_freespace)
    nr.run(task=transfer_firmware)


if __name__ == "__main__":
    main()
