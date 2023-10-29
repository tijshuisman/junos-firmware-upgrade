import logging

from nornir import InitNornir
from nornir.core.inventory import ConnectionOptions
from nornir.core.filter import F
from nornir_pyez.plugins.tasks import pyez_facts, pyez_rpc
from nornir_netmiko.tasks import netmiko_send_command


nr = InitNornir(config_file="config.yaml")
logger = logging.getLogger("nornir")


def main():
    """
    Perform post upgrade actions.
    These actions include:
    - Cleanup storage
    - Create snapshots
    - Set rescue config
    """

    nr.inventory.defaults.connection_options["pyez"] = ConnectionOptions(
        extras={"rpc_timeout": 7200}
    )
    nr.inventory.defaults.connection_options["netmiko"] = ConnectionOptions(
        extras={"device_type": "juniper"}
    )
    facts_result = nr.run(task=pyez_facts)
    for host in facts_result:
        model = facts_result[host].result["model"].split("-")[0]
        nr.inventory.hosts[host]["model"] = model
        nr.inventory.hosts[host]["platform"] = "juniper"

    extras_cleanup = {"all_members": True}
    nr.run(task=pyez_rpc, func="request-system-storage-cleanup", extras=extras_cleanup)
    nr.filter(F(model="EX3400") | F(model="EX2300") | F(model="EX4100")).run(
        task=pyez_rpc, func="request-snapshot"
    )
    extras_snapshot_recovery_ex3400 = {"recovery": True}
    nr.filter(F(model="EX3400") | F(model="EX2300") | F(model="EX4100")).run(
        task=pyez_rpc, func="request-snapshot", extras=extras_snapshot_recovery_ex3400
    )
    extras_snapshot_recovery_ex4200 = {"slice": "alternate"}
    nr.filter(F(model="EX4200")).run(
        task=pyez_rpc, func="request-snapshot", extras=extras_snapshot_recovery_ex4200
    )
    nr.run(
        task=netmiko_send_command,
        command_string="request system configuration rescue save",
    )


if __name__ == "__main__":
    main()
