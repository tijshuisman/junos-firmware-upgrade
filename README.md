> [!IMPORTANT]
> Python version 3.11 and 3.12 are not supported due to an issue with py-junos-eznc .

# JUNOS firmware upgrade tooling

This repository contains several scripts to help with automated upgrades on EX series JUNOS switches. The scripts are setup in a way so that a large amount of JUNOS switches can be upgraded simultaneously.

# Features

* Steps in the firmware upgrade process are seperated in several scripts. This way the pushing of the firmware files and the installation can be done in advance
* Tested on various EX non-chassis switches (EX2300/EX3400/EX4100/EX4200/EX4600)
* By default the scripts will execute on 10 switches in parallel

# Usage

The scripts are tested on Linux and Mac OS.

## Inventory

The scripts use the SimpleInventory plugin included with Nornir. The switches to be upgraded should be added in the file inventory/hosts.yaml.
An example is included in the inventory/ folder.

More documentation about the inventory file can be found in the [Nornir documentation](https://nornir.readthedocs.io/en/latest/tutorial/inventory.html).

## Authentication

Switch authentication parameters can be set through environment variables.
```
export NORNIR_USERNAME=your_tacacs_user
export NORNIR_PASSWORD=your_tacacs_password
```

## Firmware files

The firmware files are defined in firmware.yaml.

## Scripts

The order that the scripts should be run in is:

1. pre_upgrade.py
  - Storage cleanup
  - Delete all snapshots (EX2300/EX3400/EX4100 only)
  - Verify that there is storage space available for the firmware upgrade (EX2300/EX3400 only)
  - Transfer the firmware file as defined in firmware.yaml
2. upgrade.py
  - Upgrade switch using `no-validate`, and in the case of an EX4600 use `force-host`
3. reboot.py
  - Performs a reboot on the switch to finish the firmware upgrade, in 60 seconds
4. post_upgrade.py
  - Storage cleanup
  - Create non-recovery and recovery snapshots (this step can take very long)
  - Set rescue config

# Future

* Script to validate that the installation was done succesfully.
* Ability to schedule the reboot.
* QFX5k support