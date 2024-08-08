#!/usr/bin/env python3

# This file is part of cloud-init. See LICENSE file for license information.
"""Handle reconfiguration on mount events."""
import argparse
import logging
import os
import subprocess
import sys
from cloudinit.subp import ProcessExecutionError, subp

from cloudinit import log, reporting
from cloudinit.reporting import events
from cloudinit.stages import Init

LOG = logging.getLogger(__name__)
NAME = "mount-hook"


def generate_blkid_command(label=None, uuid=None, partuuid=None):
    """
    Generate the blkid command based on provided parameters.

    Only one of label, UUID, or PARTUUID should be provided.

    :param label: The label of the partition.
    :param uuid: The UUID of the partition.
    :param partuuid: The PARTUUID of the partition.
    :return: A list representing the blkid command.
    """

    if sum(1 for i in [label, uuid, partuuid] if i is not None) != 1:
        raise ValueError(
            "Exactly one of label, uuid, or partuuid must be specified"
        )

    cmd = ["blkid", "-o", "device"]

    if label:
        cmd += ["-t", f"LABEL={label}"]
    elif uuid:
        cmd += ["-t", f"UUID={uuid}"]
    elif partuuid:
        cmd += ["-t", f"PARTUUID={partuuid}"]

    return cmd

def generate_all_blkid_commands(query: str):
    """
    Generate all possible blkid commands based on query.
    Will try it as block device, label, UUID, and PARTUUID.
    """

    return [
        ["blkid", "-o", "device", query],
        ["blkid", "-o", "device", "-t", f"LABEL={query}"],
        ["blkid", "-o", "device", "-t", f"UUID={query}"],
        ["blkid", "-o", "device", "-t", f"PARTUUID={query}"],
    ]

def get_block_device_from_query(query: str):
    """
    Will return the path of the block device if it exists, otherwise None.
    """

    for cmd in generate_all_blkid_commands(query):
        try:
            result = subp(cmd)
            if result:
                LOG.debug(f"Device from query '{query}' exists: {result}")
            return result
        except ProcessExecutionError:
            continue
    return False


def get_device_path(label=None, uuid=None, partuuid=None, block_device=None):
    """
    Get the device path using label, UUID, PARTUUID, or block device.

    :param label: The label of the partition.
    :param uuid: The UUID of the partition.
    :param partuuid: The PARTUUID of the partition.
    :param block_device: The block device path.
    :return: The device path or None if not found.
    """
    if block_device:
        if not os.path.exists(block_device):
            LOG.error(f"Block device {block_device} does not exist")
            return None
        return block_device

    try:
        cmd = generate_blkid_command(label=label, uuid=uuid, partuuid=partuuid)
        result = subprocess.run(
            cmd, capture_output=True, text=True, check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        LOG.error(f"Failed to get device path: {e}")
        return None


def mount_device(device, mount_point):
    """
    Mount the device to the mount point.

    :param device: The device to mount.
    :param mount_point: The mount point directory.
    """
    try:
        LOG.debug(f"running mount command: mount {device} {mount_point}")
        subprocess.run(["mount", device, mount_point], check=True)
        LOG.info(f"Mounted {device} to {mount_point} successfully")
    except subprocess.CalledProcessError as e:
        LOG.error(f"Failed to mount {device} to {mount_point}: {e}")


def query_mount_status(
    label: str = None,
    uuid: str = None,
    partuuid: str = None,
    blockdevice: str = None,
):
    """
    Query the device path using the provided identifier.

    :param label: The label of the partition to retrieve.
    :param uuid: The UUID of the partition to retrieve.
    :param partuuid: The PARTUUID of the partition to retrieve.
    :param blockdevice: The block device path to retrieve.
    """
    identifiers = [label, uuid, partuuid, blockdevice]
    if sum(1 for i in identifiers if i is not None) != 1:
        raise ValueError(
            "Exactly one of blockdevice, label, uuid, or partuuid must be "
            "specified"
        )

    device = get_device_path(
        label=label, uuid=uuid, partuuid=partuuid, block_device=blockdevice
    )
    if device:
        print(f"Device path: {device}")
    else:
        print("Device not found")


def mount_device_command(
    mountpoint: str,
    label: str = None,
    uuid: str = None,
    partuuid: str = None,
    blockdevice: str = None,
):
    """
    Handle the mount event based on the provided action.

    :param mountpoint: The mount point directory (mandatory).
    :param label: The label of the partition to mount.
    :param uuid: The UUID of the partition to mount.
    :param partuuid: The PARTUUID of the partition to mount.
    :param blockdevice: The block device path.
    """
    if not mountpoint:
        raise ValueError("Mount point is required")

    identifiers = [label, uuid, partuuid, blockdevice]
    if sum(1 for i in identifiers if i is not None) != 1:
        raise ValueError(
            "Exactly one of blockdevice, label, uuid, or partuuid must be specified"
        )

    # Ensure the mount point directory exists
    if not os.path.exists(mountpoint):
        LOG.info(f"Creating mount point directory {mountpoint}")
        subp(["mkdir", "-p", mountpoint]) # THIS FAILS WITH A PERMISSION DENIED ERROR

    # Get the device path
    device = get_device_path(
        label=label, uuid=uuid, partuuid=partuuid, block_device=blockdevice
    )
    if device:
        # Mount the device
        mount_device(device, mountpoint)
    else:
        LOG.error("Device not found")


def get_cloud_init_fstab_entries() -> list[tuple[str, str]]:
    """
    Get all cloud-init generated fstab entries and return the source and target.

    :return: A tuple containing the source and target of the cloud-init fstab entry.
    """
    cloud_init_fstab = "/etc/fstab"
    results = []
    with open(cloud_init_fstab, "r") as f:
        for line in f:
            line = line.strip()
            if line.startswith("#"):
                continue
            if "cloud-init" in line:
                source, target, *_ = line.split()
                results.append((source, target))
    return results  



def handle_mount_event(udevaction: str, blockdevice: str):
    # get all cloudinit fstab entries
    # ignore any that are already mounted
    # then run get_block_device_from_query and see if it matches blockdevice
    # if it does, then mount it to the target
    # if it doesn't, then do nothing

    if udevaction != "add":
        raise ValueError("Only 'add' udev action is supported")
    
    fstab_entries = get_cloud_init_fstab_entries()
    for source, target in fstab_entries:
        if os.path.ismount(target):
            LOG.debug(f"Ignoring fstab entry {source} {target} as it is already mounted")
        found_device = get_block_device_from_query(source).stdout.strip()
        if found_device == blockdevice:
            LOG.info(f"Hotplugged block device {blockdevice} matches {source}")
            mount_device(device=blockdevice, mount_point=target)
            LOG.info(f"Mounted {blockdevice} to {target}")
            break

    # now check if all cloud-init fstab entries are mounted
    everything_mounted = True
    for source, target in fstab_entries:
        if not os.path.ismount(target):
            LOG.info(
                f"Source '{source}' is not yet mounted to '{target}'. "
                "Will keep udev rule and systemd service until all cloudinit "
                "fstab entries are mounted."    
            )
            everything_mounted = False
            break
    
    if everything_mounted:
        LOG.info("All cloud-init fstab entries are mounted. Removing udev rule and systemd service.")
        # remove udev rule 
        udev_path = "/etc/udev/rules.d/66-cloud-init-mount-hook.rules"
        try: 
            subp(["rm",  udev_path])
        except ProcessExecutionError as e:
            LOG.error(f"Failed to remove {udev_path}: {e}")
        
        # remove systemd service
        service_path = "/etc/systemd/system/cloud-init-mount-hook@.service"
        try:
            subp(["rm", service_path])
        except ProcessExecutionError as e:
            LOG.error(f"Failed to remove {service_path}: {e}")




def handle_args(name, args):
    """
    Handle the parsed command-line arguments.

    :param name: The name of the utility.
    :param args: The parsed arguments.
    """
    mount_reporter = events.ReportEventStack(
        name, __doc__, reporting_enabled=True
    )

    mount_init = Init(ds_deps=[], reporter=mount_reporter)
    mount_init.read_cfg()

    log.setup_logging(mount_init.cfg)
    if "reporting" in mount_init.cfg:
        reporting.update_configuration(mount_init.cfg.get("reporting"))

    # if blockdevice doesn't start with /dev, then check for it in /dev
    if args.blockdevice and not args.blockdevice.startswith("/dev"):
        if os.path.exists(f"/dev/{args.blockdevice}"):
            args.blockdevice = f"/dev/{args.blockdevice}"   
        else:
            LOG.error(f"Could not find full path for shorthand device {args.blockdevice}")

    LOG.debug(
        "%s called with the following arguments: {"
        "mount_hook_action: %s, udevaction: %s, blockdevice: %s}",
        name,
        args.mount_hook_action,
        args.udevaction if "udevaction" in args else None,
        args.blockdevice if "blockdevice" in args else None,
    )

    with mount_reporter:
        try:
            if args.mount_hook_action == "query":
                query_mount_status(
                    label=args.label,
                    uuid=args.uuid,
                    partuuid=args.partuuid,
                    blockdevice=args.blockdevice,
                )
            elif args.mount_hook_action == "mount":
                mount_device_command(
                    mountpoint=args.mountpoint,
                    label=args.label,
                    uuid=args.uuid,
                    partuuid=args.partuuid,
                    blockdevice=args.blockdevice,
                )
            elif args.mount_hook_action == "handle":
                handle_mount_event(
                    udevaction=args.udevaction,
                    blockdevice=args.blockdevice,
                )
            else:
                if os.getuid() != 0:
                    sys.stderr.write(
                        "Root is required. Try prepending your command with"
                        " sudo.\n"
                    )
                    sys.exit(1)

        except Exception:
            LOG.exception("Received fatal exception handling mount!")
            raise

    LOG.debug("Exiting mount handler")
    reporting.flush_events()


def get_parser(parser=None):
    """
    Build or extend an arg parser for mount-hook utility.

    :param parser: Optional existing ArgumentParser instance representing the subcommand.
    :return: ArgumentParser with proper argument configuration.
    """
    if not parser:
        parser = argparse.ArgumentParser(prog=NAME, description=__doc__)

    parser.description = __doc__

    subparsers = parser.add_subparsers(
        title="Mount Hook Action",
        dest="mount_hook_action",
    )
    subparsers.required = True

    query_parser = subparsers.add_parser(
        "query",
        help="Detect the device path based on provided identifier.",
    )
    query_parser.add_argument(
        "--label",
        help="Check for existing block device path using label",
    )
    query_parser.add_argument(
        "--uuid",
        help="Check for existing block device path using UUID",
    )
    query_parser.add_argument(
        "--partuuid",
        help="Check for existing block device path using PARTUUID",
    )
    query_parser.add_argument(
        "--blockdevice",
        help="Check for existing block device path",
    )

    handle_parser = subparsers.add_parser(
        "handle",
        help="Handle the mount event",
    )
    handle_parser.add_argument(
        "--udevaction",
        required=True,
        help="Specify udev action",
        choices=["add", "remove"],
    )
    handle_parser.add_argument(
        "--blockdevice",
        help="Block device path that triggered the udev event",
    )

    mount_parser = subparsers.add_parser(
        "mount",
        help="Mount given device to the mount point",
    )
    mount_parser.add_argument(
        "--label",
        help="Label of the partition to mount",
    )
    mount_parser.add_argument(
        "--uuid",
        help="UUID of the partition to mount",
    )
    mount_parser.add_argument(
        "--partuuid",
        help="PARTUUID of the partition to mount",
    )
    mount_parser.add_argument(
        "--blockdevice",
        help="Block device path (e.g., /dev/sdb1)",
    )
    mount_parser.add_argument(
        "--mountpoint",
        required=True,
        help="Mount point directory",
    )

    return parser


if __name__ == "__main__":
    args = get_parser().parse_args()
    handle_args(NAME, args)
