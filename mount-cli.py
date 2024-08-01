#!/usr/bin/env python3

import argparse
import logging
import os
import subprocess
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def generate_blkid_command(label=None, uuid=None, partuuid=None):
    """Generate the blkid command based on provided parameters."""
    cmd = ["blkid", "-o", "device"]

    if label:
        cmd += ["-t", f"LABEL={label}"]
    elif uuid:
        cmd += ["-t", f"UUID={uuid}"]
    elif partuuid:
        cmd += ["-t", f"PARTUUID={partuuid}"]

    return cmd


def get_device_path(label=None, uuid=None, partuuid=None, block_device=None):
    """Get the device path using label, UUID, PARTUUID, or block device."""
    if block_device:
        # Check if the block device exists
        if not os.path.exists(block_device):
            logger.error(f"Block device {block_device} does not exist")
            return None
        return block_device

    try:
        cmd = generate_blkid_command(label=label, uuid=uuid, partuuid=partuuid)
        result = subprocess.run(
            cmd, capture_output=True, text=True, check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to get device path: {e}")
        return None


def mount_device(device, mount_point):
    """Mount the device to the mount point."""
    try:
        subprocess.run(["mount", device, mount_point], check=True)
        logger.info(f"Mounted {device} to {mount_point} successfully")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to mount {device} to {mount_point}: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Mount a device using various identifiers"
    )
    parser.add_argument(
        "-l", "--label", help="Label of the partition to mount"
    )
    parser.add_argument("-u", "--uuid", help="UUID of the partition to mount")
    parser.add_argument(
        "-p", "--partuuid", help="PARTUUID of the partition to mount"
    )
    parser.add_argument(
        "-b", "--blockdevice", help="Block device path (e.g., /dev/sdb1)"
    )
    parser.add_argument(
        "-m", "--mountpoint", required=True, help="Mount point directory"
    )

    args = parser.parse_args()

    # Ensure the mount point directory exists
    if not os.path.exists(args.mountpoint):
        logger.info(f"Creating mount point directory {args.mountpoint}")
        os.makedirs(args.mountpoint)

    # Get the device path
    device = get_device_path(
        label=args.label,
        uuid=args.uuid,
        partuuid=args.partuuid,
        block_device=args.blockdevice,
    )
    if device:
        # Mount the device
        mount_device(device, args.mountpoint)
    else:
        logger.error("Device not found")


def test_get_device_path():
    parser = argparse.ArgumentParser(description="Test device path retrieval")
    parser.add_argument(
        "-l", "--label", help="Label of the partition to retrieve"
    )
    parser.add_argument(
        "-u", "--uuid", help="UUID of the partition to retrieve"
    )
    parser.add_argument(
        "-p", "--partuuid", help="PARTUUID of the partition to retrieve"
    )
    parser.add_argument(
        "-b", "--blockdevice", help="Block device path to retrieve"
    )

    args = parser.parse_args()

    device = get_device_path(
        label=args.label,
        uuid=args.uuid,
        partuuid=args.partuuid,
        block_device=args.blockdevice,
    )
    if device:
        print(f"Device path: {device}")
    else:
        print("Device not found")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        # Remove 'test' argument before passing to parser
        sys.argv.pop(1)
        test_get_device_path()
    else:
        main()
