###########################################################################################################
#                    CrowdStrike Outage Remediation Script by Orca Security                               #
# Copyright 2024 Orca Security, Ltd.                                                                      #
# Always ensure you have proper backups and permissions in place before running the script.               #
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.                     #
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY. #
###########################################################################################################


import argparse
import glob
import logging
import os
import subprocess
import time

import boto3

logging.basicConfig(level=logging.INFO)
logging.getLogger("botocore").setLevel(logging.ERROR)
logger = logging.getLogger("main")


# Function to stop an instance
def stop_instance(ec2_client, instance_id, dry_run=False):
    logger.info(f"Attempting to stop instance {instance_id}")
    try:
        ec2_client.stop_instances(InstanceIds=[instance_id], DryRun=dry_run)
        waiter = ec2_client.get_waiter("instance_stopped")
        waiter.wait(InstanceIds=[instance_id])
    except Exception as e:
        if "DryRunOperation" not in str(e):
            logger.error(f"Failed to stop instance {instance_id}: {e}")


# Function to start an instance
def start_instance(ec2_client, instance_id, dry_run=False):
    logger.info(f"Attempting to start instance {instance_id}")
    try:
        ec2_client.start_instances(InstanceIds=[instance_id], DryRun=dry_run)
        waiter = ec2_client.get_waiter("instance_running")
        waiter.wait(InstanceIds=[instance_id])
    except Exception as e:
        if "DryRunOperation" not in str(e):
            logger.error(f"Failed to start instance {instance_id}: {e}")


# Function to detach volumes
def detach_volumes(ec2_client, instance_id, dry_run=False):
    logger.info(f"Attempting to detach volumes from instance {instance_id}")
    try:
        volumes = ec2_client.describe_volumes(
            Filters=[{"Name": "attachment.instance-id", "Values": [instance_id]}]
        )
    except Exception as e:
        if "DryRunOperation" not in str(e):
            logger.error(f"Failed to get volumes for instance {instance_id}: {e}")
        return

    logger.info(f"Found {len(volumes['Volumes'])} volumes to detach")
    for volume in volumes["Volumes"]:
        volume_id = volume["VolumeId"]
        try:
            logger.info(f"Detaching volume {volume_id}")
            res = ec2_client.detach_volume(VolumeId=volume_id, DryRun=dry_run)
            waiter = ec2_client.get_waiter("volume_available")
            waiter.wait(VolumeIds=[volume_id])
        except Exception as e:
            if "DryRunOperation" not in str(e):
                logger.error(f"Failed to detach volume {volume_id}: {e}")
            continue
        yield volume_id, res["Device"]


# Function to attach volume to the current instance
def attach_volume(ec2_client, instance_id, volume_id, device, dry_run=False):
    logger.info(f"Attempting to attach volume {volume_id} to instance {instance_id}")
    try:
        ec2_client.attach_volume(
            InstanceId=instance_id, VolumeId=volume_id, Device=device, DryRun=dry_run
        )
        waiter = ec2_client.get_waiter("volume_in_use")
        waiter.wait(VolumeIds=[volume_id])
    except Exception as e:
        if "DryRunOperation" not in str(e):
            logger.error(f"Failed to attach volume {volume_id}: {e}")


# Function to detach volume from the current instance
def detach_volume(ec2_client, volume_id, dry_run=False):
    logger.info(f"Attempting to detach volume {volume_id} from the current instance")
    try:
        ec2_client.detach_volume(VolumeId=volume_id, DryRun=dry_run)
        waiter = ec2_client.get_waiter("volume_available")
        waiter.wait(VolumeIds=[volume_id])
    except Exception as e:
        if "DryRunOperation" not in str(e):
            logger.error(f"Failed to detach volume {volume_id}: {e}")


# Function to remove the file
def remove_crowdstrike_file(mount_point):
    logger.info(f"Attempting to remove bad CrowdStrike file from {mount_point}")
    file_pattern = f"{mount_point}/Windows/System32/drivers/CrowdStrike/C-00000291*.sys"
    files = glob.glob(file_pattern)
    if not files:
        logger.warning(f"No matching CrowdStrike files found in {file_pattern}")
        return

    for file in files:
        try:
            os.remove(file)
            logger.info(f"Successfully removed {file}")
        except OSError as e:
            logger.error(f"Failed to remove {file}: {e}")
            raise
    logger.info("Exiting remove_crowdstrike_file")


# Function to get the device name
def get_device_name():
    res = subprocess.run(["fdisk -l"], capture_output=True, shell=True).stdout.decode()
    for line in res.splitlines():
        if "NTFS" in line:
            device_name = line.split(" ")[0]
            return device_name, "ntfs"
        elif "HPFS/NTFS/exFAT" in line:
            device_name = line.split(" ")[0]
            return device_name, "ntfs"
    return "", ""


# Function to check we have the required pre-requisites
def check_prereq():
    if os.geteuid() != 0:
        raise PermissionError("You need to be root to run this script")
    if subprocess.run(["which", "fdisk"], capture_output=True).returncode != 0:
        raise FileNotFoundError("fdisk not found")
    if subprocess.run(["which", "ec2metadata"], capture_output=True).returncode != 0:
        raise FileNotFoundError("ec2metadata not found")
    if subprocess.run(["which", "ntfs-3g"], capture_output=True).returncode != 0:
        raise FileNotFoundError("ntfs-3g not found")


def main() -> None:
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument(
        "--instance-ids", required=True, help="Instance IDs to remediate"
    )
    arg_parser.add_argument("--dry-run", action="store_true")
    args = arg_parser.parse_args()

    check_prereq()

    vms_to_remediate = (
        args.instance_ids.split(",")
        if "," in args.instance_ids
        else args.instance_ids.split(" ")
    )
    dry_run = args.dry_run

    region = (
        subprocess.run(
            "ec2metadata --availability-zone", capture_output=True, shell=True, check=False
        )
        .stdout.decode()
        .strip()
    )[:-1]
    self_instance_id = (
        subprocess.run("ec2metadata --instance-id", capture_output=True, shell=True, check=False)
        .stdout.decode()
        .strip()
    )
    ec2_client = boto3.client("ec2", region_name=region)

    mount_point = "/mnt/windows"
    os.makedirs(mount_point, exist_ok=True)

    for instance_id in vms_to_remediate:
        logger.info(f"Remediating instance {instance_id}")

        try:
            stop_instance(
                ec2_client=ec2_client, instance_id=instance_id, dry_run=dry_run
            )
        except Exception as e:
            logger.error(f"Failed to stop instance {instance_id}: {e}")
            continue

        for volume_id, device in detach_volumes(
            ec2_client=ec2_client, instance_id=instance_id, dry_run=dry_run
        ):
            try:
                attach_volume(
                    ec2_client=ec2_client,
                    instance_id=self_instance_id,
                    volume_id=volume_id,
                    device="/dev/sdf",
                    dry_run=dry_run,
                )
            except Exception as e:
                if "DryRunOperation" not in str(e):
                    logger.error(f"Failed to attach volume {volume_id}: {e}")
                    attach_volume(
                        ec2_client, instance_id, volume_id, device, dry_run=dry_run
                    )
                    continue

            try:
                device_name = ""
                fs_type = ""
                for retry in range(12):
                    logger.info(f"Attempt {retry + 1} to get device name")
                    device_name, fs_type = get_device_name()
                    if device_name:
                        break
                    time.sleep(2)

                logger.info(f"Found device name: {device_name}, FS type: {fs_type}")

                if not dry_run:
                    if fs_type == "ntfs":
                        # Prior to mounting, let's ensure we have a clean FS
                        logger.info("Attempting to fix NTFS filesystem prior to mounting")
                        subprocess.run(["ntfsfix", device_name], check=False)
                        mount_cmd = ["ntfs-3g", device_name, mount_point, "-o", "rw,force"]
                    else:
                        mount_cmd = ["mount", device_name, mount_point]
                    logger.info(f"Running mount command: {mount_cmd}")
                    subprocess.run(mount_cmd, capture_output=True, check=False)
                    logger.info("Attempting to remove CrowdStrike bad file")
                    remove_crowdstrike_file(mount_point)
                    subprocess.run(["umount", mount_point], capture_output=True, check=False)
            finally:
                detach_volume(ec2_client, volume_id, dry_run=dry_run)
                attach_volume(
                    ec2_client, instance_id, volume_id, device, dry_run=dry_run
                )

        start_instance(ec2_client, instance_id, dry_run=dry_run)


if __name__ == "__main__":
    main()
