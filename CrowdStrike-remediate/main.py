import argparse
import glob
import os
import re
import subprocess
import time

import boto3


# Function to stop an instance
def stop_instance(ec2_client, instance_id):
    ec2_client.stop_instances(InstanceIds=[instance_id])
    waiter = ec2_client.get_waiter("instance_stopped")
    waiter.wait(InstanceIds=[instance_id])


# Function to start an instance
def start_instance(ec2_client, instance_id):
    ec2_client.start_instances(InstanceIds=[instance_id])
    waiter = ec2_client.get_waiter("instance_running")
    waiter.wait(InstanceIds=[instance_id])


# Function to detach volumes
def detach_volumes(ec2_client, instance_id):
    volumes = ec2_client.describe_volumes(
        Filters=[{"Name": "attachment.instance-id", "Values": [instance_id]}]
    )
    for volume in volumes["Volumes"]:
        volume_id = volume["VolumeId"]
        res = ec2_client.detach_volume(VolumeId=volume_id)
        waiter = ec2_client.get_waiter("volume_available")
        waiter.wait(VolumeIds=[volume_id])
        yield volume_id, res["Device"]


# Function to attach volume to the current instance
def attach_volume(ec2_client, instance_id, volume_id, device):
    ec2_client.attach_volume(InstanceId=instance_id, VolumeId=volume_id, Device=device)
    waiter = ec2_client.get_waiter("volume_in_use")
    waiter.wait(VolumeIds=[volume_id])


# Function to detach volume from the current instance
def detach_volume(ec2_client, volume_id):
    ec2_client.detach_volume(VolumeId=volume_id)
    waiter = ec2_client.get_waiter("volume_available")
    waiter.wait(VolumeIds=[volume_id])


# Function to remove the file
def remove_crowdstrike_file(mount_point):
    file_pattern = (
        f"{mount_point}/Windows/System32/drivers/CrowdStrike/C-00000291*.sys"
    )
    for file in glob.glob(file_pattern):
        os.remove(file)


# Function to get the device name
def get_device_name():
    res = (
        subprocess.run(["fdisk -l"], capture_output=True, shell=True)
        .stdout.decode()
    )
    for line in res.splitlines():
        if "NTFS" in line:
            device_name = line.split(" ")[0]
            return device_name
    return ""


def main() -> None:
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument(
        "--instance-ids", required=True, help="Instance IDs to remediate"
    )
    args = arg_parser.parse_args()

    vms_to_remediate = (
        args.instance_ids.split(",")
        if "," in args.instance_ids
        else args.instance_ids.split(" ")
    )

    mount_point = "/mnt/windows"
    os.makedirs(mount_point, exist_ok=True)
    region = (
        subprocess.run(
            "ec2metadata --availability-zone", capture_output=True, shell=True
        )
        .stdout.decode()
        .strip()
    )[:-1]
    self_instance_id = (
        subprocess.run(
            "ec2metadata --instance-id", capture_output=True, shell=True
        )
        .stdout.decode()
        .strip()
    )
    ec2_client = boto3.client("ec2", region_name=region)

    for instance_id in vms_to_remediate:
        stop_instance(ec2_client, instance_id)
        for volume_id, device in detach_volumes(ec2_client, instance_id):
            attach_volume(
                ec2_client=ec2_client,
                instance_id=self_instance_id,
                volume_id=volume_id,
                device="/dev/sdf",
            )
            device_name = ""
            for retry in range(12):
                device_name = get_device_name()
                if device_name:
                    break
                time.sleep(2)
            subprocess.run(["mount", device_name, mount_point])
            remove_crowdstrike_file(mount_point)
            subprocess.run(["umount", mount_point])

            detach_volume(ec2_client, volume_id)
            attach_volume(ec2_client, instance_id, volume_id, device)

        start_instance(ec2_client, instance_id)


if __name__ == "__main__":
    main()
