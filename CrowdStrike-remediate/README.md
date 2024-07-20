# Orca Security Tool for Remediating CrowdStrike 2024-07-19 Incident #

This tool is designed to help you quickly identify and remediate the CrowdStrike 2024-07-19 incident in your AWS account.

## Pre-requisites ##

* An AWS EC2 instance running Linux OS with Python 3.11 or higher
  * We recommend creating a new instance running the latest official Ubuntu image
  * **The instance must be in the same availablitity zone as the affected instances**
* An AWS IAM role, attached to the instance, with the following permissions:
  * `ec2:StartInstances`
  * `ec2:StopInstances`
  * `ec2:DescribeInstances`
  * `ec2:DescribeVolumes`
  * `ec2:AttachVolume`
  * `ec2:DetachVolume`
* `ntfs-3g` and `ec2metadata` packages installed on the instance
  * you can install these packages using `sudo apt-get install ntfs-3g ec2metadata`
* (Optional) `poetry` Python package installed on the instance
  * You can install this package using `pip3 install poetry`
  * This is only required if you want to use the virtual environment created by poetry

## Usage ##

> [!IMPORTANT]
> The following steps should be performed on the instance created in the pre-requisites section as
> the root user.

1. Identify the instance(s) affected by the CrowdStrike 19-07-2024 incident
1. Clone this repository to the instance
1. Change directory to the repository root

    ```bash
    cd orca-toolbox/CrowdStrike-remediate
    ```

1. (Recommended) Run `poetry install` to install the required Python dependencies in a virtual environment,

    **OR**

    Install the dependencies manually using `pip3 install -r requirements.txt`

### If you are using poetry ###

* Run the following command to start the tool

    ```bash
    poetry run python main.py --instance-ids <instance_id>,<instance_id>,...
    ```

### If you are *not* using poetry ###

* Run the following command to start the tool

    ```bash
    python3 main.py --instance-ids <instance_id>,<instance_id>,...
    ```

## Disclaimer ##

This tool is provided as-is and without warranties or guarantees.
We recommend testing this tool in a non-production environment before using it in production.
Always ensure you have proper backups and permissions in place before running the script.
