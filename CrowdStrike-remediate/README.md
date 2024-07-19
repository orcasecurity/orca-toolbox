# Orca Security Tool for Remediating CrowdStrike 19-07-2024 Incident #

This tool is designed to help you quickly identify and remediate the CrowdStrike 19-07-2024 incident in your AWS account.

## Pre-requisites ##
* An AWS EC2 instance running Linux OS with Python 3.11 or higher
  * We recommend creating a new instance running the latest official Ubuntu image
  * **The instance must be in the same availablitity zone as the affected instances**
* An AWS IAM role, attached to the instance, with the following permissions:
  * `ec2:StartInstances`
  * `ec2:StopInstances`
  * `ec2:DescribeVolumes`
  * `ec2:AttachVolume`
  * `ec2:DetachVolume`
* `boto3` Python package installed on the instance
  * you can install this package using `pip3 install boto3`
* `ntfs-3g` and `ec2metadata` packages installed on the instance
  * you can install these packages using `sudo apt-get install ntfs-3g ec2metadata`

## Usage ##
1. Identify the instance(s) affected by the CrowdStrike 19-07-2024 incident
2. Clone this `main.py` to your EC2 instance
3. Run the script using `python3 main.py --instance-ids <instance_id>,<instance_id>,...`

## Disclaimer ##
This tool is provided as-is and without warranties or guarantees.  
We recommend testing this tool in a non-production environment before using it in production.  
Always ensure you have proper backups and permissions in place before running the script.
