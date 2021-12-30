# Azure Managed Identity Explorer

The script iterates through all the managed-identities in a tenant and searches for the vulnerabilities 
described in
https://orca.security/resources/blog/azure-ad-iam-ii-privilege-escalation-managed-identities/


## Disclaimer
This tool is for testing and educational purposes only.

Any other usage for this code is not allowed. Use at your own risk.

The author bears NO responsibility for misuse of this tool.

By using this you accept the fact that any damage caused by the use of this tool is your responsibility.


## Installation 
The tools is packaged as .whl file and can be installed using pip


## Dependencies
The following python modules are necessary:
1. msrest.authentication
2. azure.common
3. azure.graphrbac
4. azure.mgmt
5. azure.core.pipeline
6. json

   
## Usage
1. Login to az cli
2. Run main.py


## Author
Roee Sagi