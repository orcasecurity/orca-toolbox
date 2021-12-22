# GCP-Storage-Explorer

The script crawls through all of the accessible projects in your GCP account (according to your token's access level) and determines which compute engine instances have access to all storage data within the scope of their project. 
This is accomplished by enumerating all compute engine instances with the proper permissions (such as 'devstorage.read write' 'devstorage.full control' storage.objects.get' and more).
You can use the instance's token or enter your own user credentials in the script.
Examine the results to quickly identify which compute engine instances have read permissions on storage data (given unintentionally via inheritance) and remove them where they aren't needed.

# Disclaimer
This tool is for testing and educational purposes only. 
Any other usage for this code is not allowed. Use at your own risk.
The author bears NO responsibility for misuse of this tool.
By using this you accept the fact that any damage caused by the use of this tool is your responsibility.

# Dependencies
1. Install the gcloud sdk prior running the script. You can get the installation instructions for your OS here: https://cloud.google.com/sdk/docs/install
2. Sudo apt-get install jq

# Usage
./gcp-storage-explorer.sh -o results.txt

# TODO
Add iteration for organizations level

# Author
<a href="https://twitter.com/ellicho007">Liat Vaknin</a>
