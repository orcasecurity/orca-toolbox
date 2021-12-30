from azure.common.client_factory import get_client_from_cli_profile
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.graphrbac import GraphRbacManagementClient
from azure_identity_credential_adapter import AzureIdentityCredentialAdapter
import json

ROOT_MANAGEMENT_GROUP = "rootManagementGroup"
MANAGEMENT_GROUP = "managementGroups"
SUBSCRIPTION = "subscriptions"
RESOURCE_GROUP = "resourceGroups"
PERMISSIVE_SCOPES = [ROOT_MANAGEMENT_GROUP, MANAGEMENT_GROUP, SUBSCRIPTION, RESOURCE_GROUP]

PERMISSIVE_ROLES = ["Owner", "Contributor", "User Access Administrator",
                    "Service Administrator", "Co-Administrator", "Account Administrator"]
ESCALATION_ROLES = ["Website Contributor", "Logic App Contributor"]
PROVIDERS_DICT = {
    "Website Contributor": "Microsoft.Web/sites",
    "Logic App Contributor": "Microsoft.Logic"
}


def auth():

    with open("config.json") as f:
        config = json.loads(f.read())

    if not config:
        print("[+] No Configuration File, Exit...")
        return None, None

    tenant_id = config["TENANT_ID"]
    subscription_id = config["SUBSCRIPTION_ID"]

    if not (tenant_id and subscription_id):
        raise Exception("There is no subscription and tenant in the config file.")

    # Auth client creds
    credentials = AzureIdentityCredentialAdapter()
    credentials.set_token()

    # Rbac client creds
    rbac_credentials = AzureIdentityCredentialAdapter(resource_id="https://graph.windows.net")
    rbac_credentials.set_token()
    graph_rbac_client = get_client_from_cli_profile(GraphRbacManagementClient, tenant_id=tenant_id, subscription_id=subscription_id)

    auth_client = AuthorizationManagementClient(
        credentials=credentials,
        subscription_id=subscription_id
    )

    return graph_rbac_client, auth_client


def calc_scope(resource_id):
    """
    Returns the ARM level for a specific scope id

    Examples for ids:
    "/"
    "/providers/Microsoft.Management/managementGroups/aaaaa07d-7f78-cccc-96aa-eeeeea597f2f"
    "/subscriptions/aaaaa07d-7f78-cccc-96aa-eeeeea597f2f"
    "/subscriptions/aaaaa07d-7f78-cccc-96aa-eeeeea597f2f/resourceGroups/Functions-RG"
    "/subscriptions/aaaaa07d-7f78-cccc-96aa-eeeeea597f2f/resourceGroups/ORCA-SECURITY/providers/Microsoft.Compute/virtualMachines/vm1"
    """
    scope = resource_id.split("/")[-2]

    if not scope:
        return ROOT_MANAGEMENT_GROUP

    return scope


def run():

    print("[+] MI-Explorer started")

    # Initialize rbac, auth clients
    print("[+] Authenticating using cli credentials")
    graph_rbac_client, auth_client = auth()

    if not graph_rbac_client or not auth_client:
        raise Exception("[+] Authenticating failed. Run 'az login'")

    print("[+] Authentication completed\n[+] Attack vectors found: \n")

    # List service principals
    sp_list = list(graph_rbac_client.service_principals.list())
    sp_dict = {}
    susp_users = []
    attack_vec_cnt = 0

    # Create dictionary of active service principals who belongs to managed-identities
    for sp in sp_list:
        # Filter enabled accounts with managed-identity type to exclude applications
        if sp.additional_properties.get("accountEnabled") and sp.additional_properties.get("servicePrincipalType") == "ManagedIdentity":
            sp_dict[sp.object_id] = {"name": sp.display_name, "alternative_name": sp.additional_properties.get('alternativeNames')[1],
                                     "role_assignments": []}

    # List role assignments
    assignments = list(auth_client.role_assignments.list())

    for role_assignment in assignments:
        principal_id = role_assignment.principal_id
        result = auth_client.role_definitions.get_by_id(role_assignment.role_definition_id)
        role_name = result.role_name
        role_type = result.role_type

        # Add to the dictionary the role assignments for every service principal
        if principal_id in sp_dict.keys():
            scope = calc_scope(role_assignment.scope)
            assignment_dict = {"role_name": role_name, "role_type": role_type, "scope": scope,
                               "full_scope": role_assignment.scope}

            if sp_dict[principal_id]["role_assignments"]:
                sp_dict[principal_id]["role_assignments"].append(assignment_dict)
            else:
                sp_dict[principal_id]["role_assignments"] = [assignment_dict]

        # Add users with the mentioned roles
        if role_name in ESCALATION_ROLES:
            obj_user = list(graph_rbac_client.users.list(filter=f"objectId eq '{principal_id}'"))[0]
            if obj_user and obj_user.account_enabled:
                user_dict = {
                    "display_name": obj_user.display_name,
                    "object_id": obj_user.object_id,
                    "user_type": obj_user.user_type,
                    "role_name": role_name,
                    "role_type": role_type,
                    "scope": role_assignment.scope
                }
                susp_users.append(user_dict)

    attack_vec_cnt = len(susp_users
                         )
    # Find the permissive managed-identities
    for key in sp_dict.keys():
        sp = sp_dict[key]

        for assignment in sp["role_assignments"]:

            # First Vector - User-Assigned Managed-Identity with permissions in the subscription
            if (assignment["scope"] in PERMISSIVE_SCOPES) \
                    and "userAssignedIdentities" in sp["alternative_name"]:
                print(
                    "[+] Privilege Escalation Path - User-Assigned Managed-Identity with permissions in the "
                    "Resource Group scope or above")
                print("ֿ\t", sp)
                attack_vec_cnt += 1

            # Second Vector - Permissive Managed-Identities in resource group level and above
            elif assignment["role_name"] in PERMISSIVE_ROLES and assignment["scope"] in PERMISSIVE_SCOPES:
                print("[+] Privilege Escalation Path - Permissive Managed-Identity")
                print("ֿ\t", sp)
                attack_vec_cnt += 1

            # Third Vector - Custom Role in resource group level and above
            elif assignment["role_type"] != "BuiltInRole" and assignment["scope"] in PERMISSIVE_SCOPES:
                print("[+] Privilege Escalation Path - Custom Role for Managed-Identity")
                print("ֿ\t", sp)
                attack_vec_cnt += 1

        # Fourth Vector - Role Assignment which allows escalation to privileged managed-identity
        for user in susp_users:
            if user["scope"] in sp['alternative_name'] and \
                    PROVIDERS_DICT.get(user["role_name"]) in sp['alternative_name']:
                print(
                    f"[+] The user {user['display_name']}  with scope {user['scope']} can escalate to the following",
                    f"managed-identity : {sp}")

    if not attack_vec_cnt:
        print("[+] Did not find any attack vectors.")


if __name__ == '__main__':
    run()
