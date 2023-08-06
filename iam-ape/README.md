<p align="center">
    <img src="https://raw.githubusercontent.com/orcasecurity/orca-toolbox/main/iam-ape/iam-ape.png" width="680" height="350">
</p>

## IAM AWS Policy Evaluator ##

APE takes all of your AWS IAM policies attached to a User, Group, or Role object, and presents you with a single policy,
summarizing all of their *actual* permissions.
Taking into account permissions, denials, inherited permissions and permission boundaries!

## Setup ##
*Requires Python >= 3.9*
### From PyPI ###
1. Run `pip install iam-ape`
2. Run `iam-ape`

### From source
1. Clone this repository
2. Change directory to iam_ape
3. Run `python -m pip install .`
4. Run `iam-ape`

## Usage ##
> #### Prerequisite ####
> Have [aws-cli](https://aws.amazon.com/cli/) installed on your machine and a profile with `aws:GetAccountAuthorizationDetails` permissions.  
Alternatively, have the json output from `aws iam get-account-authorization-details` saved to a file.  

> Before your first run, it's recommended to run `iam-ape --update` - this updates APE's database with the most current list of all available AWS IAM actions.  

The simplest way to use `iam-ape` is to simply run `iam-ape --arn <your-arn-here>`  
APE will then attempt to fetch the account authorization details, evaluate your permissions, and output a neatly formatted policy to stdout  
#### The `--input` flag: ####
If you don't want to fetch the report every time, you can run `aws iam get-account-authorization-details` by yourself and save the output to a json file. You can then pass that output to APE using the `--input` flag.

#### Additional flags: ####
`-o, --output` write the output to file instead of stdout  
`-f, --format (clean|verbose)` output the policy in _clean_, AWS policy-like JSON format, or a long _verbose_ JSON containing all specific actions allowed to the entity, the denied actions, and the ineffective (allowed in one place, denied in another) permissions.  
`-p, --profile` the AWS CLI profile to use when fetching Account Authorization Details  
`-u, --update` update APE's database with the most current list of all available AWS IAM actions  
`-v, --verbose` set logging level to DEBUG

**Important note**: the policy created by this tool might not always be compliant with AWS's constraints. For example, if a user is granted `ec2:AttachVolume` access to `arn:aws:ec2:*` by one policy, but denied access to `arn:aws:ec2:us-east-1:123456789012:instance/i-123456abc`, the resulting policy statement will look like this:
```json
{
    "Action": "ec2:AttachVolume",
    "Resource": "arn:aws:ec2:*",
    "NotResource": "arn:aws:ec2:us-east-1:123456789012:instance/i-123456abc"
}
```
This statement, having both `Resource` and `NotResource` together, is not supported by AWS but makes more sense when trying to understand what the effective permissions of a user are.

## Roadmap ##
- [ ] Add an option to supply a resource policy and evaluate whether the entity has access to that resource 
- [ ] Support additional permissions inherited by Role assumption
- [x] Support SCP Policies