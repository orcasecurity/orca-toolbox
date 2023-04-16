import argparse
import json
import logging
import os
import re
import sys
from typing import Any, Dict, Optional, Union, List, Tuple

import boto3  # type: ignore
from botocore.exceptions import AccessDeniedException, AWSOrganizationsNotInUseException, ProfileNotFound  # type: ignore

from iam_ape.aws_iam_actions.scrape_iam_actions import scrape_iam_actions
from iam_ape.evaluator import AuthorizationDetails, EffectivePolicyEvaluator
from iam_ape.helper_classes import PolicyWithSource
from iam_ape.helper_functions import deep_update
from iam_ape.helper_types import (
    AwsPolicyType,
    EntityType,
    FinalReportT,
)

logger = logging.getLogger("IAM-APE")
entity_regex_string = r"arn:aws(-cn|-us-gov)?:iam::(?P<account>\d{12}):(?P<entity_type>user|group|role)/[\w-]+"
entity_regex = re.compile(entity_regex_string)

banner = """
  __   __   _  _        __   ____  ____ 
 (  ) / _\ ( \/ ) ___  / _\ (  _ \(  __)
  )( /    \/ \/ \(___)/    \ ) __/ ) _) 
 (__)\_/\_/\_)(_/     \_/\_/(__)  (____)
 By Orca Security  https://orca.security
"""


class LogFormatter(logging.Formatter):
    err_fmt = "ERROR: %(msg)s"
    dbg_fmt = "DBG: %(module)s: %(lineno)d: %(msg)s"
    info_fmt = "%(msg)s"

    def __init__(self):
        super().__init__(fmt="%(levelno)d: %(msg)s", datefmt=None, style="%")

    def format(self, record):
        format_orig = self._style._fmt

        if record.levelno == logging.DEBUG:
            self._style._fmt = LogFormatter.dbg_fmt

        elif record.levelno == logging.INFO:
            self._style._fmt = LogFormatter.info_fmt

        elif record.levelno == logging.ERROR:
            self._style._fmt = LogFormatter.err_fmt

        result = logging.Formatter.format(self, record)

        self._style._fmt = format_orig

        return result


def print_banner() -> None:
    logger.info("\033[93m" + banner + "\033[0m")


def initialize_logger() -> None:
    format = LogFormatter()
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(format)
    logging.root.addHandler(handler)
    logging.root.setLevel(logging.INFO)


def validate_arn(arn: str) -> Tuple[EntityType, str]:
    regex_match = entity_regex.fullmatch(arn)
    try:
        assert regex_match
    except AssertionError:
        raise ValueError(
            f'Invalid ARN format: "{arn}". Expected: "{entity_regex_string}"'
        )

    entity_type = regex_match.group("entity_type")
    account_id = regex_match.group("account")

    if entity_type == "user":
        return EntityType.user, account_id
    elif entity_type == "group":
        return EntityType.group, account_id
    else:
        return EntityType.role, account_id


def load_auth_details_from_json(inp: str) -> AuthorizationDetails:
    with open(inp, "r") as f:
        auth_report = json.load(f)
    return AuthorizationDetails(auth_report)


def load_auth_details_from_aws(profile: Optional[str] = None) -> AuthorizationDetails:
    logger.info("Attempting to fetch authorization details report from AWS...")
    auth_report: Dict[str, Any] = {}
    profile = profile or os.environ.get("AWS_PROFILE")
    if not profile:
        raise ValueError("No AWS profile found")
    boto3.setup_default_session(profile_name=profile)
    iam_client = boto3.client("iam")
    paginator = iam_client.get_paginator("get_account_authorization_details")
    for page in paginator.paginate():
        auth_report = deep_update(auth_report, page)
    a = AuthorizationDetails(auth_report)
    return a


def load_scp_from_json(inp: str) -> PolicyWithSource:
    with open(inp) as f:
        policy_description = json.load(f)
        return PolicyWithSource(
            policy_description["Policy"]["PolicySummary"]["Arn"],
            json.loads(policy_description["Policy"]["Content"]),
        )


def load_scp_from_aws(
    account_id: str, profile: Optional[str] = None
) -> List[PolicyWithSource]:
    logger.info("Attempting to fetch Service Control Policies from AWS...")
    profile = profile or os.environ.get("AWS_PROFILE")
    policies = []

    if not profile:
        raise ValueError("No AWS profile found")

    boto3.setup_default_session(profile_name=profile)
    org_client = boto3.client("organizations")
    paginator = org_client.get_paginator("list-policies-for-target")

    for page in paginator.paginate(
        TargetId=account_id, Filter="SERVICE_CONTROL_POLICY"
    ):
        for policy in page["Policies"]:
            policy_description = org_client.describe_policy(PolicyId=policy["Id"])
            policies.append(
                PolicyWithSource(
                    policy_description["Policy"]["PolicySummary"]["Arn"],
                    json.loads(policy_description["Policy"]["Content"]),
                )
            )

    return policies


def get_auth_details(input_path: str, profile: str) -> AuthorizationDetails:
    if input_path:
        auth_details = load_auth_details_from_json(input_path)
    else:
        auth_details = load_auth_details_from_aws(profile)
    return auth_details


def get_scp_policies(
    scp_policy_arg: Optional[str], profile: Optional[str], entity_account: str
) -> List[PolicyWithSource]:
    policy_jsons = []
    if scp_policy_arg:
        scp_policy_paths = (
            scp_policy_arg.split(",")
            if "," in scp_policy_arg
            else scp_policy_arg.split(" ")
        )
        for policy_path in scp_policy_paths:
            policy_jsons.append(load_scp_from_json(inp=policy_path))

    elif profile:
        try:
            policy_jsons.extend(
                load_scp_from_aws(profile=profile, account_id=entity_account)
            )
        except AWSOrganizationsNotInUseException:
            logger.debug("SCP Policies not in use for this account")
        except AccessDeniedException:
            logger.info("Could not fetch SCP policies due to insufficient permissions")

    return policy_jsons


def build_arg_parser() -> argparse.ArgumentParser:
    arg_parser = argparse.ArgumentParser()
    basic_usage = arg_parser.add_argument_group()
    adv_usage = arg_parser.add_argument_group()
    misc_usage = arg_parser.add_argument_group()

    basic_usage.add_argument(
        "--arn",
        help="ARN of the User/Group/Role for which to evaluate the effective permissions",
    )

    adv_usage.add_argument(
        "-i",
        "--input",
        help='Path to report generated by "aws iam get-account-authorization-details"',
        required=False,
    )
    adv_usage.add_argument(
        "-s",
        "--scp-policy",
        help='Path to report(s) generated by "aws organizations describe-policy --policy-id <SCP_Policy_ID>"',
        required=False,
    )
    adv_usage.add_argument(
        "-o",
        "--output",
        help="File path to write the output to (default: stdout)",
        default="stdout",
    )
    adv_usage.add_argument(
        "-f",
        "--format",
        help="Output format",
        choices=["clean", "verbose"],
        default="clean",
    )
    adv_usage.add_argument(
        "-p",
        "--profile",
        help="AWS Profile to use when fetching authorization data",
        required=False,
    )
    adv_usage.add_argument(
        "-v", "--verbose", help="Set verbosity level to DEBUG", action="store_true"
    )

    misc_usage.add_argument(
        "-u",
        "--update",
        help="Update the IAM actions database",
        required=False,
        action="store_true",
    )

    return arg_parser


def main() -> int:
    initialize_logger()
    logger = logging.getLogger("IAM-APE")
    print_banner()

    arg_parser = build_arg_parser()
    arguments = arg_parser.parse_args()

    if arguments.verbose:
        logging.root.setLevel(logging.DEBUG)

    if not (arguments.arn or arguments.update):
        arg_parser.print_help()
        return 0

    if arguments.update:
        scrape_iam_actions()
        if not arguments.arn:
            return 0

    try:
        entity_type, entity_account = validate_arn(arguments.arn)
    except ValueError as e:
        logger.error(e)
        return -1

    try:
        auth_details = get_auth_details(arguments.input, arguments.profile)
    except (ValueError, ProfileNotFound) as e:
        logger.error(e)
        return -1

    scp_policies = get_scp_policies(
        arguments.scp_policy, arguments.profile, entity_account
    )

    logger.info("Evaluating effective permissions")
    calculator = EffectivePolicyEvaluator(auth_details)

    try:
        res = calculator.evaluate(arn=arguments.arn, entity_type=entity_type)
    except ValueError as e:
        logger.error(e)
        return -1

    out: Union[AwsPolicyType, FinalReportT]
    if arguments.format == "clean":
        out = calculator.policy_expander.shrink_policy(res.allowed_permissions)
    else:
        out = calculator.create_json_report(res)

    if arguments.output == "stdout":
        logger.info(f"Effective permissions policy for {arguments.arn}\n")
        logger.info(json.dumps(out, indent=2))
    else:
        with open(arguments.output, "w") as f:
            json.dump(out, f)

    return 0


if __name__ == "__main__":
    exit(main())
