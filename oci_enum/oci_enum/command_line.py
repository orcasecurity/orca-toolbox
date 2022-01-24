import argparse
import datetime
import json
import logging
import os
import sys
from collections import defaultdict
from typing import List, Dict, Any, Optional, DefaultDict

import oci  # type: ignore
from texttable import Texttable  # type: ignore

from .oci_enumerator import OciEnumerator

DEFAULT_OCI_CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".oci", "config")
DEFAULT_OCI_PROFILE_NAME = "DEFAULT"
BANNER = """
 ██████╗  ██████╗██╗    ███████╗███╗   ██╗██╗   ██╗███╗   ███╗
██╔═══██╗██╔════╝██║    ██╔════╝████╗  ██║██║   ██║████╗ ████║
██║   ██║██║     ██║    █████╗  ██╔██╗ ██║██║   ██║██╔████╔██║
██║   ██║██║     ██║    ██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║
╚██████╔╝╚██████╗██║    ███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║
 ╚═════╝  ╚═════╝╚═╝    ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝
"""

USAGE = """
%(prog)s [options]
%(prog)s [--interactive]
%(prog)s [-c CONFIG] [-p PROFILE] [-i IDENTITY] [--all|--compute|--iam|--object-storage|--load-balancers]

Example:
    %(prog)s -c /path/to/config -p MY_PROFILE --all
    %(prog)s -i /path/to/identity/file.json --compute --iam
"""
MAIN_MENU = """
Choose an option to continue:

1. Setup
2. Enumerate
3. Quit
"""
SETUP_MENU = """
Let's set up your environment
Choose how you'd like to authenticate to OCI:

1. Configuration file
2. Instance Identity file
3. Back
"""
ENUM_MENU = """
Choose component to enumerate:

1. Compute Instances
2. IAM
3. Object Storage
4. Load Balancers
5. All
6. Back
"""


class ColorFormatter(logging.Formatter):
    """Logging colored formatter, adapted from https://stackoverflow.com/a/56944256/3638629"""

    grey = "\x1b[38;21m"
    blue = "\x1b[38;5;39m"
    yellow = "\x1b[38;5;226m"
    red = "\x1b[38;5;196m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"

    def __init__(self, fmt):
        super().__init__()
        self.fmt = fmt
        self.FORMATS = {
            logging.DEBUG: self.grey + self.fmt + self.reset,
            logging.INFO: self.blue + self.fmt + self.reset,
            logging.WARNING: self.yellow + self.fmt + self.reset,
            logging.ERROR: self.red + self.fmt + self.reset,
            logging.CRITICAL: self.bold_red + self.fmt + self.reset,
        }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


logger = logging.getLogger("OCI Enumerator")
logger.setLevel(logging.INFO)
sh = logging.StreamHandler()
sh.setLevel(logging.INFO)
sh.setFormatter(ColorFormatter("\n%(name)s - %(levelname)s: %(message)s"))
logger.addHandler(sh)


class ValidateRegion(argparse.Action):
    def __call__(self, parser, namespace, value, option_string=None):
        if not oci.regions.is_region(value):
            logger.error(f"Invalid region provided: {value}")
            sys.exit(1)
        setattr(namespace, self.dest, value)


class InteractiveEnumerator:
    def __init__(self) -> None:
        self.config_file = DEFAULT_OCI_CONFIG_PATH
        self.profile_name = DEFAULT_OCI_PROFILE_NAME
        self.config_valid = False
        self.identity_file = ""
        self.identity_file_valid = False

    def _validate_config(self, config_file: str, profile_name: str) -> bool:
        if os.path.isfile(config_file):
            try:
                oci.config.from_file(config_file, profile_name)
                self.config_valid = True
                return True
            except oci.exceptions.InvalidConfig:
                print(f"Invalid configuration file: {config_file}")
            except oci.exceptions.ProfileNotFound:
                print(
                    f'Could not find profile "{self.profile_name}" in config file {self.config_file}'
                )
        else:
            print(f"File not found: {config_file}")
        return False

    def _setup_config(self) -> None:
        self.profile_name = (
            input(f'Enter your profile name (default: "{self.profile_name}"): ')
            or DEFAULT_OCI_PROFILE_NAME
        )
        if os.path.isfile(DEFAULT_OCI_CONFIG_PATH) and self._validate_config(
            self.config_file, self.profile_name
        ):
            print("\nYou already have an OCI config file ready to go!")
            choice = input("Would you like to use another file instead? [y/N] ").lower()
            if not choice or choice == "n" or choice == "no":
                return
        while True:
            try:
                self.config_file = input("Enter the full path to your config file: ")
                if self._validate_config(self.config_file, self.profile_name):
                    return
            except KeyboardInterrupt:
                return

    def _setup_identity(self) -> None:
        while True:
            self.identity_file = input(
                "Enter full path to your instance identity file: "
            )
            if os.path.isfile(self.identity_file):
                try:
                    with open(self.identity_file) as idf:
                        data = json.load(idf)
                    assert {
                        "cert.pem",
                        "intermediate.pem",
                        "key.pem",
                    }.issubset(set(data.keys()))
                    self.identity_file_valid = True
                    return
                except json.JSONDecodeError:
                    print(f"File contains invalid JSON: {self.identity_file}")
                except AssertionError:
                    print(
                        "File does not contain necessary data. It should contain: cert.pem, intermediate.pem and key.pem"
                    )
                except KeyboardInterrupt:
                    return
            else:
                print(f"File not found: {self.identity_file}")

    def do_setup(self) -> None:
        choice = input(SETUP_MENU).lower()
        while True:
            if choice == "1":
                self._setup_config()
                break
            elif choice == "2":
                self._setup_identity()
                break
            elif choice == "3":
                break
            else:
                choice = input("Invalid input. Choose 1, 2, or 3: ").lower()
        return

    def do_enum(self) -> None:
        if (
            self.config_valid
            or self.identity_file_valid
            or self._validate_config(self.config_file, self.profile_name)
        ):
            if enumerator := get_enumerator(
                self.config_file, self.profile_name, self.identity_file
            ):
                while True:
                    choice = input(ENUM_MENU).lower()
                    if choice == "1":
                        print_compute_results(enumerator.enum_compute())
                    elif choice == "2":
                        print_iam_results(enumerator.enum_iam())
                    elif choice == "3":
                        print_object_storage_results(enumerator.enum_storage())
                    elif choice == "4":
                        print_load_balancer_results(enumerator.enum_load_balancers())
                    elif choice == "5":
                        print_compute_results(enumerator.enum_compute())
                        print_iam_results(enumerator.enum_iam())
                        print_object_storage_results(enumerator.enum_storage())
                        print_load_balancer_results(enumerator.enum_load_balancers())
                    elif choice == "6":
                        break
        else:
            print(
                "Could not validate your authentication method. Please run setup first."
            )
            return

    def run(self) -> int:
        print("Welcome to Orca OCI Enumerator!")
        choice = input(MAIN_MENU).lower()
        while True:
            if choice in ["1", "setup"]:
                self.do_setup()
                choice = input(MAIN_MENU).lower()
            elif choice in ["2", "enumerate", "enum"]:
                self.do_enum()
                choice = input(MAIN_MENU).lower()
            elif choice in ["3", "quit", "exit"]:
                return 0
            else:
                choice = input("Invalid input. Choose 1, 2, or 3: ").lower()


def print_banner() -> None:
    today = datetime.datetime.today().strftime("%a %b %d %H:%M:%S %Y")
    print("\033[96m" + BANNER)
    print()
    print(f"+-----------------------------------------------------+")
    print(f"| Authors: Lidor Ben Shitrit / 0xczar @ Orca Security |")
    print(f"|          Tohar Braun                @ Orca Security |")
    print(f"| {today}".ljust(54, " ") + "|")
    print(f"+-----------------------------------------------------+" + "\033[0m")
    print(flush=True)


def print_table(json_to_print: List[Dict[str, Any]]) -> None:
    if not json_to_print:
        return

    header = list(json_to_print[0].keys())
    rows_to_print = [header]
    for entry in json_to_print:
        rows_to_print.append(list(entry.values()))

    table = Texttable(max_width=0)
    table.set_deco(Texttable.HEADER)
    table.add_rows(rows_to_print)
    print()
    print(table.draw())


def parse_args() -> argparse.Namespace:
    arg_parser = argparse.ArgumentParser(prog="oci-enum", usage=USAGE)
    config_or_id = arg_parser.add_mutually_exclusive_group()
    config_or_id.add_argument(
        "-c",
        "--config",
        help="Path to OCI config file",
        default=DEFAULT_OCI_CONFIG_PATH,
    )
    arg_parser.add_argument(
        "-p", "--profile", help="OCI Profile name", default="DEFAULT"
    )
    config_or_id.add_argument(
        "-i",
        "--identity",
        help="OCI Instance Metadata Identity file path",
        required=False,
    )

    arg_parser.add_argument(
        "--region",
        help="OCI Region to enumerate (default: us-ashburn-1)",
        default="us-ashburn-1",
        action=ValidateRegion,
    )
    arg_parser.add_argument(
        "--compartment-id",
        help="Compartment ID to enumerate (optional, use if you only want to enumerate a subcompartment)",
    )

    arg_parser.add_argument(
        "--raw", help="Output raw JSON information", action="store_true"
    )
    arg_parser.add_argument(
        "-q", "--quiet", help="Suppress unnecessary output", action="store_true"
    )

    arg_parser.add_argument(
        "--interactive", help="Launch tool in interactive mode", action="store_true"
    )
    arg_parser.add_argument(
        "--all",
        help="Enumerate all supported components (default)",
        action="append_const",
        const="all",
        dest="enum_options",
    )
    arg_parser.add_argument(
        "--compute",
        help="Enumerate compute instances",
        action="append_const",
        const="compute",
        dest="enum_options",
    )
    arg_parser.add_argument(
        "--iam",
        help="Enumerate IAM compartments, domains, and users",
        action="append_const",
        const="iam",
        dest="enum_options",
    )
    arg_parser.add_argument(
        "--object-storage",
        help="Enumerate Object Storage",
        action="append_const",
        const="object_storage",
        dest="enum_options",
    )
    arg_parser.add_argument(
        "--load-balancers",
        help="Enumerate Load Balancers",
        action="append_const",
        const="load_balancers",
        dest="enum_options",
    )
    args = arg_parser.parse_args()
    if not args.enum_options and not args.interactive:
        arg_parser.print_help()
        sys.exit(0)

    return args


def get_enumerator(
    config_file: Optional[str] = None,
    profile_name: str = "DEFAULT",
    identity_file: Optional[str] = None,
    region: Optional[str] = None,
    compartment_id: Optional[str] = None,
) -> Optional[OciEnumerator]:
    try:
        enumerator = OciEnumerator(
            config_file=config_file,
            profile_name=profile_name,
            identity_file=identity_file,
            region=region,
            compartment_id=compartment_id,
        )
        return enumerator
    except oci.exceptions.ServiceError as e:
        if e.code == "NotAuthenticated":
            logger.error("Invalid authentication details provided")
            if identity_file:
                logger.error("You may need to refresh your identity.json file")
            return None
    except oci.exceptions.ProfileNotFound:
        logger.error(f'Profile name "{profile_name}" not found')
        return None
    except Exception as e:
        raise e
    return None


def _get_instance_ips(
    data: Dict[str, Any]
) -> DefaultDict[str, DefaultDict[str, List[str]]]:
    attachments = defaultdict(list)
    res: DefaultDict[str, DefaultDict[str, List[str]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for vnic in data.get("list_vnic_attachments", []):
        attachments[vnic.instance_id].append(vnic.vnic_id)
        if public_ip := getattr(data["vnic_info"][vnic.vnic_id], "public_ip", None):
            res[vnic.instance_id]["public_ips"].append(public_ip)
        if private_ip := getattr(data["vnic_info"][vnic.vnic_id], "private_ip", None):
            res[vnic.instance_id]["private_ips"].append(private_ip)
    return res


def print_compute_results(results: Dict[str, Any], raw: Optional[bool] = False) -> None:
    if raw:
        print(results)
    elif list_instances := results.get("list_instances"):
        instance_ips = _get_instance_ips(results)
        res = []
        for instance in list_instances:
            ips: Dict[str, List[str]] = instance_ips.get(instance.id, {})
            res.append(
                {
                    "Instance Name": instance.display_name,
                    "ID": instance.id,
                    "Public IPs": " ".join(ips.get("public_ips", [])),
                    "Private IPs": " ".join(ips.get("private_ips", [])),
                    "State": instance.lifecycle_state,
                }
            )
        print_table(res)


def print_iam_results(results: Dict[str, Any], raw: Optional[bool] = False) -> None:
    if raw:
        print(results)
    elif compartments := results.get("list_compartments"):
        res = []
        for compartment in compartments:
            res.append(
                {
                    "Name": compartment.name,
                    "Compartment ID": compartment.compartment_id,
                    "Description": compartment.description,
                    "State": compartment.lifecycle_state,
                }
            )
        print_table(res)

    if domains := results.get("list_domains"):
        res = []
        for domain in domains:
            res.append(
                {
                    "Domain Name": domain.display_name,
                    "Description": domain.description,
                    "URL": domain.url,
                }
            )
        print_table(res)

    if users := results.get("list_users"):
        res = []
        for user in users:
            res.append(
                {
                    "User Name": user.name,
                    "Description": user.description,
                    "Email": user.email,
                    "ID": user.id,
                    "State": user.lifecycle_state,
                }
            )
        print_table(res)


def print_object_storage_results(
    results: Dict[str, Any], raw: Optional[bool] = False
) -> None:
    if raw:
        print(results)
    elif buckets := results.get("list_buckets"):
        res = []
        for bucket in buckets:
            res.append({"Bucket Name": bucket.name, "Namespace": bucket.namespace})
        print_table(res)


def print_load_balancer_results(
    results: Dict[str, Any], raw: Optional[bool] = False
) -> None:
    if raw:
        print(results)
    if load_balancers := results.get("list_load_balancers"):
        res = []
        for lb in load_balancers:
            res.append(
                {
                    "Load Balancer Name": lb.display_name,
                    "Hostnames": " ".join(lb.hostnames.values())
                    if lb.hostnames
                    else None,
                    "IP Addresses": " ".join(lb.ip_addresses)
                    if lb.ip_addresses
                    else None,
                    "State": lb.lifecycle_state,
                }
            )
        print_table(res)


def verify_input(args: argparse.Namespace) -> bool:
    try:
        if args.identity:
            assert os.path.isfile(args.identity), "Identity file not found"
        else:
            assert os.path.isfile(args.config), "Config file not found"

    except AssertionError as e:
        logger.error(f"{e}")
        return False

    return True


def main() -> int:
    cli_args = parse_args()
    if not cli_args.quiet:
        print_banner()
    else:
        logger.setLevel(logging.WARNING)
        logger.removeHandler(sh)

    if cli_args.interactive:
        try:
            logger.setLevel(logging.WARNING)
            return InteractiveEnumerator().run()
        except KeyboardInterrupt:
            return 1

    if not verify_input(cli_args):
        return 1

    if enumerator := get_enumerator(
        cli_args.config,
        cli_args.profile,
        cli_args.identity,
        cli_args.region,
        cli_args.compartment_id,
    ):
        if "all" in cli_args.enum_options:
            cli_args.enum_options = ["all"]
            print_compute_results(enumerator.enum_compute(), cli_args.raw)
            print_iam_results(enumerator.enum_iam(), cli_args.raw)
            print_object_storage_results(enumerator.enum_storage(), cli_args.raw)
            print_load_balancer_results(enumerator.enum_load_balancers(), cli_args.raw)

        else:
            if "compute" in cli_args.enum_options:
                print_compute_results(enumerator.enum_compute(), cli_args.raw)
            if "iam" in cli_args.enum_options:
                print_iam_results(enumerator.enum_iam(), cli_args.raw)
            if "object_storage" in cli_args.enum_options:
                print_object_storage_results(enumerator.enum_storage(), cli_args.raw)
            if "load_balancers" in cli_args.enum_options:
                print_load_balancer_results(
                    enumerator.enum_load_balancers(), cli_args.raw
                )
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
