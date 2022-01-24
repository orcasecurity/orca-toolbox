import json
import logging
from typing import Optional, Any, Protocol, Dict

import oci  # type: ignore
from oci import Response  # type: ignore

from .instance_metdata_config import (
    InstancePrincipalsSecurityTokenSigner,
)

logger = logging.getLogger("OCI Enumerator")


class OCICommand(Protocol):
    __name__: str

    def __call__(self, compartment_id: str, *args: Any, **kwargs: Any) -> Response:
        ...


class OciEnumerator:
    def __init__(
        self,
        config_file: Optional[str] = None,
        profile_name: str = "DEFAULT",
        identity_file: Optional[str] = None,
        region: Optional[str] = None,
        compartment_id: Optional[str] = None,
    ) -> None:
        self.config_file = config_file
        self.profile_name = profile_name
        self.identity_file = identity_file
        self.region = region
        self.compartment_id = compartment_id
        self.identity: Optional[InstancePrincipalsSecurityTokenSigner] = None
        self.config: Dict[str, Any] = {}
        self.client_kwargs = {}

        if self.identity_file:
            self.identity = self.get_identity(self.identity_file)
            self.client_kwargs = {"signer": self.identity}
        elif self.config_file:
            self.config = self.get_config()
        else:
            raise ValueError("Must provide either config file or identity file")

        if not self.compartment_id:
            if self.config:
                self.compartment_id = self.config.get("tenancy")
            elif self.identity:
                self.compartment_id = self.identity.tenancy_id

    def run_command(self, command: OCICommand, **kwargs: Any) -> Dict[str, Response]:
        try:
            if command.__name__.startswith("get_"):
                res = command(**kwargs)
                return {command.__name__: res.data}

            kwargs.update({"compartment_id": self.compartment_id})
            res = oci.pagination.list_call_get_all_results(command, **kwargs)
            # res: Response = command(compartment_id=self.compartment_id, **kwargs)
            return {command.__name__: res.data}

        except oci.exceptions.ServiceError as e:

            if e.code in [
                "NotAuthorizedOrNotFound",
                "NotAuthenticated",
                "NamespaceNotFound",
            ]:
                logger.error(f"{e.message} Request: {command.__name__}")
            else:
                raise e

            return {}

    @staticmethod
    def get_identity(identity_file_path: str) -> InstancePrincipalsSecurityTokenSigner:
        with open(identity_file_path) as f:
            data = json.load(f)
        return InstancePrincipalsSecurityTokenSigner(data)

    def get_config(self) -> Dict[str, Any]:
        conf = oci.config.from_file(self.config_file, self.profile_name)
        if self.region:
            conf["region"] = self.region
        oci.config.validate_config(conf)
        return conf

    def enum_compute(self) -> Dict[str, Any]:
        logger.info("Enumerating compute instances...")
        results: Dict[str, Any] = {}
        compute_client = oci.core.ComputeClient(
            config=self.config, **self.client_kwargs
        )
        compute_commands = [
            compute_client.list_instances,
            compute_client.list_vnic_attachments,
            compute_client.list_images,
        ]
        for command in compute_commands:
            results.update(self.run_command(command))

        results["vnic_info"] = {}
        network_client = oci.core.VirtualNetworkClient(
            config=self.config, **self.client_kwargs
        )
        for vnic in results.get("list_vnic_attachments", []):
            vnic_info = network_client.get_vnic(vnic_id=vnic.vnic_id)
            results["vnic_info"][vnic.vnic_id] = vnic_info.data
        return results

    def enum_iam(self) -> Dict[str, Any]:
        logger.info("Enumerating IAM")
        results = {}
        iam_client = oci.identity.IdentityClient(
            config=self.config, **self.client_kwargs
        )
        iam_commands = [
            iam_client.list_compartments,
            iam_client.list_domains,
            iam_client.list_users,
        ]
        for command in iam_commands:
            results.update(self.run_command(command))
        return results

    def enum_storage(self) -> Dict[str, Any]:
        logger.info("Enumerating Object Storage")
        results: Dict[str, Any] = {}
        storage_client = oci.object_storage.ObjectStorageClient(
            config=self.config, **self.client_kwargs
        )
        try:
            namespace = storage_client.get_namespace().data
        except oci.exceptions.ServiceError as e:
            logger.error(
                f"{e.message} Request: {storage_client.__class__.__name__}.get_namespace"
            )
            return results

        # List buckets
        results.update(
            self.run_command(storage_client.list_buckets, namespace_name=namespace)
        )
        return results

    def enum_load_balancers(self) -> Dict[str, Any]:
        logger.info("Enumerating Load Balancers")
        results = {}
        lb_client = oci.load_balancer.LoadBalancerClient(
            config=self.config, **self.client_kwargs
        )

        # List load balancers
        results.update(self.run_command(lb_client.list_load_balancers))
        return results
