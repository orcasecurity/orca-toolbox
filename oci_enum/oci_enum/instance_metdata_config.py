from typing import Optional, Dict, ByteString, Union

import oci  # type: ignore
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509 import Certificate
from oci.auth import auth_utils  # type: ignore
from oci.auth.federation_client import X509FederationClient  # type: ignore
from oci.auth.session_key_supplier import SessionKeySupplier  # type: ignore
from oci.auth.signers import X509FederationClientBasedSecurityTokenSigner  # type: ignore


class LeafCertRetriever:
    def __init__(self, cert: str, private: Optional[str] = None) -> None:
        self.cert = cert.encode()
        self.private: Optional[bytes] = None
        if private is not None:
            self.private = private.encode()

    def refresh(self) -> None:
        pass

    def get_certificate_raw(self) -> ByteString:
        return self.cert

    def get_certificate_as_certificate(self) -> Certificate:
        return x509.load_pem_x509_certificate(self.cert, default_backend())

    def get_private_key(self) -> Optional[
        Union[
            Ed25519PrivateKey,
            Ed448PrivateKey,
            RSAPrivateKey,
            DSAPrivateKey,
            EllipticCurvePrivateKey,
        ]
    ]:
        if self.private is None:
            return self.private

        return serialization.load_pem_private_key(
            self.private, None, backend=default_backend()
        )


class InstancePrincipalsSecurityTokenSigner(
    X509FederationClientBasedSecurityTokenSigner
):
    def __init__(self, identity_data: Dict[str, str], region="us-ashburn-1") -> None:
        self.session_key_supplier = SessionKeySupplier()
        self.leaf_certificate_retriever = LeafCertRetriever(
            cert=identity_data["cert.pem"], private=identity_data["key.pem"]
        )
        self.intermediate_certificate_retriever = LeafCertRetriever(
            identity_data["intermediate.pem"]
        )
        leaf_cert_as_cert = (
            self.leaf_certificate_retriever.get_certificate_as_certificate()
        )
        self.tenancy_id = auth_utils.get_tenancy_id_from_certificate(leaf_cert_as_cert)
        self.region = region

        federation_endpoint = oci.regions.endpoint_for("auth", self.region)
        federation_endpoint = f"{federation_endpoint}/v1/x509"

        federation_client = X509FederationClient(
            federation_endpoint=federation_endpoint,
            tenancy_id=self.tenancy_id,
            session_key_supplier=self.session_key_supplier,
            leaf_certificate_retriever=self.leaf_certificate_retriever,
            intermediate_certificate_retrievers=[
                self.intermediate_certificate_retriever
            ],
            cert_bundle_verify=None,
            retry_strategy=None,
            purpose=None,
        )
        super(InstancePrincipalsSecurityTokenSigner, self).__init__(federation_client)
