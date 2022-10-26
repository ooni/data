from datetime import datetime, date, timedelta
import logging
from multiprocessing.sharedctypes import Value
from typing import Dict, Iterable, List, Any, Optional, Tuple, Union
from dataclasses import dataclass
from functools import partial, singledispatch
import re
import ipaddress

from base64 import b64decode

from OpenSSL.crypto import load_certificate, FILETYPE_PEM, FILETYPE_ASN1
from OpenSSL.crypto import X509Store, X509StoreContext

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization


from oonidata.dataformat import (
    HeadersListBytes,
    HeadersListStr,
    BinaryData,
    guess_decode,
)


log = logging.getLogger("oonidata.datautils")

META_TITLE_REGEXP = re.compile(
    b'<meta.*?property="og:title".*?content="(.*?)"', re.IGNORECASE | re.DOTALL
)


def get_html_meta_title(body: bytes) -> str:
    m = META_TITLE_REGEXP.search(body, re.IGNORECASE | re.DOTALL)
    if m:
        return guess_decode(m.group(1))
    return ""


TITLE_REGEXP = re.compile(b"<title.*?>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def get_html_title(body: bytes) -> str:
    m = META_TITLE_REGEXP.search(body, re.IGNORECASE | re.DOTALL)
    if m:
        return guess_decode(m.group(1))
    return ""


def get_first_http_header(
    header_name: str,
    header_list: HeadersListBytes,
    case_sensitive: bool = False,
) -> bytes:
    if not header_list:
        return b""

    if case_sensitive == False:
        header_name = header_name.lower()

    for k, v in header_list:
        if case_sensitive == False:
            k = k.lower()

        if header_name == k:
            return v

    return b""


# TODO: come up with some nicer way to refactor this stuff so we don't have so much duplicate functions
def get_first_http_header_str(
    header_name: str,
    header_list: HeadersListStr,
    case_sensitive: bool = False,
) -> Union[bytes, str, None]:
    if not header_list:
        return ""

    if case_sensitive == False:
        header_name = header_name.lower()

    for k, v in header_list:
        if case_sensitive == False:
            k = k.lower()

        if header_name == k:
            return v

    return ""


# This comes from: https://ipinfo.io/bogon and https://publicdata.caida.org/datasets/bogon/bogon-bn-agg/
bogon_ipv4_ranges = [
    ipaddress.ip_network("0.0.0.0/8"),  # "This" network
    ipaddress.ip_network("10.0.0.0/8"),  # Private-use networks
    ipaddress.ip_network("100.64.0.0/10"),  # Carrier-grade NAT
    ipaddress.ip_network("127.0.0.0/8"),  # Loopback
    ipaddress.ip_network("169.254.0.0/16"),  # Link local
    ipaddress.ip_network("172.16.0.0/12"),  # Private-use networks
    ipaddress.ip_network("192.0.0.0/24"),  # IETF protocol assignments
    ipaddress.ip_network("192.0.2.0/24"),  # TEST-NET-1
    ipaddress.ip_network("192.168.0.0/16"),  # Private-use networks
    # Network interconnect device benchmark testing
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/3"),  # Multicast
]


bogon_ipv6_ranges = [
    # Node-scope unicast unspecified address
    ipaddress.ip_network("::/128"),
    # Node-scope unicast loopback address
    ipaddress.ip_network("::1/128"),
    # IPv4-mapped addresses
    ipaddress.ip_network("::ffff:0:0/96"),
    # IPv4-compatible addresses
    ipaddress.ip_network("::/96"),
    # Remotely triggered black hole addresses
    ipaddress.ip_network("100::/64"),
    # Overlay routable cryptographic hash identifiers (ORCHID)
    ipaddress.ip_network("2001:10::/28"),
    # Documentation prefix
    ipaddress.ip_network("2001:db8::/32"),
    # Unique local addresses (ULA)
    ipaddress.ip_network("fc00::/7"),
    # Link-local unicast
    ipaddress.ip_network("fe80::/10"),
    # Site-local unicast (deprecated)
    ipaddress.ip_network("fec0::/10"),
    # Multicast (Note: ff0e:/16 is global scope and may appear on the global internet.)
    ipaddress.ip_network("ff00::/8"),
    # 6to4 bogon (0.0.0.0/8)
    ipaddress.ip_network("2002::/24"),
    # 6to4 bogon (10.0.0.0/8)
    ipaddress.ip_network("2002:a00::/24"),
    # 6to4 bogon (127.0.0.0/8)
    ipaddress.ip_network("2002:7f00::/24"),
    # 6to4 bogon (169.254.0.0/16)
    ipaddress.ip_network("2002:a9fe::/32"),
    # 6to4 bogon (172.16.0.0/12)
    ipaddress.ip_network("2002:ac10::/28"),
    # 6to4 bogon (192.0.0.0/24)
    ipaddress.ip_network("2002:c000::/40"),
    # 6to4 bogon (192.0.2.0/24)
    ipaddress.ip_network("2002:c000:200::/40"),
    # 6to4 bogon (192.168.0.0/16)
    ipaddress.ip_network("2002:c0a8::/32"),
    # 6to4 bogon (198.18.0.0/15)
    ipaddress.ip_network("2002:c612::/31"),
    # 6to4 bogon (198.51.100.0/24)
    ipaddress.ip_network("2002:c633:6400::/40"),
    # 6to4 bogon (203.0.113.0/24)
    ipaddress.ip_network("2002:cb00:7100::/40"),
    # 6to4 bogon (224.0.0.0/4)
    ipaddress.ip_network("2002:e000::/20"),
    # 6to4 bogon (240.0.0.0/4)
    ipaddress.ip_network("2002:f000::/20"),
    # 6to4 bogon (255.255.255.255/32)
    ipaddress.ip_network("2002:ffff:ffff::/48"),
    # Teredo bogon (0.0.0.0/8)
    ipaddress.ip_network("2001::/40"),
    # Teredo bogon (10.0.0.0/8)
    ipaddress.ip_network("2001:0:a00::/40"),
    # Teredo bogon (127.0.0.0/8)
    ipaddress.ip_network("2001:0:7f00::/40"),
    # Teredo bogon (169.254.0.0/16)
    ipaddress.ip_network("2001:0:a9fe::/48"),
    # Teredo bogon (172.16.0.0/12)
    ipaddress.ip_network("2001:0:ac10::/44"),
    # Teredo bogon (192.0.0.0/24)
    ipaddress.ip_network("2001:0:c000::/56"),
    # Teredo bogon (192.0.2.0/24)
    ipaddress.ip_network("2001:0:c000:200::/56"),
    # Teredo bogon (192.168.0.0/16)
    ipaddress.ip_network("2001:0:c0a8::/48"),
    # Teredo bogon (198.18.0.0/15)
    ipaddress.ip_network("2001:0:c612::/47"),
    # Teredo bogon (198.51.100.0/24)
    ipaddress.ip_network("2001:0:c633:6400::/56"),
    # Teredo bogon (203.0.113.0/24)
    ipaddress.ip_network("2001:0:cb00:7100::/56"),
    # Teredo bogon (224.0.0.0/4)
    ipaddress.ip_network("2001:0:e000::/36"),
    # Teredo bogon (240.0.0.0/4)
    ipaddress.ip_network("2001:0:f000::/36"),
    # Teredo bogon (255.255.255.255/32)
    ipaddress.ip_network("2001:0:ffff:ffff::/64"),
]


def is_ipv4_bogon(ip: str) -> bool:
    try:
        ipv4addr = ipaddress.IPv4Address(ip)
    except ipaddress.AddressValueError:
        return False
    if any([ipv4addr in ip_range for ip_range in bogon_ipv4_ranges]):
        return True
    return False


def is_ipv6_bogon(ip: str) -> bool:
    try:
        ipv6addr = ipaddress.IPv6Address(ip)
    except ipaddress.AddressValueError:
        return False
    if any([ipv6addr in ip_range for ip_range in bogon_ipv6_ranges]):
        return True
    return False


def is_ip_bogon(ip: str) -> bool:
    ipaddr = ipaddress.ip_address(ip)
    if any([ipaddr in ip_range for ip_range in bogon_ipv4_ranges + bogon_ipv6_ranges]):
        return True
    return False


@dataclass
class CertificateMeta:
    cert: x509.Certificate
    issuer: str
    issuer_common_name: str
    subject: str
    subject_common_name: str
    san_list: List[str]
    not_valid_before: datetime
    not_valid_after: datetime
    fingerprint: str


def get_common_name(cert_name: x509.Name) -> str:
    try:
        attributes = cert_name.get_attributes_for_oid(NameOID.COMMON_NAME)
        if attributes:
            return str(attributes[0].value)
    except x509.AttributeNotFound:
        return ""
    return ""


def get_san_list(cert: x509.Certificate) -> List[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        san_ext: x509.SubjectAlternativeName = ext.value  # type: ignore
        return san_ext.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        return []


def get_certificate_meta(peer_cert: BinaryData) -> CertificateMeta:
    raw_cert = b64decode(peer_cert.data)
    assert raw_cert, "either peer_cert or raw_cert must be specified"
    cert = x509.load_der_x509_certificate(raw_cert, default_backend())

    return CertificateMeta(
        cert=cert,
        issuer=cert.issuer.rfc4514_string(),
        issuer_common_name=get_common_name(cert.issuer),
        subject=cert.subject.rfc4514_string(),
        subject_common_name=get_common_name(cert.subject),
        san_list=get_san_list(cert),
        not_valid_before=cert.not_valid_before,
        not_valid_after=cert.not_valid_after,
        fingerprint=cert.fingerprint(hashes.SHA256()).hex(),
    )


class InvalidCertificateChain(ValueError):
    pass


class TLSCertStore:
    def __init__(self, pem_cert_store: Iterable[bytes] = []):
        self._store: Dict[x509.Name, x509.Certificate] = {}
        for pem_cert in pem_cert_store:
            self.add_cert_to_store(pem_cert)

    def add_cert_to_store(self, pem_cert: bytes):
        root_cert = x509.load_pem_x509_certificate(pem_cert)

        if root_cert.issuer in self._store:
            log.error(f"duplicate cert {root_cert.issuer} in store {self._store}")
            return

        self._store[root_cert.issuer] = root_cert

    def validate_cert_chain(
        self, timestamp: datetime, certificate_chain: List[bytes]
    ) -> Tuple[str, List[str]]:
        """
        Validate a certificate chain provided as a list of bytes in DER format
        against a set of trust anchors (`pem_cert_store`).
        The pem_cert_store should be a list of bytes of root certificates in PEM
        format.

        The user of this function needs to implement their own logic for verifying
        if the returned SAN list and common name matches the expectations.

        It's important to highlight that this function doesn't make any sort of
        strong security guarantees and doesn't take into account the many
        nuances and edge cases that MUST be considered if you care to have a
        secure certificate chain validation function as per:
        https://www.rfc-editor.org/rfc/rfc5280#section-6

        Returns:
            (common_name, List[SAN list])

        Raises:
            InvalidCertificateChain if the certificate is not valid
        """
        # The cert chain as `x509.Certificates` object. The first item in the list
        # is the leaf node of the chain.
        cert_chain = list(
            map(
                partial(x509.load_der_x509_certificate, backend=default_backend),
                certificate_chain,
            )
        )

        try:
            issuing_root = self._store[cert_chain[-1].issuer]
        except KeyError:
            raise InvalidCertificateChain(
                f"missing issuing_root {cert_chain[-1].issuer.rfc4514_string()} in cert store"
            )

        store = X509Store()
        store.set_time(timestamp)
        store.add_cert(
            load_certificate(
                FILETYPE_PEM,
                issuing_root.public_bytes(encoding=serialization.Encoding.PEM),
            )
        )
        for cert in reversed(certificate_chain):
            pcert = x509.load_der_x509_certificate(cert)
            if pcert.subject == issuing_root.issuer:
                # Skip certificates that are already in the store and hence are
                # considered trusted.
                # XXX: From a security perspective this might go wrong in some ways,
                # but we aren't really aiming for a secure implementation.
                continue

            unstrusted_cert = load_certificate(FILETYPE_ASN1, cert)
            store_ctx = X509StoreContext(store, unstrusted_cert)

            try:
                store_ctx.verify_certificate()
            except Exception as exc:
                log.error(f"failed to verify i={pcert.issuer} s={pcert.subject} {exc}")
                log.error(f"using i={issuing_root.issuer} s={issuing_root.subject}")
                raise InvalidCertificateChain(
                    f"failed to verify i={pcert.issuer} s={pcert.subject} {exc}"
                    f"using i={issuing_root.issuer} s={issuing_root.subject}"
                )

            store.add_cert(unstrusted_cert)

        san_list = get_san_list(cert_chain[0])
        common_name = get_common_name(cert_chain[0].subject)
        return common_name, san_list


def validate_cert_chain(
    timestamp: datetime,
    certificate_chain: List[bytes],
    pem_cert_store: Iterable[bytes],
) -> Tuple[str, List[str]]:
    store = TLSCertStore(pem_cert_store)
    return store.validate_cert_chain(timestamp, certificate_chain)


# Taken from:
# https://github.com/Jigsaw-Code/net-analysis/blob/master/netanalysis/ooni/data/sync_measurements.py#L33
@singledispatch
def trim_measurement(json_obj, max_string_size: int):
    return json_obj


@trim_measurement.register(dict)
def _(json_dict: dict, max_string_size: int):
    keys_to_delete: List[str] = []
    for key, value in json_dict.items():
        if type(value) == str and len(value) > max_string_size:
            keys_to_delete.append(key)
        else:
            trim_measurement(value, max_string_size)
    for key in keys_to_delete:
        del json_dict[key]
    return json_dict


@trim_measurement.register(list)
def _(json_list: list, max_string_size: int):
    for item in json_list:
        trim_measurement(item, max_string_size)
    return json_list


def one_day_dict(day: date) -> dict[str, Any]:
    start_day = datetime(year=day.year, month=day.month, day=day.day)
    end_day = start_day + timedelta(days=1)
    return {"start_day": start_day, "end_day": end_day}
