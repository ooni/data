import re
import ipaddress
from oonidata.dataformat import HeadersListBytes

META_TITLE_REGEXP = re.compile(
    b'<meta.*?property="og:title".*?content="(.*?)"', re.IGNORECASE | re.DOTALL
)


def get_html_meta_title(body: bytes) -> bytes:
    m = META_TITLE_REGEXP.search(body, re.IGNORECASE | re.DOTALL)
    if m:
        return m.group(1)
    return b""


TITLE_REGEXP = re.compile(b"<title.*?>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def get_html_title(body: bytes) -> bytes:
    m = META_TITLE_REGEXP.search(body, re.IGNORECASE | re.DOTALL)
    if m:
        return m.group(1)
    return b""


def get_first_http_header(
    header_name: str, header_list: HeadersListBytes, case_sensitive: bool = False
) -> bytes:
    if case_sensitive == False:
        header_name = header_name.lower()

    for k, v in header_list:
        if case_sensitive == False:
            k = k.lower()

        if header_name == k:
            return v
    return b""


bogon_ipv4_ranges = [
    ipaddress.ip_network("0.0.0.0/8"),  # "This" network
    ipaddress.ip_network("10.0.0.0/8"),  # Private-use networks
    ipaddress.ip_network("100.64.0.0/10"),  # Carrier-grade NAT
    ipaddress.ip_network("127.0.0.0/8"),  # Loopback
    ipaddress.ip_network("127.0.53.53"),  # Name collision occurrence
    ipaddress.ip_network("169.254.0.0/16"),  # Link local
    ipaddress.ip_network("172.16.0.0/12"),  # Private-use networks
    ipaddress.ip_network("192.0.0.0/24"),  # IETF protocol assignments
    ipaddress.ip_network("192.0.2.0/24"),  # TEST-NET-1
    ipaddress.ip_network("192.168.0.0/16"),  # Private-use networks
    # Network interconnect device benchmark testing
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),  # Multicast
    ipaddress.ip_network("240.0.0.0/4"),  # Reserved for future use
    ipaddress.ip_network("255.255.255.255/32"),  # Limited broadcast
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
    ipv4addr = ipaddress.IPv4Address(ip)
    if any([ipv4addr in ip_range for ip_range in bogon_ipv4_ranges]):
        return True
    return False


def is_ipv6_bogon(ip: str) -> bool:
    ipv6addr = ipaddress.IPv6Address(ip)
    if any([ipv6addr in ip_range for ip_range in bogon_ipv4_ranges]):
        return True
    return False
