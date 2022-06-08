import re
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
