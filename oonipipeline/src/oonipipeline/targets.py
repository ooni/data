"""
Named targets for the instant-messaging nettests.

web_connectivity has a `domain` to analyse against, derived from the measured
URL. The IM tests do not: they probe a fixed, named pool of platform endpoints
with no per-measurement input, so grouping their observations by `domain(input)`
the way the web analysis does would collapse every row into one empty group.

WebObservation.target_id already exists for this — transforms/nettests/tor.py
uses it to tag the named sub-targets within one measurement — but the IM
transformers never set it. This module supplies the mapping.

Targets are keyed by *service role*, not by hostname, so that a series stays
continuous across an infrastructure rename — a target that silently changes
identity looks exactly like a blocking event to a changepoint detector.

Signal is the case in point: its chat endpoint is
textsecure-service.whispersystems.org in every fixture we have (through 2025)
but chat.signal.org in the current spec, and likewise
api.directory.signal.org vs cdsi.signal.org. Both names map to one target_id.
Note the newer names are carried here on the strength of the spec only — no
fixture exercises them yet, so they are insurance against the migration rather
than tested behaviour. tests/test_transforms.py fails on any endpoint that
resolves to no target, which is what catches the rename when it lands.

`combination_rule` records how per-endpoint outcomes combine into a verdict for
the platform, which differs by platform and is already implicit in each test's
own spec logic:

  any_of  the endpoints are redundant fallbacks — reaching any one of them means
          the service works, so it is blocked only if all of them fail.
  all_of  the endpoint is an independently required service — if it fails the
          platform is degraded regardless of the others.
"""

import ipaddress
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence

ANY_OF = "any_of"
ALL_OF = "all_of"


@dataclass(frozen=True)
class Target:
    target_id: str
    platform: str
    combination_rule: str
    description: str


TARGETS: List[Target] = [
    Target(
        target_id="telegram/dc_pool",
        platform="telegram",
        combination_rule=ANY_OF,
        description=(
            "Telegram datacentre access points, probed by IP. They are "
            "redundant fallbacks, so the app works if any one is reachable."
        ),
    ),
    Target(
        target_id="telegram/web",
        platform="telegram",
        combination_rule=ALL_OF,
        description="web.telegram.org, the browser client.",
    ),
    Target(
        target_id="whatsapp/endpoints",
        platform="whatsapp",
        combination_rule=ANY_OF,
        description=(
            "The eN.whatsapp.net server pool. The spec treats WhatsApp as "
            "blocked only when every endpoint in the pool fails."
        ),
    ),
    Target(
        target_id="whatsapp/registration",
        platform="whatsapp",
        combination_rule=ALL_OF,
        description="v.whatsapp.net, the registration service.",
    ),
    Target(
        target_id="whatsapp/web",
        platform="whatsapp",
        combination_rule=ALL_OF,
        description="web.whatsapp.com, the browser client.",
    ),
    Target(
        target_id="signal/chat",
        platform="signal",
        combination_rule=ALL_OF,
        description=(
            "Signal's main chat service. chat.signal.org today, "
            "textsecure-service.whispersystems.org historically."
        ),
    ),
    Target(
        target_id="signal/directory",
        platform="signal",
        combination_rule=ALL_OF,
        description=(
            "Contact discovery. cdsi.signal.org today, "
            "api.directory.signal.org historically."
        ),
    ),
    Target(
        target_id="signal/cdn",
        platform="signal",
        combination_rule=ALL_OF,
        description="Attachment CDNs (cdn.signal.org, cdn2.signal.org, ...).",
    ),
    Target(
        target_id="signal/sfu",
        platform="signal",
        combination_rule=ALL_OF,
        description="sfu.voip.signal.org, the calling relay.",
    ),
    Target(
        target_id="signal/storage",
        platform="signal",
        combination_rule=ALL_OF,
        description="storage.signal.org, encrypted account storage.",
    ),
    Target(
        target_id="signal/uptime",
        platform="signal",
        combination_rule=ALL_OF,
        description="uptime.signal.org, the status endpoint.",
    ),
    Target(
        target_id="facebook_messenger/star",
        platform="facebook_messenger",
        combination_rule=ALL_OF,
        description="star.c10r.facebook.com.",
    ),
    Target(
        target_id="facebook_messenger/b_api",
        platform="facebook_messenger",
        combination_rule=ALL_OF,
        description="b-api.facebook.com.",
    ),
    Target(
        target_id="facebook_messenger/b_graph",
        platform="facebook_messenger",
        combination_rule=ALL_OF,
        description="b-graph.facebook.com.",
    ),
    Target(
        target_id="facebook_messenger/edge",
        platform="facebook_messenger",
        combination_rule=ALL_OF,
        description="edge-mqtt.facebook.com, the message transport.",
    ),
    Target(
        target_id="facebook_messenger/external_cdn",
        platform="facebook_messenger",
        combination_rule=ALL_OF,
        description="external.xx.fbcdn.net.",
    ),
    Target(
        target_id="facebook_messenger/scontent_cdn",
        platform="facebook_messenger",
        combination_rule=ALL_OF,
        description="scontent.xx.fbcdn.net.",
    ),
    Target(
        target_id="facebook_messenger/stun",
        platform="facebook_messenger",
        combination_rule=ALL_OF,
        description="stun.fbsbx.com, the STUN server.",
    ),
]

TARGETS_BY_ID: Dict[str, Target] = {t.target_id: t for t in TARGETS}

# Exact hostname matches, per platform. Historical and current hostnames for the
# same service deliberately share a target_id.
_EXACT: Dict[str, Dict[str, str]] = {
    "telegram": {
        "web.telegram.org": "telegram/web",
    },
    "whatsapp": {
        "v.whatsapp.net": "whatsapp/registration",
        "web.whatsapp.com": "whatsapp/web",
    },
    "signal": {
        "chat.signal.org": "signal/chat",
        "textsecure-service.whispersystems.org": "signal/chat",
        "cdsi.signal.org": "signal/directory",
        "api.directory.signal.org": "signal/directory",
        "sfu.voip.signal.org": "signal/sfu",
        "storage.signal.org": "signal/storage",
        "uptime.signal.org": "signal/uptime",
    },
    "facebook_messenger": {
        "star.c10r.facebook.com": "facebook_messenger/star",
        "b-api.facebook.com": "facebook_messenger/b_api",
        "b-graph.facebook.com": "facebook_messenger/b_graph",
        "edge-mqtt.facebook.com": "facebook_messenger/edge",
        "external.xx.fbcdn.net": "facebook_messenger/external_cdn",
        "scontent.xx.fbcdn.net": "facebook_messenger/scontent_cdn",
        "stun.fbsbx.com": "facebook_messenger/stun",
    },
}

# Pattern matches, applied when no exact match hit. Ordered.
_PATTERNS: Dict[str, Sequence[tuple]] = {
    "whatsapp": (
        # e1.whatsapp.net .. e16.whatsapp.net, and any future members.
        (re.compile(r"^e\d+\.whatsapp\.net$"), "whatsapp/endpoints"),
    ),
    "signal": (
        # cdn.signal.org, cdn2.signal.org, and any future numbered CDN.
        (re.compile(r"^cdn\d*\.signal\.org$"), "signal/cdn"),
    ),
}


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def resolve_target_id(
    platform: str, hostname: Optional[str], ip: Optional[str] = None
) -> Optional[str]:
    """
    Map one observation onto a named target, or None if it doesn't belong to a
    known one.

    Falls back to `ip` when hostname is unset: the Telegram test probes its
    datacentres by address, so most of its rows have no hostname at all.
    """
    candidate = hostname or ip
    if not candidate:
        return None

    exact = _EXACT.get(platform, {})
    if candidate in exact:
        return exact[candidate]

    for pattern, target_id in _PATTERNS.get(platform, ()):
        if pattern.match(candidate):
            return target_id

    # Telegram addresses its datacentres by IP, and the set changes over time,
    # so treat any bare address in a telegram measurement as pool membership
    # rather than pinning a list that would silently go stale.
    if platform == "telegram" and _is_ip_literal(candidate):
        return "telegram/dc_pool"

    return None


def assign_target_ids(platform: str, observations) -> None:
    """
    Tag observations in place with the target they belong to.

    Applied after consume_web_observations rather than by calling it once per
    target, because that call maps DNS/TCP/TLS/HTTP observations to each other
    by transaction_id and ip:port across the whole measurement — splitting the
    input by target would change which observations get merged, and so change
    the row count.
    """
    for obs in observations:
        target_id = resolve_target_id(platform, obs.hostname, obs.ip)
        if target_id is not None:
            obs.target_id = target_id
