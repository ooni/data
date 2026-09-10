"""
Generate the initial target registry seed from the citizenlab test lists and
the endpoints the nettests themselves probe.

Outputs (TSV, tab-separated, header row):

  targets_seed.tsv           one row per target_id, with enrichable metadata
  target_hostnames_seed.tsv  one row per (matcher_kind, matcher) -> target_id
  unmapped.txt               inputs the rules could not classify, for review

Identity rule (see docs/ontology.md section 4):

  1. exact hostname match in the curated map (nettest endpoints, resolver
     hostnames) -> curated `<service>/<role>` id
  2. pattern match (e.g. e\\d+.whatsapp.net) -> curated id
  3. IP literal in the curated resolver map -> curated id
  4. domain-suffix match in the curated domain map -> curated
     `<service>/<role>` id (e.g. any facebook.com hostname -> facebook/website).
     A *suffix* walk, not the PSL registrable domain: googleapis.com sits on
     the PSL private section, so play.googleapis.com is its own registrable
     domain, yet it must still land on google/api.
  5. fallback: the PSL registrable domain itself is the target_id.

A target_id is therefore either `<service>/<role>` (curated) or a bare
`<registrable-domain>` (mechanical, meaning "role not yet curated"). The
curated set is minted NOW, at seed time, because it is free while no series
exist; promoting a bare domain to a service/role id later is a rename, which
the changepoint detector reads as a blocking event. For the long tail the
mechanical fallback is the common case on purpose: enrichment accumulates in
the metadata columns (service, role, category_code, notes), never by renaming
stamped ids.

Usage:
  python scripts/targets/seed_targets.py \
      --hostnames docs/uniq-hostnames.txt \
      --test-lists ~/repos/ooni/test-lists/lists \
      --out scripts/targets/
"""

import argparse
import csv
import ipaddress
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlsplit

# Make the pipeline's curated IM targets importable without installing it.
REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "oonipipeline" / "src"))
from oonipipeline.targets import TARGETS, _EXACT, _PATTERNS  # noqa: E402


# --- Public Suffix List ------------------------------------------------------


def load_psl(path: Path):
    rules = set()
    wildcard = set()
    exceptions = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        if line.startswith("!"):
            exceptions.add(line[1:])
        elif line.startswith("*."):
            wildcard.add(line[2:])
        else:
            rules.add(line)
    return rules, wildcard, exceptions


def registrable_domain(hostname, psl):
    """eTLD+1 per the PSL algorithm; the hostname itself if it is a suffix."""
    rules, wildcard, exceptions = psl
    labels = hostname.lower().rstrip(".").split(".")
    suffix_len = 1  # unknown TLDs are treated as a suffix of one label
    for i in range(len(labels)):
        candidate = ".".join(labels[i:])
        parent = ".".join(labels[i + 1 :])
        if candidate in exceptions:
            suffix_len = len(labels) - i - 1
            break
        if candidate in rules:
            suffix_len = len(labels) - i
            break
        if parent in wildcard:
            suffix_len = len(labels) - i
            break
    if suffix_len >= len(labels):
        return hostname.lower()
    return ".".join(labels[-(suffix_len + 1) :])


# --- Curated: public DNS resolvers (dnscheck inputs & citizenlab entries) ----
#
# These violate the default rule on purpose: a bare anycast IP is an address,
# never a name, and the mozilla/family variants of cloudflare-dns are distinct
# resolver products behind one registrable domain.

RESOLVER_TARGETS = [
    # (target_id, service, description, exact_hosts, ips)
    (
        "cloudflare_dns/standard",
        "cloudflare_dns",
        "Cloudflare public DNS (1.1.1.1), DoH/DoT/UDP.",
        ["cloudflare-dns.com", "one.one.one.one"],
        ["1.1.1.1", "1.0.0.1"],
    ),
    (
        "cloudflare_dns/family",
        "cloudflare_dns",
        "Cloudflare family/malware-filtering resolver.",
        ["family.cloudflare-dns.com", "security.cloudflare-dns.com"],
        ["1.1.1.3", "1.0.0.3", "1.1.1.2", "1.0.0.2"],
    ),
    (
        "cloudflare_dns/mozilla",
        "cloudflare_dns",
        "Mozilla-branded Cloudflare DoH endpoint used by Firefox TRR.",
        ["mozilla.cloudflare-dns.com"],
        [],
    ),
    (
        "google_dns/resolver",
        "google_dns",
        "Google public DNS (8.8.8.8), DoH/DoT/UDP.",
        ["dns.google", "dns.google.com"],
        ["8.8.8.8", "8.8.4.4"],
    ),
    (
        "quad9/resolver",
        "quad9",
        "Quad9 public DNS (9.9.9.9), DoH/DoT/UDP.",
        ["dns.quad9.net", "dns9.quad9.net", "dns10.quad9.net", "dns11.quad9.net"],
        ["9.9.9.9", "9.9.9.10", "9.9.9.11", "149.112.112.112", "149.112.112.9", "149.112.112.10", "149.112.112.11"],
    ),
    (
        "adguard_dns/resolver",
        "adguard_dns",
        "AdGuard public DNS resolver.",
        ["dns.adguard.com", "dns.adguard-dns.com", "dns-unfiltered.adguard.com"],
        ["94.140.14.14", "94.140.15.15"],
    ),
    (
        "opendns/resolver",
        "opendns",
        "Cisco OpenDNS resolver (doh.opendns.com); the marketing site stays on opendns.com.",
        ["doh.opendns.com", "doh.familyshield.opendns.com"],
        ["208.67.222.222", "208.67.220.220"],
    ),
]

# Special-purpose probe hostnames that are not a service anyone browses.
SPECIAL_HOSTS = {
    "use-application-dns.net": (
        "mozilla/doh_canary",
        "mozilla",
        "Mozilla DoH canary domain: an NXDOMAIN here tells Firefox to disable "
        "DoH, so networks answer it deliberately. Not a browsable service.",
    ),
}

# --- Curated: domain-level identities ---------------------------------------
#
# Registrable domain -> (target_id, service, role, description). These become
# `domain` matcher rows, so *any* hostname under the domain -- including ones
# not yet observed -- stamps to the curated id rather than diverging into the
# mechanical fallback. Restricted to services where the role is known today:
# this is identity, so entries added later are renames (series breaks), while
# entries here at seed time are free.
#
# One target per domain unless two domains are genuinely the same service
# (twitter.com/x.com; signal.org/whispersystems.org). Splitting one of these
# targets later is also a rename -- when in doubt, keep domains separate.

CURATED_DOMAIN_TARGETS = {
    # google
    "google.com": ("google/website", "google", "website", "google.com: search, accounts and apps."),
    "googleapis.com": ("google/api", "google", "api", "googleapis.com API endpoints (FCM, Play, Firebase...)."),
    "gstatic.com": ("google/static_cdn", "google", "cdn", "gstatic.com static asset CDN."),
    "googleusercontent.com": ("google/user_content", "google", "cdn", "googleusercontent.com user-uploaded content."),
    "ggpht.com": ("google/media_cdn", "google", "cdn", "ggpht.com photo/media CDN."),
    "translate.goog": ("google/translate_proxy", "google", "proxy", "translate.goog translated-page proxy, a de-facto circumvention path."),
    "youtube.com": ("youtube/website", "youtube", "website", "youtube.com."),
    "youtu.be": ("youtube/shortener", "youtube", "shortener", "youtu.be short links."),
    "ytimg.com": ("youtube/static_cdn", "youtube", "cdn", "ytimg.com thumbnails and static assets."),
    "googlevideo.com": ("youtube/video_cdn", "youtube", "cdn", "googlevideo.com video delivery; blocking it breaks playback while youtube.com still loads."),
    # meta
    "facebook.com": ("facebook/website", "facebook", "website", "facebook.com. Messenger-specific endpoints under it are mapped separately (facebook_messenger/*)."),
    "fbcdn.net": ("facebook/cdn", "facebook", "cdn", "fbcdn.net media/static CDN (the messenger nettest's xx.fbcdn.net hosts stay on facebook_messenger/*)."),
    "fbsbx.com": ("facebook/cdn", "facebook", "cdn", "fbsbx.com sandbox/attachment CDN (stun.fbsbx.com stays on facebook_messenger/stun)."),
    "messenger.com": ("facebook_messenger/website", "facebook_messenger", "website", "messenger.com browser client."),
    "instagram.com": ("instagram/website", "instagram", "website", "instagram.com."),
    "cdninstagram.com": ("instagram/cdn", "instagram", "cdn", "cdninstagram.com media CDN."),
    "whatsapp.com": ("whatsapp/website", "whatsapp", "website", "whatsapp.com marketing site; web.whatsapp.com stays on whatsapp/web."),
    "whatsapp.net": ("whatsapp/media_cdn", "whatsapp", "cdn", "whatsapp.net media/upload hosts (mmg, pps, media.*); the e<N> chat pool stays on whatsapp/endpoints via pattern."),
    "wa.me": ("whatsapp/shortener", "whatsapp", "shortener", "wa.me click-to-chat links."),
    # twitter/x
    "twitter.com": ("twitter/website", "twitter", "website", "twitter.com, now x.com."),
    "x.com": ("twitter/website", "twitter", "website", "x.com, same website as twitter.com."),
    "twimg.com": ("twitter/cdn", "twitter", "cdn", "twimg.com media/static CDN."),
    "t.co": ("twitter/shortener", "twitter", "shortener", "t.co link shortener."),
    # wikimedia
    "wikipedia.org": ("wikipedia/website", "wikipedia", "website", "wikipedia.org, all language editions."),
    "wikimedia.org": ("wikimedia/website", "wikimedia", "website", "wikimedia.org, including upload.wikimedia.org media."),
    # messaging
    "telegram.org": ("telegram/website", "telegram", "website", "telegram.org; web.telegram.org stays on telegram/web."),
    "telegram.me": ("telegram/links", "telegram", "shortener", "telegram.me invite/profile links."),
    "t.me": ("telegram/links", "telegram", "shortener", "t.me invite/profile links."),
    "signal.org": ("signal/website", "signal", "website", "signal.org; the app endpoints under it stay on signal/* via exact/pattern."),
    "whispersystems.org": ("signal/website", "signal", "website", "whispersystems.org, historical Signal domain; app endpoints stay on signal/*."),
    # tor / proton / github / reddit / tiktok
    "torproject.org": ("tor/website", "tor", "website", "torproject.org."),
    "proton.me": ("proton/website", "proton", "website", "proton.me web apps and account."),
    "protonmail.com": ("proton/website", "proton", "website", "protonmail.com, historical Proton domain."),
    "github.com": ("github/website", "github", "website", "github.com."),
    "githubusercontent.com": ("github/user_content", "github", "cdn", "githubusercontent.com raw/user content."),
    "reddit.com": ("reddit/website", "reddit", "website", "reddit.com."),
    "redd.it": ("reddit/shortener", "reddit", "shortener", "redd.it short links."),
    "redditstatic.com": ("reddit/static_cdn", "reddit", "cdn", "redditstatic.com assets."),
    "tiktok.com": ("tiktok/website", "tiktok", "website", "tiktok.com."),
    "tiktokcdn.com": ("tiktok/cdn", "tiktok", "cdn", "tiktokcdn.com media CDN."),
}

# --- Curated: service annotation (metadata only, never identity) -------------
#
# Maps registrable domain -> service slug so "is X blocked?" can group across
# domains at query time. These keep their mechanical bare-domain target_id;
# extending or correcting this table is safe at any point.

SERVICE_BY_DOMAIN = {
    "blogspot.com": "blogger",
    "blogger.com": "blogger",
    # wikimedia sister projects: recognisably one org, but each is its own
    # website, so identity stays per-domain.
    "wikidata.org": "wikimedia",
    "wiktionary.org": "wikimedia",
    "wikiquote.org": "wikimedia",
    "wikisource.org": "wikimedia",
    "wikinews.org": "wikimedia",
    "wikibooks.org": "wikimedia",
    "wikiversity.org": "wikimedia",
    "wikivoyage.org": "wikimedia",
    # messaging / voip
    "viber.com": "viber",
    "line.me": "line",
    "wechat.com": "wechat",
    "qq.com": "qq",
    "discord.com": "discord",
    "discord.gg": "discord",
    "discordapp.com": "discord",
    "slack.com": "slack",
    "slack-edge.com": "slack",
    "zoom.us": "zoom",
    "skype.com": "skype",
    "wire.com": "wire",
    "element.io": "element",
    "riot.im": "element",
    "matrix.org": "matrix",
    "adium.im": "adium",
    # privacy / circumvention
    "protonvpn.com": "proton",
    "riseup.net": "riseup",
    "psiphon.ca": "psiphon",
    "psiphon3.com": "psiphon",
    "openvpn.net": "openvpn",
    "wireguard.com": "wireguard",
    "expressvpn.com": "expressvpn",
    "nordvpn.com": "nordvpn",
    "mullvad.net": "mullvad",
    "tunnelbear.com": "tunnelbear",
    "hotspotshield.com": "hotspotshield",
    "windscribe.com": "windscribe",
    "lantern.io": "lantern",
    "getlantern.org": "lantern",
    "eff.org": "eff",
    "accessnow.org": "accessnow",
    "amnesty.org": "amnesty",
    # microsoft
    "microsoft.com": "microsoft",
    "live.com": "microsoft",
    "outlook.com": "microsoft",
    "bing.com": "bing",
    "linkedin.com": "linkedin",
    # apple
    "apple.com": "apple",
    "icloud.com": "apple",
    # yandex / vk
    "yandex.ru": "yandex",
    "yandex.com": "yandex",
    "yandex.net": "yandex",
    "vk.com": "vk",
    "ok.ru": "odnoklassniki",
    # mozilla
    "mozilla.org": "mozilla",
    "firefox.com": "mozilla",
    # media/misc heavy hitters
    "medium.com": "medium",
    "tumblr.com": "tumblr",
    "flickr.com": "flickr",
    "vimeo.com": "vimeo",
    "twitch.tv": "twitch",
    "spotify.com": "spotify",
    "netflix.com": "netflix",
    "1337x.to": "1337x",
    "1337x.st": "1337x",
    "thepiratebay.org": "thepiratebay",
    "grindr.com": "grindr",
    "cloudflare.com": "cloudflare",
    "cloudflare-dns.com": "cloudflare_dns",
    "opendns.com": "opendns",
    "quad9.net": "quad9",
    "adguard.com": "adguard_dns",
    "dns.google": "google_dns",
}


def load_test_list_categories(lists_dir: Path):
    """hostname -> Counter of citizenlab category codes across all lists."""
    cats = defaultdict(Counter)
    for csv_path in sorted(lists_dir.glob("*.csv")):
        if csv_path.name.startswith("00-"):
            continue
        with csv_path.open(encoding="utf-8", errors="replace") as f:
            for row in csv.DictReader(f):
                url = (row.get("url") or "").strip()
                code = (row.get("category_code") or "").strip()
                if not url or not code:
                    continue
                host = urlsplit(url).hostname
                if host:
                    # global.csv counts double: it is the primary curated list
                    weight = 2 if csv_path.name == "global.csv" else 1
                    cats[host.lower()][code] += weight
    return cats


def curated_domain_lookup(host):
    """Longest-suffix match of `host` against CURATED_DOMAIN_TARGETS.

    Deliberately not the PSL registrable domain: private-section suffixes
    (googleapis.com) would make their subdomains invisible to the map.
    """
    labels = host.split(".")
    for i in range(len(labels) - 1):
        candidate = ".".join(labels[i:])
        if candidate in CURATED_DOMAIN_TARGETS:
            return CURATED_DOMAIN_TARGETS[candidate]
    return None


def is_ip_literal(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def build_curated_maps():
    """Flatten nettest + resolver curation into exact/pattern/ip lookup maps."""
    exact, ip_map, patterns = {}, {}, []
    # IM nettest endpoints from oonipipeline.targets: same ids, applied to
    # every nettest at stamping time so web_connectivity of e.g.
    # web.telegram.org lands on the same series as the telegram test.
    for platform_map in _EXACT.values():
        exact.update(platform_map)
    for plat_patterns in _PATTERNS.values():
        patterns.extend(plat_patterns)
    for target_id, _svc, _desc, hosts, ips in RESOLVER_TARGETS:
        for h in hosts:
            exact[h] = target_id
        for ip in ips:
            ip_map[ip] = target_id
    for host, (target_id, _svc, _desc) in SPECIAL_HOSTS.items():
        exact[host] = target_id
    return exact, ip_map, patterns


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hostnames", type=Path, default=REPO_ROOT / "docs/uniq-hostnames.txt")
    ap.add_argument("--test-lists", type=Path, default=Path.home() / "repos/ooni/test-lists/lists")
    ap.add_argument("--psl", type=Path, default=Path(__file__).parent / "public_suffix_list.dat")
    ap.add_argument("--out", type=Path, default=Path(__file__).parent)
    args = ap.parse_args()

    psl = load_psl(args.psl)
    categories = load_test_list_categories(args.test_lists)
    exact, ip_map, patterns = build_curated_maps()

    hostnames = [
        line.strip().lower()
        for line in args.hostnames.read_text().splitlines()
        if line.strip()
    ]

    # target_id -> {service, rule, description, source, hosts, cats}
    targets = {}
    hostname_rows = []  # (matcher_kind, matcher, target_id, source)
    unmapped = []

    def ensure_target(tid, service="", role="", rule="any_of", description="", source="seed"):
        t = targets.setdefault(
            tid,
            {
                "service": service,
                "role": role,
                "rule": rule,
                "description": description,
                "source": source,
                "hosts": [],
                "cats": Counter(),
            },
        )
        if service and not t["service"]:
            t["service"] = service
        if role and not t["role"]:
            t["role"] = role
        return t

    # Pre-register every curated target so they exist even when the dump
    # happens not to contain one of their hostnames. Only curated matchers are
    # emitted as rows: the mechanical eTLD+1 fallback covers everything else
    # in code, so redundant per-hostname rows would only invite drift.
    for t in TARGETS:
        ensure_target(
            t.target_id,
            service=t.platform,
            role=t.target_id.split("/", 1)[1],
            rule=t.combination_rule,
            description=t.description,
            source="nettest",
        )
    for tid, svc, desc, hosts, ips in RESOLVER_TARGETS:
        ensure_target(tid, service=svc, role="resolver", rule="any_of", description=desc, source="curated")
        for h in hosts:
            hostname_rows.append(("exact", h, tid, "curated"))
        for ip in ips:
            hostname_rows.append(("ip", ip, tid, "curated"))
    for host, (tid, svc, desc) in SPECIAL_HOSTS.items():
        ensure_target(tid, service=svc, role="canary", rule="all_of", description=desc, source="curated")
        hostname_rows.append(("exact", host, tid, "curated"))
    for platform_map in _EXACT.values():
        for h, tid in platform_map.items():
            hostname_rows.append(("exact", h, tid, "nettest"))
    for plat, plat_patterns in _PATTERNS.items():
        for pattern, tid in plat_patterns:
            hostname_rows.append(("pattern", pattern.pattern, tid, "nettest"))
    for dom, (tid, svc, role, desc) in CURATED_DOMAIN_TARGETS.items():
        ensure_target(tid, service=svc, role=role, rule="any_of", description=desc, source="curated")
        hostname_rows.append(("domain", dom, tid, "curated"))

    for host in hostnames:
        cats = categories.get(host, Counter())
        if host in exact:
            targets[exact[host]]["hosts"].append(host)
            targets[exact[host]]["cats"].update(cats)
            continue
        matched = next((tid for p, tid in patterns if p.match(host)), None)
        if matched:
            targets[matched]["hosts"].append(host)
            targets[matched]["cats"].update(cats)
            continue
        if is_ip_literal(host):
            if host in ip_map:
                targets[ip_map[host]]["hosts"].append(host)
                targets[ip_map[host]]["cats"].update(cats)
            else:
                unmapped.append(host)
            continue
        curated = curated_domain_lookup(host)
        if curated:
            targets[curated[0]]["hosts"].append(host)
            targets[curated[0]]["cats"].update(cats)
            continue
        # mechanical fallback: registrable domain is the identity
        domain = registrable_domain(host, psl)
        t = ensure_target(
            domain,
            service=SERVICE_BY_DOMAIN.get(domain, ""),
            rule="any_of",
            description="",
            source="citizenlab",
        )
        t["hosts"].append(host)
        t["cats"].update(cats)

    args.out.mkdir(parents=True, exist_ok=True)

    with (args.out / "targets_seed.tsv").open("w") as f:
        w = csv.writer(f, delimiter="\t", lineterminator="\n")
        w.writerow(
            ["target_id", "service", "role", "combination_rule", "category_code",
             "description", "source", "n_hostnames"]
        )
        for tid in sorted(targets):
            t = targets[tid]
            top_cat = t["cats"].most_common(1)[0][0] if t["cats"] else ""
            w.writerow(
                [tid, t["service"], t["role"], t["rule"], top_cat,
                 t["description"], t["source"], len(t["hosts"])]
            )

    with (args.out / "target_hostnames_seed.tsv").open("w") as f:
        w = csv.writer(f, delimiter="\t", lineterminator="\n")
        w.writerow(["matcher_kind", "matcher", "target_id", "source"])
        for row in sorted(set(hostname_rows)):
            w.writerow(row)

    (args.out / "unmapped.txt").write_text("\n".join(unmapped) + "\n" if unmapped else "")

    n_cat = sum(1 for t in targets.values() if t["cats"])
    n_svc = sum(1 for t in targets.values() if t["service"])
    print(f"hostnames in:        {len(hostnames)}")
    print(f"targets out:         {len(targets)}")
    print(f"  with category:     {n_cat}")
    print(f"  with service tag:  {n_svc}")
    print(f"hostname rows:       {len(set(hostname_rows))}")
    print(f"unmapped:            {len(unmapped)}  (see unmapped.txt)")


if __name__ == "__main__":
    main()
