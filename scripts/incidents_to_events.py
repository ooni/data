#!/usr/bin/env python3
"""Turn OONI's published incidents into draft `label_event` rows.

Incidents are the cheapest source of event labels there is: they are already
adjudicated by a human, cite their evidence, and carry scope and dates. What
they do not carry is anything about *mechanism*, and their dates are
day-granular, so this converter produces **drafts** rather than labels. Every
row lands with `mechanisms: []` and `confidence: "uncertain"` and has to be
opened in the event editor before it counts.

Two things it deliberately refuses to invent:

- **Mechanism.** An incident says "Telegram was blocked in Iran", not "by SNI
  reset". Guessing from the tags would fabricate exactly the field the detector
  harness scores against.
- **A precise onset.** `start_time` is midnight on a date, which supports a
  one-day bracket and nothing narrower. `onset_earliest`/`onset_latest` carry
  that honestly rather than pretending to a timestamp.

Usage:
    python3 scripts/incidents_to_events.py docs/incidents.json \\
        docs/labels/2026-08-04-event-labels-draft.json
"""

import json
import sys
import uuid
from datetime import datetime, timedelta
from pathlib import Path

EXPORT_VERSION = "1"
MECHANISM_TAXONOMY = "v1"

# Deterministic ids: rerunning the converter must not mint new events, or a
# re-import would duplicate everything already adjudicated. Keyed on the
# numeric incident id, not the slug -- half the incidents have slug: null.
NAMESPACE = uuid.UUID("6ba7b812-9dad-11d1-80b4-00c04fd430c8")


def parse(ts):
    if not ts:
        return None
    return datetime.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S")


def scope(inc):
    """Scope, with 'unknown' used rather than an empty set that reads as 'none'."""
    asns = sorted(inc.get("ASNs") or [])
    domains = sorted(inc.get("domains") or [])
    return {
        # Every incident in the current file names exactly one country; a
        # multi-country incident would need splitting, which is flagged below.
        "probe_cc": (inc.get("CCs") or [""])[0],
        "asn_scope": asns,
        # No ASNs listed means the report did not name them, not that no
        # network was affected. That distinction is what `scoreable` and the
        # coverage check in the editor exist to resolve.
        "asn_scope_kind": "listed" if asns else "unknown",
        "target_set": domains,
        "target_set_kind": "enumerated" if domains else "unknown",
    }


def onset(inc):
    """Day-granular source dates become a one-day bracket.

    An incident with no `end_time` is recorded as ongoing (both resolution
    bounds null) rather than resolved-at-import-time, which would be a claim
    the source does not make.
    """
    start = parse(inc["start_time"])
    end = parse(inc.get("end_time"))
    return {
        "onset_earliest": start.isoformat(),
        "onset_latest": (start + timedelta(days=1)).isoformat(),
        "resolution_earliest": end.isoformat() if end else None,
        "resolution_latest": (end + timedelta(days=1)).isoformat() if end else None,
    }


def convert(inc):
    ev = {
        "event_id": str(uuid.uuid5(NAMESPACE, str(inc["id"]))),
        "incident_id": str(inc["id"]),
        "slug": inc.get("slug") or "",
        "title": inc["title"],
        **scope(inc),
        **onset(inc),
        # Left empty on purpose. The editor is where a human supplies these.
        "mechanisms": [],
        "mechanism_taxonomy": MECHANISM_TAXONOMY,
        "event_class": "true_event",
        # Not yet checked against coverage; the editor's coverage query
        # resolves this to yes/no_coverage.
        "scoreable": "unknown",
        # An OONI report is strong evidence the event happened, and no
        # evidence at all about mechanism or exact onset. 'uncertain' until
        # someone opens it.
        "confidence": "uncertain",
        "source": "ooni_report",
        "source_urls": [f"https://explorer.ooni.org/findings/{inc['id']}"]
        + list(inc.get("links") or []),
        "corroborators": [],
        "test_names": sorted(inc.get("test_names") or []),
        "adjudicator": "",
        "adjudicated_at": None,
        "rationale": (inc.get("short_description") or "").strip(),
        "added_at": datetime.utcnow().isoformat(timespec="seconds"),
        "superseded_by": None,
        "supersede_reason": None,
        "import_source": "incidents.json",
        "needs_review": [],
    }
    if len(inc.get("CCs") or []) > 1:
        ev["needs_review"].append(
            f"multi-country incident ({inc['CCs']}); split into one event per country")
    if not inc.get("domains"):
        ev["needs_review"].append("no targets named; set target_set or leave unknown")
    if not inc.get("ASNs"):
        ev["needs_review"].append("no ASNs named; confirm national scope or list them")
    ev["needs_review"].append("mechanisms empty; required before the event scores")
    return ev


def main(src, dst):
    incidents = json.loads(Path(src).read_text())["incidents"]
    events = [convert(i) for i in sorted(incidents, key=lambda i: i["start_time"])]
    payload = {
        "export_version": EXPORT_VERSION,
        "grain": "event",
        "exported_at": datetime.utcnow().isoformat(timespec="seconds"),
        "adjudicator": "",
        "note": ("Draft events imported from OONI published incidents. Every row "
                 "needs mechanisms and a coverage check before it can be scored; "
                 "see needs_review."),
        "events": events,
    }
    Path(dst).write_text(json.dumps(payload, indent=2) + "\n")

    ongoing = sum(1 for e in events if e["resolution_earliest"] is None)
    print(f"{len(events)} events -> {dst}")
    print(f"  {ongoing} ongoing, {len(events) - ongoing} resolved")
    print(f"  {sum(1 for e in events if e['asn_scope_kind'] == 'unknown')} with unknown ASN scope")
    print(f"  {sum(1 for e in events if e['target_set_kind'] == 'unknown')} with unknown targets")
    print(f"  all {len(events)} need mechanisms before they score")


if __name__ == "__main__":
    main(*sys.argv[1:3])
