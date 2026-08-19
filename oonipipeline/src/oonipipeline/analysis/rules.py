"""
The fuzzy-logic rule set used to score web observations.

Previously these rules lived as literal ``multiIf`` cascades inside the analysis query's f-string,
which had two consequences:

1. The only way to exercise a rule was to stand up ClickHouse, write a fixture measurement and run
    the whole query. The rules themselves had no unit tests.
2. The output recorded *what score* a row got but not *which rule produced it*, so the distribution
    of rule firings was unknowable, weights could not be attributed to outcomes, and re-scoring
    required reprocessing observations.

Representing them as data fixes both. The SQL is generated from the tables below, so the outcome
cascade and the rule-id cascade are guaranteed to share the same conditions in the same order — a
row's ``*_rule_id`` always names the rule that produced its score. The semantics of existing rules
should not be changed, but one should rather create a new `rule_id` with the new semantics.

Rule ordering is significant: ``multiIf`` takes the first match, so a rule only fires when every
rule above it did not. This is a decision tree whose leaves are hand-set, and the conditions are not
mutually exclusive on their own.

Outcome triples are ``(blocked, down, ok)``. They do not all sum to 1 necessarily.
Masking rules sum to 0. That 0 is overloaded: it covers "no observation here", "observed but
discarded" and "observed, nothing wrong" alike.

Each rule therefore also carries an ``Evidence`` level saying which of those it means, so aggregates
do not have to infer it from the numbers. Read the level, never ``blocked == 0``.

TODO(art): the Evidence label carries with it a similar meaning to the Masking rules and should
eventually be consolidated.
"""

from dataclasses import dataclass
from enum import IntEnum
from typing import List, Tuple

RULES_VERSION = 1


class Evidence(IntEnum):
    """How much a row has to say about its layer, independent of the score.

    The triple cannot answer this: a rule scores (0, 0, 0) whether the layer
    was never exercised, or was exercised and then discarded because an
    earlier layer was untrustworthy. Both are "no verdict", but only the
    second one names a cause, and neither is "we looked and found nothing
    wrong". Ordered, so aggregates can prefer the row that saw the most.
    """

    NONE = 0  # layer produced no data on this row
    DISCARDED = 1  # observed, but an earlier layer makes it uninterpretable
    SCORED = 2  # observed and scored

class OutcomeClass(IntEnum):
    """Whether this particular rule is blocked, down or ok leaning.
    Used to derived a final verdict"""

    UNKNOWN = 0 # there is not enough data to say anything
    OK = 1 # available and not blocked
    DOWN = 2 # unavailable, but not due to network interference
    BLOCKED = 3 # unavailable, due not network interference

@dataclass(frozen=True)
class Rule:
    """One branch of a layer's scoring cascade."""

    # Stable identifier, unique within a layer. Persisted to
    # analysis_web_measurement, so renaming one is a breaking change for
    # anything analysing historical rule distributions.
    rule_id: str
    # SQL boolean expression, evaluated against the analysis query's scope.
    condition: str
    blocked: float
    down: float
    ok: float
    comment: str
    evidence: Evidence = Evidence.SCORED
    outcome_class: OutcomeClass = OutcomeClass.UNKNOWN

    @property
    def outcome(self) -> Tuple[float, float, float]:
        return (self.blocked, self.down, self.ok)


# The rule id used when no condition matched. Nothing was established, so it
# carries Evidence.NONE along with the (0, 0, 0) outcome.
NO_MATCH_RULE_ID = "none"
NO_MATCH_EVIDENCE = Evidence.NONE


DNS_RULES: List[Rule] = [
    Rule(
        rule_id="no_dns_data",
        condition="length(dns_answers) = 0 AND dns_failure IS NULL",
        blocked=0.0,
        down=0.0,
        ok=0.0,
        comment=(
            "Row has no DNS data attached, most likely an HTTP(s)-only "
            "observation. Masked out of aggregate analysis."
        ),
        evidence=Evidence.NONE,
    ),
    Rule(
        rule_id="country_consistent_blockpage",
        condition="dns_blocking_country_consistent",
        blocked=1.0,
        down=0.0,
        ok=0.0,
        outcome_class=OutcomeClass.BLOCKED,
        comment="Matched a known blockpage fingerprint for this country.",
    ),
    Rule(
        rule_id="tls_consistent_answer",
        condition="dns_tls_consistent > 0",
        blocked=0.0,
        down=0.0,
        ok=1.0,
        outcome_class=OutcomeClass.OK,
        comment=(
            "The answer is TLS-consistent, a very strong signal that it is "
            "genuine — absent a TLS MITM."
        ),
    ),
    Rule(
        rule_id="bogon_not_in_ctrl",
        condition="dns_answers_contain_bogon > 0 AND dns_answer_matches_ctrl = 0",
        blocked=0.95,
        down=0.05,
        ok=0.0,
        outcome_class=OutcomeClass.BLOCKED,
        comment="Bogon answer that the control never returned. Likely blocking.",
    ),
    Rule(
        rule_id="bogon_in_ctrl",
        condition="dns_answers_contain_bogon > 0 AND dns_answer_matches_ctrl > 0",
        blocked=0.1,
        down=0.9,
        ok=0.0,
        outcome_class=OutcomeClass.DOWN,
        comment=(
            "Bogon answer that the control also returned — a DNS "
            "misconfiguration rather than blocking."
        ),
    ),
    Rule(
        rule_id="tls_inconsistent_not_in_ctrl",
        condition="dns_tls_inconsistent > 0 AND dns_answer_matches_ctrl = 0",
        blocked=0.9,
        down=0.05,
        ok=0.05,
        outcome_class=OutcomeClass.BLOCKED,
        comment=(
            "Certificates fail for this answer and the control never returned "
            "it. Most likely true blocking."
        ),
    ),
    Rule(
        rule_id="answer_matches_ctrl",
        condition="dns_answer_matches_ctrl > 0",
        blocked=0.0,
        down=0.0,
        ok=0.9,
        outcome_class=OutcomeClass.OK,
        comment="Direct answer match against the control.",
    ),
    Rule(
        rule_id="answer_asn_matches_ctrl",
        condition="dns_answer_asn_matches_ctrl > 0",
        blocked=0.2,
        down=0.0,
        ok=0.8,
        outcome_class=OutcomeClass.OK,
        comment=(
            "Experiment and control answers share an ASN. Usually a valid "
            "answer, especially given no earlier rule fired."
        ),
    ),
    Rule(
        rule_id="failure_ctrl_also_failing",
        condition="dns_failure IS NOT NULL AND ctrl_dns_success_rate <= 0.5",
        blocked=0.1,
        down=0.9,
        ok=0.0,
        outcome_class=OutcomeClass.DOWN,
        comment=(
            "DNS is failing but also fails in the control — likely an issue "
            "with the fqdn itself, e.g. NXDOMAIN."
        ),
    ),
    Rule(
        rule_id="failure_ctrl_ok",
        condition="dns_failure IS NOT NULL AND ctrl_dns_success_rate > 0.5",
        blocked=0.9,
        down=0.1,
        ok=0.0,
        outcome_class=OutcomeClass.BLOCKED,
        comment="DNS is failing but succeeds in the control. Likely blocking.",
    ),
    Rule(
        rule_id="failure_no_ctrl",
        condition="dns_failure IS NOT NULL",
        blocked=0.5,
        down=0.5,
        ok=0.0,
        outcome_class=OutcomeClass.UNKNOWN,
        comment="DNS is failing and we have no usable control to compare to.",
    ),
    Rule(
        rule_id="answer_unmatched",
        condition="dns_failure IS NULL",
        blocked=0.75,
        down=0.0,
        ok=0.25,
        outcome_class=OutcomeClass.BLOCKED,
        comment=(
            "Catch-all: we got an answer that matched nothing in the control. "
            "Fires for legitimately rotating CDN/geo-DNS answers the control "
            "did not happen to see, so it is a likely false-positive source "
            "and a priority for calibration."
        ),
    ),
]


TCP_RULES: List[Rule] = [
    Rule(
        rule_id="no_tcp_data",
        condition="tcp_success != 1 AND tcp_failure IS NULL",
        blocked=0.0,
        down=0.0,
        ok=0.0,
        outcome_class=OutcomeClass.UNKNOWN,
        comment="Row has no TCP data attached. Masked out of aggregate analysis.",
        evidence=Evidence.NONE,
    ),
    Rule(
        rule_id="connect_ok",
        condition="tcp_failure IS NULL AND tcp_success = 1",
        blocked=0.0,
        down=0.0,
        ok=1.0,
        outcome_class=OutcomeClass.OK,
        comment="We can connect, nothing to see here.",
    ),
    Rule(
        rule_id="ipv6_broken_probe",
        condition="tcp_failure IS NOT NULL AND ip_is_v6 = 1 AND tcp_ipv6_failure_rate > 0.5",
        blocked=0.0,
        down=0.0,
        ok=0.0,
        outcome_class=OutcomeClass.UNKNOWN,
        comment=(
            "Failure against an IPv6 target while IPv6 is failing broadly for "
            "this report_id — the probe most likely has broken IPv6. Masked."
        ),
        evidence=Evidence.DISCARDED,
    ),
    Rule(
        rule_id="failure_ctrl_ok",
        condition=(
            "tcp_failure IS NOT NULL AND ctrl_tcp_success_rate > 0.5 "
            "AND ctrl_tcp_success_count > 0"
        ),
        blocked=0.75,
        down=0.25,
        ok=0.0,
        outcome_class=OutcomeClass.BLOCKED,
        comment="Failure against an address that mostly succeeds in the control.",
    ),
    Rule(
        rule_id="dns_untrusted",
        condition="dns_blocked > 0 AND dns_ok <= (dns_blocked + dns_down)",
        blocked=0.0,
        down=0.0,
        ok=0.0,
        outcome_class=OutcomeClass.UNKNOWN,
        comment=(
            "DNS was not trustworthy, so the addresses we connected to cannot "
            "be trusted either. Masked."
            # TODO(art): this sits below connect_ok, so a successful connection
            # to a blockpage address is still scored as OK. Is that right?
        ),
        evidence=Evidence.DISCARDED,
    ),
    Rule(
        rule_id="failure_ctrl_also_failing",
        condition=(
            "tcp_failure IS NOT NULL AND ctrl_tcp_success_rate <= 0.5 "
            "AND ctrl_tcp_failing_count > 0"
        ),
        blocked=0.25,
        down=0.75,
        ok=0.0,
        outcome_class=OutcomeClass.DOWN,
        comment="Failure, but the control is failing a lot too. Likely down.",
    ),
]


_TLS_CTRL_OK = (
    "tls_failure IS NOT NULL AND ctrl_tls_success_rate > 0.5 "
    "AND ctrl_tls_success_count > 0"
)

TLS_RULES: List[Rule] = [
    Rule(
        rule_id="no_tls_data",
        condition="tls_is_certificate_valid IS NULL AND tls_failure IS NULL",
        blocked=0.0,
        down=0.0,
        ok=0.0,
        outcome_class=OutcomeClass.UNKNOWN,
        comment="Row has no TLS data attached. Masked out of aggregate analysis.",
        evidence=Evidence.NONE,
    ),
    Rule(
        rule_id="certificate_valid",
        condition="tls_is_certificate_valid = 1",
        blocked=0.0,
        down=0.0,
        ok=1.0,
        outcome_class=OutcomeClass.OK,
        comment="Valid certificate, nothing to see here.",
    ),
    # These three were a nested multiIf under a shared outer condition. Flattened
    # by conjoining the outer condition onto each branch, which preserves
    # first-match semantics exactly while keeping every rule a single row.
    Rule(
        rule_id="failure_ctrl_ok_ssl",
        condition=f"{_TLS_CTRL_OK} AND startsWith(tls_failure, 'ssl_')",
        blocked=0.9,
        down=0.1,
        ok=0.0,
        outcome_class=OutcomeClass.BLOCKED,
        comment="Failure where the control succeeds; SSL errors are most suspicious.",
    ),
    Rule(
        rule_id="failure_ctrl_ok_reset",
        condition=f"{_TLS_CTRL_OK} AND tls_failure = 'connection_reset'",
        blocked=0.8,
        down=0.2,
        ok=0.0,
        outcome_class=OutcomeClass.BLOCKED,
        comment=(
            "Failure where the control succeeds; connection reset carries more "
            "weight than timeouts."
        ),
    ),
    Rule(
        rule_id="failure_ctrl_ok_other",
        condition=_TLS_CTRL_OK,
        blocked=0.7,
        down=0.3,
        ok=0.0,
        outcome_class=OutcomeClass.BLOCKED,
        comment="Failure where the control succeeds, with a less specific error.",
    ),
    Rule(
        rule_id="dns_untrusted",
        condition="dns_blocked > 0 AND dns_ok <= (dns_blocked + dns_down)",
        blocked=0.0,
        down=0.0,
        ok=0.0,
        outcome_class=OutcomeClass.UNKNOWN,
        comment="DNS was not trustworthy, so this result cannot be either. Masked.",
        evidence=Evidence.DISCARDED,
    ),
    Rule(
        rule_id="tcp_blocked",
        condition="tcp_blocked > 0 AND tcp_ok <= (tcp_blocked + tcp_down)",
        blocked=0.0,
        down=0.0,
        ok=0.0,
        outcome_class=OutcomeClass.UNKNOWN,
        comment=(
            "TCP analysis says this address is blocked, so the TLS result is "
            "downstream of that. Masked."
        ),
        evidence=Evidence.DISCARDED,
    ),
    Rule(
        rule_id="failure_ctrl_also_failing",
        condition=(
            "tls_failure IS NOT NULL AND ctrl_tls_success_rate <= 0.5 "
            "AND ctrl_tls_failing_count > 0"
        ),
        blocked=0.2,
        down=0.8,
        ok=0.0,
        outcome_class=OutcomeClass.DOWN,
        comment="Failure, but the control is failing a lot too. Likely down.",
    ),
]


LAYER_RULES = {
    "dns": DNS_RULES,
    "tcp": TCP_RULES,
    "tls": TLS_RULES,
}


def _indent(s: str, level: int = 8) -> str:
    return " " * level + s


def render_outcome_multiif(rules: List[Rule]) -> str:
    """
    Render the (blocked, down, ok) cascade for a layer.

    Falls through to tuple(0, 0, 0) when nothing matched, matching
    NO_MATCH_RULE_ID in render_rule_id_multiif.
    """
    parts = ["multiIf("]
    for rule in rules:
        parts.append(_indent(f"-- {rule.rule_id}: {rule.comment}"))
        parts.append(_indent(f"{rule.condition},"))
        parts.append(_indent(f"tuple({rule.blocked}, {rule.down}, {rule.ok}),"))
        parts.append("")
    parts.append(_indent("tuple(0.0, 0.0, 0.0)"))
    parts.append(_indent(")", level=4))
    return "\n".join(parts)


def render_rule_id_multiif(rules: List[Rule]) -> str:
    """
    Render the matching rule-id cascade for a layer.

    Uses the same conditions in the same order as render_outcome_multiif, so
    the emitted id always names the rule that produced the score.
    """
    parts = ["multiIf("]
    for rule in rules:
        parts.append(_indent(f"{rule.condition},"))
        parts.append(_indent(f"'{rule.rule_id}',"))
    parts.append(_indent(f"'{NO_MATCH_RULE_ID}'"))
    parts.append(_indent(")", level=4))
    return "\n".join(parts)


def render_evidence_multiif(rules: List[Rule]) -> str:
    """
    Render the Evidence cascade for a layer.

    Same conditions in the same order as the other two cascades, so a row's
    evidence level is the one belonging to the rule that scored it.
    """
    parts = ["multiIf("]
    for rule in rules:
        parts.append(_indent(f"{rule.condition},"))
        parts.append(_indent(f"{int(rule.evidence)},"))
    parts.append(_indent(f"{int(NO_MATCH_EVIDENCE)}"))
    parts.append(_indent(")", level=4))
    return "\n".join(parts)


def render_top_rule_argmax(layer: str) -> str:
    """
    Render the aggregate picking the rule that drove a measurement's verdict.

    A measurement has one row per resolved IP plus one per redirect hop, and
    the redirect rows carry only HTTP, so at the DNS/TCP/TLS layers they score
    Evidence.NONE. Ranking those rows against real observations is what has to
    be avoided: `argMax(rule_id, blocked)` alone ties them at 0 on every
    unblocked measurement, which is nearly all of them, and the winner then
    comes down to row order.

    So rank on evidence first, and only then on blocked.
    """
    return (
        f"argMax({layer}_rule_id, ({layer}_evidence, {layer}_blocked, "
        f"{layer}_rule_id)) as top_{layer}_rule_id"
    )
