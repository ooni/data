"""
Unit tests for the fuzzy-logic rule set.

These need no database: the rules are data and the SQL is generated from them,
so the invariants that used to be unverifiable (ids unique, weights in range,
the outcome and rule-id cascades agreeing) can be asserted directly.
"""
from collections import defaultdict

import re

import pytest

from oonipipeline.analysis.rules import (
    RULES_VERSION,
    CURRENT_RULES,
    LEGACY_RULES,
    DNS_RULES,
    LAYER_RULES,
    NO_MATCH_EVIDENCE,
    NO_MATCH_RULE_ID,
    TCP_RULES,
    TLS_RULES,
    Evidence,
    render_evidence_multiif,
    render_outcome_multiif,
    render_rule_id_multiif,
    render_top_rule_argmax,
    RuleLayer,
)
from oonipipeline.analysis.web_analysis import format_query_analysis_web_fuzzy_logic

ALL_LAYERS = pytest.mark.parametrize(
    "layer,rules", sorted(LAYER_RULES.items()), ids=sorted(LAYER_RULES)
)


@ALL_LAYERS
def test_rule_ids_unique_within_layer(layer, rules):
    ids = [r.rule_id for r in rules]
    assert len(ids) == len(set(ids)), f"duplicate rule ids in {layer}: {ids}"


@ALL_LAYERS
def test_rule_ids_do_not_collide_with_no_match_sentinel(layer, rules):
    assert NO_MATCH_RULE_ID not in {r.rule_id for r in rules}


@ALL_LAYERS
def test_weights_are_in_range(layer, rules):
    for rule in rules:
        for name, value in (
            ("blocked", rule.blocked),
            ("down", rule.down),
            ("ok", rule.ok),
        ):
            assert 0.0 <= value <= 1.0, f"{layer}/{rule.rule_id}.{name} = {value}"


@ALL_LAYERS
def test_weights_do_not_oversum(layer, rules):
    """
    Triples must not sum above 1. They are allowed to sum below it: the "no
    data" rules sum to 0 as a mask, and answer_matches_ctrl deliberately sums
    to 0.9. Anything above 1 would be a typo.
    """
    for rule in rules:
        total = rule.blocked + rule.down + rule.ok
        assert total <= 1.0 + 1e-9, f"{layer}/{rule.rule_id} sums to {total}"


@ALL_LAYERS
def test_every_rule_has_a_comment(layer, rules):
    for rule in rules:
        assert rule.comment.strip(), f"{layer}/{rule.rule_id} has no comment"


def _strip_sql_comments(sql: str) -> str:
    return re.sub(r"--[^\n]*", "", sql)


@ALL_LAYERS
def test_cascades_share_conditions_in_order(layer, rules):
    """
    The outcome and rule-id cascades must test the same conditions in the same
    order, otherwise a row's rule id would not name the rule that scored it.

    Compared via the per-rule markers rather than substring search, because
    several conditions are prefixes of others (e.g. the TLS control-succeeds
    condition is a prefix of its ssl_/connection_reset refinements) and a naive
    index() would match the wrong occurrence.
    """
    expected = [r.rule_id for r in rules]

    # The outcome cascade tags each branch with a "-- <rule_id>: <comment>" line.
    outcome_order = re.findall(r"--\s+(\w+):", render_outcome_multiif(rules))
    assert outcome_order == expected

    # The rule-id cascade emits each id on its own line, then the sentinel.
    # Line-anchored so string literals inside conditions (e.g. 'connection_reset'
    # in the TLS rules) aren't mistaken for rule ids.
    rule_id_order = re.findall(
        r"^\s*'(\w+)',?\s*$", render_rule_id_multiif(rules), re.MULTILINE
    )
    assert rule_id_order == expected + [NO_MATCH_RULE_ID]

    # Both renderings contain every condition verbatim.
    for rule in rules:
        assert rule.condition in render_outcome_multiif(rules)
        assert rule.condition in render_rule_id_multiif(rules)


@ALL_LAYERS
def test_rule_id_cascade_emits_every_id(layer, rules):
    sql = render_rule_id_multiif(rules)
    for rule in rules:
        assert f"'{rule.rule_id}'" in sql
    assert f"'{NO_MATCH_RULE_ID}'" in sql


@ALL_LAYERS
def test_cascades_are_balanced(layer, rules):
    # Comments are stripped first: prose is allowed to contain stray brackets.
    for sql in (render_outcome_multiif(rules), render_rule_id_multiif(rules)):
        body = _strip_sql_comments(sql)
        assert body.count("(") == body.count(")"), sql


def test_dns_catch_all_is_last():
    """
    answer_unmatched is the fallthrough for "we got an answer that matched
    nothing". If a rule were added below it, it would be unreachable.
    """
    assert DNS_RULES[-1].rule_id == "dns_system_answer_unmatched"


def test_tls_flattened_branches_are_ordered_most_specific_first():
    """
    These three were a nested multiIf under one outer condition. Flattening
    relies on the specific branches preceding the general one; reordering them
    would silently change scores.
    """
    ids = [r.rule_id for r in TLS_RULES]
    assert ids.index("failure_ctrl_ok_ssl") < ids.index("failure_ctrl_ok_other")
    assert ids.index("failure_ctrl_ok_reset") < ids.index("failure_ctrl_ok_other")


def test_generated_query_embeds_rules_and_rule_ids():
    sql, params = format_query_analysis_web_fuzzy_logic(
        start_time=__import__("datetime").datetime(2024, 1, 1),
        end_time=__import__("datetime").datetime(2024, 1, 2),
        probe_cc=["IT"],
    )
    for alias in ("dns_rule_id", "tcp_rule_id", "tls_rule_id"):
        assert f"as {alias}" in sql
    for alias in ("top_dns_rule_id", "top_tcp_rule_id", "top_tls_rule_id"):
        assert f"as {alias}" in sql

    # Every rule id from every layer reaches the generated SQL.
    for rules in (DNS_RULES, TCP_RULES, TLS_RULES):
        for rule in rules:
            assert f"'{rule.rule_id}'" in sql

    body = _strip_sql_comments(sql)
    assert body.count("(") == body.count(")")
    assert params["probe_cc"] == ["IT"]


def test_generated_query_select_list_matches_table_column_count():
    """
    write_analysis_web_fuzzy_logic does a positional INSERT .. SELECT, so the
    number of columns the outer SELECT projects must equal the number of columns
    in analysis_web_measurement. This catches the common mistake of adding a
    column to one side only.
    """
    from oonipipeline.db.create_tables import make_create_queries

    ddl = next(
        q for q, name in make_create_queries() if name == "analysis_web_measurement"
    )
    body = ddl[ddl.index("(") + 1 : ddl.rindex("ENGINE")]
    # Count backtick-quoted column names, ignoring SQL comments.
    body = re.sub(r"--[^\n]*", "", body)
    table_columns = re.findall(r"`(\w+)`", body)

    sql, _ = format_query_analysis_web_fuzzy_logic(
        start_time=__import__("datetime").datetime(2024, 1, 1),
        end_time=__import__("datetime").datetime(2024, 1, 2),
        probe_cc=[],
    )
    # The outer projection runs from the top-level SELECT to its FROM.
    select_body = sql[sql.index("\n    SELECT\n") : sql.index("\n    FROM (")]
    select_body = re.sub(r"--[^\n]*", "", select_body)
    aliases = re.findall(r"\bas (\w+)\b", select_body)
    plain = [
        "domain",
        "input",
        "test_name",
        "probe_asn",
        "probe_as_org_name",
        "probe_cc",
        "resolver_asn",
        "resolver_as_cc",
        "network_type",
        "measurement_start_time",
        "measurement_uid",
        "ooni_run_link_id",
        "probe_id",
    ]
    projected = len(aliases) + len(plain) - 1  # 'domain' is both plain and an alias

    assert projected == len(table_columns), (
        f"outer SELECT projects {projected} columns but "
        f"analysis_web_measurement has {len(table_columns)}: "
        f"aliases={aliases} table={table_columns}"
    )


# --------------------------------------------------------------------- evidence

@ALL_LAYERS
def test_evidence_agrees_with_the_outcome_triple(layer, rules):
    """A scored rule must say something; a masked rule must not."""
    for rule in rules:
        if rule.evidence is Evidence.SCORED:
            assert rule.outcome != (0.0, 0.0, 0.0), (
                f"{layer}/{rule.rule_id} claims to be scored but is all zeros")
        else:
            assert rule.outcome == (0.0, 0.0, 0.0), (
                f"{layer}/{rule.rule_id} is masked but scores {rule.outcome}")


@ALL_LAYERS
def test_every_layer_has_a_no_data_rule(layer, rules):
    """Without one, HTTP-only rows fall through to a scoring rule."""
    assert [r for r in rules if r.evidence is Evidence.NONE], layer


@ALL_LAYERS
def test_evidence_cascade_matches_the_others(layer, rules):
    sql = render_evidence_multiif(rules)
    levels = re.findall(r"^\s*(\d),?\s*$", sql, re.MULTILINE)
    assert levels == [str(int(r.evidence)) for r in rules] + [
        str(int(NO_MATCH_EVIDENCE))
    ]
    for rule in rules:
        assert rule.condition in sql


# --------------------------------------------------------------- the top rule

def _rank(rule):
    """The ordering render_top_rule_argmax generates, evaluated in Python."""
    return (int(rule.evidence), rule.blocked, rule.rule_id)


@ALL_LAYERS
def test_rows_with_no_data_never_outrank_rows_with_data(layer, rules):
    """The reported regression: an unblocked measurement still carries
    HTTP-only rows, and those were winning the tie for top_*_rule_id."""
    absent = [r for r in rules if r.evidence is Evidence.NONE]
    present = [r for r in rules if r.evidence is not Evidence.NONE]
    for a in absent:
        for p in present:
            assert _rank(p) > _rank(a), f"{layer}: {a.rule_id} beats {p.rule_id}"


@ALL_LAYERS
def test_discarded_rows_lose_to_scored_ones_but_beat_empty_ones(layer, rules):
    """Discarding a result because DNS was untrusted is worth reporting, but
    only when nothing better was observed."""
    for rule in rules:
        if rule.evidence is not Evidence.DISCARDED:
            continue
        for other in rules:
            if other.evidence is Evidence.SCORED:
                assert _rank(other) > _rank(rule)
            elif other.evidence is Evidence.NONE:
                assert _rank(rule) > _rank(other)


@ALL_LAYERS
def test_top_rule_ranking_is_total(layer, rules):
    """No two rules may tie, or the winner depends on row order again."""
    ranks = [_rank(r) for r in rules]
    assert len(set(ranks)) == len(ranks)


@ALL_LAYERS
def test_top_rule_does_not_rank_on_down_or_ok(layer, rules):
    """Lexicographic ordering across the triple holds only while the weights
    are hand-set constants in [0, 1]. Ranking on blocked alone survives the
    move to fitted log-likelihood ratios."""
    sql = render_top_rule_argmax(layer)
    assert f"{layer}_down" not in sql
    assert f"{layer}_ok" not in sql
    assert f"({layer}_evidence, {layer}_blocked, {layer}_rule_id)" in sql

def test_all_rules_unique():
    all_rules = [rule for layer in LAYER_RULES.values() for rule in layer]
    unique_rule_ids = defaultdict(list)

    for r in all_rules:
        unique_rule_ids[r.rule_id].append(r)

    assert len(all_rules) == len(unique_rule_ids), \
    f"""There are duplicated rule_ids: {
        [rid for (rid, rls) in unique_rule_ids.items() if len(rls) > 1]
    }"""

def test_current_rules_match_layers():
    assert len(DNS_RULES) + len(TCP_RULES) + len(TLS_RULES) == len(CURRENT_RULES)

def test_legacy_rules_have_old_version():
    for rule in LEGACY_RULES:
        assert rule.version < RULES_VERSION

def test_layer_list_consistency():
    assert all(rule.layer == RuleLayer.TCP for rule in TCP_RULES)
    assert all(rule.layer == RuleLayer.DNS for rule in DNS_RULES)
    assert all(rule.layer == RuleLayer.TLS for rule in TLS_RULES)
