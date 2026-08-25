from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Mapping
from .rules import get_layer, get_rule, Evidence, OutcomeClass
from clickhouse_driver import Client as ClickhouseClient
import logging

log = logging.getLogger(__name__)


@dataclass()
class Cell:
    domain: str
    probe_cc: str
    probe_asn: str
    resolver_asn: str
    ts_hour: datetime  # hour
    n_measurements: int
    n_probes: int
    dns_rule_counts: Mapping[str, int]  # sumMap([top_dns_rule_id], [toUInt32(1)])
    tcp_rule_counts: Mapping[str, int]  # sumMap([top_tcp_rule_id], [toUInt32(1)])
    tls_rule_counts: Mapping[str, int]  # sumMap([top_tls_rule_id], [toUInt32(1)])
    # layer -> amount of blocked measurements in that layer
    k_blocked: Mapping[str, int] # layer -> |Blocked measurements|
    n_ok: Mapping[str, int] # layer -> |Ok measurements|


@dataclass
class ChangePoints:
    domain: str
    probe_cc: str
    probe_asn: str
    resolver_asn: str
    ts: datetime
    s: float
    h: float


def get_cells(
    clickhouse: ClickhouseClient,
    domains: list[str],
    start_time: datetime,
    end_time: datetime,
    probe_cc: str | None = None,
) -> list[Cell]:
    query = f"""
    SELECT
        domain, probe_cc, probe_asn,
        -- Kept as its own key column for DNS series, never substituted for
        -- probe_asn: on-path injection answers for whatever resolver was
        -- addressed, so folding the resolver into the network key would attribute
        -- a middlebox to the resolver operator's AS. See ontology §11.
        resolver_asn,
        toStartOfHour(measurement_start_time)      AS ts_hour,
        sumMap([top_dns_rule_id], [toUInt32(1)])   AS dns_rule_counts,
        sumMap([top_tcp_rule_id], [toUInt32(1)])   AS tcp_rule_counts,
        sumMap([top_tls_rule_id], [toUInt32(1)])   AS tls_rule_counts,
        count()                                    AS n_measurements,
        uniqIf(probe_id, probe_id != '')           AS n_probes


    FROM analysis_web_measurement
    WHERE
        domain IN %(domains)s
        AND ts_hour >= %(start_time)s
        AND ts_hour <= %(end_time)s
        {"AND probe_cc=%(probe_cc)s" if probe_cc else ""}
    GROUP BY domain, probe_cc, probe_asn, resolver_asn, ts_hour;
    """

    params = {
        "domains": domains,
        "start_time": start_time,
        "end_time": end_time
    }
    if probe_cc:
        params["probe_cc"] = probe_cc

    result = clickhouse.execute_iter(
        query,
        params=params,
        with_column_types=True,
    )
    col_names = [t[0] for t in next(result)]
    rows = [dict(zip(col_names, r)) for r in result]

    rule_maps = ["dns_rule_counts", "tcp_rule_counts", "tls_rule_counts"]
    for row in rows:
        row['k_blocked'] = defaultdict(int)
        row['n_ok'] = defaultdict(int)
        for rule_map in rule_maps:

            if not row.get(rule_map):
                continue

            rule_ids, counts = row[rule_map]
            # convert mapping to a format easier to use
            row[rule_map] = dict(zip(rule_ids, counts)) # TODO not sure if useful

            for (rule_id, count) in row[rule_map].items():
                try:
                    rule = get_rule(rule_id)
                except ValueError as e:
                    # old entries can have old rule names, ignore those
                    log.warning(str(e))
                    continue
                # See: https://docs.ooni.org/data/pipeline-implementation-plan ,
                # section 3.6
                if rule.evidence == Evidence.SCORED and rule.outcome_class == OutcomeClass.BLOCKED:
                    row['k_blocked'][get_layer(rule_id)] += count
                if rule.outcome_class == OutcomeClass.OK:
                    row['n_ok'][get_layer(rule_id)] += count


    return [Cell(**row) for row in rows]


def run_detector(
    series: list[Cell], p_block: float = 0.1, p_ok: float = 0.9, edd: int = 1
) -> list[ChangePoints]:
    return []
