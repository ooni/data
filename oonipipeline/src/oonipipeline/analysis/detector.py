import logging
from datetime import datetime, timedelta
from enum import Enum
from itertools import groupby as itertools_groupby
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

from clickhouse_driver import Client as ClickhouseClient

log = logging.getLogger(__name__)

Change = Enum("Change", [("POS", 1), ("NO", 0), ("NEG", -1)])


class Changepoint(dict):
    probe_asn: int
    probe_cc: str
    domain: str
    ts: datetime

    count_isp_resolver: int
    count_other_resolver: int
    count: int

    dns_isp_blocked: float
    dns_other_blocked: float
    tcp_blocked: float
    tls_blocked: float

    change_dir: int
    s_pos: float
    s_neg: float
    current_state: str
    h: float
    block_type: str


class CusumStep(dict):
    ts: datetime
    probe_cc: str
    probe_asn: int
    domain: str
    block_type: str
    obs_value: float
    weight: float
    s_pos: float
    s_neg: float
    h: float
    current_state: str
    is_changepoint: bool


class Observation(dict):
    probe_asn: int
    probe_cc: str
    domain: str
    ts: datetime

    count_isp_resolver: int
    count_other_resolver: int
    count: int

    dns_isp_blocked: float
    dns_other_blocked: float
    tcp_blocked: float
    tls_blocked: float


def get_observations(
    db: ClickhouseClient,
    start_time: datetime,
    end_time: datetime,
    domains: List[str],
    probe_cc: Optional[List[str]] = None,
) -> Iterator[Observation]:
    params: Dict[str, Any] = {"since": start_time, "until": end_time, "domain": domains}
    where = """
    WHERE domain IN %(domain)s
    AND measurement_start_time > %(since)s
    AND measurement_start_time < %(until)s
    """
    if probe_cc:
        where += "AND probe_cc IN %(probe_cc)s"
        params["probe_cc"] = probe_cc

    q = f"""
    WITH
    IF(resolver_asn = probe_asn, 1, 0) as is_isp_resolver

    SELECT
        probe_cc, probe_asn, domain,
        toStartOfHour(measurement_start_time) as ts,
        countIf(is_isp_resolver = 1) as count_isp_resolver,
        countIf(is_isp_resolver = 0) as count_other_resolver,
        COUNT() as count,
        quantileIf(0.5)(dns_blocked, is_isp_resolver = 1) AS dns_isp_blocked,
        quantileIf(0.5)(dns_blocked, is_isp_resolver = 0) AS dns_other_blocked,
        quantile(0.5)(tcp_blocked) AS tcp_blocked,
        quantile(0.5)(tls_blocked) AS tls_blocked

    FROM analysis_web_measurement

    {where}
    GROUP BY probe_cc, probe_asn, domain, ts
    ORDER BY probe_cc, probe_asn, domain, ts ASC
    """
    res = db.execute_iter(q, params=params, with_column_types=True)
    cols = [name for name, _ in next(res)]
    for row in res:
        yield Observation(**dict(zip(cols, row)))


class LastCusum(dict):
    probe_asn: int
    probe_cc: str
    domain: str
    ts: datetime

    dns_isp_blocked_current_state: str
    dns_isp_blocked_s_pos: float
    dns_isp_blocked_s_neg: float

    dns_other_blocked_current_state: str
    dns_other_blocked_s_pos: float
    dns_other_blocked_s_neg: float

    tcp_blocked_current_state: str
    tcp_blocked_s_pos: float
    tcp_blocked_s_neg: float

    tls_blocked_current_state: str
    tls_blocked_s_pos: float
    tls_blocked_s_neg: float

    def __missing__(self, key):
        if isinstance(key, str) and key.endswith("_current_state"):
            return "unk"
        return 0.0


def get_cusum_map(
    db: ClickhouseClient,
    start_time: datetime,
    probe_cc: List[str],
    freshness: timedelta = timedelta(days=10),
) -> Dict[str, LastCusum]:
    fresh_ts = start_time - freshness
    where = "WHERE ts < %(start_time)s AND ts > %(fresh_ts)s"
    params: Dict[str, Any] = {"start_time": start_time, "fresh_ts": fresh_ts}
    if probe_cc:
        where += " AND probe_cc IN %(probe_cc)s"
        params["probe_cc"] = probe_cc

    data, columns = db.execute(
        f"""
    SELECT
    probe_asn,
    probe_cc,
    domain,
    max(ts) as max_ts,
    argMax(dns_isp_blocked_current_state, ts) as dns_isp_blocked_current_state,
    argMax(dns_isp_blocked_s_pos, ts) as dns_isp_blocked_s_pos,
    argMax(dns_isp_blocked_s_neg, ts) as dns_isp_blocked_s_neg,
    argMax(dns_other_blocked_current_state, ts) as dns_other_blocked_current_state,
    argMax(dns_other_blocked_s_pos, ts) as dns_other_blocked_s_pos,
    argMax(dns_other_blocked_s_neg, ts) as dns_other_blocked_s_neg,
    argMax(tcp_blocked_current_state, ts) as tcp_blocked_current_state,
    argMax(tcp_blocked_s_pos, ts) as tcp_blocked_s_pos,
    argMax(tcp_blocked_s_neg, ts) as tcp_blocked_s_neg,
    argMax(tls_blocked_current_state, ts) as tls_blocked_current_state,
    argMax(tls_blocked_s_pos, ts) as tls_blocked_s_pos,
    argMax(tls_blocked_s_neg, ts) as tls_blocked_s_neg

    FROM event_detector_cusums
    {where}
    GROUP BY probe_asn, probe_cc, domain
    """,
        params=params,
        with_column_types=True,
    )
    assert isinstance(columns, list)

    last_cusum = {}
    cols: List[str] = ["ts" if name == "max_ts" else name for name, _ in columns]
    for d in data:
        lcsm = LastCusum(**dict(zip(cols, d)))
        key = f"{lcsm['probe_cc']}_{lcsm['probe_asn']}_{lcsm['domain']}"
        last_cusum[key] = lcsm

    return last_cusum


class CusumDetector:
    """
    Implements a two-sided CUSUM detector as per 2.2.5 from
    Detection of Abrupt Changes: Theory and Application, M. Basseville, 1993
    (https://people.irisa.fr/Michele.Basseville/kniga/kniga.pdf).

    The detector is state-aware: it tracks whether the process is currently in
    an OK or BLK state and uses the appropriate fixed reference mean for each
    state when computing the CUSUM innovation z.

    When in OK state:
      s_pos accumulates deviations above mu_0 to detect OK->BLK transitions.
      s_neg is held at zero (inactive).

    When in BLK state:
      s_neg accumulates deviations below mu_1 to detect BLK->OK transitions.
      s_pos is held at zero (inactive).

    Zeroing the inactive accumulator prevents noise accumulated in one state
    from causing spurious detections immediately after a state transition.

    No online mean estimation is performed. mu_0 and mu_1 are fixed a-priori
    parameters. For OONI data mu_0=0.0 (expected blocking rate when OK) and
    mu_1=0.7 (expected blocking rate when BLK) are reasonable defaults.
    """

    def __init__(
        self,
        s_pos: float = 0.0,
        s_neg: float = 0.0,
        current_state: str = "unk",
        mu_0: float = 0.0,  # a-priori mean for the OK state
        mu_1: float = 0.7,  # a-priori mean for the BLK state
        edd: int = 20,
    ) -> None:
        self.mu_0 = mu_0
        self.mu_1 = mu_1
        self.v = mu_1 - mu_0
        self.edd = edd
        self.h = self.edd * self.v / 2.0

        self.current_obs = 0.0
        self.current_state = current_state
        self.s_pos = s_pos or 0.0
        self.s_neg = s_neg or 0.0
        self.last_change: Change = Change.NO

    def run(
        self,
        observations: List[Observation],
        col: str,
        count_col: str,
        warmup: bool = False,
        trace: bool = False,
    ) -> Tuple[List[Changepoint], List[CusumStep]]:
        """
        Run the detector against a list of Observation dicts.

        Assumptions:
        1. Observations are for the same (probe_cc, probe_asn, domain) tuple.
        2. The list is already sorted by timestamp.

        col: the signal column to run detection on.
        count_col: used to determine observation weight; w==0 means no
                   measurements in that window and the observation is skipped.

        When trace=True, records per-step detector state for debugging.
        """
        changepoints: List[Changepoint] = []
        steps: List[CusumStep] = []
        for obs in observations:
            y = obs[col]
            w = obs[count_col]
            change = self._detect(y, w, warmup=warmup)
            is_changepoint = change != Change.NO
            if trace:
                steps.append(
                    CusumStep(
                        ts=obs["ts"],
                        probe_cc=obs["probe_cc"],
                        probe_asn=obs["probe_asn"],
                        domain=obs["domain"],
                        block_type=col,
                        obs_value=y,
                        weight=w,
                        s_pos=self.s_pos,
                        s_neg=self.s_neg,
                        h=self.h,
                        current_state=self.current_state,
                        is_changepoint=is_changepoint,
                    )
                )

            if is_changepoint:
                cp = Changepoint(**obs)
                cp["change_dir"] = change.value
                cp["s_pos"] = self.s_pos
                cp["s_neg"] = self.s_neg
                cp["current_state"] = self.current_state
                cp["h"] = self.h
                cp["block_type"] = col
                changepoints.append(cp)
                self.last_change = change  # remember last emitted direction
                if change == Change.POS:
                    self.current_state = "blk"
                elif change == Change.NEG:
                    self.current_state = "ok"
                self._reset()

        return changepoints, steps

    def _detect(self, y, w, warmup) -> Change:
        self.current_obs = y
        if w == 0.0:
            return Change.NO
        return self._detect_changepoint(warmup)

    def _reset(self) -> None:
        """Flip state and reset accumulators after a changepoint."""
        self.s_pos = 0.0
        self.s_neg = 0.0

    def _detect_changepoint(self, warmup) -> Change:
        z_pos = self.current_obs - self.mu_0
        z_neg = self.current_obs - self.mu_1

        if self.current_state == "unk":
            # Run both accumulators to determine initial state — no changepoint emitted.
            self.s_pos = max(0.0, self.s_pos + z_pos - self.v / 2.0)
            self.s_neg = max(0.0, self.s_neg - z_neg - self.v / 2.0)
            if self.s_pos > self.h:
                self.current_state = "blk"
                self._reset()
            elif self.s_neg > self.h:
                self.current_state = "ok"
                self._reset()
            return Change.NO

        if self.current_state == "ok":
            self.s_pos = max(0.0, self.s_pos + z_pos - self.v / 2.0)
            self.s_neg = 0.0
            if not warmup and self.s_pos > self.h:
                # Only emit if this is a different direction than last change
                if self.last_change != Change.POS:
                    return Change.POS
                else:
                    # Same direction as last change — absorb and stay in state
                    self._reset()

        elif self.current_state == "blk":
            self.s_neg = max(0.0, self.s_neg - z_neg - self.v / 2.0)
            self.s_pos = 0.0
            if not warmup and self.s_neg > self.h:
                if self.last_change != Change.NEG:
                    return Change.NEG
                else:
                    self._reset()

        return Change.NO


ANALYSIS_COLS = [
    ("dns_isp_blocked", "count_isp_resolver"),
    ("dns_other_blocked", "count_other_resolver"),
    ("tcp_blocked", "count"),
    ("tls_blocked", "count"),
]


def detect_changepoints(
    observations: Iterable[Observation],
    cusum_map: Dict[str, LastCusum],
    edd: int,
    analysis_columns: List[Tuple[str, str]] = ANALYSIS_COLS,
    warmup: bool = False,
    trace: bool = False,
) -> Tuple[List[Changepoint], List[LastCusum], List[CusumStep]]:
    changepoints: List[Changepoint] = []
    updated_cusums: List[LastCusum] = []
    all_steps: List[CusumStep] = []

    def key_func(o):
        return (o["probe_cc"], o["probe_asn"], o["domain"])

    for grp, grp_iter in itertools_groupby(observations, key=key_func):
        grp_obs = list(grp_iter)
        cc, asn, domain = grp
        key = f"{cc}_{asn}_{domain}"
        max_ts = max(o["ts"] for o in grp_obs)
        prior_cusum = cusum_map.get(key)
        cusum = prior_cusum or LastCusum(
            probe_cc=cc, probe_asn=asn, domain=domain, ts=max_ts
        )
        for col, count_col in analysis_columns:
            detector = CusumDetector(
                edd=edd,
                current_state=cusum[f"{col}_current_state"],
                s_pos=cusum[f"{col}_s_pos"],
                s_neg=cusum[f"{col}_s_neg"],
            )
            c, steps = detector.run(grp_obs, col, count_col, warmup=warmup, trace=trace)
            log.debug(
                f"Detector results for {col} ({key}): "
                f"state={detector.current_state} "
                f"s_pos={detector.s_pos:.3f} "
                f"s_neg={detector.s_neg:.3f}"
            )
            changepoints += c
            all_steps += steps
            cusum[f"{col}_current_state"] = detector.current_state
            cusum[f"{col}_s_pos"] = detector.s_pos
            cusum[f"{col}_s_neg"] = detector.s_neg
        cusum["ts"] = max_ts
        updated_cusums.append(cusum)
    return changepoints, updated_cusums, all_steps


def get_domain_list(db: ClickhouseClient) -> List[str]:
    rows = db.execute(
        "SELECT domain FROM citizenlab WHERE category_code = 'GRP' AND cc = 'ZZ'"
    )
    grp_domains = [row[0] for row in rows]
    grp_domains += ["twitter.com"]
    return grp_domains


def insert_rows(
    db: ClickhouseClient,
    table_name: str,
    col_names: List[str],
    rows: List[Dict[str, Any]],
):
    col_str = "(" + ", ".join(col_names) + ")"
    q = f"INSERT INTO {table_name} {col_str} VALUES"
    return db.execute(q, rows)


def update_tables(db, updated_cusums: List[LastCusum], changepoints: List[Changepoint]):
    log.info(f"updating cusums table with last_cusums len={len(updated_cusums)}")
    if len(updated_cusums) > 0:
        insert_rows(
            db,
            "event_detector_cusums",
            list(LastCusum.__annotations__.keys()),
            updated_cusums,
        )

    log.info(f"detected {len(changepoints)} changepoints")
    if len(changepoints) > 0:
        insert_rows(
            db,
            "event_detector_changepoints",
            list(Changepoint.__annotations__.keys()),
            changepoints,
        )


def run_detector(
    clickhouse_url: str,
    start_time: datetime,
    end_time: datetime,
    probe_cc: List[str],
    edd: int = 10,
    warmup: bool = False,
    trace: bool = False,
) -> Tuple[List[Changepoint], List[LastCusum], List[CusumStep]]:
    db = ClickhouseClient.from_url(clickhouse_url)
    domains = get_domain_list(db)

    observations = get_observations(
        db,
        start_time=start_time,
        end_time=end_time,
        probe_cc=probe_cc,
        domains=domains,
    )

    cusum_map = get_cusum_map(db=db, start_time=start_time, probe_cc=probe_cc)
    changepoints, updated_cusums, steps = detect_changepoints(
        observations=observations,
        cusum_map=cusum_map,
        edd=edd,
        analysis_columns=ANALYSIS_COLS,
        warmup=warmup,
        trace=trace,
    )
    update_tables(db, updated_cusums, changepoints)

    return changepoints, updated_cusums, steps


def plot(steps: List[CusumStep], block_type: str):
    import altair as alt
    import pandas as pd

    df_steps = pd.DataFrame([s for s in steps if s["block_type"] == block_type])
    df_last = df_steps.loc[[df_steps["ts"].idxmax()]]

    base = alt.Chart(df_steps).encode(x="ts:T")

    def make_label(df, field, label, color):
        return (
            alt.Chart(df)
            .mark_text(align="left", dx=5, fontSize=11, color=color)
            .encode(
                x="ts:T",
                y=alt.Y(f"{field}:Q"),
                text=alt.value(label),
            )
        )

    obs_line = base.mark_line(color="steelblue", opacity=0.5).encode(
        y=alt.Y("obs_value:Q", title="value"),
        tooltip=["ts:T", "obs_value:Q", "weight:Q", "current_state:N"],
    )
    s_pos_line = base.mark_line(color="red").encode(
        y=alt.Y("s_pos:Q"),
        tooltip=["ts:T", "s_pos:Q"],
    )
    s_neg_line = base.mark_line(color="orange").encode(
        y=alt.Y("s_neg:Q"),
        tooltip=["ts:T", "s_neg:Q"],
    )
    threshold = (
        alt.Chart(df_steps).mark_rule(color="green", strokeDash=[4, 4]).encode(y="h:Q")
    )
    cp_points = (
        alt.Chart(df_steps[df_steps["is_changepoint"]])
        .mark_point(color="black", size=100, shape="diamond")
        .encode(
            x="ts:T",
            y=alt.Y("obs_value:Q"),
            tooltip=["ts:T", "obs_value:Q", "s_pos:Q", "s_neg:Q", "current_state:N"],
        )
    )

    obs_label = make_label(df_last, "obs_value", "observed", "steelblue")
    s_pos_label = make_label(df_last, "s_pos", "S+", "red")
    s_neg_label = make_label(df_last, "s_neg", "S−", "orange")
    df_h = df_last[["ts", "h"]].copy()
    threshold_label = (
        alt.Chart(df_h)
        .mark_text(align="left", dx=5, fontSize=11, color="green")
        .encode(x="ts:T", y="h:Q", text=alt.value("threshold (h)"))
    )

    chart = (
        (
            obs_line
            + obs_label
            + s_pos_line
            + s_pos_label
            + s_neg_line
            + s_neg_label
            + threshold
            + threshold_label
            + cp_points
        )
        .properties(
            width=900,
            height=400,
            title=f"CUSUM Detector: {block_type}",
        )
        .interactive()
    )
    chart.show()
