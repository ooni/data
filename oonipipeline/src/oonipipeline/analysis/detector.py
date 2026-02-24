import logging
import math
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
    current_mean: float
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
    variance: float
    current_mean: float
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

    dns_isp_blocked_obs_w_sum: float = 0
    dns_isp_blocked_w_sum: float = 0
    dns_isp_blocked_s_pos: float = 0
    dns_isp_blocked_s_neg: float = 0

    dns_other_blocked_obs_w_sum: float = 0
    dns_other_blocked_w_sum: float = 0
    dns_other_blocked_s_pos: float = 0
    dns_other_blocked_s_neg: float = 0

    tcp_blocked_obs_w_sum: float = 0
    tcp_blocked_w_sum: float = 0
    tcp_blocked_s_pos: float = 0
    tcp_blocked_s_neg: float = 0

    tls_blocked_obs_w_sum: float = 0
    tls_blocked_w_sum: float = 0
    tls_blocked_s_pos: float = 0
    tls_blocked_s_neg: float = 0

    def __missing__(self, key) -> float:
        # used to return 0.0 for when the dns_,tcp_,tls_ keys are not set
        return 0.0


def get_cusum_map(
    db: ClickhouseClient,
    start_time: datetime,
    probe_cc: List[str],
    freshness: timedelta = timedelta(days=10),
) -> Dict[str, LastCusum]:
    fresh_ts = start_time - freshness
    where = "WHERE ts < %(start_time)s AND ts > %(fresh_ts)s"
    # Workaround for timezone aware bug
    params: Dict[str, Any] = {"start_time": start_time, "fresh_ts": fresh_ts}
    if probe_cc:
        where += "AND probe_cc IN %(probe_cc)s"
        params["probe_cc"] = probe_cc

    data, columns = db.execute(
        f"""
    SELECT
    probe_asn,
    probe_cc,
    domain,
    max(ts) as max_ts,
    argMax(dns_isp_blocked_obs_w_sum, ts) as dns_isp_blocked_obs_w_sum,
    argMax(dns_isp_blocked_w_sum, ts) as dns_isp_blocked_w_sum,
    argMax(dns_isp_blocked_s_pos, ts) as dns_isp_blocked_s_pos,
    argMax(dns_isp_blocked_s_neg, ts) as dns_isp_blocked_s_neg,
    argMax(dns_other_blocked_obs_w_sum, ts) as dns_other_blocked_obs_w_sum,
    argMax(dns_other_blocked_w_sum, ts) as dns_other_blocked_w_sum,
    argMax(dns_other_blocked_s_pos, ts) as dns_other_blocked_s_pos,
    argMax(dns_other_blocked_s_neg, ts) as dns_other_blocked_s_neg,
    argMax(tcp_blocked_obs_w_sum, ts) as tcp_blocked_obs_w_sum,
    argMax(tcp_blocked_w_sum, ts) as tcp_blocked_w_sum,
    argMax(tcp_blocked_s_pos, ts) as tcp_blocked_s_pos,
    argMax(tcp_blocked_s_neg, ts) as tcp_blocked_s_neg,
    argMax(tls_blocked_obs_w_sum, ts) as tls_blocked_obs_w_sum,
    argMax(tls_blocked_w_sum, ts) as tls_blocked_w_sum,
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
    # rename max_ts to ts
    cols: List[str] = ["ts" if name == "max_ts" else name for name, _ in columns]
    for d in data:
        lcsm = LastCusum(**dict(zip(cols, d)))
        key = f"{lcsm['probe_cc']}_{lcsm['probe_asn']}_{lcsm['domain']}"
        last_cusum[key] = lcsm

    return last_cusum


# this is the main hyper-parameter
# per-sample drift is estimated at v/2
# so to determine the estimated detection delay we can use
# the formula h = edd * v/2
# EDD hence becomes a hyperparameter
class CusumDetector:
    """
    Implements a two-sided CUSUM detector as per 2.2.5 from
    Detection of Abrupt Changes: Theory and Application, M. Basseville, 1993 (
    https://people.irisa.fr/Michele.Basseville/kniga/kniga.pdf).

    Some nuances specific to the OONI dataset are applied.

    These are:

    * We take the median of the values for the hourly aggregations to control for outliers
    * The Estimated Detection Delay (EDD) is used to determine the h value by
      canceling out the multiplicative term mu1-mu0/stddev^2
    * The v value is estimated a-priori by making the assumption that mean for
      the control process for an OK state is 0.0 (mu0), while the BLK state is
      0.7 (mu1)
    """

    def __init__(
        self,
        obs_w_sum=0.0,
        w_sum=0.0,
        s_pos=0.0,
        s_neg=0.0,
        mu_0=0.0,  # a-priori estimated parameter for the mean of the OK state
        mu_1=0.7,  # a-priori estimated parameter for the mean of the BLK state
        edd=20,  #
    ) -> None:
        self.mu_0 = mu_0
        self.mu_1 = mu_1
        self.sample_variance = 0.1

        self.v = 0.7
        self.edd = edd
        self.h = self.edd * self.v / 2.0

        # These can be initialized to existing values
        self.current_obs_w_sum = obs_w_sum or 0.0
        self.current_w_sum = w_sum or 0.0

        # default to prevent linter complaining
        self.current_obs = 0.0
        self.current_mean = 0.0

        self.s_pos = s_pos or 0.0
        self.s_neg = s_neg or 0.0

    def run(
        self,
        observations: List[Observation],
        col: str,
        count_col: str,
        trace: bool = False,
    ) -> Tuple[List[Changepoint], List[CusumStep]]:
        """
        Run the detector against a list of Observation dicts.

        The following assumptions are made:
        1. We only have metrics for the same probe_cc, probe_asn, domain tuple
        2. The list is already sorted by timestamp

        col is a string that specifies which column we should be performing
        detection on.

        count_col: is a column which we use to derive weights to apply to the
        col value. In practice this will be a count so that we can calculate the
        mean value to use in the cusum that's weighed by the count of each
        observation window.

        When trace=True, records per-step detector state for debugging.
        """
        changepoints: List[Changepoint] = []
        steps: List[CusumStep] = []
        for obs in observations:
            y = obs[col]
            w = obs[count_col]
            change = self._detect(y, w)
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
                        variance=self.sample_variance,
                        h=self.h,
                        current_mean=self.current_mean,
                        is_changepoint=is_changepoint,
                    )
                )
            if is_changepoint:
                cp = Changepoint(**obs)
                cp["change_dir"] = change.value
                cp["s_pos"] = self.s_pos
                cp["s_neg"] = self.s_neg
                cp["current_mean"] = self.current_mean
                cp["h"] = self.h
                cp["block_type"] = col
                changepoints.append(cp)
                self._reset()

        return changepoints, steps

    def _detect(self, y, w) -> Change:
        self.current_obs = y
        self.current_obs_w_sum += y * w
        self.current_w_sum += w
        if w > 0:
            self.sample_variance += ((y - self.current_mean) * w) ** 2 / w
        return self._detect_changepoint()

    def _reset(self) -> None:
        self.current_obs = 0.0
        self.current_obs_w_sum = 0.0
        self.current_w_sum = 0.0
        self.sample_variance = 0.1

        self.s_pos = 0.0
        self.s_neg = 0.0

    def _detect_changepoint(self) -> Change:
        # Special case when the weights are zero
        if self.current_w_sum == 0:
            return Change.NO
        self.current_mean = self.current_obs_w_sum / self.current_w_sum
        z = (self.current_obs - self.current_mean) / math.sqrt(self.sample_variance)
        self.s_pos = max(0.0, self.s_pos + z - self.v / 2.0)
        self.s_neg = max(0.0, self.s_neg - z - self.v / 2.0)
        if self.s_pos > self.h:
            return Change.POS
        if self.s_neg > self.h:
            return Change.NEG
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
    trace: bool = False,
) -> Tuple[List[Changepoint], List[LastCusum], List[CusumStep]]:
    changepoints: List[Changepoint] = []
    updated_cusums: List[LastCusum] = []
    all_steps: List[CusumStep] = []
    log.info("running with observations")

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
                obs_w_sum=cusum[f"{col}_obs_w_sum"],
                w_sum=cusum[f"{col}_w_sum"],
                s_pos=cusum[f"{col}_s_pos"],
                s_neg=cusum[f"{col}_s_neg"],
            )
            c, steps = detector.run(grp_obs, col, count_col, trace=trace)
            log.info(f"Detector results for {col}: {grp_obs}")
            log.info(f" {detector.s_neg}, {detector.s_pos}")
            changepoints += c
            all_steps += steps
            cusum[f"{col}_obs_w_sum"] = detector.current_obs_w_sum
            cusum[f"{col}_w_sum"] = detector.current_w_sum
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
        trace=trace,
    )
    update_tables(db, updated_cusums, changepoints)

    return changepoints, updated_cusums, steps


def plot(steps: List[CusumStep], block_type: str):
    import altair as alt
    import pandas as pd

    df_steps = pd.DataFrame([s for s in steps if s["block_type"] == block_type])

    base = alt.Chart(df_steps).encode(x="ts:T")

    obs_line = base.mark_line(color="steelblue", opacity=0.5).encode(
        y=alt.Y("obs_value:Q", title="value"),
        tooltip=["ts:T", "obs_value:Q", "weight:Q", "last_cusum_ts:T"],
    )

    s_pos_line = base.mark_line(color="red").encode(
        y=alt.Y("s_pos:Q"),
        tooltip=["ts:T", "s_pos:Q"],
    )

    s_neg_line = base.mark_line(color="orange").encode(
        y=alt.Y("s_neg:Q"),
        tooltip=["ts:T", "s_neg:Q"],
    )

    variance = base.mark_line(color="grey").encode(
        y=alt.Y("variance:Q"),
        tooltip=["ts:T", "variance:Q"],
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
            tooltip=["ts:T", "obs_value:Q", "s_pos:Q", "s_neg:Q"],
        )
    )

    chart = (
        (obs_line + s_pos_line + s_neg_line + variance + threshold + cp_points)
        .properties(
            width=900,
            height=400,
            title=f"CUSUM Detector: {block_type}",
        )
        .interactive()
    )

    chart.show()
