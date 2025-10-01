from datetime import datetime
import logging
from typing import Any, Dict, List, Optional, Tuple
from enum import Enum
from dataclasses import dataclass

import pandas as pd
import numpy as np
from clickhouse_driver import Client as ClickhouseClient

log = logging.getLogger(__name__)

Change = Enum('Change', [('POS', 1), ('NO', 0), ('NEG', -1)])

def query_dataframe(
    db: ClickhouseClient,
    start_time: datetime,
    end_time: datetime,
    probe_cc: Optional[List[str]] = None):
    params : Dict[str, Any] = {
        "since": start_time,
        "until": end_time,
    }
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
    ORDER BY ts
    """
    return db.query_dataframe(q, params=params)

def get_lastcusums(db: ClickhouseClient, start_time: datetime, probe_cc: List[str]):
    where = "WHERE ts <= %(start_time)s"
    params : Dict[str, Any] = {"start_time": start_time}
    if probe_cc:
        where += "AND probe_cc IN %(probe_cc)s"
        params["probe_cc"] = probe_cc

    return db.query_dataframe("""
    SELECT
    probe_asn,
    probe_cc,
    domain,
    last_value_respect_nulls(ts) as last_ts,
    last_value_respect_nulls(dns_isp_blocked_obs_w_sum) as dns_isp_blocked_obs_w_sum,
    last_value_respect_nulls(dns_isp_blocked_w_sum) as dns_isp_blocked_w_sum,
    last_value_respect_nulls(dns_isp_blocked_s_pos) as dns_isp_blocked_s_pos,
    last_value_respect_nulls(dns_isp_blocked_s_neg) as dns_isp_blocked_s_neg,
    last_value_respect_nulls(dns_other_blocked_obs_w_sum) as dns_other_blocked_obs_w_sum,
    last_value_respect_nulls(dns_other_blocked_w_sum) as dns_other_blocked_w_sum,
    last_value_respect_nulls(dns_other_blocked_s_pos) as dns_other_blocked_s_pos,
    last_value_respect_nulls(dns_other_blocked_s_neg) as dns_other_blocked_s_neg,
    last_value_respect_nulls(tcp_blocked_obs_w_sum) as tcp_blocked_obs_w_sum,
    last_value_respect_nulls(tcp_blocked_w_sum) as tcp_blocked_w_sum,
    last_value_respect_nulls(tcp_blocked_s_pos) as tcp_blocked_s_pos,
    last_value_respect_nulls(tcp_blocked_s_neg) as tcp_blocked_s_neg,
    last_value_respect_nulls(tls_blocked_obs_w_sum) as tls_blocked_obs_w_sum,
    last_value_respect_nulls(tls_blocked_w_sum) as tls_blocked_w_sum,
    last_value_respect_nulls(tls_blocked_s_pos) as tls_blocked_s_pos,
    last_value_respect_nulls(tls_blocked_s_neg) as tls_blocked_s_neg

    FROM (
        SELECT *
        FROM event_detector_cusums 
        {where}
        ORDER BY ts DESC
    )
    GROUP BY probe_asn, probe_cc, domain
    """, params=params)

@dataclass
class LastCuSum:
    probe_asn: int
    probe_cc: str
    domain: str
    ts: datetime

    dns_isp_blocked_obs_w_sum: Optional[float] = None
    dns_isp_blocked_w_sum: Optional[float] = None
    dns_isp_blocked_s_pos: Optional[float] = None
    dns_isp_blocked_s_neg: Optional[float] = None

    dns_other_blocked_obs_w_sum: Optional[float] = None
    dns_other_blocked_w_sum: Optional[float] = None
    dns_other_blocked_s_pos: Optional[float] = None
    dns_other_blocked_s_neg: Optional[float] = None

    tcp_blocked_obs_w_sum: Optional[float] = None
    tcp_blocked_w_sum: Optional[float] = None
    tcp_blocked_s_pos: Optional[float] = None
    tcp_blocked_s_neg: Optional[float] = None

    tls_blocked_obs_w_sum: Optional[float] = None
    tls_blocked_w_sum: Optional[float] = None
    tls_blocked_s_pos: Optional[float] = None
    tls_blocked_s_neg: Optional[float] = None

@dataclass
class ChangePoint:
    direction : Change
    s_pos: float
    s_neg: float
    current_mean: float
    h: float

# this is the main hyper-parameter
# per-sample drift is estimated at v/2
# so to determine the estimated detection delay we can use
# the formula h = edd * v/2
# EDD hence becomes a hyperparameter
class CusumDetector():
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
    def __init__(self,
                 obs_w_sum = 0,
                 w_sum = 0,
                 s_pos = 0,
                 s_neg = 0,
                 mu_0 = 0.0, # a-priori estimated parameter for the mean of the OK state
                 mu_1 = 0.7, # a-priori estimated parameter for the mean of the BLK state
                 stddev = 0.1, # a-priori this is the stddev of a stable series
                 edd = 20, #
        ) -> None:
        self.mu_0 = mu_0
        self.mu_1 = mu_1
        self.stddev = stddev

        self.v = mu_1 - mu_0
        self.edd = edd
        self.h = self.edd * self.v/2

        # These can be initialized to existing values
        self._current_obs_w_sum = obs_w_sum or 0
        self._current_w_sum = w_sum or 0

        self._s_pos = s_pos or 0
        self._s_neg = s_neg or 0

    def run(self, df: pd.DataFrame, col: str, count_col: str):
        """
        Run the detector against the specified pandas dataframe.

        The following assumptions about the dataframe are made:
        1. We only have metrics for the same probe_cc, probe_asn, domain tuple 
            (i.e. groupby(['probe_cc', 'probe_asn', 'domain']))
        2. The dataframe is already sorted by timestamp

        col is a string that specifies which column of the dataframe we should
        be performing detection on.

        count_col: is a column which we use to derive weights to apply to the
        col value. In practice this will be a count so that we can calculate the
        mean value to use in the cusum that's weighed by the count of each
        observation window.
        """
        changepoints = []
        for _, row in df.iterrows():
            y = row[col]
            w = row[count_col]
            change = self.detect(y, w)
            if change != Change.NO:
                row['change_dir'] = change.value
                row['s_pos'] = self.s_pos
                row['s_neg'] = self.s_neg
                row['current_mean'] = self.current_mean
                row['h'] = self.h
                changepoints.append(row)
                self._reset()

        return changepoints

    def detect(self, y, w) -> Change:
        self._update_data(y, w)
        return self._detect_changepoint()

    @property
    def current_obs_w_sum(self):
        return self._current_obs_w_sum

    @property
    def current_w_sum(self):
        return self._current_w_sum

    @property
    def s_pos(self):
        return self._s_pos

    @property
    def s_neg(self):
        return self._s_neg
    
    def _reset(self) -> None:
        self.current_obs = 0
        self._current_obs_w_sum = 0
        self._current_w_sum = 0

        self._s_pos = 0
        self._s_neg = 0

    def _update_data(self, y, w) -> None:
        self.current_obs = y
        self._current_obs_w_sum += y * w
        self._current_w_sum += w

    def _detect_changepoint(self) -> Change:
        # Special case when the weights are zero
        if self.current_w_sum == 0:
            return Change.NO
        self.current_mean = self.current_obs_w_sum / self.current_w_sum
        self._s_pos = max(0, self.s_pos + self.current_obs - self.current_mean - self.v/2)
        self._s_neg = max(0, self.s_neg - self.current_obs + self.current_mean - self.v/2)
        if self.s_pos > self.h:
            return Change.POS
        if self.s_neg > self.h:
            return Change.NEG
        return Change.NO

def run_detector(
    clickhouse_url: str,
    start_time: datetime,
    end_time: datetime,
    probe_cc: List[str],
    edd: int = 10
):
    db = ClickhouseClient.from_url(clickhouse_url)
    df = query_dataframe(db, start_time=start_time, end_time=end_time, probe_cc=probe_cc)

    df_last_cusums = get_lastcusums(db, start_time=start_time, probe_cc=probe_cc)
    if not len(df_last_cusums):
        log.info(f"no cusums found in last cusums table for start_time = {start_time}")
    else:
        last_ts = df_last_cusums["last_ts"].max()
        log.info(f"last cusum timestamp is {last_ts}")
        cusums_delta = (start_time - last_ts).total_seconds()/3600
        if cusums_delta < 10:
            log.info("we have a fresh cusum, will use it to bootstrap the cusum detector")
            df = df.join(
                df_last_cusums.set_index(['probe_cc', 'probe_asn', 'domain']),
                on=['probe_cc', 'probe_asn', 'domain']
            )

    COLS = [
        ('dns_isp_blocked', 'count_isp_resolver'),
        ('dns_other_blocked', 'count_other_resolver'),
        ('tcp_blocked', 'count'),
        ('tls_blocked', 'count')
    ]
    changepoints = []
    last_cusums = []
    for grp, df_grp in df.groupby(['probe_cc', 'probe_asn', 'domain']):
        cc, asn, domain = grp
        last_cusum = LastCuSum(
            probe_cc=cc,
            probe_asn=asn,
            domain=domain,
            ts=df_grp['ts'].max()
        )
        for col, count_col in COLS:
            row = df_grp.iloc[0]
            obs_w_sum = row[f"{col}_obs_w_sum"]
            w_sum = row[f"{col}_w_sum"]
            s_pos = row[f"{col}_s_pos"]
            s_neg = row[f"{col}_s_neg"]
            detector = CusumDetector(edd=edd, obs_w_sum=obs_w_sum, w_sum=w_sum, s_pos=s_pos, s_neg=s_neg)
            c = detector.run(df_grp, col, count_col)
            changepoints += c
            setattr(last_cusum, f"{col}_obs_w_sum", detector.current_obs_w_sum)
            setattr(last_cusum, f"{col}_w_sum", detector.current_w_sum)
            setattr(last_cusum, f"{col}_s_pos", detector.s_pos)
            setattr(last_cusum, f"{col}_s_neg", detector.s_neg)
        last_cusums.append(last_cusum)

    log.info(f"updating cusums table with last_cusums len={len(last_cusums)}")
    db.insert_dataframe("INSERT INTO event_detector_cusums VALUES", pd.DataFrame(last_cusums))

    log.info(f"detected {len(changepoints)} changepoints")
    if len(changepoints) > 0:
        db.insert_dataframe("INSERT INTO event_detector_changepoints VALUES", pd.DataFrame(changepoints))