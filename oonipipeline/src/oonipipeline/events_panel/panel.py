from collections import defaultdict
import streamlit as st
from oonipipeline.analysis.detector import make_cusums_chart, run_detector_for
from datetime import datetime, timezone, timedelta, date
import logging

log = logging.getLogger(__name__)


def sample(lst: list, n: int):
    if n >= len(lst):
        return lst
    step = len(lst) / n
    return [lst[int(i * step)] for i in range(n)]

def to_datetime(d: date):
    datetime.combine(d, datetime.min.time(), timezone.utc)

st.write(
    """
# Event Detector
Run the event detector over the specified input to get a simulation of results
for the given input
Results are **not** saved to db
"""
)

now = datetime.now(timezone.utc)

clickhouse_url = st.sidebar.text_input(
    "**Clickhouse url**", "clickhouse://localhost:9000/ooni"
)

with st.form("detector_params"):
    c1, c2 = st.columns(2)

    # column 1
    start_time = c1.date_input("**Start time**", now - timedelta(days=30))
    probe_cc = c1.text_input("**Country code (two chars)**", "VE")
    edd = c1.number_input("**Estimated Detection Delay (EDD)**", value=10)

    # column2
    end_time = c2.date_input("**End time**", now)
    domain = c2.text_input("**domain**", "x.com")
    gap_halflife = c2.number_input("**Gap half life**", value=48.0)

    warmup = st.checkbox("**Warmup**", True)
    submitted = st.form_submit_button("Run detector")




if submitted:
    changepoints, _, cusum_steps = run_detector_for(
        clickhouse_url,
        to_datetime(start_time),
        to_datetime(end_time),
        probe_cc,
        [domain],
        edd,
        gap_halflife,
        warmup,
    )

    asns = defaultdict(int)
    for step in cusum_steps:
        asns[step['probe_asn']] += 1

    # st.table(asns)

    st.altair_chart(make_cusums_chart(sample(cusum_steps, 1000), "dns_isp_blocked"))
    c1, c2 = st.columns(2)
    c1.write(f"Changepoints: **{len(changepoints)}**")
    c2.write(f"Cusum steps: **{len(cusum_steps)}**")

    pass
