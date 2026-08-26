from datetime import datetime, timezone, timedelta

import pandas as pd
import streamlit as st
from clickhouse_driver import Client as ClickhouseClient

from oonipipeline.analysis.detectorV2 import (
    Cell,
    get_cells,
    make_cells_histogram_chart,
    make_rule_histogram_chart, Detector,
)


@st.cache_data(ttl=300)
def get_cells_cached(
    clickhouse_url: str,
    domains: list[str],
    start_time: datetime,
    end_time: datetime,
    probe_cc: str | None,
) -> list[Cell]:
    client = ClickhouseClient.from_url(clickhouse_url)
    return get_cells(client, domains, start_time, end_time, probe_cc)


def detector_v2_panel():
    st.write(
        """
    # Event Detector V2

    Work in progress: rule-histogram-based cell construction for the
    Bernoulli-share CUSUM described in
    [docs.ooni.org/data/pipeline-implementation-plan §3.6](
    https://docs.ooni.org/data/pipeline-implementation-plan/#36-cell-state-as-a-rule-histogram).
    """
    )

    now = datetime.now(timezone.utc)

    clickhouse_url = st.sidebar.text_input(
        "**Clickhouse url**", "clickhouse://localhost:9000/ooni"
    )

    with st.form("detector_v2_params"):
        c1, c2 = st.columns(2)

        start_time = c1.datetime_input(
            "**Start date**", now - timedelta(days=7), key="v2_start_time_input"
        )
        probe_cc = c1.text_input(
            "**Country code (two chars, optional)**", "VE", key="v2_probe_cc_input"
        )

        end_time = c2.datetime_input("**End date**", now, key="v2_end_time_input")
        domains_raw = c2.text_input(
            "**Domains (comma separated)**", "www.caraotadigital.net", key="v2_domains_input"
        )

        submitted = st.form_submit_button("Run")

    if submitted:
        domains = [d.strip() for d in domains_raw.split(",") if d.strip()]
        st.session_state["v2_cells"] = get_cells_cached(
            clickhouse_url,
            domains,
            start_time,
            end_time,
            probe_cc.strip() or None,
        )

    if "v2_cells" not in st.session_state:
        return

    cells = st.session_state["v2_cells"]
    if not cells:
        st.warning("No cells found for the given inputs")
        return

    st.write(f"Cells: **{len(cells)}**")

    domains_in_result = sorted({c.domain for c in cells})
    selected_domain = st.selectbox("Domain", domains_in_result, key="v2_domain_select")

    ccs_in_result = sorted(
        {c.probe_cc for c in cells if c.domain == selected_domain}
    )
    selected_cc = st.selectbox("Country", ccs_in_result, key="v2_cc_select")

    series_cells = [
        c for c in cells if c.domain == selected_domain and c.probe_cc == selected_cc
    ]
    series_cells.sort(key=lambda c: c.ts_hour)

    if not series_cells:
        st.warning("No cells found for this domain/country selection")
        return

    layers = ['tcp', 'tls', 'dns']
    detectors = dict()
    changepoints = dict()
    for layer in layers:
        detectors[layer] = Detector(debug=True)
        changepoints[layer] = detectors[layer].compute_changepoints(series_cells, layer)

    st.write("**Outcome histogram** (blocked / ok / discarded)")
    st.altair_chart(make_cells_histogram_chart(series_cells, detectors))

    st.write("**Rule histogram** (stacked by individual rule id)")
    st.altair_chart(make_rule_histogram_chart(series_cells, detectors))

    with st.expander("🔧 Debug"):
        if st.checkbox("Show cells as dataframe", key="v2_debug_show_cells"):
            st.dataframe(pd.DataFrame(series_cells))
