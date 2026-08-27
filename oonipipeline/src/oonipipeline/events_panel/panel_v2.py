import math
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

STATE_COLORS = {
    "UNK": "#fff3cd",
    "OK": "#d4edda",
    "BLOCK": "#f8d7da",
}


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
        date_range = st.date_input(
            "**Date range**",
            value=(now.date() - timedelta(days=7), now.date()),
            key="v2_date_range_input",
        )

        c1, c2 = st.columns(2)
        probe_cc = c1.text_input(
            "**Country code (two chars, optional)**", "VE", key="v2_probe_cc_input"
        )
        domain = c2.text_input(
            "**Domain**", "www.caraotadigital.net", key="v2_domain_input"
        )

        submitted = st.form_submit_button("Run")

    # While only the first date of the range has been picked, date_input
    # returns a one-element tuple — treat that as not-yet-submittable.
    if submitted and len(date_range) == 2:
        start_time = datetime.combine(date_range[0], datetime.min.time())
        # inclusive of the whole end date, since we only collect a date
        end_time = datetime.combine(date_range[1], datetime.min.time()) + timedelta(days=1)

        st.session_state["v2_cells"] = get_cells_cached(
            clickhouse_url,
            [domain.strip()],
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
    w_clear = math.log((1 - 0.9) / (1 - 0.1))
    w_block = math.log(0.9 / 0.1)
    st.write(f"w_clear: {w_clear:.3f}, w_block: {w_block:.3f}")

    ccs_in_result = sorted({c.probe_cc for c in cells})
    selected_cc = st.selectbox("Country", ccs_in_result, key="v2_cc_select")

    series_cells = [c for c in cells if c.probe_cc == selected_cc]
    series_cells.sort(key=lambda c: c.ts_hour)

    if not series_cells:
        st.warning("No cells found for this country selection")
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

    for layer in layers:
        llr_series = detectors[layer].compute_llr_series(series_cells, layer)
        st.write(f"**LLR** ({layer})")
        llr_df = pd.DataFrame(
            {
                "ts_hour": [c.ts_hour for c in series_cells],
                "llr": llr_series,
            }
        )
        st.line_chart(llr_df, x="ts_hour", y="llr")

    with st.expander("🔧 Debug"):
        if st.checkbox("Show cells as dataframe", key="v2_debug_show_cells"):
            st.dataframe(pd.DataFrame(series_cells))

        if st.checkbox("Show s_pos/s_neg as dataframe", key="v2_debug_show_s_values"):
            s_records = [
                {
                    "layer": layer,
                    "ts_hour": series_cells[i].ts_hour,
                    "s_neg": detector.series[i][0],
                    "s_pos": detector.series[i][1],
                    "state": detector.series[i][2],
                }
                for layer, detector in detectors.items()
                for i in range(min(len(series_cells), len(detector.series)))
            ]
            s_df = pd.DataFrame(
                s_records, columns=["layer", "ts_hour", "s_neg", "s_pos", "state"]
            )
            s_df = s_df.sort_values(["layer", "ts_hour"]).reset_index(drop=True)

            def _style_state(val):
                color = STATE_COLORS.get(str(val))
                return f"background-color: {color}" if color else ""

            st.dataframe(
                s_df.style.applymap(_style_state, subset=["state"]),
                hide_index=True,
            )
