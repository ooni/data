import math
from collections import defaultdict
from dataclasses import asdict
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


def render_scrollable_chart(chart, height: int = 650):
    """
    These charts grow wider than the page as the date range grows (bar
    width is scaled to the number of hourly bars so they don't overlap).
    st.altair_chart renders the chart at its native width and lets the page
    itself grow instead of scrolling — build the embed by hand instead, in
    an explicit overflow-x:auto div, so it scrolls within a fixed-height
    iframe (via st.iframe) instead.

    height must comfortably fit the whole rendered chart (title + stacked
    subplots + bottom x-axis tick labels): overflow-y is hidden, so unlike
    overflow-x there's no scroll fallback if it's too short — content just
    gets clipped instead.
    """
    html = f"""
    <div style="overflow-x: auto; overflow-y: hidden; width: 100%; padding-bottom: 8px;">
      <div id="vis"></div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/vega@5"></script>
    <script src="https://cdn.jsdelivr.net/npm/vega-lite@4.17.0"></script>
    <script src="https://cdn.jsdelivr.net/npm/vega-embed@6"></script>
    <script type="text/javascript">
      vegaEmbed('#vis', {chart.to_json()}).catch(console.error);
    </script>
    """
    # The iframe itself never scrolls (full height always visible); the
    # inner div's overflow-x:auto is what actually scrolls.
    st.iframe(html, width="stretch", height=height)


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

        c3, c4, c5 = st.columns(3)
        p0 = c3.number_input(
            "**p0**", value=0.05, min_value=0.0, max_value=1.0, key="v2_p0_input"
        )
        p1 = c4.number_input(
            "**p1**", value=0.50, min_value=0.0, max_value=1.0, key="v2_p1_input"
        )
        h = c5.number_input("**h**", value=30.0, key="v2_h_input")

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
        # New results — drop any ASN selection from a previous run so the
        # default (an anomalous ASN, if any) gets recomputed below.
        st.session_state.pop("v2_asn_select", None)

    if "v2_cells" not in st.session_state:
        return

    cells = st.session_state["v2_cells"]
    if not cells:
        st.warning("No cells found for the given inputs")
        return

    st.write(f"Cells: **{len(cells)}**")
    w_clear = math.log((1 - p1) / (1 - p0))
    w_block = math.log(p1 / p0)
    st.write(f"w_clear: {w_clear:.3f}, w_block: {w_block:.3f}")

    # The CUSUM state is per (probe_cc, probe_asn, resolver_asn, domain)
    # series — mixing every ASN's cells into one detector run conflates
    # unrelated series and produces meaningless s_pos/s_neg. Run the
    # detector separately per ASN instead, same as the original detector.
    layers = ['tcp', 'tls', 'dns']
    cells_by_asn = defaultdict(list)
    for c in cells:
        cells_by_asn[c.probe_asn].append(c)
    for asn_cells in cells_by_asn.values():
        asn_cells.sort(key=lambda c: c.ts_hour)

    asn_counts = {asn: len(asn_cells) for asn, asn_cells in cells_by_asn.items()}

    detectors_by_asn = dict()
    changepoints_by_asn = dict()
    asns_with_changepoints = set()
    for asn, asn_cells in cells_by_asn.items():
        detectors_by_asn[asn] = dict()
        changepoints_by_asn[asn] = dict()
        for layer in layers:
            detector = Detector(debug=True)
            cps = detector.compute_changepoints(asn_cells, layer, p0=p0, p1=p1, h=h)
            detectors_by_asn[asn][layer] = detector
            changepoints_by_asn[asn][layer] = cps
            if cps:
                asns_with_changepoints.add(asn)

    asn_list = sorted(cells_by_asn.keys(), key=lambda a: asn_counts[a], reverse=True)

    # Default to an ASN with anomalies, same as the original detector panel;
    # fall back to the ASN with the most cells if none have anomalies.
    if "v2_asn_select" not in st.session_state:
        st.session_state["v2_asn_select"] = next(
            (a for a in asn_list if a in asns_with_changepoints), asn_list[0]
        )

    selected_asn = st.selectbox(
        "ASN",
        asn_list,
        format_func=lambda a: f"{'❗️' if a in asns_with_changepoints else ''}{a} ({asn_counts[a]})",
        key="v2_asn_select",
    )

    series_cells = cells_by_asn[selected_asn]
    detectors = detectors_by_asn[selected_asn]
    changepoints = changepoints_by_asn[selected_asn]

    all_changepoints = [
        {**asdict(cp), "layer": layer}
        for layer, cps in changepoints.items()
        for cp in cps
    ]
    if all_changepoints:
        st.write("**Changepoints**")
        cp_df = pd.DataFrame(all_changepoints)
        cp_df = cp_df.sort_values("ts_hour", ascending=False).reset_index(drop=True)
        display_cols = [
            c
            for c in [
                "ts_hour", "probe_asn", "resolver_asn", "domain",
                "layer", "state", "s_pos", "s_neg", "h",
            ]
            if c in cp_df.columns
        ]
        st.dataframe(cp_df[display_cols], hide_index=True)

    st.write("**Outcome histogram** (blocked / ok / discarded)")
    render_scrollable_chart(make_cells_histogram_chart(series_cells, detectors))

    st.write("**Rule histogram** (stacked by individual rule id)")
    render_scrollable_chart(make_rule_histogram_chart(series_cells, detectors))

    for layer in layers:
        llr_series = detectors[layer].compute_llr_series(series_cells, layer, p0=p0, p1=p1)
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
