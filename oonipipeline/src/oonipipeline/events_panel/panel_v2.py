import math
from collections import defaultdict
from dataclasses import asdict
from datetime import date, datetime, timezone, timedelta
from urllib.parse import urlencode
import pandas as pd
import streamlit as st
from clickhouse_driver import Client as ClickhouseClient

from oonipipeline.analysis.detectorV2 import (
    Cell,
    iter_cells,
    make_cells_histogram_chart,
    Detector, compute_llr_series,
)

STATE_COLORS = {
    "UNK": "#fff3cd",
    "OK": "#d4edda",
    "BLOCK": "#f8d7da",
}

# When every one of these is present the form auto-runs on first load
QUERY_FIELD_TO_WIDGET_KEY = {
    "probe_cc": "v2_probe_cc_input",
    "domain": "v2_domain_input",
    "p0": "v2_p0_input",
    "p1": "v2_p1_input",
    "h": "v2_h_input",
}

DATE_RANGE_QUERY_FIELDS = ("start_time", "end_time")


def _parse_query_value(field: str, raw: str):
    if field in ("p0", "p1", "h"):
        return float(raw)
    if field in ("probe_asn", "resolver_asn"):
        return int(raw)
    if field in DATE_RANGE_QUERY_FIELDS:
        return date.fromisoformat(raw)
    return raw


def _widget_kwargs(key: str, default):
    """
    Return kwargs that supply `value` only when
    session_state hasn't already set it.
    """
    return {} if key in st.session_state else {"value": default}


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
    return list(iter_cells(client, domains, start_time, end_time, probe_cc))


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

    # Prefill the form from URL query params on first load
    if "v2_query_params_applied" not in st.session_state:
        st.session_state["v2_query_params_applied"] = True
        parsed_ok = set()
        for field, widget_key in QUERY_FIELD_TO_WIDGET_KEY.items():
            raw = st.query_params.get(field)
            if raw is not None:
                try:
                    st.session_state[widget_key] = _parse_query_value(field, raw)
                    parsed_ok.add(field)
                except (ValueError, TypeError):
                    pass
        raw_start = st.query_params.get("start_time")
        raw_end = st.query_params.get("end_time")
        if raw_start is not None and raw_end is not None:
            try:
                st.session_state["v2_date_range_input"] = (
                    _parse_query_value("start_time", raw_start),
                    _parse_query_value("end_time", raw_end),
                )
                parsed_ok.update(DATE_RANGE_QUERY_FIELDS)
            except (ValueError, TypeError):
                pass

        st.session_state["v2_auto_submit_pending"] = parsed_ok == (
            set(QUERY_FIELD_TO_WIDGET_KEY) | set(DATE_RANGE_QUERY_FIELDS)
        )

        raw_probe_asn = st.query_params.get("probe_asn")
        raw_resolver_asn = st.query_params.get("resolver_asn")
        if raw_probe_asn is not None and raw_resolver_asn is not None:
            try:
                st.session_state["v2_query_asn"] = (
                    _parse_query_value("probe_asn", raw_probe_asn),
                    _parse_query_value("resolver_asn", raw_resolver_asn),
                )
            except (ValueError, TypeError):
                pass

    clickhouse_url = st.sidebar.text_input(
        "**Clickhouse url**", "clickhouse://localhost:9000/ooni"
    )

    with st.form("detector_v2_params"):
        date_range = st.date_input(
            "**Date range**",
            key="v2_date_range_input",
            **_widget_kwargs(
                "v2_date_range_input", (now.date() - timedelta(days=7), now.date())
            ),
        )

        c1, c2 = st.columns(2)
        probe_cc = c1.text_input(
            "**Country code (two chars, optional)**",
            key="v2_probe_cc_input",
            **_widget_kwargs("v2_probe_cc_input", "VE"),
        )
        domain = c2.text_input(
            "**Domain**",
            key="v2_domain_input",
            **_widget_kwargs("v2_domain_input", "www.caraotadigital.net"),
        )

        c3, c4, c5 = st.columns(3)
        p0 = c3.number_input(
            "**p0**",
            min_value=0.0,
            max_value=1.0,
            key="v2_p0_input",
            **_widget_kwargs("v2_p0_input", 0.05),
        )
        p1 = c4.number_input(
            "**p1**",
            min_value=0.0,
            max_value=1.0,
            key="v2_p1_input",
            **_widget_kwargs("v2_p1_input", 0.50),
        )
        h = c5.number_input(
            "**h**", key="v2_h_input", **_widget_kwargs("v2_h_input", 30.0)
        )
        use_decay = st.checkbox(
            "**Use decay**",
            key="v2_use_decay_input",
            **_widget_kwargs("v2_use_decay_input", True),
        )

        submitted = st.form_submit_button("Run")

    if len(date_range) == 2:
        v1_query_params = {
            "probe_cc": probe_cc.strip(),
            "domain": domain.strip(),
            "start_time": date_range[0].isoformat(),
            "end_time": date_range[1].isoformat(),
        }
        carried_asn = st.session_state.get("v2_asn_select")
        if carried_asn is not None:
            v1_query_params["probe_asn"] = str(carried_asn[0])

        st.link_button(
            "Try in Detector V1 →",
            f"/?{urlencode(v1_query_params)}",
            icon="📉",
        )

    auto_submit = st.session_state.pop("v2_auto_submit_pending", False)

    # While only the first date of the range has been picked, date_input
    # returns a one-element tuple — treat that as not-yet-submittable.
    if (submitted or auto_submit) and len(date_range) == 2:
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

    layers = ['tcp', 'tls', 'dns']
    # The CUSUM series key is (probe_cc, probe_asn, resolver_asn, domain) —
    # probe_cc and domain are already fixed by the query inputs above, so
    # group by (probe_asn, resolver_asn) here.
    cells_by_asn = defaultdict(list)
    for c in cells:
        cells_by_asn[(c.probe_asn, c.resolver_asn)].append(c)
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
            cps = detector.compute_changepoints(
                asn_cells, layer, p0=p0, p1=p1, h=h, use_decay=use_decay
            )
            detectors_by_asn[asn][layer] = detector
            changepoints_by_asn[asn][layer] = cps
            if cps:
                asns_with_changepoints.add(asn)

    asn_list = sorted(cells_by_asn.keys(), key=lambda a: asn_counts[a], reverse=True)

    # Default to an (asn, resolver_asn) with anomalies, same as the original
    # detector panel; fall back to the one with the most cells otherwise.
    if "v2_asn_select" not in st.session_state:
        query_asn = st.session_state.get("v2_query_asn")
        if query_asn is not None and query_asn in asn_list:
            st.session_state["v2_asn_select"] = query_asn
        else:
            st.session_state["v2_asn_select"] = next(
                (a for a in asn_list if a in asns_with_changepoints), asn_list[0]
            )

    selected_asn = st.selectbox(
        "ASN / resolver ASN",
        asn_list,
        format_func=lambda a: (
            f"{'❗️' if a in asns_with_changepoints else ''}"
            f"{a[0]} / {a[1]} ({asn_counts[a]})"
        ),
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

    for layer in layers:
        llr_series = compute_llr_series(series_cells, layer, p0=p0, p1=p1)
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
