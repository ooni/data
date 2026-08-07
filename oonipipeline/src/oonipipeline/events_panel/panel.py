from collections import defaultdict
import streamlit as st
from oonipipeline.analysis.detector import (
    make_cusums_chart_grid,
    run_detector_for,
    ANALYSIS_COLS,
)
from datetime import datetime, timezone, timedelta
import logging
import pandas as pd
import vl_convert as vlc

log = logging.getLogger(__name__)


@st.cache_data(ttl=300)
def run_detector_cached(*args, **kwargs):
    return run_detector_for(*args, **kwargs)

st.set_page_config(layout="wide")

# Query params that can prefill the form, e.g.
# ?probe_cc=VE&domain=x.com&start_time=2024-01-01T00:00:00&end_time=2024-01-15T00:00:00&edd=10&gap_halflife=48&warmup=false
# When every one of these is present (and parses cleanly), the form auto-runs
# on first load instead of waiting for a manual "Run detector" click.
QUERY_FIELD_TO_WIDGET_KEY = {
    "probe_cc": "probe_cc_input",
    "domain": "domain_input",
    "start_time": "start_time_input",
    "end_time": "end_time_input",
    "edd": "edd_input",
    "gap_halflife": "gap_halflife_input",
    "warmup": "warmup_input",
}


def _parse_query_value(field: str, raw: str):
    if field in ("start_time", "end_time"):
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    if field == "edd":
        return int(raw)
    if field == "gap_halflife":
        return float(raw)
    if field == "warmup":
        return raw.strip().lower() in ("1", "true", "yes")
    return raw


def detector_panel():
    st.write(
        """
    # Event Detector
    Run the event detector over the specified input to get a simulation of results
    for the given input
    Results are **not** saved to db
    """
    )

    now = datetime.now(timezone.utc)

    # Prefill the form from URL query params on first load, and remember
    # whether every field was present so we can auto-run below.
    if "query_params_applied" not in st.session_state:
        st.session_state["query_params_applied"] = True
        parsed_ok = set()
        for field, widget_key in QUERY_FIELD_TO_WIDGET_KEY.items():
            raw = st.query_params.get(field)
            if raw is not None:
                try:
                    st.session_state[widget_key] = _parse_query_value(field, raw)
                    parsed_ok.add(field)
                except (ValueError, TypeError):
                    pass
        st.session_state["auto_submit_pending"] = parsed_ok == set(
            QUERY_FIELD_TO_WIDGET_KEY
        )

    clickhouse_url = st.sidebar.text_input(
        "**Clickhouse url**", "clickhouse://localhost:9000/ooni"
    )

    with st.form("detector_params"):
        c1, c2 = st.columns(2)

        # column 1
        start_time = c1.datetime_input(
            "**Start date**", now - timedelta(days=30), key="start_time_input"
        )
        probe_cc = c1.text_input(
            "**Country code (two chars)**", "VE", key="probe_cc_input"
        )
        edd = c1.number_input(
            "**Estimated Detection Delay (EDD)**", value=10, key="edd_input"
        )

        # column2
        end_time = c2.datetime_input("**End date**", now, key="end_time_input")
        domain = c2.text_input("**domain**", "x.com", key="domain_input")
        gap_halflife = c2.number_input(
            "**Gap half life**", value=48.0, key="gap_halflife_input"
        )

        warmup = st.checkbox(
            "**Warmup**",
            False,
            help="When enabled, no changepoints will be returned.",
            key="warmup_input",
        )
        submitted = st.form_submit_button("Run detector")

    auto_submit = st.session_state.pop("auto_submit_pending", False)

    # Only recompute on submit (or on a fully-specified first load via query
    # params); store in session_state so results survive reruns triggered by
    # the selectboxes below.
    if submitted or auto_submit:
        # Drop any cusum-related state left over from a previous submission
        for key in ("changepoints", "cusum_steps", "block_type_select", "asn_select"):
            st.session_state.pop(key, None)

        changepoints, _, cusum_steps = run_detector_cached(
            clickhouse_url,
            start_time,
            end_time,
            probe_cc,
            [domain],
            edd,
            gap_halflife,
            warmup,
        )
        st.session_state["changepoints"] = changepoints
        st.session_state["cusum_steps"] = cusum_steps

    if "cusum_steps" not in st.session_state:
        return

    changepoints = st.session_state["changepoints"]
    cusum_steps = st.session_state["cusum_steps"]

    if len(cusum_steps) == 0:
        st.warning(
            "The detector ran successfully but **no cusum steps were returned** for the given inputs"
        )
        return

    asns = defaultdict(int)
    for step in cusum_steps:
        asns[step["probe_asn"]] += 1

    asns_with_changepoints = {cp["probe_asn"] for cp in changepoints}

    c1, c2 = st.columns(2)
    c1.write(f"Changepoints: **{len(changepoints)}**")
    c2.write(f"Cusum steps: **{len(cusum_steps)}**")

    if changepoints:
        st.write("**Changepoints**")
        cp_df = pd.DataFrame(changepoints)
        cp_df = cp_df.sort_values("ts", ascending=False).reset_index(drop=True)
        display_cols = [
            c
            for c in ["ts", "probe_asn", "domain", "block_type", "change_dir", "s_pos", "s_neg", "h"]
            if c in cp_df.columns
        ]
        st.dataframe(cp_df[display_cols], hide_index=True)

    asn_list = list(asns.keys())
    asn_list.sort(key=lambda k: asns[k], reverse=True)
    selected_asn = st.selectbox(
        "ASN",
        asn_list,
        format_func=lambda k: f"{'❗️' if k in asns_with_changepoints else ''}{k} ({asns[k]})",
        key="asn_select",
    )

    chart_steps = [s for s in cusum_steps if s["probe_asn"] == selected_asn]

    if len(chart_steps) == 0:
        st.warning(f"No cusum steps found for ASN {selected_asn}")
        return

    block_types = [c[0] for c in ANALYSIS_COLS]
    for block_type in block_types:
        block_steps = [s for s in chart_steps if s["block_type"] == block_type]
        if block_steps and all(
            s["obs_value"] is None or s["obs_value"] != s["obs_value"] for s in block_steps
        ):
            st.info(
                f"No **{block_type}** measurements were observed for this ASN in the "
                "selected window (the underlying weight/count was zero every hour), so "
                "the observed-value line has nothing to plot for that row. The CUSUM "
                "statistics still reflect the detector's last known state."
            )

    chart = make_cusums_chart_grid(chart_steps, block_types)
    if chart is None:
        st.warning(f"No cusum steps found for ASN {selected_asn}")
        return
    st.altair_chart(chart)

    with st.expander("🔧 Debug"):
        if st.checkbox("Render chart as PNG", key="debug_render_png"):
            spec = chart.to_dict()
            png_bytes = vlc.vegalite_to_png(spec, scale=2)
            st.image(png_bytes, caption="Chart rendered to PNG via vl-convert")

        if st.checkbox("Show Vega-Lite spec", key="debug_show_spec"):
            st.json(chart.to_dict())

        if st.checkbox("Show cusum data as dataframe", key="debug_show_cusum_df"):
            st.dataframe(pd.DataFrame(chart_steps))

    if asns:
        df = pd.DataFrame({"ASN": list(asns.keys()), "total": list(asns.values())})
        df = df.sort_values("total", ascending=False).reset_index(drop=True)
        df["ASN"] = df["ASN"].astype(str)
        st.dataframe(df, hide_index=True)


detector_panel()
