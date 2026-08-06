from collections import defaultdict
import streamlit as st
from oonipipeline.analysis.detector import make_cusums_chart, run_detector_for, ANALYSIS_COLS
from datetime import datetime, timezone, timedelta
import logging
import pandas as pd
import vl_convert as vlc

log = logging.getLogger(__name__)


@st.cache_data(ttl=300)
def run_detector_cached(*args, **kwargs):
    return run_detector_for(*args, **kwargs)

st.set_page_config(layout="wide")

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

    clickhouse_url = st.sidebar.text_input(
        "**Clickhouse url**", "clickhouse://localhost:9000/ooni"
    )

    with st.form("detector_params"):
        c1, c2 = st.columns(2)

        # column 1
        start_time = c1.datetime_input("**Start date**", now - timedelta(days=30))
        probe_cc = c1.text_input("**Country code (two chars)**", "VE")
        edd = c1.number_input("**Estimated Detection Delay (EDD)**", value=10)

        # column2
        end_time = c2.datetime_input("**End date**", now)
        domain = c2.text_input("**domain**", "x.com")
        gap_halflife = c2.number_input("**Gap half life**", value=48.0)

        warmup = st.checkbox("**Warmup**", True)
        submitted = st.form_submit_button("Run detector")

    # Only recompute on submit; store in session_state so results survive
    # reruns triggered by the selectboxes below.
    if submitted:
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

    c1, c2 = st.columns(2)
    c1.write(f"Changepoints: **{len(changepoints)}**")
    c2.write(f"Cusum steps: **{len(cusum_steps)}**")

    c1, c2 = st.columns(2)
    block_type = c1.selectbox(
        "Block type", [c[0] for c in ANALYSIS_COLS], key="block_type_select"
    )

    asn_list = list(asns.keys())
    asn_list.sort(key=lambda k: asns[k], reverse=True)
    selected_asn = c2.selectbox(
        "ASN", asn_list, format_func=lambda k: f"{k} ({asns[k]})", key="asn_select"
    )

    chart_steps = [s for s in cusum_steps if s["probe_asn"] == selected_asn]

    if len(chart_steps) == 0:
        st.warning(f"No cusum steps found for ASN {selected_asn}")
        return

    chart = make_cusums_chart(chart_steps, block_type)
    st.altair_chart(chart)

    if asns:
        df = pd.DataFrame({"ASN": list(asns.keys()), "total": list(asns.values())})
        df = df.sort_values("total", ascending=False).reset_index(drop=True)
        df["ASN"] = df["ASN"].astype(str)
        st.dataframe(df, hide_index=True)

    with st.expander("🔧 Debug"):
        if st.checkbox("Render chart as PNG", key="debug_render_png"):
            spec = chart.to_dict()
            png_bytes = vlc.vegalite_to_png(spec, scale=2)
            st.image(png_bytes, caption="Chart rendered to PNG via vl-convert")

        if st.checkbox("Show Vega-Lite spec", key="debug_show_spec"):
            st.json(chart.to_dict())


detector_panel()
