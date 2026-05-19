import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import xml.etree.ElementTree as ET
import google.generativeai as genai
import json
import os
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np
st.set_page_config(
    page_title="ThreatWatch — CVE Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ──────────────────────────────────────────────────────────────
st.markdown("""
<style>
[data-testid="stAppViewContainer"] { background-color: #0a0d14; }
[data-testid="stSidebar"] { background-color: #0d1117; border-right: 1px solid #1e2533; }
[data-testid="stHeader"] { background-color: #0d1117; }
.metric-card {
    background: #0d1117;
    border: 1px solid #1e2533;
    border-radius: 8px;
    padding: 16px 20px;
    margin-bottom: 12px;
}
.stMetric label { color: #5a6478 !important; font-size: 11px !important; letter-spacing: 1.2px; }
.stMetric [data-testid="metric-container"] { background: #0d1117; border: 1px solid #1e2533; border-radius: 8px; padding: 12px 16px; }
div[data-testid="stMetricValue"] > div { color: #e8eaf0 !important; }
.sev-critical { color: #e24b4a; font-weight: 600; }
.sev-high     { color: #ef9f27; font-weight: 600; }
.sev-medium   { color: #97c459; font-weight: 600; }
.sev-low      { color: #5ba4e8; font-weight: 600; }
.ai-box {
    background: #0d0a1a;
    border: 1px solid #534ab7;
    border-radius: 8px;
    padding: 16px 20px;
    margin-top: 12px;
    color: #c8cdd8;
    font-size: 14px;
    line-height: 1.7;
}
.stButton > button {
    background: #132135;
    border: 1px solid #1e3a5f;
    color: #5ba4e8;
    border-radius: 5px;
    font-size: 13px;
}
.stButton > button:hover { background: #1a2e4d; border-color: #2a4a6e; }
h1, h2, h3 { color: #e8eaf0 !important; }
</style>
""", unsafe_allow_html=True)


# ── XML CVE Parsing (cve.org schema) ────────────────────────────────────────
def _get_text(el, tag: str, default: str = "N/A") -> str:
    if el is None:
        return default
    child = el.find(tag)
    if child is not None and child.text and child.text.strip() not in ("", "unknown", "Unknown"):
        return child.text.strip()
    return default


def _pick_cvss(vuln_el) -> tuple:
    cvss_el = vuln_el.find("cvss_features")
    if cvss_el is None:
        return None, "Unknown", "N/A"
    score_txt = _get_text(cvss_el, "score", "")
    try:
        score = float(score_txt)
    except ValueError:
        score = None
    raw_sev = _get_text(cvss_el, "severity_level", "unknown")
    severity = raw_sev.capitalize() if raw_sev != "N/A" else "Unknown"
    return score, severity, "N/A"


def _extract_cwes(vuln_el) -> str:
    cwe_el = vuln_el.find("cwe_features")
    if cwe_el is None:
        return "N/A"
    raw = _get_text(cwe_el, "cwe_ids", "N/A")
    if raw == "N/A":
        return "N/A"
    return ", ".join(raw.split("|"))

#@st.cache_data(show_spinner=False)
def parse_xml_file(xml_bytes: bytes, _filename: str = "") -> pd.DataFrame:
    if xml_bytes.startswith(b'\xef\xbb\xbf'):
        xml_bytes = xml_bytes[3:]

    try:
        xml_str = xml_bytes.decode("utf-8")
    except UnicodeDecodeError:
        xml_str = xml_bytes.decode("latin-1")

    if not xml_str.lstrip().startswith("<?xml"):
        xml_str = '<?xml version="1.0" encoding="utf-8"?>\n' + xml_str.lstrip()

    try:
        root = ET.fromstring(xml_str.encode("utf-8"))
    except ET.ParseError as e:
        st.error(f"XML parse error: {e}")
        return pd.DataFrame()

    rows = []
    for vuln in root.findall("vulnerability"):
        cve_id      = _get_text(vuln, "cve_id")
        title       = _get_text(vuln, "title")
        desc_el     = vuln.find("description_features")
        description = _get_text(desc_el, "text")
        vendor      = _get_text(vuln, "vendor")
        attack_type = _get_text(vuln, "attack_type")
        published   = _get_text(vuln, "dates/published")
        last_mod    = _get_text(vuln, "dates/last_modified")
        cwe         = _extract_cwes(vuln)
        score, severity, _ = _pick_cvss(vuln)

        if cve_id == "N/A":
            continue

        rows.append({
            "CVE ID":       cve_id,
            "Title":        title,
            "Description":  description,
            "CVSS Score":   score,
            "Severity":     severity,
            "Attack Type":  attack_type,
            "CWE":          cwe,
            "Vendor":       vendor,
            "Published":    published,
            "Last Modified":last_mod,
        })

    if not rows:
        st.warning("No valid CVE entries found in the XML file.")
        return pd.DataFrame()

    df = pd.DataFrame(rows)
    df["CVSS Score"] = pd.to_numeric(df["CVSS Score"], errors="coerce")
    return df

# ── TF-IDF Search Engine ─────────────────────────────────────────────────────
def build_tfidf_index(df: pd.DataFrame):
    """Build a TF-IDF matrix over combined CVE text fields."""
    corpus = (
        df["CVE ID"].fillna("") + " " +
        df["Title"].fillna("") + " " +
        df["Description"].fillna("") + " " +
        df["Vendor"].fillna("") + " " +
        df["CWE"].fillna("") + " " +
        df["Attack Type"].fillna("")
    ).tolist()

    vectorizer = TfidfVectorizer(
        analyzer="word",
        token_pattern=r"(?u)\b\w[\w-]*\b",  # keeps CVE-2026, CWE-89 etc.
        ngram_range=(1, 2),                  # unigrams + bigrams
        min_df=1,
        sublinear_tf=True,                   # log normalization on TF
        stop_words="english",
    )
    matrix = vectorizer.fit_transform(corpus)
    return vectorizer, matrix


def tfidf_search(query: str, vectorizer, matrix, df: pd.DataFrame, top_k: int = None) -> pd.DataFrame:
    """
    Score every CVE against the query using cosine similarity.
    Returns the DataFrame sorted by relevance, with a Score column.
    """
    if not query.strip():
        return df.copy().assign(**{"Relevance Score": None})

    query_vec = vectorizer.transform([query])
    scores = cosine_similarity(query_vec, matrix).flatten()

    result = df.copy()
    result["Relevance Score"] = scores
    result = result[result["Relevance Score"] > 0]
    result = result.sort_values("Relevance Score", ascending=False)

    if top_k:
        result = result.head(top_k)

    return result

with st.sidebar:
    st.markdown("## ThreatWatch")
    st.caption("CVE Intelligence Platform")
    st.divider()

    st.subheader("Data Source")
    uploaded_file = st.file_uploader(
        "Upload CVE XML file",
        type=["xml"],
        help="Upload your cve.org XML export file",
    )

    st.divider()
    st.subheader("Filters")
    severity_filter = st.multiselect(
        "Severity",
        ["Critical", "High", "Medium", "Low", "Unknown"],
        default=["Critical", "High", "Medium", "Low"],
    )
    attack_type_filter = st.multiselect(
        "Attack Type",
        ["Prompt Injection", "SQL Injection", "XSS", "RCE", "SSRF", "Other"],
        default=[],
        placeholder="All attack types",
    )
    min_cvss = st.slider("Min CVSS Score", 0.0, 10.0, 0.0, step=0.5)

    st.divider()

if uploaded_file is None:
    st.info("Upload your CVE XML file from the sidebar to get started.")
    st.stop()

with st.spinner("Parsing XML file…"):
    xml_bytes = uploaded_file.read()
    raw_df = parse_xml_file(xml_bytes, _filename=uploaded_file.name)

if raw_df.empty:
    st.error("No data could be parsed from the uploaded file. Please check the file format.")
    st.stop()

with st.expander("Debug — parsed data preview", expanded=False):
    st.write(f"Rows parsed: {len(raw_df)}")
    st.write(f"Columns: {list(raw_df.columns)}")
    st.dataframe(raw_df.head(3))

# Apply filters
df = raw_df.copy()
if severity_filter:
    df = df[df["Severity"].isin(severity_filter)]
if attack_type_filter:
    df = df[df["Attack Type"].isin(attack_type_filter)]
df = df[df["CVSS Score"].fillna(0) >= min_cvss]

st.title("Cybersecurity Threat Monitoring Dashboard")
st.caption(f"Showing {len(df)} vulnerabilities · Source: {uploaded_file.name} · Parsed {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")

c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Total CVEs",     len(df))
c2.metric("🔴 Critical",   len(df[df["Severity"] == "Critical"]))
c3.metric("🟠 High",       len(df[df["Severity"] == "High"]))
c4.metric("🟡 Medium",     len(df[df["Severity"] == "Medium"]))
avg_cvss = df["CVSS Score"].mean()
c5.metric("Avg CVSS",      f"{avg_cvss:.1f}" if pd.notna(avg_cvss) else "N/A")

st.divider()

col_l, col_r = st.columns(2)

with col_l:
    st.subheader("Severity Distribution")
    sev_counts = df["Severity"].value_counts().reset_index()
    sev_counts.columns = ["Severity", "Count"]
    sev_order  = ["Critical", "High", "Medium", "Low", "Unknown"]
    color_map  = {"Critical":"#e24b4a","High":"#ef9f27","Medium":"#97c459","Low":"#5ba4e8","Unknown":"#5a6478"}
    fig_sev = px.bar(
        sev_counts,
        x="Severity", y="Count",
        color="Severity",
        color_discrete_map=color_map,
        category_orders={"Severity": sev_order},
        template="plotly_dark",
    )
    fig_sev.update_layout(
        paper_bgcolor="#0d1117", plot_bgcolor="#0d1117",
        showlegend=False, margin=dict(t=10, b=10, l=10, r=10),
    )
    st.plotly_chart(fig_sev, use_container_width=True)

with col_r:
    st.subheader("Attack Type Breakdown")
    atk_counts = df["Attack Type"].value_counts().reset_index()
    atk_counts.columns = ["Attack Type", "Count"]
    fig_atk = px.pie(
        atk_counts, names="Attack Type", values="Count",
        color_discrete_sequence=["#5ba4e8","#afa9ec","#5dcaa5","#ef9f27","#e24b4a","#97c459"],
        template="plotly_dark",
        hole=0.45,
    )
    fig_atk.update_layout(
        paper_bgcolor="#0d1117",
        margin=dict(t=10, b=10, l=10, r=10),
        legend=dict(font=dict(color="#8896a8")),
    )
    st.plotly_chart(fig_atk, use_container_width=True)

st.subheader("CVSS Score Distribution")
cvss_valid = df["CVSS Score"].dropna()
fig_hist = px.histogram(
    cvss_valid, x="CVSS Score", nbins=20,
    color_discrete_sequence=["#378add"],
    template="plotly_dark",
)
fig_hist.update_layout(
    paper_bgcolor="#0d1117", plot_bgcolor="#0d1117",
    margin=dict(t=10, b=10, l=10, r=10),
    bargap=0.05,
)
fig_hist.add_vline(x=9.0, line_dash="dash", line_color="#e24b4a", annotation_text="Critical (9+)", annotation_font_color="#e24b4a")
fig_hist.add_vline(x=7.0, line_dash="dash", line_color="#ef9f27", annotation_text="High (7+)",     annotation_font_color="#ef9f27")
st.plotly_chart(fig_hist, use_container_width=True)

col_a, col_b = st.columns(2)

with col_a:
    st.subheader("Top CWE Categories")
    cwe_counts = (
        df[df["CWE"] != "N/A"]["CWE"]
        .value_counts()
        .head(10)
        .reset_index()
    )
    cwe_counts.columns = ["CWE", "Count"]
    if not cwe_counts.empty:
        fig_cwe = px.bar(
            cwe_counts, x="Count", y="CWE", orientation="h",
            color="Count", color_continuous_scale=["#132135","#5ba4e8"],
            template="plotly_dark",
        )
        fig_cwe.update_layout(
            paper_bgcolor="#0d1117", plot_bgcolor="#0d1117",
            margin=dict(t=10, b=10, l=10, r=10),
            yaxis=dict(autorange="reversed"),
            coloraxis_showscale=False,
        )
        st.plotly_chart(fig_cwe, use_container_width=True)
    else:
        st.info("No CWE data available.")

with col_b:
    st.subheader("Top Affected Vendors")
    all_vendors = (
        df["Vendor"]
        .dropna()
        .str.split(", ")
        .explode()
        .str.strip()
        .replace("N/A", pd.NA)
        .dropna()
        .value_counts()
        .head(10)
        .reset_index()
    )
    all_vendors.columns = ["Vendor", "Count"]
    if not all_vendors.empty:
        fig_vend = px.bar(
            all_vendors, x="Count", y="Vendor", orientation="h",
            color="Count", color_continuous_scale=["#1a1330","#afa9ec"],
            template="plotly_dark",
        )
        fig_vend.update_layout(
            paper_bgcolor="#0d1117", plot_bgcolor="#0d1117",
            margin=dict(t=10, b=10, l=10, r=10),
            yaxis=dict(autorange="reversed"),
            coloraxis_showscale=False,
        )
        st.plotly_chart(fig_vend, use_container_width=True)
    else:
        st.info("No vendor data available.")

st.divider()

# ── Vulnerability Feed with TF-IDF Search ────────────────────────────────────
st.subheader("Vulnerability Feed")

vectorizer, tfidf_matrix = build_tfidf_index(df)

col_search, col_top = st.columns([4, 1])
with col_search:
    search_query = st.text_input(
        "Search CVE ID, title, description, vendor, or CWE",
        placeholder="e.g. remote code execution, CWE-89, buffer overflow",
    )
with col_top:
    top_k = st.selectbox("Show top", [10, 25, 50, 100, 0], index=1,
                         format_func=lambda x: "All" if x == 0 else str(x))

if search_query:
    display_df = tfidf_search(
        search_query, vectorizer, tfidf_matrix, df,
        top_k=top_k if top_k > 0 else None
    )
    st.caption(f"{len(display_df)} results ranked by TF-IDF relevance · query: *{search_query}*")
else:
    display_df = df.copy()
    display_df["Relevance Score"] = None
    st.caption(f"{len(display_df)} vulnerabilities · enter a query to rank by relevance")

st.dataframe(
    display_df.reset_index(drop=True),
    use_container_width=True,
    height=380,
    column_config={
        "CVE ID":          st.column_config.TextColumn("CVE ID",      width="small"),
        "Title":           st.column_config.TextColumn("Title",       width="large"),
        "Description":     st.column_config.TextColumn("Description", width="large"),
        "CVSS Score":      st.column_config.NumberColumn("CVSS",      format="%.1f", width="small"),
        "Severity":        st.column_config.TextColumn("Severity",    width="small"),
        "Attack Type":     st.column_config.TextColumn("Attack Type", width="medium"),
        "CWE":             st.column_config.TextColumn("CWE",         width="medium"),
        "Vendor":          st.column_config.TextColumn("Vendor",      width="medium"),
        "Published":       st.column_config.TextColumn("Published",   width="small"),
        "Last Modified":   st.column_config.TextColumn("Modified",    width="small"),
        "Relevance Score": st.column_config.NumberColumn("Relevance", format="%.4f", width="small"),
    },
    hide_index=True,
)

st.divider()