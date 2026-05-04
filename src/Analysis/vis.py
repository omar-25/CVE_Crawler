"""
====================================================
  CVE Dataset — Exploratory Data Analysis (EDA)
             & Data Visualization
====================================================
Requirements:
    pip install matplotlib seaborn pandas lxml wordcloud
"""

import xml.etree.ElementTree as ET
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import matplotlib.patches as mpatches
import seaborn as sns
import warnings

warnings.filterwarnings("ignore")

# ─────────────────────────────────────────────
# 1.  LOAD & PARSE XML
# ─────────────────────────────────────────────
XML_FILE = r"C:\Users\Ahmed\Desktop\CVE_Crawler\src\Analysis\output.xml"

try:
    tree = ET.parse(XML_FILE)
    root = tree.getroot()
except Exception as e:
    print(f"Error loading XML: {e}")
    exit()

records = []
for vuln in root.findall("vulnerability"):
    cve_id = vuln.findtext("cve_id", "")
    
    # --- BULLETPROOF VENDOR CHECK ---
    raw_vendor = vuln.findtext("vendor")
    if not raw_vendor or not raw_vendor.strip():
        vendor = "Unknown Vendor"
    else:
        vendor = raw_vendor.strip()
    # --------------------------------
        
    product = vuln.findtext("product", "")
    attack_type = vuln.findtext("attack_type", "Unknown")
    published = vuln.findtext("dates/published", "") 

    # Prioritize newest CVSS version instead of just taking the max score
    best_score = None
    highest_version = 0.0
    for cvss in vuln.findall("cvss_list/cvss"):
        try:
            score = float(cvss.findtext("score", "0"))
            version_str = cvss.findtext("version", "0")
            version = float(version_str) if version_str else 0.0
            
            if version > highest_version:
                highest_version = version
                best_score = score
        except ValueError:
            pass
    max_score = best_score
    
    # Properly handle missing CWEs so they don't skew the charts to 0
    cwes = vuln.findall("cwe_list/cwe")
    num_cwes = len(cwes) if cwes else None

    records.append({
        "cve_id":      cve_id,
        "vendor":      vendor,
        "product":     product,
        "attack_type": attack_type,
        "published":   published,
        "max_score":   max_score,
        "num_cwes":    num_cwes,
    })

df = pd.DataFrame(records)

# Clean ghost records and empty strings to prevent blank data pollution
df["cve_id"].replace("", pd.NA, inplace=True)
df.dropna(subset=["cve_id"], inplace=True)
df["product"].replace("", "Unknown Product", inplace=True)
df["attack_type"].replace("", "Unknown", inplace=True)

df["published"]  = pd.to_datetime(df["published"], errors="coerce")
df["year_month"] = df["published"].dt.to_period("M")

def severity_bucket(score):
    if pd.isna(score):  return "Unknown"
    if score >= 9.0:    return "CRITICAL"
    if score >= 7.0:    return "HIGH"
    if score >= 4.0:    return "MEDIUM"
    return "LOW"

df["severity"] = df["max_score"].apply(severity_bucket)

# ─────────────────────────────────────────────
# 2.  EDA — PRINT STATISTICS
# ─────────────────────────────────────────────
print("=" * 60)
print("  EXPLORATORY DATA ANALYSIS — CVE DATASET")
print("=" * 60)
print(f"\n Total vulnerabilities : {len(df):,}")
if not df["published"].dropna().empty:
    print(f" Date range            : {df['published'].min().date()} -> {df['published'].max().date()}")
print(f" Unique vendors        : {df['vendor'].nunique()}")
print(f" Unique products       : {df['product'].nunique()}")
print("\n-- CVSS Score Statistics --")
print(df["max_score"].describe().round(2).to_string())
print("\n-- Attack Type Distribution --")
print(df["attack_type"].value_counts().to_string())
print("\n-- Top 10 Vendors --")
print(df["vendor"].value_counts().head(10).to_string())
print("\n-- Severity Distribution --")
print(df["severity"].value_counts().to_string())

# ─────────────────────────────────────────────
# 3.  STYLE
# ─────────────────────────────────────────────
SEVERITY_COLORS = {
    "CRITICAL": "#d62728",
    "HIGH":     "#ff7f0e",
    "MEDIUM":   "#1f77b4",
    "LOW":      "#2ca02c",
    "Unknown":  "#7f7f7f",
}

sns.set_theme(style="whitegrid")
plt.rcParams.update({
    "font.size":        8,
    "axes.titlesize":   9,
    "axes.titleweight": "bold",
    "axes.labelsize":   8,
    "xtick.labelsize":  7,
    "ytick.labelsize":  7,
    "figure.facecolor": "white",
})

# ─────────────────────────────────────────────
# 4.  SINGLE FIGURE — 2x4 GRID
# ─────────────────────────────────────────────
fig = plt.figure(figsize=(26, 22))
fig.suptitle("CVE Dataset — Exploratory Data Analysis & Visualizations",
             fontsize=14, fontweight="bold", y=0.99)

# ── Plot 1: Severity Pie Chart ────────────────────────────
ax1 = fig.add_subplot(2, 4, 1)
sev_counts = df["severity"].value_counts()
colors = [SEVERITY_COLORS.get(s, "#aaa") for s in sev_counts.index]
wedges, _, autotexts = ax1.pie(
    sev_counts.values,
    labels=None,
    autopct="%1.1f%%",
    colors=colors,
    startangle=140,
    pctdistance=0.75,
    wedgeprops={"linewidth": 1.5, "edgecolor": "white"},
)
for at in autotexts:
    at.set_fontsize(7)

severity_ranges = {
    "CRITICAL": "≥ 9.0",
    "HIGH":     "7.0 – 8.9",
    "MEDIUM":   "4.0 – 6.9",
    "LOW":      "0.0 – 3.9",
    "Unknown":  "No score",
}
legend_labels = [
    f"{s}  ({severity_ranges.get(s, '')}):  {sev_counts[s]}"
    for s in sev_counts.index
]
ax1.legend(
    wedges,
    legend_labels,
    title="Severity (CVSS Range) : Count",
    loc="lower left",
    fontsize=6.5,
    title_fontsize=7,
    bbox_to_anchor=(-0.35, -0.25),
)
ax1.set_title("Severity Distribution\n(Highest CVSS Score per CVE)")

# ── Plot 2: CVSS Score Histogram ──────────────────────────
ax2 = fig.add_subplot(2, 4, 2)
bins = 20
n, bin_edges, patches = ax2.hist(
    df["max_score"].dropna(), bins=bins,
    edgecolor="white", linewidth=0.6
)
for patch, left_edge in zip(patches, bin_edges[:-1]):
    mid = left_edge + (bin_edges[1] - bin_edges[0]) / 2
    if mid >= 9.0:
        patch.set_facecolor(SEVERITY_COLORS["CRITICAL"])
    elif mid >= 7.0:
        patch.set_facecolor(SEVERITY_COLORS["HIGH"])
    elif mid >= 4.0:
        patch.set_facecolor(SEVERITY_COLORS["MEDIUM"])
    else:
        patch.set_facecolor(SEVERITY_COLORS["LOW"])

mean_val = df["max_score"].mean()
if pd.notna(mean_val):
    ax2.axvline(mean_val, color="black", linestyle="--", linewidth=1.5,
                label=f"Mean = {mean_val:.2f}")

ax2.axvline(4.0, color=SEVERITY_COLORS["MEDIUM"],   linestyle=":", linewidth=1.2, label="MEDIUM ≥ 4.0")
ax2.axvline(7.0, color=SEVERITY_COLORS["HIGH"],     linestyle=":", linewidth=1.2, label="HIGH ≥ 7.0")
ax2.axvline(9.0, color=SEVERITY_COLORS["CRITICAL"], linestyle=":", linewidth=1.2, label="CRITICAL ≥ 9.0")

legend_patches = [
    mpatches.Patch(color=SEVERITY_COLORS["CRITICAL"], label="CRITICAL (≥ 9.0)"),
    mpatches.Patch(color=SEVERITY_COLORS["HIGH"],     label="HIGH (7.0 – 8.9)"),
    mpatches.Patch(color=SEVERITY_COLORS["MEDIUM"],   label="MEDIUM (4.0 – 6.9)"),
    mpatches.Patch(color=SEVERITY_COLORS["LOW"],      label="LOW (< 4.0)"),
]
if pd.notna(mean_val):
    legend_patches.append(plt.Line2D([0], [0], color="black", linestyle="--", linewidth=1.5, label=f"Mean = {mean_val:.2f}"))

ax2.legend(handles=legend_patches, fontsize=6.5, loc="upper left")
ax2.set_title("CVSS Score Distribution\n(Bars coloured by Severity Level)")
ax2.set_xlabel("Highest Version CVSS Score per CVE")
ax2.set_ylabel("Number of CVEs")

# ── Plot 3: Monthly CVE Trend (Dynamic Recent Year) ───────
ax3 = fig.add_subplot(2, 4, 3)
df_valid_dates = df.dropna(subset=["published"])

if not df_valid_dates.empty:
    recent_year = df_valid_dates["published"].dt.year.max()
    df_recent = df_valid_dates[df_valid_dates["published"].dt.year == recent_year]
    monthly = df_recent.groupby("year_month").size().reset_index(name="count")
    monthly["period_str"] = monthly["year_month"].astype(str)

    ax3.plot(monthly["period_str"], monthly["count"],
             marker="o", linewidth=1.8, color="#2196F3", markersize=5)
    ax3.fill_between(monthly["period_str"], monthly["count"],
                     alpha=0.15, color="#2196F3")
    ax3.set_title(f"Monthly CVE Publication Trend\n({int(recent_year)} only)")
    ax3.set_xlabel("Month")
    ax3.set_ylabel("CVEs Published")
    ax3.set_xticks(range(len(monthly)))
    ax3.set_xticklabels(monthly["period_str"], rotation=35, ha="right", fontsize=6.5)

    for i, row in monthly.iterrows():
        idx = monthly.index.get_loc(i)
        ax3.annotate(str(row["count"]),
                     xy=(idx, row["count"]),
                     xytext=(0, 6), textcoords="offset points",
                     ha="center", fontsize=7)
else:
    ax3.set_title("Monthly CVE Publication Trend\n(No Valid Dates Found)")
    ax3.text(0.5, 0.5, "Insufficient Data", ha="center", va="center")

# ── Plot 4: Top 10 Vendors ────────────────────────────────
ax4 = fig.add_subplot(2, 4, 4)
top_vendors = df["vendor"].value_counts().head(10)
bars = ax4.bar(range(len(top_vendors)), top_vendors.values,
               color=sns.color_palette("husl", len(top_vendors)), width=0.6)
ax4.set_title("Top 10 Vendors by CVE Count")
ax4.set_xlabel("Vendor")
ax4.set_ylabel("Number of CVEs")
ax4.set_xticks(range(len(top_vendors)))

# Fix: Rotate 45 degrees and anchor to the right to stop labels floating away
ax4.set_xticklabels(
    top_vendors.index, 
    rotation=45, 
    ha="right", 
    rotation_mode="anchor", 
    fontsize=7
)

ax4.set_ylim(0, top_vendors.max() * 1.18)
for bar in bars:
    ax4.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + (top_vendors.max()*0.02),
             str(int(bar.get_height())), ha="center", fontsize=7)

# ── Plot 5: CVSS Box Plot by Severity ────────────────────
ax5 = fig.add_subplot(2, 4, 5)
order_present = [s for s in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
                 if s in df["severity"].values]
data_by_sev   = [df[df["severity"] == s]["max_score"].dropna() for s in order_present]
box_colors    = [SEVERITY_COLORS[s] for s in order_present]

if data_by_sev:
    bp = ax5.boxplot(data_by_sev, labels=order_present, patch_artist=True,
                     widths=0.4, medianprops={"color": "black", "linewidth": 1.5})
    for patch, color in zip(bp["boxes"], box_colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.75)

    range_labels = {"LOW": "0–3.9", "MEDIUM": "4.0–6.9",
                    "HIGH": "7.0–8.9", "CRITICAL": "9.0–10"}
    new_labels = [f"{s}\n({range_labels[s]})" for s in order_present]
    ax5.set_xticklabels(new_labels, fontsize=7)

ax5.set_title("CVSS Score by Severity Level\n(Severity defined by CVSS thresholds)")
ax5.set_xlabel("Severity  (CVSS Score Range)")
ax5.set_ylabel("CVSS Score")
ax5.set_ylim(0, 11)

ax5.axhline(4.0, color=SEVERITY_COLORS["MEDIUM"],   linestyle="--",
            linewidth=0.8, alpha=0.6, label="MEDIUM threshold (4.0)")
ax5.axhline(7.0, color=SEVERITY_COLORS["HIGH"],     linestyle="--",
            linewidth=0.8, alpha=0.6, label="HIGH threshold (7.0)")
ax5.axhline(9.0, color=SEVERITY_COLORS["CRITICAL"], linestyle="--",
            linewidth=0.8, alpha=0.6, label="CRITICAL threshold (9.0)")
ax5.legend(fontsize=6, loc="upper left")

# ── Plot 6: CWE Count per Vulnerability (WITH ATTACK TYPES) ─
ax6 = fig.add_subplot(2, 4, 6)
df_cwe = df.dropna(subset=['num_cwes'])

if not df_cwe.empty:
    cwe_dist = df_cwe["num_cwes"].value_counts().sort_index()
    bars = ax6.bar(cwe_dist.index.astype(str), cwe_dist.values,
                   color="#9C27B0", width=0.5)
    ax6.set_title("Number of CWEs per Vulnerability\n(Displaying Top Attack Types)")
    ax6.set_xlabel("Number of CWEs mapped")
    ax6.set_ylabel("Number of CVEs")
    ax6.set_ylim(0, cwe_dist.max() * 1.35) 
    
    for bar, cwe_val in zip(bars, cwe_dist.index):
        attack_counts = df_cwe[df_cwe['num_cwes'] == cwe_val]['attack_type'].value_counts()
        types_list = [f"{idx} ({val})" for idx, val in attack_counts.items()]
        
        if len(types_list) <= 3:
            label = "\n".join(types_list)
        else:
            label = "\n".join(types_list[:2]) + f"\n(+{len(types_list)-2} more)"
            
        ax6.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + (cwe_dist.max() * 0.02),
                 label, ha="center", va="bottom", fontsize=6)
else:
    ax6.set_title("Number of CWEs per Vulnerability")
    ax6.text(0.5, 0.5, "No CWE Data", ha="center", va="center")

# ── Plot 7: Avg CVSS by Attack Type ──────────────────────
ax7 = fig.add_subplot(2, 4, 7)
avg_cvss = (df.groupby("attack_type")["max_score"]
              .mean().dropna()
              .sort_values(ascending=False))
colors7 = ["#d62728" if v >= 9 else "#ff7f0e" if v >= 7 else "#1f77b4"
           for v in avg_cvss.values]

if not avg_cvss.empty:
    ax7.barh(avg_cvss.index[::-1], avg_cvss.values[::-1],
             color=colors7[::-1], height=0.55)
    for i, v in enumerate(avg_cvss.values[::-1]):
        ax7.text(v + 0.15, i, f"{v:.2f}", va="center", fontsize=7)

ax7.axvline(7.0, color="orange", linestyle="--", linewidth=1.2, label="HIGH (≥ 7.0)")
ax7.axvline(9.0, color="red",    linestyle="--", linewidth=1.2, label="CRITICAL (≥ 9.0)")
ax7.set_title("Avg CVSS Score by Attack Type")
ax7.set_xlabel("Average CVSS Score")
ax7.set_xlim(0, 11)
ax7.legend(fontsize=7, loc="lower right")

# ── Plot 8: Stacked Bar — Severity per Attack Type ────────
ax8 = fig.add_subplot(2, 4, 8)
pivot = (df.groupby(["attack_type", "severity"])
           .size().unstack(fill_value=0))
sev_order = [s for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "Unknown"]
             if s in pivot.columns]
pivot = pivot[sev_order]

if not pivot.empty:
    bottom = pd.Series([0] * len(pivot), index=pivot.index)
    for sev in sev_order:
        ax8.bar(range(len(pivot)), pivot[sev], bottom=bottom.values,
                label=sev, color=SEVERITY_COLORS.get(sev, "#aaa"), alpha=0.88, width=0.5)
        bottom += pivot[sev]

    ax8.set_title("Severity Breakdown\nper Attack Type")
    ax8.set_xlabel("Attack Type")
    ax8.set_ylabel("Number of CVEs")
    ax8.set_xticks(range(len(pivot)))
    ax8.set_xticklabels(pivot.index, rotation=25, ha="right", fontsize=7)
    ax8.legend(title="Severity", fontsize=7, title_fontsize=7,
               loc="upper right", bbox_to_anchor=(1.0, 1.0))

    totals = pivot.sum(axis=1)
    for i, total in enumerate(totals):
        ax8.text(i, total + (totals.max()*0.02), str(int(total)), ha="center", fontsize=7)

# ── Final layout ──────────────────────────────────────────
plt.subplots_adjust(
    left=0.06, right=0.97,
    top=0.93,  bottom=0.10,
    wspace=0.40, hspace=0.85 # Increased height space to prevent overlapping labels
)
plt.savefig("cve_eda_visualizations.png", dpi=150, bbox_inches="tight")
plt.show()
print("\nSaved: cve_eda_visualizations.png")

# ─────────────────────────────────────────────
# 5.  KEY INSIGHTS
# ─────────────────────────────────────────────
print("\n" + "=" * 60)
print("  KEY INSIGHTS")
print("=" * 60)
print(f"  * {len(df):,} total valid vulnerabilities across {df['vendor'].nunique()} vendors.")
if not df['attack_type'].empty:
    print(f"  * Most common attack : '{df['attack_type'].value_counts().idxmax()}'")
if pd.notna(df['max_score'].mean()):
    print(f"  * Avg CVSS score     : {df['max_score'].mean():.2f}")
crit_pct = (df['severity'] == 'CRITICAL').mean() * 100
print(f"  * CRITICAL severity  : {crit_pct:.1f}% of all CVEs")
if not df_valid_dates.empty:
    recent_year = df_valid_dates["published"].dt.year.max()
    df_recent = df_valid_dates[df_valid_dates["published"].dt.year == recent_year]
    if not df_recent.empty:
        busiest = df_recent.groupby("year_month").size().idxmax()
        busiest_count = df_recent.groupby("year_month").size().max()
        print(f"  * Busiest month ({int(recent_year)}): {busiest} ({busiest_count} CVEs)")
if not df['vendor'].empty:
    print(f"  * Top vendor         : {df['vendor'].value_counts().idxmax()!r}")
print("=" * 60)