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
import seaborn as sns
import warnings

warnings.filterwarnings("ignore")

# ─────────────────────────────────────────────
# 1.  LOAD & PARSE XML
# ─────────────────────────────────────────────
XML_FILE = r"C:\Users\abdog\OneDrive\Desktop\CVE_Crawler\Analysis\output.xml"

tree = ET.parse(XML_FILE)
root = tree.getroot()

records = []
for vuln in root.findall("vulnerability"):
    cve_id      = vuln.findtext("cve_id", "")
    vendor      = vuln.findtext("vendor", "")
    product     = vuln.findtext("product", "")
    attack_type = vuln.findtext("attack_type", "Unknown")
    published   = vuln.findtext("dates/published", "")

    scores = []
    for cvss in vuln.findall("cvss_list/cvss"):
        try:
            scores.append(float(cvss.findtext("score", "0")))
        except ValueError:
            pass
    max_score = max(scores) if scores else None
    num_cwes  = len(vuln.findall("cwe_list/cwe"))

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
# 4.  SINGLE FIGURE — 3x3 GRID
# ─────────────────────────────────────────────
fig = plt.figure(figsize=(26, 24))
fig.suptitle("CVE Dataset — Exploratory Data Analysis & Visualizations",
             fontsize=14, fontweight="bold", y=0.99)

# ── Plot 1: Top 10 Attack Types ───────────────────────────
ax1 = fig.add_subplot(3, 3, 1)
attack_counts = df["attack_type"].value_counts().head(10)
bars = ax1.barh(attack_counts.index[::-1], attack_counts.values[::-1],
                color=sns.color_palette("tab10", len(attack_counts)), height=0.6)
ax1.set_title("Top 10 Attack Types")
ax1.set_xlabel("Count")
ax1.set_xlim(0, attack_counts.max() * 1.2)
for bar in bars:
    ax1.text(bar.get_width() + 0.5, bar.get_y() + bar.get_height() / 2,
             str(int(bar.get_width())), va="center", fontsize=7)

# ── Plot 2: Severity Pie Chart ────────────────────────────
ax2 = fig.add_subplot(3, 3, 2)
sev_counts = df["severity"].value_counts()
colors = [SEVERITY_COLORS.get(s, "#aaa") for s in sev_counts.index]
wedges, _, autotexts = ax2.pie(
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
ax2.legend(sev_counts.index, title="Severity", loc="lower left",
           fontsize=7, title_fontsize=7, bbox_to_anchor=(-0.15, -0.05))
ax2.set_title("Severity Distribution\n(by highest CVSS score)")

# ── Plot 3: CVSS Score Histogram ──────────────────────────
ax3 = fig.add_subplot(3, 3, 3)
ax3.hist(df["max_score"].dropna(), bins=20, color="#4c72b0", edgecolor="white", linewidth=0.6)
mean_val = df["max_score"].mean()
ax3.axvline(mean_val, color="red", linestyle="--", linewidth=1.5,
            label=f"Mean={mean_val:.2f}")
ax3.set_title("CVSS Score Distribution")
ax3.set_xlabel("Highest CVSS Score")
ax3.set_ylabel("Number of CVEs")
ax3.legend(fontsize=7)

# ── Plot 4: Monthly CVE Trend ─────────────────────────────
ax4 = fig.add_subplot(3, 3, 4)
monthly = df.groupby("year_month").size().reset_index(name="count")
monthly["period_str"] = monthly["year_month"].astype(str)
ax4.plot(monthly["period_str"], monthly["count"],
         marker="o", linewidth=1.8, color="#2196F3", markersize=4)
ax4.fill_between(monthly["period_str"], monthly["count"], alpha=0.15, color="#2196F3")
ax4.set_title("Monthly CVE Publication Trend")
ax4.set_xlabel("Month")
ax4.set_ylabel("CVEs Published")
# Show only every 4th label
step = max(1, len(monthly) // 6)
ax4.set_xticks(range(0, len(monthly), step))
ax4.set_xticklabels(monthly["period_str"].iloc[::step], rotation=35, ha="right", fontsize=6)

# ── Plot 5: Top 10 Vendors ────────────────────────────────
ax5 = fig.add_subplot(3, 3, 5)
top_vendors = df["vendor"].value_counts().head(10)
bars = ax5.bar(range(len(top_vendors)), top_vendors.values,
               color=sns.color_palette("husl", len(top_vendors)), width=0.6)
ax5.set_title("Top 10 Vendors by CVE Count")
ax5.set_xlabel("Vendor")
ax5.set_ylabel("Number of CVEs")
ax5.set_xticks(range(len(top_vendors)))
ax5.set_xticklabels(top_vendors.index, rotation=35, ha="right", fontsize=6)
ax5.set_ylim(0, top_vendors.max() * 1.18)
for bar in bars:
    ax5.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.3,
             str(int(bar.get_height())), ha="center", fontsize=7)

# ── Plot 6: CVSS Box Plot by Severity ────────────────────
ax6 = fig.add_subplot(3, 3, 6)
order_present = [s for s in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
                 if s in df["severity"].values]
data_by_sev   = [df[df["severity"] == s]["max_score"].dropna() for s in order_present]
box_colors    = [SEVERITY_COLORS[s] for s in order_present]
bp = ax6.boxplot(data_by_sev, labels=order_present, patch_artist=True,
                 widths=0.4, medianprops={"color": "black", "linewidth": 1.5})
for patch, color in zip(bp["boxes"], box_colors):
    patch.set_facecolor(color)
    patch.set_alpha(0.75)
ax6.set_title("CVSS Score by Severity Level")
ax6.set_xlabel("Severity")
ax6.set_ylabel("CVSS Score")

# ── Plot 7: CWE Count per Vulnerability ──────────────────
ax7 = fig.add_subplot(3, 3, 7)
cwe_dist = df["num_cwes"].value_counts().sort_index()
bars = ax7.bar(cwe_dist.index.astype(str), cwe_dist.values,
               color="#9C27B0", width=0.5)
ax7.set_title("Number of CWEs per Vulnerability")
ax7.set_xlabel("Number of CWEs")
ax7.set_ylabel("Number of CVEs")
ax7.set_ylim(0, cwe_dist.max() * 1.18)
for bar in bars:
    ax7.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1,
             str(int(bar.get_height())), ha="center", fontsize=7)

# ── Plot 8: Avg CVSS by Attack Type ──────────────────────
ax8 = fig.add_subplot(3, 3, 8)
avg_cvss = (df.groupby("attack_type")["max_score"]
              .mean().dropna()
              .sort_values(ascending=False)
              .head(10))
colors8 = ["#d62728" if v >= 9 else "#ff7f0e" if v >= 7 else "#1f77b4"
           for v in avg_cvss.values]
ax8.barh(avg_cvss.index[::-1], avg_cvss.values[::-1],
         color=colors8[::-1], height=0.55)
ax8.axvline(7.0, color="orange", linestyle="--", linewidth=1.2, label="HIGH (7.0)")
ax8.axvline(9.0, color="red",    linestyle="--", linewidth=1.2, label="CRITICAL (9.0)")
ax8.set_title("Avg CVSS Score by Attack Type")
ax8.set_xlabel("Average CVSS Score")
ax8.set_xlim(0, 12)
ax8.legend(fontsize=7, loc="lower right")
for i, v in enumerate(avg_cvss.values[::-1]):
    ax8.text(v + 0.15, i, f"{v:.2f}", va="center", fontsize=7)

# ── Plot 9: Stacked Bar — Severity per Attack Type ────────
ax9 = fig.add_subplot(3, 3, 9)
top_attacks = df["attack_type"].value_counts().head(6).index
df_top      = df[df["attack_type"].isin(top_attacks)]
pivot       = (df_top.groupby(["attack_type", "severity"])
                     .size().unstack(fill_value=0))
sev_order   = [s for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "Unknown"]
               if s in pivot.columns]
pivot       = pivot[sev_order]
bottom      = pd.Series([0] * len(pivot), index=pivot.index)
for sev in sev_order:
    ax9.bar(range(len(pivot)), pivot[sev], bottom=bottom.values,
            label=sev, color=SEVERITY_COLORS.get(sev, "#aaa"), alpha=0.88, width=0.5)
    bottom += pivot[sev]
ax9.set_title("Severity Breakdown\nper Top-6 Attack Types")
ax9.set_xlabel("Attack Type")
ax9.set_ylabel("Number of CVEs")
ax9.set_xticks(range(len(pivot)))
ax9.set_xticklabels(pivot.index, rotation=35, ha="right", fontsize=6)
ax9.legend(title="Severity", fontsize=7, title_fontsize=7,
           loc="upper right", bbox_to_anchor=(1.0, 1.0))

# ── Final layout ──────────────────────────────────────────
plt.subplots_adjust(
    left=0.06, right=0.97,
    top=0.90,  bottom=0.07,
    wspace=0.38, hspace=0.55   # <-- generous spacing between subplots
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
print(f"  * {len(df):,} vulnerabilities across {df['vendor'].nunique()} vendors.")
print(f"  * Most common attack : '{df['attack_type'].value_counts().idxmax()}'")
print(f"  * Avg CVSS score     : {df['max_score'].mean():.2f}  (HIGH range)")
crit_pct = (df['severity'] == 'CRITICAL').mean() * 100
print(f"  * CRITICAL severity  : {crit_pct:.1f}% of all CVEs")
busiest = df.groupby("year_month").size().idxmax()
print(f"  * Busiest month      : {busiest} ({df.groupby('year_month').size().max()} CVEs)")
print(f"  * Top vendor         : {df['vendor'].value_counts().idxmax()!r}")
print("=" * 60)