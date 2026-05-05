import xml.etree.ElementTree as ET
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# ---------------------------------------------------------
# 1. Parse the XML file
# ---------------------------------------------------------
# Get the directory where this script is located
script_dir = Path(__file__).resolve().parent
xml_path = script_dir / 'output.xml'
reports_dir = script_dir.parent / 'Reports' / 'Charts'
reports_dir.mkdir(parents=True, exist_ok=True)

if not xml_path.exists():
    raise FileNotFoundError(f"XML file not found: {xml_path}")

tree = ET.parse(xml_path)
root = tree.getroot()

data = []
for vuln in root.findall('vulnerability'):
    # Extract highest CVSS score if available
    cvss_score, cvss_severity = None, None
    cvss_list = vuln.find('cvss_list')

    if cvss_list is not None:
        scores = []
        for cvss in cvss_list.findall('cvss'):
            score_text = cvss.findtext('score')
            if score_text:
                try:
                    scores.append((float(score_text), cvss.findtext('severity')))
                except ValueError:
                    continue
        if scores:
            max_score = max(scores, key=lambda x: x[0])
            cvss_score, cvss_severity = max_score[0], max_score[1]

    # Extract the published date
    published = vuln.findtext('dates/published')

    data.append({
        'CVE_ID': vuln.findtext('cve_id'),
        'Vendor': vuln.findtext('vendor'),
        'Attack_Type': vuln.findtext('attack_type'),
        'CVSS_Score': cvss_score,
        'Severity': cvss_severity,
        'Published': published,
    })

df = pd.DataFrame(data)

# ---------------------------------------------------------
# 2. Exploratory Data Analysis (EDA)
# ---------------------------------------------------------
print("=== EXPLORATORY DATA ANALYSIS ===")
print(f"Total Vulnerabilities: {len(df)}")
print("\n--- Missing Values ---")
print(df.isnull().sum())
print("\n--- Summary Statistics (CVSS Scores) ---")
print(df['CVSS_Score'].describe())
print("\n--- Top Attack Types ---")
print(df['Attack_Type'].value_counts())

# ---------------------------------------------------------
# 3. Data Visualization
# ---------------------------------------------------------
sns.set_theme(style="whitegrid")

# Plot 1: Top Vendors
plt.figure(figsize=(10, 6))
top_vendors = df['Vendor'].value_counts().head(10).reset_index()
top_vendors.columns = ['Vendor', 'Count'] 

sns.barplot(
    data=top_vendors, 
    x='Count', 
    y='Vendor', 
    hue='Vendor', 
    palette='viridis', 
    legend=False
)
plt.title("Top 10 Vendors with Most Vulnerabilities")
plt.xlabel("Number of CVEs")
plt.ylabel("Vendor")
plt.tight_layout()
plt.savefig(reports_dir / "top_vendors_eda.png")
plt.close()

# Plot 2: Average CVSS Score by Attack Type
plt.figure(figsize=(10, 6))
avg_cvss = df.groupby('Attack_Type', dropna=False)['CVSS_Score'].mean().dropna().sort_values(ascending=False).reset_index()
avg_cvss.columns = ['Attack_Type', 'Average_CVSS']

sns.barplot(
    data=avg_cvss, 
    x='Average_CVSS', 
    y='Attack_Type', 
    hue='Attack_Type', 
    palette='magma', 
    legend=False
)
plt.title("Average CVSS Score by Attack Type")
plt.xlabel("Average CVSS Score")
plt.ylabel("Attack Type")
plt.tight_layout()
plt.savefig(reports_dir / "avg_cvss_attack_type.png")
plt.close()

# Plot 3: Severity Breakdown (Foolproof Pandas version)
plt.figure(figsize=(8, 6))
s_counts = df['Severity'].value_counts().reindex(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], fill_value=0)
severity_counts = pd.DataFrame({
    'Severity': s_counts.index,
    'Count': s_counts.values
})

sns.barplot(
    data=severity_counts,
    x='Count',
    y='Severity',
    hue='Severity',
    palette=["#4CAF50", "#FFC107", "#FF9800", "#F44336"],
    legend=False
)
plt.title("Vulnerability Severity Breakdown")
plt.xlabel("Count")
plt.ylabel("Severity Level")
plt.tight_layout()
plt.savefig(reports_dir / "severity_breakdown_eda.png")
plt.close()

# Plot 4: Timeline of Vulnerabilities
# Convert 'Published' to datetime objects, handling errors gracefully
df['Published'] = pd.to_datetime(df['Published'], errors='coerce')

if df['Published'].isnull().any():
    print("Warning: some Published values could not be converted to datetime and were dropped from the timeline plot.")

daily_counts = df.dropna(subset=['Published']).groupby('Published').size()

plt.figure(figsize=(12, 6))
plt.plot(daily_counts.index, daily_counts.values, marker='o', linestyle='-', color='#d32f2f', linewidth=2)
plt.fill_between(daily_counts.index, daily_counts.values, color='#d32f2f', alpha=0.1)
plt.title('Timeline of Vulnerabilities Published', fontsize=14, pad=15)
plt.xlabel('Publication Date', fontsize=12)
plt.ylabel('Number of CVEs Published', fontsize=12)
plt.xticks(rotation=45)
plt.grid(True, linestyle='--', alpha=0.7)
plt.tight_layout()
plt.savefig(reports_dir / "timeline_vulnerabilities.png")
plt.close()

print("\nVisualizations saved successfully to:")
print(f"- {reports_dir / 'top_vendors_eda.png'}")
print(f"- {reports_dir / 'avg_cvss_attack_type.png'}")
print(f"- {reports_dir / 'severity_breakdown_eda.png'}")
print(f"- {reports_dir / 'timeline_vulnerabilities.png'}")