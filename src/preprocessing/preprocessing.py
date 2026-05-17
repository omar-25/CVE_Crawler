import xml.etree.ElementTree as ET
from xml.dom import minidom
import pandas as pd
import re

# ─────────────────────────────────────────────
# 1. LOAD XML
# ─────────────────────────────────────────────
XML_PATH = "output2.xml"
OUT_PATH = "cve_features_clean.xml"

tree = ET.parse(XML_PATH)
root = tree.getroot()

records = []

for vuln in root.findall("vulnerability"):

    def get(tag, default=""):
        el = vuln.find(tag)
        return el.text.strip() if el is not None and el.text else default

    cve_id      = get("cve_id")
    title       = get("title")
    description = get("description")
    published   = get("dates/published")
    last_mod    = get("dates/last_modified")
    vendor      = get("vendor")
    product     = get("product")
    attack_type = get("attack_type")

    cwe_elements = vuln.findall("cwe_list/cwe")
    cwe_ids   = [c.findtext("id", "").strip() for c in cwe_elements if c.findtext("id", "").strip()]
    cwe_names = [c.findtext("name", "").strip() for c in cwe_elements if c.findtext("name", "").strip()]

    cvss_elements   = vuln.findall("cvss_list/cvss")
    cvss_scores     = []
    cvss_severities = []
    cvss_versions   = []

    for cvss in cvss_elements:
        score    = cvss.findtext("score",    "").strip()
        severity = cvss.findtext("severity", "").strip()
        version  = cvss.findtext("version",  "").strip()
        if score:
            try:
                cvss_scores.append(float(score))
            except ValueError:
                pass
        if severity and severity.lower() != "unknown":
            cvss_severities.append(severity.upper())
        if version:
            cvss_versions.append(version)

    records.append({
        "cve_id"          : cve_id,
        "title"           : title,
        "description"     : description,
        "published"       : published,
        "last_modified"   : last_mod,
        "vendor"          : vendor,
        "product"         : product,
        "attack_type"     : attack_type,
        "cwe_ids"         : "|".join(cwe_ids),
        "cwe_names"       : "|".join(cwe_names),
        "cvss_scores"     : "|".join(str(s) for s in cvss_scores),
        "cvss_severities" : "|".join(cvss_severities),
        "cvss_versions"   : "|".join(cvss_versions),
    })

df = pd.DataFrame(records)
print(f"[1] Total records loaded      : {len(df)}")

# ─────────────────────────────────────────────
# 2. DROP UNKNOWNS
# ─────────────────────────────────────────────
IS_UNKNOWN = (
    (df["cve_id"].str.lower()      == "unknown") |
    (df["description"].str.lower() == "unknown") |
    (df["title"].str.lower()       == "unknown")
)
unknown_count = IS_UNKNOWN.sum()
df = df[~IS_UNKNOWN].reset_index(drop=True)
print(f"[2] Unknown records dropped   : {unknown_count}")
print(f"    Records remaining         : {len(df)}")

# ─────────────────────────────────────────────
# 3. CLEAN & NORMALIZE
# ─────────────────────────────────────────────

def clean_text(s):
    """Remove newlines, tabs, and extra spaces from any text field."""
    if not s:
        return ""
    s = re.sub(r"[\r\n\t]+", " ", s)
    s = re.sub(r" {2,}", " ", s)
    return s.strip()

df["description"] = df["description"].apply(clean_text)
df["title"]       = df["title"].apply(clean_text)

def parse_date(s):
    try:
        return pd.to_datetime(s, format="%Y-%m-%d", errors="raise")
    except Exception:
        return pd.NaT

df["published_dt"]     = df["published"].apply(parse_date)
df["last_modified_dt"] = df["last_modified"].apply(parse_date)

def clean_vendor(v):
    v = str(v).strip()
    v = re.sub(r"^[\d\W]+", "", v).strip()
    return v if v else "Unknown"

df["vendor_clean"] = df["vendor"].apply(clean_vendor)

df["attack_type_clean"] = (
    df["attack_type"]
    .str.strip()
    .str.replace(r"\s+", " ", regex=True)
    .str.title()
)

def clean_cwe_names(names_str):
    parts = names_str.split("|") if names_str else []
    cleaned = []
    for p in parts:
        p = re.sub(r"^CWE-\d+[:\s]+", "", p).strip()
        if p:
            cleaned.append(p)
    return "|".join(cleaned)

df["cwe_names_clean"] = df["cwe_names"].apply(clean_cwe_names)

# ─────────────────────────────────────────────
# 4. FEATURE EXTRACTION
# ─────────────────────────────────────────────
PREFERRED_VERSION_ORDER = ["3.1", "3.0", "4.0", "2.0"]
SEVERITY_ORDER          = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

df["year"]               = df["published_dt"].dt.year
df["description_length"] = df["description"].str.len()
df["cwe_count"]          = df["cwe_ids"].apply(lambda x: len(x.split("|")) if x else 0)

def pick_best_cvss_score(scores_str, versions_str):
    if not scores_str:
        return None
    scores   = scores_str.split("|")
    versions = versions_str.split("|") if versions_str else []
    pairs    = list(zip(versions, scores)) if len(versions) == len(scores) else []
    for pref in PREFERRED_VERSION_ORDER:
        for ver, sc in pairs:
            if ver == pref:
                try:
                    return float(sc)
                except ValueError:
                    pass
    try:
        return float(scores[0])
    except (ValueError, IndexError):
        return None

df["cvss_score"] = df.apply(
    lambda r: pick_best_cvss_score(r["cvss_scores"], r["cvss_versions"]), axis=1
)

def pick_best_severity(severities_str, versions_str, scores_str):
    if not severities_str:
        return None
    sev      = severities_str.split("|")
    versions = versions_str.split("|") if versions_str else []
    scores   = scores_str.split("|")   if scores_str   else []
    triples  = list(zip(versions, sev, scores)) if len(versions) == len(sev) == len(scores) else []
    for pref in PREFERRED_VERSION_ORDER:
        for ver, s, _ in triples:
            if ver == pref and s:
                return s.upper()
    for s_level in SEVERITY_ORDER:
        if s_level in sev:
            return s_level
    return sev[0].upper() if sev else None

df["severity_level"]   = df.apply(
    lambda r: pick_best_severity(r["cvss_severities"], r["cvss_versions"], r["cvss_scores"]), axis=1
)
SEVERITY_MAP           = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
df["severity_numeric"] = df["severity_level"].map(SEVERITY_MAP)
df["has_cvss"]         = df["cvss_score"].notna().astype(int)

# ─────────────────────────────────────────────
# 5. BUILD CLEAN DATAFRAME
# ─────────────────────────────────────────────
FEATURE_COLS = [
    "cve_id", "title", "vendor_clean", "attack_type_clean",
    "published_dt", "last_modified_dt", "year",
    "cvss_score", "severity_level", "severity_numeric",
    "cwe_count", "cwe_ids", "cwe_names_clean",
    "description_length", "has_cvss", "description",
]
df_clean = df[FEATURE_COLS].copy()
df_clean["published_dt"]     = df_clean["published_dt"].dt.strftime("%Y-%m-%d").fillna("")
df_clean["last_modified_dt"] = df_clean["last_modified_dt"].dt.strftime("%Y-%m-%d").fillna("")
df_clean = df_clean.fillna("")

# ─────────────────────────────────────────────
# 6. SAVE AS PRETTY XML
# ─────────────────────────────────────────────
xml_root = ET.Element("vulnerabilities")

for _, row in df_clean.iterrows():
    vuln_el = ET.SubElement(xml_root, "vulnerability")

    ET.SubElement(vuln_el, "cve_id").text      = str(row["cve_id"])
    ET.SubElement(vuln_el, "title").text        = str(row["title"])
    ET.SubElement(vuln_el, "vendor").text       = str(row["vendor_clean"])
    ET.SubElement(vuln_el, "attack_type").text  = str(row["attack_type_clean"])

    dates_el = ET.SubElement(vuln_el, "dates")
    ET.SubElement(dates_el, "published").text     = str(row["published_dt"])
    ET.SubElement(dates_el, "last_modified").text = str(row["last_modified_dt"])

    ET.SubElement(vuln_el, "year").text = str(int(row["year"])) if row["year"] != "" else ""

    cvss_el = ET.SubElement(vuln_el, "cvss_features")
    ET.SubElement(cvss_el, "score").text            = str(row["cvss_score"])
    ET.SubElement(cvss_el, "severity_level").text   = str(row["severity_level"])
    ET.SubElement(cvss_el, "severity_numeric").text = str(row["severity_numeric"])
    ET.SubElement(cvss_el, "has_cvss").text         = str(row["has_cvss"])

    cwe_el = ET.SubElement(vuln_el, "cwe_features")
    ET.SubElement(cwe_el, "cwe_count").text = str(row["cwe_count"])
    ET.SubElement(cwe_el, "cwe_ids").text   = str(row["cwe_ids"])
    ET.SubElement(cwe_el, "cwe_names").text = str(row["cwe_names_clean"])

    desc_el = ET.SubElement(vuln_el, "description_features")
    ET.SubElement(desc_el, "length").text = str(row["description_length"])
    ET.SubElement(desc_el, "text").text   = str(row["description"])

# Pretty-print
raw_xml   = ET.tostring(xml_root, encoding="unicode")
pretty    = minidom.parseString(raw_xml).toprettyxml(indent="  ")
lines     = pretty.splitlines()
final_xml = "\n".join(lines[1:])  # drop minidom's own declaration

with open(OUT_PATH, "w", encoding="utf-8") as f:
    f.write('<?xml version="1.0" encoding="utf-8"?>\n')
    f.write(final_xml)

# ─────────────────────────────────────────────
# 7. STATS
# ─────────────────────────────────────────────
print("\n── Feature Summary ──────────────────────────────────")
print(f"  Final record count        : {len(df_clean)}")
print(f"  CVSS score  (mean)        : {pd.to_numeric(df_clean['cvss_score'], errors='coerce').mean():.2f}")
print(f"  Avg CWE count             : {df_clean['cwe_count'].mean():.2f}")
print(f"  Avg description length    : {df_clean['description_length'].mean():.0f} chars")
print(f"  Severity distribution:\n{df_clean['severity_level'].value_counts().to_string()}")
print("─────────────────────────────────────────────────────")
print(f"\n✅ Clean XML saved → {OUT_PATH}")
