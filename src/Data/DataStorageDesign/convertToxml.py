import json
import xml.etree.ElementTree as ET
import os

def safe(val):
    if val is None:
        return ""
    if isinstance(val, list):
        return val
    return str(val).strip()

base_dir = os.path.dirname(os.path.abspath(__file__))
json_path = os.path.join(base_dir, "..", "preprocessing", "cleaned_version_2_cve.json")

with open(json_path, "r", encoding="utf-8") as f:
    data = json.load(f)

root = ET.Element("vulnerabilities")

for item in data:
    vuln = ET.SubElement(root, "vulnerability")

    ET.SubElement(vuln, "cve_id").text       = safe(item.get("cve_id"))
    ET.SubElement(vuln, "title").text        = safe(item.get("title"))
    ET.SubElement(vuln, "description").text  = safe(item.get("description"))

    dates = ET.SubElement(vuln, "dates")
    ET.SubElement(dates, "published").text      = safe(item.get("published_date"))
    ET.SubElement(dates, "last_modified").text  = safe(item.get("last_modified_date"))

    ET.SubElement(vuln, "vendor").text       = safe(item.get("vendor"))
    ET.SubElement(vuln, "product").text      = safe(item.get("product"))
    ET.SubElement(vuln, "attack_type").text  = safe(item.get("attack_type"))

    cwe_list = ET.SubElement(vuln, "cwe_list")
    cwe_data = item.get("cwe")
    if isinstance(cwe_data, list):
        for cwe in cwe_data:
            if isinstance(cwe, dict):
                cwe_el = ET.SubElement(cwe_list, "cwe")
                ET.SubElement(cwe_el, "id").text    = safe(cwe.get("id"))
                ET.SubElement(cwe_el, "name").text  = safe(cwe.get("name"))

    cvss_list = ET.SubElement(vuln, "cvss_list")
    cvss_data = item.get("cvss")
    if isinstance(cvss_data, list):
        for cvss in cvss_data:
            if isinstance(cvss, dict):
                cvss_el = ET.SubElement(cvss_list, "cvss")
                ET.SubElement(cvss_el, "score").text     = safe(cvss.get("score"))
                ET.SubElement(cvss_el, "severity").text  = safe(cvss.get("severity"))
                ET.SubElement(cvss_el, "version").text   = safe(cvss.get("version"))

def indent(elem, level=0):
    i = "\n" + level * "  "
    if len(elem):
        if not elem.text or not elem.text.strip():
            elem.text = i + "  "
        for e in elem:
            indent(e, level + 1)
        if not e.tail or not e.tail.strip():
            e.tail = i
    if level and (not elem.tail or not elem.tail.strip()):
        elem.tail = i

indent(root)

output_path2 = "output2.xml"
tree = ET.ElementTree(root)
tree.write(output_path2, encoding="utf-8", xml_declaration=True)
