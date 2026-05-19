import os

from groq import Groq
import xml.etree.ElementTree as ET
from xml.dom import minidom
import time
API_KEY = os.getenv("GROQ_API_KEY") 


XML_FILE    = "../../cve_features_clean.xml"
OUTPUT_FILE = "cve_explanations.xml"


LIMIT = 200



def explain_attack(client, cve):
    prompt = f"""You are a cybersecurity expert. Given the following CVE vulnerability, explain in exactly 3 simple sentences:
1. What the vulnerability is
2. How the attacker exploits it
3. What damage it can cause

Keep it simple enough for a non-expert to understand. Write 3 plain sentences, no bullet points.

CVE ID: {cve['cve_id']}
Attack Type: {cve['attack_type']}
Description: {cve['description']}

Explanation:"""

    try:
        response = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=200
        )
        return response.choices[0].message.content.strip()

    except Exception as e:
        print(f"  Error on {cve['cve_id']}: {e}")
        return "Error generating explanation."



def load_cves(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()

    cve_list = []
    for vuln in root.findall('vulnerability'):
        description = vuln.findtext('description_features/text', default='').strip()

        if not description:
            continue  

        cve_list.append({
            'cve_id':      vuln.findtext('cve_id',                       default='Unknown'),
            'title':       vuln.findtext('title',                        default='Unknown'),
            'vendor':      vuln.findtext('vendor',                       default='Unknown'),
            'attack_type': vuln.findtext('attack_type',                  default='Unknown'),
            'severity':    vuln.findtext('cvss_features/severity_level', default='Unknown'),
            'score':       vuln.findtext('cvss_features/score',          default='N/A'),
            'description': description
        })

    return cve_list


def save_to_xml(results, output_file):
    root = ET.Element("cve_explanations")

    for r in results:
        vuln = ET.SubElement(root, "vulnerability")

        ET.SubElement(vuln, "cve_id").text         = r['cve_id']
        ET.SubElement(vuln, "title").text           = r['title']
        ET.SubElement(vuln, "vendor").text          = r['vendor']
        ET.SubElement(vuln, "attack_type").text     = r['attack_type']
        ET.SubElement(vuln, "severity").text        = r['severity']
        ET.SubElement(vuln, "score").text           = r['score']
        ET.SubElement(vuln, "description").text     = r['description']
        ET.SubElement(vuln, "ai_explanation").text  = r['ai_explanation']


    raw_xml = ET.tostring(root, encoding="utf-8")
    pretty_xml = minidom.parseString(raw_xml).toprettyxml(indent="  ")


    lines = pretty_xml.split("\n")
    pretty_xml = "\n".join(lines[1:])

    with open(output_file, "w", encoding="utf-8") as f:
        f.write('<?xml version="1.0" encoding="utf-8"?>\n')
        f.write(pretty_xml)



def main():
    print("=" * 60)
    print("   CVE Attack Explanation using Groq API")
    print("=" * 60)


    print(f"\n Loading CVEs from {XML_FILE}...")
    cve_list = load_cves(XML_FILE)
    print(f" Loaded {len(cve_list)} CVEs with descriptions")

    # Apply limit
    subset = cve_list[:LIMIT] if LIMIT else cve_list
    print(f" Processing {len(subset)} CVEs\n")

    # Connect to Groq
    client = Groq(api_key=API_KEY)
    print(" Connected to Groq API\n")


    results = []
    for i, cve in enumerate(subset):
        print(f"[{i+1}/{len(subset)}] {cve['cve_id']} ({cve['attack_type']})")

        explanation = explain_attack(client, cve)
        print(f"  → {explanation[:80]}...")

        results.append({
            'cve_id':         cve['cve_id'],
            'title':          cve['title'],
            'vendor':         cve['vendor'],
            'attack_type':    cve['attack_type'],
            'severity':       cve['severity'],
            'score':          cve['score'],
            'description':    cve['description'],
            'ai_explanation': explanation
        })

        time.sleep(2)  


    print(f"\n Saving results to {OUTPUT_FILE}...")
    save_to_xml(results, OUTPUT_FILE)

    print(f"\nDone! {len(results)} CVEs saved to {OUTPUT_FILE}")
    print("\nGive this XML to:")
    print("   (to show explanations in the dashboard)")
    print("  (to evaluate the AI output quality)")


if __name__ == "__main__":
    main()