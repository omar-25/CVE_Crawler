import os
import re
import json

def clean_cve(raw):

    
    def normalize_vendor_product(vendor, product):
        corrections = {
            "PromtEngineer": "PromptEngineer"
        }

      
        vendor = (vendor or "").strip()
        product = (product or "").strip()

        vendor = corrections.get(vendor, vendor)

        return vendor, product

      
   
    def remove_markdown(text):
        if not text:
            return "unknown"
        return re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', text)
        


    def clean_title(title):
        if not title:
            return "unknown"
        
        title = re.sub(r'^Title:\s*', '', title)   
        title = remove_markdown(title)

     
        title = re.sub(r'\b\w+\.py\b', '', title)

       
        title = re.sub(r'\b_[a-zA-Z0-9_]+\b', '', title)

        
        title = re.sub(r'\b(injection)\b.*\b\1\b', r'\1', title, flags=re.IGNORECASE)

        
        title = re.sub(r'\s+', ' ', title).strip()

        return title

    def clean_nulls(text):
        if not text:
            return "unknown"
        else:
            return text

        
        
   
    def clean_cvss(cvss_list):
        result = []
        seen = set()

        for item in cvss_list:

            version = item.get("version") or "unknown"
            score = item.get("score")
            severity = item.get("severity") or "unknown"
            vector = item.get("vector")
         

            if vector == "":
                vector = "unknown"

            key = (version, score)
            if key in seen:
                continue
            seen.add(key)

            # Normalize severity
            if severity in ("—", "-", "", None):
                severity = "unknown"

            cleaned_item = {
                "version": version,
                "score": score,
                "severity": severity,
                "vector": vector
            }

            result.append(cleaned_item)

        return result

   
    def clean_cwe(cwe_list):
        if not cwe_list:
            return ["unknown"]
        result = []
        for cwe in cwe_list:
            match = re.match(r'(CWE-\d+):\s*(.+)', cwe)
            if match:
                result.append({
                    "id":   match.group(1),
                    "name": match.group(2)
                })
        return result


    
    def clean_versions(versions):
        if not versions:
            return ["unknown"]
        return [v.replace("affected at ", "") for v in versions]


    
    vendor, product = normalize_vendor_product(
        raw["vendor"],
        raw["product"]
    )


    
    return {
        "cve_id":             clean_nulls(raw["cve_id"]) ,
        "title":              clean_title(raw["title"]),
        "description":        remove_markdown(raw["description"]),
        "published_date":     clean_nulls(raw["published_date"]),
        "last_modified_date": clean_nulls(raw["last_modified_date"]),
        "cwe":                clean_cwe(raw["cwe"]),
        "cvss":               clean_cvss(raw["cvss"]),
        "vendor":             clean_nulls(raw["vendor"]),    
        "product":            clean_nulls(raw["last_modified_date"]),
        "affected_versions":  clean_versions(raw["product"]),
        "attack_type":        clean_nulls(raw["attackType"]),
    }


BASE_DIR  = os.path.dirname(os.path.abspath(__file__))
input_path = os.path.join(BASE_DIR, "..", "Raw", "cve_data2.json")
output_path = os.path.join(BASE_DIR, "cleaned_version_2_cve.json")

with open(input_path, "r", encoding="utf-8") as file:
    data = json.load(file)

cleaned = [clean_cve(item) for item in data]

with open(output_path, "w", encoding="utf-8") as file:
    json.dump(cleaned, file, indent=4, ensure_ascii=False)

print(f"Done! {len(cleaned)} records written to {output_path}")