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
            return ""
        return re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', text)
        


    def clean_title(title):
        if not title:
            return ""
        
        title = re.sub(r'^Title:\s*', '', title)   
        title = remove_markdown(title)

     
        title = re.sub(r'\b\w+\.py\b', '', title)

       
        title = re.sub(r'\b_[a-zA-Z0-9_]+\b', '', title)

        
        title = re.sub(r'\b(injection)\b.*\b\1\b', r'\1', title, flags=re.IGNORECASE)

        
        title = re.sub(r'\s+', ' ', title).strip()

        return title


   
    def clean_cvss(cvss_list):
        
        result = []
        seen   = set()

        for item in cvss_list:
            key = (item["version"], item["score"])
            if key in seen:
                continue
            seen.add(key)

            if item["severity"] in ("—", "-", ""):
                item["severity"] = "UNKNOWN"

            item["score"] = float(item["score"])

            result.append(item)

        return result


   
    def clean_cwe(cwe_list):
        if not cwe_list:
            return []
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
            return []
        return [v.replace("affected at ", "") for v in versions]


    
    vendor, product = normalize_vendor_product(
        raw["vendor"],
        raw["product"]
    )


    
    return {
        "cve_id":             raw["cve_id"],
        "title":              clean_title(raw["title"]),
        "description":        remove_markdown(raw["description"]),
        "published_date":     raw["published_date"],
        "last_modified_date": raw["last_modified_date"],
        "cwe":                clean_cwe(raw["cwe"]),
        "cvss":               clean_cvss(raw["cvss"]),
        "vendor":             vendor,     # ← updated
        "product":            product,    # ← normalized
        "affected_versions":  clean_versions(raw["affected_versions"]),
        "attack_type":        raw["attackType"],
    }


with open("src/Data/Raw/cve_data2.json", "r", encoding="utf-8") as file:
    data = json.load(file)

cleaned = [clean_cve(item) for item in data]

with open("cleaned_version_2_cve.json", "w", encoding="utf-8") as file:
    json.dump(cleaned, file, indent=4, ensure_ascii=False)