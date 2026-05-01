from bs4 import BeautifulSoup
import requests as req
import time
import cveData
class ScrapData:
    def __init__(self, driver):
        self.headers = {"User-Agent": "CVECrawler/1.0"}
        self.driver = driver


    def scrap(self, url):
        self.driver.get(url)
        time.sleep(0.5) 
        soup=BeautifulSoup(self.driver.page_source, "html.parser")
        cveObj = self.createObj(soup=soup)
        ###################################object needs to be sent somewhere
        self.driver.back()
        return cveObj

    def getProductStatus(self, soup):
        nav = soup.find("nav", id="cve-vendor-product-platforms")
        
        if not nav:
            return None
        
        items = nav.find_all("div", class_="level-item")
        vendor = None
        product = None
        
        for item in items:
            heading = item.find("p", class_="cve-product-status-heading")
            value   = heading.find_next_sibling("p") if heading else None
            
            if heading and value:
                if heading.text.strip() == "Vendor":
                    vendor = value.text.strip()
                elif heading.text.strip() == "Product":
                    product = value.text.strip()
        
        # Get affected versions
        affectedVersions = []
        versionItems = soup.find_all("li")
        for item in versionItems:
            if "affected at" in item.text:
                affectedVersions.append(item.text.strip())
        
        return {
            "vendor"            : vendor,
            "product"           : product,
            "affected_versions" : affectedVersions  # ← lowercase v
        }
    
    def getCVSSTable(self, soup):
        cvssData = []
        table = soup.find("table", class_="cve-border-dark-blue")
        
        if not table:
            #print("Table not found")
            return cvssData
        
        rows = table.find("tbody").find_all("tr")
        #print(f"Found {len(rows)} rows")  # debug
        
        for row in rows:
            score    = row.find("td", attrs={"data-label": "Score"})
            severity = row.find("td", attrs={"data-label": "Severity"})
            version  = row.find("td", attrs={"data-label": "Version"})
            vector   = row.find("td", attrs={"data-label": "Vector String"})
            
            cvssData.append({
                "score"    : score.text.strip()    if score    else None,
                "severity" : severity.text.strip() if severity else None,
                "version"  : version.text.strip()  if version  else None,
                "vector"   : vector.text.strip()   if vector   else None,
            })
        
        return cvssData

    def createObj(self, soup):
        cve_id      = soup.find("h1", class_="title").text.strip() if soup.find("h1", class_="title") else None
        titleTag    = soup.find("p", class_="mb-0")
        title       = titleTag.text.strip() if titleTag else None
        
        descTag     = soup.find("p", class_="content")
        description = descTag.text.strip() if descTag else None
        
        times       = soup.find_all("time")
        published   = times[0].text.strip() if len(times) > 0 else None
        updated     = times[1].text.strip() if len(times) > 1 else None
        
        cweTag      = soup.find("div", class_="cve-y-scroll")
        cwe         = cweTag.find("ul").find_all("li") if cweTag else []
        
        productStatus    = self.getProductStatus(soup)
        vendor           = productStatus["vendor"]            if productStatus else None
        product          = productStatus["product"]           if productStatus else None
        affectedVersions = productStatus["affected_versions"] if productStatus else None
        
        cvssData = self.getCVSSTable(soup)
        
        return cveData.CVE(
            cve_id             = cve_id,
            title              = title,
            description        = description,
            published_date     = published,
            last_modified_date = updated,
            cwe                = cwe,
            cvss               = cvssData,
            vendor             = vendor,
            product            = product,
            affected_versions  = affectedVersions
        )
