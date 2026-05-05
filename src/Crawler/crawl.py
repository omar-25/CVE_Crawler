import os

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
import json
import time

import Information
import Movement
import ScrapData

url = "https://www.cve.org/"
robots_url = url+"robots.txt"
chrome_options = Options()
chrome_options.add_argument("user-agent=CVECrawler/1.0")
chrome_options.add_experimental_option("detach", True)

driver = webdriver.Chrome(
    service=Service(ChromeDriverManager().install()),
    options=chrome_options,
)

driver.get(url)

info = Information.Information(driver)
move = Movement.Movement(driver, info)
scrap = ScrapData.ScrapData(driver)
notAllowedPaths =[]
notAllowedPaths = scrap.checkRobotsTxt(robots_url)
print(len(notAllowedPaths))
#since there is nothing disallowed, we can proceed with crawling and scraping

attacks = ["Prompt Injection", "SQL Injection", "Cross-Site Scripting", "Buffer Overflow"]
# move.dismissCookieBanner()
# move.searchForAttack(attacks[0])
# info.getLink()

# move.searchForAttack("Prompt Injection")
# Links=info.getLink()
# print(len(Links))
# for link in Links:
#     scrap.scrap(link.get_attribute("href"), driver.current_url)
#     print(len(Links))
# while True:
#     if move.goToNextPage():
#         continue
#     else:
#         break
# linkCt=0
# for attack in attacks:
#     move.searchForAttack(attack)
#     Links=info.getLink()
#     print(len(Links))
#     for link in Links:
#         scrap.scrap(link.get_attribute("href"))
#         linkCt+=1
#         print(f"Scrapped {linkCt} out of {len(Links)} links for attack: {attack}")
#         if linkCt==len(Links):
#             if move.goToNextPage():
#                 linkCt=0
#                 print("Moving to next page")
#                 continue
#             else:
#                 break
# for attack in attacks:
#     move.searchForAttack(attack)
    
#     while True:
#         links = info.getLink()
#         hrefs = [link.get_attribute("href") for link in links]  # grab before visiting
#         print(f"Found {len(hrefs)} links for {attack}")
        
#         for i, href in enumerate(hrefs):
#             if href:
#                 resultsUrl = driver.current_url
#                 scrap.scrap(href, resultsUrl)
#                 print(f"Scraped {i+1} of {len(hrefs)}")
        
#         if move.goToNextPage():
#             print("Moving to next page")
#             continue  # re-fetch links at top of while loop
#         else:
#             print(f"Done with {attack}")
#             break     # move to next attack

# allCVEs = []
# ctPage=0
# for attack in attacks:
#     move.searchForAttack(attack)
#     ctPage=0
#     while True:
#         links  = info.getLink()
#         hrefs  = [link.get_attribute("href") for link in links]
#         for href in hrefs:
#             if href:
#                 #resultsUrl = driver.current_url
#                 cveObj = scrap.scrap(href)
#                 if cveObj:
#                     allCVEs.append(cveObj)
#                 #driver.get(resultsUrl)
        
#         if move.goToNextPage() and ctPage<3:
#             ctPage+=1
#             continue
#         else:
#             break




allCVEs = []

for attack in attacks:
    attack_start = time.perf_counter()
    
    move.searchForAttack(attack)
    move.selectShowMore()
    ctPage = 0
    
    while True:
        links = info.getLink()
        hrefs = [link.get_attribute("href") for link in links]
        
        for href in hrefs:
            if href:
                cveObj = scrap.scrap(href)
                if cveObj:
                    cveObj.attackType = attack
                    allCVEs.append(cveObj)
        
        ctPage += 1
        print(f"Page {ctPage} done for {attack}")
        
        if ctPage >= 3:
            print(f"Reached page limit for {attack}")
            break
        
        if not move.goToNextPage():
            print(f"No more pages for {attack}")
            break

    attack_elapsed = time.perf_counter() - attack_start
    print(f"'{attack}' took {attack_elapsed:.2f}s ({len([c for c in allCVEs if c.attackType == attack])} CVEs)")

print(f"Total CVEs scraped: {len(allCVEs)}")
def saveRaw(allCVEs, filename="cve_data2.json"):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_path = os.path.join(script_dir, "..", "..", "Data", "Raw", filename)
    output_path = os.path.normpath(output_path)
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    data = [cve.to_dict() for cve in allCVEs]
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    print(f"Saved {len(data)} raw CVEs to {output_path}")

saveRaw(allCVEs)


driver.quit()