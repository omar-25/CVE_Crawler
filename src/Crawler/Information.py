from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

class Information:
    def __init__(self, driver):
        self.driver = driver
        self.wait = WebDriverWait(self.driver, 10)
        
        self.searchButtonClass = "cve-button-accent-warm"
        self.searchBarClass = "cve-id-input"
        self.cookieCloseClass = "osano-cm-dialog__close"
        
        self.CVELink="https://www.cve.org/CVERecord?id="
        self.CVE_CSS_Selector="a[href^='/CVERecord?id=']"
        self.forwardButtonClass = "pagination-next"
        
        self.backButtonClass = "pagination-previous"        
        self.showMoreButtonCss ='[aria-label="Select how many search results to show"]'
        self.searchButton = self.waitAndGet(By.CLASS_NAME, self.searchButtonClass)
        self.searchBar = self.waitAndGet(By.CLASS_NAME, self.searchBarClass)
        self.ShowMoreButton=None
        self.forwardButton = self.backButton = None


    def getElement(self, by, value):
        return self.driver.find_element(by, value)
    
    def getElements(self, by, value):
        return self.driver.find_elements(by, value)
    
    def waitAndGet(self, by, value):
        self.wait.until(EC.presence_of_element_located((by, value)))
        return self.driver.find_element(by, value)
    
    
    def loadPaginationButtons(self):
        self.forwardButton = self.waitAndGet(By.CLASS_NAME, self.forwardButtonClass)
        self.backButton = self.waitAndGet(By.CLASS_NAME, self.backButtonClass)

    def waitAndGetAll(self, by, value):
        self.wait.until(EC.presence_of_all_elements_located((by, value)))
        return self.driver.find_elements(by, value)
    
    def getLink(self):
        self.wait.until(EC.presence_of_all_elements_located((By.CSS_SELECTOR, self.CVE_CSS_Selector)))
        return self.waitAndGetAll(By.CSS_SELECTOR, self.CVE_CSS_Selector)
