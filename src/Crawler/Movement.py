from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

class Movement:
    def __init__(self, driver, info):
        self.driver = driver
        self.info = info
        self.wait = WebDriverWait(self.driver, 10)

    def dismissCookieBanner(self):
        try:
            self.wait.until(
                EC.presence_of_element_located((By.CLASS_NAME, self.info.cookieCloseClass))
            )
            closeButton = self.driver.find_element(By.CLASS_NAME, self.info.cookieCloseClass)
            closeButton.click()
            self.wait.until(
                EC.invisibility_of_element_located((By.CLASS_NAME, "osano-cm-dialog"))
            )
            print("Cookie banner dismissed")
        except Exception as e:
            print(f"No cookie banner: {e}")

    def searchForAttack(self, attack):
        self.dismissCookieBanner()
        self.info.searchBar.clear()
        self.info.searchBar.send_keys(attack)
        self.wait.until(
            EC.element_to_be_clickable((By.CLASS_NAME, self.info.searchButtonClass))
        )
        self.info.searchButton.click()    
    def goToNextPage(self):
        try:
            self.info.loadPaginationButtons()
            if not self.info.forwardButton.is_enabled():
                print("Forward button is disabled, cannot go to next page.")
                return False
            self.info.forwardButton.click()
            return True
        except Exception as e:
            print(f"Error occurred while clicking forward button: {e}")

    def goToPreviousPage(self):
        try:
            self.info.loadPaginationButtons()
            if not self.info.backButton.is_enabled():
                print("Back button is disabled, cannot go to previous page.")
                return
            self.info.backButton.click()
        except Exception as e:
            print(f"Error occurred while clicking back button: {e}")

