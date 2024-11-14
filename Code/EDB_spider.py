from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium import webdriver
from bs4 import BeautifulSoup
import pandas as pd

def get_table(url, table_id = "exploits-table"):
    driver = webdriver.Chrome()
    driver.get(url)
    try:
        WebDriverWait(driver, 20).until(
            EC.presence_of_element_located((By.ID, table_id))
        )
        soup = BeautifulSoup(driver.page_source, "html.parser")
    #print(soup.prettify()) 
        table = soup.find("table")
        if table is None:
            print("No table found on the page.")
    finally:
        driver.quit()
    return table

def parser_table(table):
    if table is None:
        return [], []
    headers = []
    for th in table.find_all("th"):
        headers.append(th.text.strip())

    data = []
    for row in table.find_all("tr")[1:]:
        row_data = [td.text.strip() for td in row.find_all("td")]
        data.append(row_data)

    #df = pd.DataFrame(data, columns = headers)
    return headers, data

if __name__ == "__main__":
    url = "https://www.exploit-db.com/exploits/"
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
    table = get_table(url, headers)
    print(table)
    headers, data = parser_table(table)

    print(headers,data)