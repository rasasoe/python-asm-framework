from __future__ import annotations

from typing import List
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from webdriver_manager.chrome import ChromeDriverManager

def collect_ui_functions_observe_only(url: str, headless: bool = True, max_buttons: int = 80) -> List[str]:
    """
    Selenium은 '관찰(읽기)' 용도로만 사용:
    - 클릭/입력/로그인/상태변화 없음
    - 화면에 보이는 버튼/링크 텍스트 등만 수집
    """
    options = Options()
    if headless:
        options.add_argument("--headless=new")
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1280,900")

    driver = webdriver.Chrome(options=options, service=None)
    try:
        driver.get(url)

        texts: List[str] = []

        # 버튼 텍스트
        btns = driver.find_elements(By.TAG_NAME, "button")[:max_buttons]
        for b in btns:
            t = (b.text or "").strip()
            if t:
                texts.append(t)

        # 링크 텍스트
        links = driver.find_elements(By.TAG_NAME, "a")[:max_buttons]
        for a in links:
            t = (a.text or "").strip()
            if t:
                texts.append(t)

        # 중복 제거
        uniq = sorted(set(texts))
        return uniq
    finally:
        driver.quit()
