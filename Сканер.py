import cv2
from pyzbar.pyzbar import decode
import requests
import ssl
import socket
import validators
import tldextract
import ipaddress
import re
from datetime import datetime
from urllib.parse import urlparse
from html import unescape

#НАСТРОЙКИ

#Подозрительные слова в URL
SUSPICIOUS_URL_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification",
    "account", "update", "secure", "banking", "confirm",
    "password", "credential", "suspend", "unlock", "alert",
    "paypal", "payments"
]

#Подозрительные слова на странице
SUSPICIOUS_PAGE_KEYWORDS = [
    #Формы ввода данных
    "enter your password",
    "enter your credit card",
    "enter your card number",
    "введите пароль",
    "введите номер карты",
    "введите код из смс",
    "введите cvv",

    #Угрозы
    "your account has been suspended",
    "your account will be closed",
    "your account has been compromised",
    "unusual activity detected",
    "unauthorized access",
    "suspicious activity",
    "ваш аккаунт заблокирован",
    "подозрительная активность",

    #Срочность
    "verify immediately",
    "act now",
    "urgent action required",
    "expires in 24 hours",
    "last warning",
    "срочно подтвердите",

    #Запрос данных
    "social security number",
    "date of birth",
    "mother's maiden name",
    "pin code",
    "cvv",
    "card number",
    "card expiration",
    "billing address",

    #Фишинговые призывы
    "click here to verify",
    "click here to confirm",
    "click here to unlock",
    "click below to restore",
    "confirm your identity",
    "verify your identity",
    "update your payment",
    "update your information",
    "restore access",
    "recover your account",
    "подтвердите вашу личность",
    "восстановите доступ",
]

POPULAR_BRANDS = [
    "google", "facebook", "apple", "microsoft", "amazon",
    "paypal", "netflix", "instagram", "twitter", "linkedin",
    "github", "youtube", "whatsapp", "telegram", "yahoo",
    "outlook", "sberbank", "tinkoff", "vtb", "gosuslugi",
    "yandex", "mail", "vk", "snapchat", "tiktok", "discord",
    "spotify", "pinterest", "reddit", "twitch", "steam",
    "epicgames", "roblox", "dropbox", "icloud", "onedrive",
    "adobe", "zoom", "skype", "slack", "trello", "notion",
    "wordpress", "cloudflare", "godaddy", "namecheap",
    "shopify", "ebay", "aliexpress", "alibaba", "walmart",
    "samsung", "huawei", "xiaomi", "sony", "nvidia", "intel",
    "chase", "wellsfargo", "bankofamerica", "citibank",
    "hsbc", "barclays", "revolut", "binance", "coinbase",
    "kraken", "blockchain", "metamask", "trustwallet",
    "uber", "airbnb", "booking", "fedex", "dhl", "ups",
    "openai", "chatgpt", "midjourney", "canva", "figma",
    "aws", "azure", "ozon", "wildberries", "avito",
    "alfabank", "raiffeisen", "mts", "megafon", "beeline",
]

SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd",
    "cutt.ly", "ow.ly", "buff.ly", "adf.ly", "bit.do",
    "shorte.st", "bc.vc", "j.mp", "rb.gy", "clck.ru",
    "qps.ru", "v.gd", "v.ht", "x.co", "youtu.be", "fb.me",
    "amzn.to", "amzn.eu", "apple.co", "msft.it", "aka.ms",
    "pin.it", "redd.it", "spoti.fi", "vk.cc", "g.co",
    "forms.gle", "cli.re", "mcaf.ee", "smarturl.it",
    "linktr.ee", "hubs.ly", "lnkd.in", "rebrand.ly",
    "bl.ink", "short.io", "t2m.io", "tiny.cc", "tiny.one",
    "shorturl.at", "shorturl.me", "ouo.io", "kutt.it",
    "snip.ly", "soo.gd", "dlvr.it", "ift.tt",
]

MAX_RISK_SCORE = 20

#QR-код СКАНЕР

def scan_qr_from_camera():
    cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)

    if not cap.isOpened():
        print("❌ Не удалось открыть камеру.")
        return None

    print("📷 Камера запущена. Наведите на QR-код...")

    while True:
        ret, frame = cap.read()
        if not ret:
            continue

        for barcode in decode(frame):
            qr_data = barcode.data.decode("utf-8")
            cap.release()
            cv2.destroyAllWindows()
            return qr_data

        cv2.imshow("QR Scanner", frame)
        if cv2.waitKey(1) & 0xFF == ord("q"):
            break

    cap.release()
    cv2.destroyAllWindows()
    return None


#ПРОВЕРКИ

def is_ip_address(url):
    try:
        parsed = urlparse(url)
        ipaddress.ip_address(parsed.hostname)
        return True
    except:
        return False


def check_ssl_certificate(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            if cert:
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                if not_after < datetime.now():
                    return False
                return True
            return False
    except ssl.SSLCertVerificationError:
        return False
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError):
        return None


def check_brand_impersonation(domain):
    extracted = tldextract.extract(domain)
    domain_name = extracted.domain
    subdomain = extracted.subdomain
    for brand in POPULAR_BRANDS:
        if brand in subdomain:
            return brand
        if brand in domain_name and domain_name != brand:
            return brand
    return None


def check_idn_attack(domain):
    if "xn--" in domain:
        return True
    try:
        import unicodedata
        scripts = set()
        for char in domain:
            if char.isalpha():
                scripts.add(unicodedata.category(char))
        if len(scripts) > 1:
            return True
    except:
        pass
    return False

def clean_html(html):
    text = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'<[^>]+>', ' ', text)
    text = unescape(text)
    text = re.sub(r'\s+', ' ', text)
    return text.lower()

def fetch_page(url):
    try:
        response = requests.get(
            url,
            timeout=5,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        )
        return response, response.text
    except requests.RequestException:
        return None, None


def check_page_content(html):
    results = []
    risk_score = 0

    page_text = clean_html(html)
    html_lower = html.lower()

    # 1. Подозрительные фразы на странице
    found_keywords = []
    for keyword in SUSPICIOUS_PAGE_KEYWORDS:
        if keyword.lower() in page_text:
            found_keywords.append(keyword)

    if found_keywords:
        results.append(f"🚨 Подозрительные фразы на странице ({len(found_keywords)}):")
        for kw in found_keywords[:5]:
            results.append(f"   → \"{kw}\"")
        if len(found_keywords) > 5:
            results.append(f"   ... и ещё {len(found_keywords) - 5}")
        risk_score += min(len(found_keywords) * 2, 8)
    else:
        results.append("✅ Подозрительных фраз на странице не найдено")

    # 2. Формы ввода пароля
    password_inputs = re.findall(
        r'<input[^>]*type\s*=\s*["\']password["\'][^>]*>',
        html_lower
    )
    if password_inputs:
        results.append(f"⚠️ Найдено полей ввода пароля: {len(password_inputs)}")
        risk_score += 1

    # 3. Скрытые iframe
    hidden_iframes = re.findall(
        r'<iframe[^>]*(hidden|display\s*:\s*none|width\s*=\s*["\']?0|height\s*=\s*["\']?0)[^>]*>',
        html_lower
    )
    if hidden_iframes:
        results.append("🚨 Обнаружены скрытые iframe")
        risk_score += 4

    # 4. Подозрительные скрипты
    external_scripts = re.findall(r'<script[^>]*src\s*=\s*["\']([^"\']+)["\']', html_lower)
    suspicious_scripts = [s for s in external_scripts if any(
        sh in s for sh in ["pastebin", "raw.githubusercontent", "ngrok", "serveo"]
    )]
    if suspicious_scripts:
        results.append(f"🚨 Подозрительные внешние скрипты: {len(suspicious_scripts)}")
        risk_score += 4

    # 5. Отправка данных на другой сервер
    form_actions = re.findall(r'<form[^>]*action\s*=\s*["\']([^"\']+)["\']', html_lower)
    external_forms = [a for a in form_actions if a.startswith("http")]
    if external_forms:
        results.append("⚠️ Форма отправляет данные на внешний сервер")
        risk_score += 3

    return results, risk_score

def analyze_url(url):
    if not validators.url(url):
        return {"error": "Невалидный URL"}

    results = []
    risk_score = 0

    parsed = urlparse(url)
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"

    # 6. SSL
    ssl_result = check_ssl_certificate(parsed.hostname or domain)
    if ssl_result is False:
        results.append("🚨 Проблема с SSL сертификатом")
        risk_score += 4
    elif ssl_result is None:
        results.append("⚠️ Не удалось проверить SSL")
        risk_score += 2
    else:
        results.append("✅ SSL сертификат валиден")

    # 7. IP вместо домена
    if is_ip_address(url):
        results.append("⚠️ Используется IP вместо домена")
        risk_score += 3
    else:
        results.append("✅ IP не используется")

    # 8. Сокращатели
    full_host = parsed.hostname
    if full_host in SHORTENERS or domain in SHORTENERS:
        results.append("🚨 Используется сокращение ссылок")
        risk_score += 4
    else:
        results.append("✅ Сокращение не используется")

    # 9. Подозрительные слова В URL
    url_keywords_found = []
    for word in SUSPICIOUS_URL_KEYWORDS:
        if word in url.lower():
            url_keywords_found.append(word)
    if url_keywords_found:
        results.append(f"⚠️ Подозрительные слова в URL: {', '.join(url_keywords_found)}")
        risk_score += len(url_keywords_found)

    # 10. Маскировка под бренд
    brand = check_brand_impersonation(domain)
    if brand:
        results.append(f"🚨 Возможная маскировка под бренд: {brand}")
        risk_score += 5

    # 11. Омографы
    if check_idn_attack(domain):
        results.append("🚨 Возможное использование омографов")
        risk_score += 5

    # 12. Длина URL
    if len(url) > 150:
        results.append("⚠️ Очень длинный URL")
        risk_score += 2
    else:
        results.append("✅ Размер URL нормальный")

    # 13. Поддомены
    subdomains = extracted.subdomain.split(".") if extracted.subdomain else []
    if len(subdomains) > 3:
        results.append("⚠️ Слишком много поддоменов")
        risk_score += 3

    # 14. Проверка редиректов и подозрительных слов
    print("🌐 Идет анализ ссылки...")
    response, html = fetch_page(url)

    if response is not None and html is not None:
        # Редиректы
        if len(response.history) > 2:
            results.append("⚠️ Множественные редиректы")
            risk_score += 3

        # 15. Подозрительные слова
        page_results, page_risk = check_page_content(html)
        results.extend(page_results)
        risk_score += page_risk
    else:
        results.append("❌ Сайт недоступен или блокирует соединение")
        risk_score += 1

    capped_risk = min(risk_score, MAX_RISK_SCORE)
    risk_percent = (capped_risk / MAX_RISK_SCORE) * 100
    trust_level = max(0, 100 - risk_percent)

    return {
        "results": results,
        "risk_score": risk_score,
        "trust_level": trust_level
    }


#ОТЧЁТ

def print_report(analysis):
    if "error" in analysis:
        print("❌", analysis["error"])
        return
    print("РЕЗУЛЬТАТ ПРОВЕРКИ")
    for line in analysis["results"]:
        print(line)
    print("ИТОГ")

    risk = analysis["risk_score"]
    risk_percent = min(100, int((risk / MAX_RISK_SCORE) * 100))

    print(f"📊 Уровень риска: {risk_percent}%")

    if risk >= 10:
        print("🚨 ВЫСОКИЙ РИСК! Возможный фишинг.")
    elif risk >= 5:
        print("⚠️ СРЕДНИЙ РИСК. Будьте осторожны.")
    else:
        print("✅ НИЗКИЙ РИСК. Сайт безопасен.")

    print(f"🔐 Уровень доверия: {analysis['trust_level']:.0f}%")


#MAIN

if __name__ == "__main__":
    qr_result = scan_qr_from_camera()

    if qr_result:
        print(f"\n📎 Найдено в QR-коде: {qr_result}")
        analysis = analyze_url(qr_result)
        print_report(analysis)
    else:
        print("QR-код не найден.")
