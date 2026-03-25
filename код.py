import cv2
from pyzbar.pyzbar import decode
import requests
import ssl
import socket
import validators
import tldextract
import ipaddress
from datetime import datetime
from urllib.parse import urlparse

#НАСТРОЙКИ

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification",
    "account", "update", "secure", "banking", "confirm",
    "password", "credential", "suspend", "unlock", "alert",
    "paypal"
]

POPULAR_BRANDS = [
    "google", "facebook", "apple", "microsoft", "amazon", "paypal", "netflix", "instagram",
    "twitter", "linkedin", "github", "youtube", "whatsapp", "telegram", "yahoo", "outlook",
    "sberbank", "tinkoff", "vtb", "gosuslugi", "yandex", "mail", "vk", "snapchat", "tiktok",
    "discord", "spotify", "pinterest", "reddit", "twitch", "steam", "epicgames", "roblox",
    "dropbox", "icloud", "onedrive", "adobe", "zoom", "skype", "slack", "trello", "notion",
    "wordpress", "cloudflare", "godaddy", "namecheap", "shopify", "ebay", "aliexpress",
    "alibaba", "walmart", "target", "costco", "bestbuy", "samsung", "huawei", "xiaomi",
    "oneplus", "sony", "nvidia", "intel", "amd", "oracle", "ibm", "cisco", "vmware",
    "chase", "wellsfargo", "bankofamerica", "citibank", "hsbc", "barclays", "revolut",
    "binance", "coinbase", "kraken", "blockchain", "metamask", "trustwallet", "ledger",
    "uber", "lyft", "airbnb", "booking", "trivago", "expedia", "fedex", "dhl", "ups",
    "usps", "hbo", "disneyplus", "primevideo", "hulu", "crunchyroll", "deezer",
    "openai", "chatgpt", "midjourney", "canva", "figma", "atlassian", "jira", "github",
    "gitlab", "bitbucket", "stackoverflow", "docker", "kubernetes", "aws", "azure", "gcloud",
    "ozon", "wildberries", "avito", "cian", "pochta", "alfabank", "raiffeisen", "mts",
    "megafon", "beeline", "rostelecom", "okko", "kinopoisk", "rutube", "gazprom", "rosneft"
]

SHORTENERS = [
    "bit.ly","tinyurl.com","t.co","goo.gl","is.gd","cutt.ly","ow.ly",
    "buff.ly","adf.ly","bit.do","shorte.st", "bc.vc",
    "j.mp","rb.gy","clck.ru","qps.ru","v.gd","v.ht","x.co","x.gd","u.to",
    "0rz.tw","1url.com","2.gp","2tu.us","s.coop","s.id","t.me","youtu.be","fb.me",
    "amzn.to", "amzn.eu","apple.co","msft.it", "aka.ms", "lin.ee", "pin.it", "redd.it", "spoti.fi",
    "vk.cc", "g.co", "forms.gle", "maps.app.goo.gl", "cli.re", "mcaf.ee",
    "smarturl.it","linktr.ee", "hubs.ly", "shor.by", "linkr.it",
    "lnkd.in", "rebrand.ly","bl.ink","short.io","t2m.io","urlzs.com","hyperurl.co",
    "trib.al","dlvr.it","ift.tt", "tiny.cc","tiny.one","shorturl.at","shorturl.me",
    "shrtco.de","ouo.io","za.gl","han.gl","urls.fr","u.nu","kutt.it","snip.ly","soo.gd",
    "clicky.me","budurl.com","qr.ae","lc.chat","shorten.rest","linkbucks.com","ay.gy",
    "adfoc.us","sh.st","gestyy.com","exe.io","fc.lc","shrink.pe","cpmlink.net","srt.lt","link1s.com",
    "cut-urls.com","shrinke.me","ouo.press","clicksfly.com","clck.ru", "vk.cc", "qps.ru",
    "to.click","cc.st","u.to","sbly.link",
]

MAX_RISK_SCORE = 20

#QR-код СКАНЕР

def scan_qr_from_camera():
    cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)
    print("Наведите камеру на QR-код")

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

#АНАЛИЗ

def analyze_url(url):
    if not validators.url(url):
        return {"error": "Невалидный URL"}
    results = []
    risk_score = 0

    parsed = urlparse(url)
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"

    #SSL
    if not check_ssl_certificate(domain):
        results.append("🚨 Проблема с SSL сертификатом")
        risk_score += 2
    else:
        results.append("✅ SSL сертификат валиден")

    #IP вместо домена
    if is_ip_address(url):
        results.append("⚠️ Используется IP вместо домена")
        risk_score += 3
    else:
        results.append("✅ IP не используется")

    #Shorteners
    full_host = parsed.hostname
    if full_host in SHORTENERS or domain in SHORTENERS:
        results.append("🚨 Используется сокращение ссылок")
        risk_score += 5
    else:
        results.append("✅ Сокращение не используются")

    #Подозрительные слова
    for word in SUSPICIOUS_KEYWORDS:
        if word in url.lower():
            results.append(f"⚠️ Подозрительное слово: {word}")
            risk_score += 1

    #Маскировка под бренд
    brand = check_brand_impersonation(domain)
    if brand:
        results.append(f"🚨 Возможная маскировка под бренд: {brand}")
        risk_score += 5

    #Омографы
    if check_idn_attack(domain):
        results.append("🚨 Возможное использование омографов"
                       "")
        risk_score += 5

    #Длина URL
    if len(url) > 120:
        results.append("⚠️ Очень длинный URL")
        risk_score += 2
    else:
        results.append("✅ Размер URL нормальный")

    #Поддомены
    subdomains = extracted.subdomain.split(".") if extracted.subdomain else []
    if len(subdomains) > 3:
        results.append("⚠️ Слишком много поддоменов")
        risk_score += 2

    #Редиректы
    try:
        response = requests.get(
            url,
            timeout=5,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if len(response.history) > 2:
            results.append("⚠️ Множественные редиректы")
            risk_score += 2
    except requests.RequestException:
        results.append("❌ Сайт недоступен")
        risk_score += 1

    trust_level = max(0, 100 - min(risk_score, MAX_RISK_SCORE) * 5)

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

    print("\nРЕЗУЛЬТАТ ПРОВЕРКИ\n")

    for line in analysis["results"]:
        print(line)

    print("\nИТОГ")

    risk = analysis["risk_score"]

    if risk >= 10:
        print("🚨 ВЫСОКИЙ РИСК! Возможный фишинг.")
    elif risk >= 5:
        print("⚠️ СРЕДНИЙ РИСК. Плохая защита сайта. Будьте осторожны.")
    else:
        print("✅ Низкий риск. Сайт безопасен")

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