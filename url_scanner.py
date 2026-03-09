import re
import asyncio
import tldextract
import whois
from datetime import datetime
from cachetools import TTLCache
from concurrent.futures import ThreadPoolExecutor
import Levenshtein

domain_cache = TTLCache(maxsize=10000, ttl=86400)
whois_executor = ThreadPoolExecutor(max_workers=10)

SHORTENERS = {
    'bit.ly','tinyurl.com','t.co','goo.gl','buff.ly','rebrand.ly'
}

SUSPICIOUS_TLDS = {
    'xyz','top','gq','tk','ml','cf'
}

TARGET_BRANDS = [
    'amazon','google','paypal','facebook',
    'microsoft','apple','netflix','instagram',
    'whatsapp','bankofindia','sbi'
]

def extract_urls(text):
    pattern = re.compile(r'(https?://\S+|www\.\S+)')
    return pattern.findall(text)

def check_typosquatting(domain):
    for brand in TARGET_BRANDS:
        if brand in domain and domain != brand:
            return True
        distance = Levenshtein.distance(domain, brand)
        if 1 <= distance <= 2:
            return True
    return False

def _fetch_whois(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            return (datetime.now() - creation_date).days
    except:
        pass

    return -1

async def analyze_single_url(url):

    if not url.startswith("http"):
        url = "http://" + url

    ext = tldextract.extract(url)

    domain = ext.domain
    tld = ext.suffix
    full_domain = f"{domain}.{tld}"

    is_shortened = full_domain in SHORTENERS
    suspicious_tld = tld in SUSPICIOUS_TLDS
    typosquatting = check_typosquatting(domain)

    domain_age = -1

    if full_domain in domain_cache:
        domain_age = domain_cache[full_domain]

    else:
        loop = asyncio.get_running_loop()

        domain_age = await loop.run_in_executor(
            whois_executor,
            _fetch_whois,
            full_domain
        )

        domain_cache[full_domain] = domain_age

    return {
        "url": url,
        "domain": full_domain,
        "shortened": is_shortened,
        "domain_age_days": domain_age,
        "suspicious_tld": suspicious_tld,
        "typosquatting": typosquatting
    }

async def scan_urls(text):

    urls = extract_urls(text)

    if not urls:
        return []

    tasks = [analyze_single_url(url) for url in urls]

    results = await asyncio.gather(*tasks)

    return results