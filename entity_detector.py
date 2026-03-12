import re

PHONE_PATTERN = r'(\+?\d[\d\-\s]{8,}\d)'
EMAIL_PATTERN = r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
UPI_PATTERN = r'[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}'

def extract_entities(text):

    phones = re.findall(PHONE_PATTERN, text)
    emails = re.findall(EMAIL_PATTERN, text)
    upis = re.findall(UPI_PATTERN, text)

    return {
        "phones": phones,
        "emails": emails,
        "upi_ids": upis
    }