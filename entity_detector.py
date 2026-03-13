import re

PHONE_REGEX=r"\b\d{10}\b"
EMAIL_REGEX=r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
UPI_REGEX=r"\b[\w.-]+@[a-zA-Z]+\b"

class EntityExtractor:

    def extract(self,text):

        phones=re.findall(PHONE_REGEX,text)
        emails=re.findall(EMAIL_REGEX,text)
        upi=re.findall(UPI_REGEX,text)

        return {
            "phones":phones,
            "emails":emails,
            "upi":upi
        }