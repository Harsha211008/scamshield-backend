import re

DELIVERY_WORDS=["delivery","parcel","order","amazon","flipkart","swiggy"]
REWARD_WORDS=["won","winner","prize","lottery","reward","claim","congratulations"]
URGENT_WORDS=["urgent","immediately","expire","blocked","suspended"]
BANK_WORDS=["sbi","hdfc","icici","axis","bank"]

OTP_PATTERN=re.compile(r"\b(otp|verification code|one time password)\b",re.I)

class RuleAnalyzer:

    def evaluate(self,text,entities=None,patterns=None):

        text=text.lower()

        rules=[]

        if OTP_PATTERN.search(text) and any(w in text for w in DELIVERY_WORDS):
            rules.append("delivery_otp")

        if OTP_PATTERN.search(text) and any(w in text for w in REWARD_WORDS):
            rules.append("reward_otp")

        if any(w in text for w in REWARD_WORDS):
            rules.append("reward_language")

        if any(w in text for w in URGENT_WORDS):
            rules.append("urgent_language")

        if any(w in text for w in BANK_WORDS):
            rules.append("bank_impersonation")

        return rules