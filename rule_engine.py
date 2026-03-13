import re

DELIVERY_WORDS=["delivery","parcel","order","amazon","flipkart","swiggy"]
REWARD_WORDS=["won","winner","prize","lottery","reward","claim","congratulations"]
URGENT_WORDS=["urgent","immediately","expire","blocked","suspended"]
BANK_WORDS=["sbi","hdfc","icici","axis","bank"]

OTP_PATTERN=re.compile(r"\b(otp|verification code|one time password)\b",re.I)


class RuleAnalyzer:

    def __init__(self):
        pass

    def evaluate(self,text,entities=None,patterns=None):

        text=text.lower()

        rules={
            "otp_delivery_context":False,
            "otp_reward_bait":False,
            "reward_bait_language":False,
            "urgent_language":False,
            "bank_impersonation":False
        }

        if OTP_PATTERN.search(text) and any(w in text for w in DELIVERY_WORDS):
            rules["otp_delivery_context"]=True

        if OTP_PATTERN.search(text) and any(w in text for w in REWARD_WORDS):
            rules["otp_reward_bait"]=True

        if any(w in text for w in REWARD_WORDS):
            rules["reward_bait_language"]=True

        if any(w in text for w in URGENT_WORDS):
            rules["urgent_language"]=True

        if any(w in text for w in BANK_WORDS):
            rules["bank_impersonation"]=True

        return rules