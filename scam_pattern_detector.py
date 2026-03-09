import re

PATTERNS = {
"reward_bait": re.compile(r'\b(lottery|won|reward|prize|free gift)\b', re.I),

"urgency_language": re.compile(r'\b(act now|urgent|immediate|expires today)\b', re.I),

"authority_impersonation": re.compile(r'\b(bank|income tax|government|rbi)\b', re.I),

"fear_tactics": re.compile(r'\b(account blocked|legal action|suspended)\b', re.I),

"financial_requests": re.compile(r'\b(send money|processing fee|pay now|upi)\b', re.I)
}

def analyze_patterns(text):

    results = {}

    for name,pattern in PATTERNS.items():

        results[name] = bool(pattern.search(text))

    return results