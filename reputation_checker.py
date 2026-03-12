# simple reputation memory (later this becomes database)

scam_database = {
    "phones": set(),
    "urls": set(),
    "upi_ids": set(),
    "emails": set()
}

def check_reputation(entities):

    score = 0
    reasons = []

    for p in entities["phones"]:
        if p in scam_database["phones"]:
            score += 40
            reasons.append(f"Phone number {p} reported as scam")

    for u in entities["upi_ids"]:
        if u in scam_database["upi_ids"]:
            score += 40
            reasons.append(f"UPI ID {u} reported as scam")

    for e in entities["emails"]:
        if e in scam_database["emails"]:
            score += 30
            reasons.append(f"Email {e} reported as scam")

    return score, reasons