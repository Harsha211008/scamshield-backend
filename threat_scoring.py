def calculate_threat_score(ml_prob, rules, urls):

    score = int(ml_prob * 40)

    explanations = []

    # reward bait
    if rules.get("reward_bait_language"):
        score += 15
        explanations.append(
            "This message promises rewards or prizes which scammers often use."
        )

    # urgency
    if rules.get("urgent_language"):
        score += 10
        explanations.append(
            "The message uses urgent language to pressure you."
        )

    # bank impersonation
    if rules.get("bank_impersonation"):
        score += 15
        explanations.append(
            "The message may be pretending to be from a bank."
        )

    # OTP reward scam
    if rules.get("otp_reward_bait"):
        score += 20
        explanations.append(
            "The message asks for an OTP in exchange for rewards which is unsafe."
        )

    # delivery OTP (safe context)
    if rules.get("otp_delivery_context"):
        score -= 20
        explanations.append(
            "The OTP appears related to a delivery or order which is usually safe."
        )

    # URL signals
    for url in urls:

        if url.get("is_shortened"):
            score += 10
            explanations.append(
                "The message contains a shortened link which scammers often use."
            )

        if url.get("typosquatting"):
            score += 15
            explanations.append(
                "The link looks similar to a real website but may be fake."
            )

    # clamp score
    score = max(0, min(score, 100))

    # determine category
    if score < 25:
        category = "SAFE"
    elif score < 45:
        category = "PROMO"
    elif score < 65:
        category = "SUSPICIOUS"
    else:
        category = "SCAM"

    return score, category, explanations