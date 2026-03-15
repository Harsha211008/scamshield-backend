import logging

logger = logging.getLogger("ScamAlert-Scorer")

class ThreatScorer:
    def __init__(self):
        pass

    def calculate(self, ml_prob, urls, patterns, reputation, rules):
        score = 0.0
        reasons = []

        # 1. ML Probability (From ml_model.py)
        score += (ml_prob * 100)
        if ml_prob >= 0.70:
            reasons.append(f"High AI threat probability ({ml_prob:.0%})")

        # 2. URLs (From url_scanner.py)
        for url in urls:
            domain = url.get('domain', 'Unknown Domain')
            
            # Matched to Claude's keys: 'shortened', 'typosquatting', 'suspicious_tld'
            if url.get('shortened'):
                score += 15
                reasons.append(f"Shortened URL detected ({domain})")
            if url.get('typosquatting'):
                score += 35
                reasons.append(f"Brand impersonation / typosquatting ({domain})")
            if url.get('suspicious_tld'):
                score += 20
                reasons.append(f"High-risk top-level domain ({domain})")
                
            age = url.get('domain_age_days', -1)
            if age != -1 and 0 <= age < 90:
                score += 20
                reasons.append(f"Newly registered domain ({age} days old)")

        # 3. Scam Patterns (From scam_pattern_detector.py)
        # Matched to Claude's keys: 'reward_bait_language', 'urgent_language'
        if patterns.get('reward_bait_language'):
            score += 15
            reasons.append("Contains reward or prize bait language")
        if patterns.get('urgent_language'):
            score += 15
            reasons.append("Creates artificial urgency or panic")

        # 4. Reputation (From reputation_checker.py)
        # Claude returns {"score": int, "reasons": list}
        rep_score = reputation.get('score', 0)
        if rep_score > 0:
            score += rep_score
            reasons.extend(reputation.get('reasons', []))

        # 5. Rules (From rule_engine.py)
        # Matched to Claude's list values: 'delivery_otp', 'reward_otp', etc.
        for rule in rules:
            if rule == 'delivery_otp':
                score -= 50
                reasons.append("Standard delivery/OTP context recognized (-50)")
            elif rule == 'reward_otp':
                score += 30
                reasons.append("Asking for OTP in exchange for a reward (+30)")
            elif rule == 'bank_impersonation':
                score += 30
                reasons.append("Bank impersonation detected (+30)")

        # 6. Final Formatting
        final_score = max(0, min(100, int(score)))

        if final_score < 40:
            category = "SAFE"
        elif final_score < 75:
            category = "SUSPICIOUS"
        else:
            category = "SCAM"

        if final_score < 40 and not reasons:
            reasons.append("No suspicious patterns detected.")

        return {
            "threat_score": final_score,
            "category": category,
            "reasons": reasons
        }