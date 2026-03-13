class ThreatScorer:

    def score_signals(self, ml_probability, url_data, pattern_data, rule_data, reputation_data):

        score=int(ml_probability*40)

        explanations=[]

        if pattern_data.get("reward_bait_language"):
            score+=10
            explanations.append("Reward bait language detected")

        if pattern_data.get("urgent_language"):
            score+=8
            explanations.append("Urgency pressure detected")

        if "reward_otp" in rule_data:
            score+=18
            explanations.append("OTP requested for reward")

        if url_data:
            score+=10
            explanations.append("Suspicious link detected")

        if reputation_data.get("score",0)>0:
            score+=reputation_data["score"]
            explanations.extend(reputation_data.get("reasons",[]))

        score=max(0,min(score,100))

        if score>=80:
            category="SCAM"
        elif score>=50:
            category="SUSPICIOUS"
        else:
            category="SAFE"

        return {
            "threat_score":score,
            "category":category,
            "explanations":explanations
        }