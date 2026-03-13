class ReputationLookup:

    def __init__(self):

        self.database={
            "phones":set(),
            "urls":set(),
            "emails":set(),
            "upi":set()
        }

    def check(self,entities,urls):

        score=0
        reasons=[]

        for p in entities.get("phones",[]):
            if p in self.database["phones"]:
                score+=40
                reasons.append(f"Phone {p} reported as scam")

        for e in entities.get("emails",[]):
            if e in self.database["emails"]:
                score+=30
                reasons.append(f"Email {e} reported as scam")

        return {
            "score":score,
            "reasons":reasons
        }