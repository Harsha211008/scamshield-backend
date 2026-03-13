import re

def analyze_patterns(text):

    text=text.lower()

    patterns={
        "reward_bait_language":False,
        "urgent_language":False
    }

    if re.search(r"won|prize|lottery|reward|congratulations",text):
        patterns["reward_bait_language"]=True

    if re.search(r"urgent|immediately|expire|suspended",text):
        patterns["urgent_language"]=True

    return patterns