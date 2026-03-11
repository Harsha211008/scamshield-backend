from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle
import asyncio

from url_scanner import scan_urls
from scam_pattern_detector import analyze_patterns

app = Flask(__name__)
CORS(app)

model = pickle.load(open("scam_model.pkl", "rb"))
vectorizer = pickle.load(open("vectorizer.pkl", "rb"))

@app.route("/", methods=["GET"])
def home():
    return "ScamAlert AI Backend Running"

@app.route("/predict", methods=["POST"])
def predict():

    data = request.get_json()

    if not data or "message" not in data:
        return jsonify({"error": "Message missing"}), 400

    message = data["message"]

    message_vec = vectorizer.transform([message])
    prediction = model.predict(message_vec)[0]

    text = message.lower()

    scam_keywords = [
        "prize","gift","claim","winner",
        "reward","congratulations",
        "offer","free","click here"
    ]

    if prediction == 0:
        for word in scam_keywords:
            if word in text:
                prediction = 3
                break

    scam_patterns = analyze_patterns(message)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    url_analysis = loop.run_until_complete(scan_urls(message))
    loop.close()

    for url in url_analysis:
        if (
            url.get("shortened")
            or url.get("suspicious_tld")
            or url.get("typosquatting")
            or (0 <= url.get("domain_age_days", -1) < 90)
        ):
            prediction = 3
            break

    return jsonify({
        "category": int(prediction),
        "url_analysis": url_analysis,
        "scam_patterns": scam_patterns
    })


if __name__ == "__main__":
    app.run(debug=True)