from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle
import asyncio

# Import new modules
from url_scanner import scan_urls
from scam_pattern_detector import analyze_patterns

app = Flask(__name__)
CORS(app)

# Load trained model
model = pickle.load(open("scam_model.pkl", "rb"))
vectorizer = pickle.load(open("vectorizer.pkl", "rb"))

@app.route('/predict', methods=['POST'])
async def predict():

    data = request.get_json()

    if not data or "message" not in data:
        return jsonify({"error": "Message missing"}), 400

    message = data["message"]

    # -------------------------
    # 1️⃣ Run ML model
    # -------------------------
    message_vec = vectorizer.transform([message])
    prediction = model.predict(message_vec)[0]

    # -------------------------
    # 2️⃣ Keyword fallback detection
    # -------------------------
    text = message.lower()

    scam_keywords = [
        "prize", "gift", "claim", "winner",
        "reward", "congratulations",
        "offer", "free", "click here"
    ]

    if prediction == 0:
        for word in scam_keywords:
            if word in text:
                prediction = 3
                break

    # -------------------------
    # 3️⃣ Detect scam patterns
    # -------------------------
    scam_patterns = analyze_patterns(message)

    # -------------------------
    # 4️⃣ Scan URLs
    # -------------------------
    url_analysis = await scan_urls(message)

    # -------------------------
    # 5️⃣ Escalate scam if URL high risk
    # -------------------------
    for url in url_analysis:
        if (
            url["shortened"]
            or url["suspicious_tld"]
            or url["typosquatting"]
            or (0 <= url["domain_age_days"] < 90)
        ):
            prediction = 3
            break

    # -------------------------
    # 6️⃣ Final response
    # -------------------------
    return jsonify({
        "category": int(prediction),
        "url_analysis": url_analysis,
        "scam_patterns": scam_patterns
    })


if __name__ == "__main__":
    app.run(debug=True)