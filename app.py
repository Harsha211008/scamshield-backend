from flask import Flask, request, jsonify
from flask_cors import CORS
import os

# ScamAlert modules
from ml_model import predict_scam_probability
from rule_engine import analyze_rules
from threat_scoring import score_signals
from entity_detector import detect_entities
from language_utils import detect_language, translate_category
from reputation_checker import check_reputation
from url_scanner import scan_urls
from scam_pattern_detector import analyze_patterns

app = Flask(__name__)
CORS(app)


# -----------------------------------------
# HEALTH CHECK (important for Render)
# -----------------------------------------
@app.route("/", methods=["GET"])
def home():
    return "ScamAlert AI Backend Running"


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


# -----------------------------------------
# MAIN SCAN ENDPOINT
# -----------------------------------------
@app.route("/predict", methods=["POST"])
def predict():

    data = request.get_json()

    if not data or "message" not in data:
        return jsonify({"error": "Message missing"}), 400

    message = data["message"]
    sender = data.get("sender", None)

    # -----------------------------------------
    # 1️⃣ Detect entities (phone/email/UPI)
    # -----------------------------------------
    entities = detect_entities(message)

    # -----------------------------------------
    # 2️⃣ ML prediction
    # -----------------------------------------
    ml_probability = predict_scam_probability(message)

    # -----------------------------------------
    # 3️⃣ Rule engine analysis
    # -----------------------------------------
    rule_results = analyze_rules(message, sender)

    # -----------------------------------------
    # 4️⃣ URL analysis
    # -----------------------------------------
    url_analysis = scan_urls(message)

    # -----------------------------------------
    # 5️⃣ Pattern detection
    # -----------------------------------------
    pattern_results = analyze_patterns(message)

    # -----------------------------------------
    # 6️⃣ Reputation check
    # -----------------------------------------
    reputation = check_reputation(entities)

    # -----------------------------------------
    # 7️⃣ Threat scoring
    # -----------------------------------------
    scoring_result = score_signals(
        ml_probability=ml_probability,
        rule_results=rule_results,
        url_results=url_analysis,
        pattern_results=pattern_results,
        reputation=reputation
    )

    threat_score = scoring_result["score"]
    category = scoring_result["category"]
    explanations = scoring_result["reasons"]

    # -----------------------------------------
    # 8️⃣ Language detection
    # -----------------------------------------
    detected_lang = detect_language(message)
    translated_category = translate_category(category, detected_lang)

    # -----------------------------------------
    # FINAL RESPONSE
    # -----------------------------------------
    return jsonify({
        "category": translated_category,
        "threat_score": threat_score,
        "explanations": explanations,
        "entities": entities,
        "urls": url_analysis,
        "language": detected_lang
    })


# -----------------------------------------
# RUN SERVER (RENDER COMPATIBLE)
# -----------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)