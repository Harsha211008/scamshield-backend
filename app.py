from flask import Flask, request, jsonify
from flask_cors import CORS

from ml_model import load_model, predict_probability
from rule_engine import analyze_rules
from threat_scoring import calculate_threat_score
from language_utils import detect_language, translate_category

from entity_detector import extract_entities
from reputation_checker import check_reputation

from url_scanner import scan_urls
from scam_pattern_detector import analyze_patterns

app = Flask(__name__)
CORS(app)

# Load ML model once at startup
model, vectorizer = load_model()


@app.route("/")
def home():
    return "ScamAlert AI Backend Running"


@app.route("/predict", methods=["POST"])
async def predict():

    data = request.get_json()

    if not data or "message" not in data:
        return jsonify({"error": "Message missing"}), 400

    message = data["message"]

    # Detect language
    lang = data.get("language")
    if not lang:
        lang = detect_language(message)

    # ML prediction
    ml_prob = predict_probability(message, model, vectorizer)

    # Rule engine analysis
    rules = analyze_rules(message)

    # URL analysis
    url_analysis = await scan_urls(message)

    # Pattern detection
    patterns = analyze_patterns(message)

    # Entity detection
    entities = extract_entities(message)

    # Reputation check
    rep_score, rep_reasons = check_reputation(entities)

    # Threat scoring
    threat_score, category, explanations = calculate_threat_score(
        ml_prob,
        rules,
        url_analysis
    )

    # Add reputation signals
    threat_score += rep_score
    explanations.extend(rep_reasons)

    # Clamp score
    threat_score = max(0, min(100, threat_score))

    # Translate category if needed
    translated_category = translate_category(category, lang)

    response = {
        "category": translated_category,
        "category_code": category,
        "threat_score": threat_score,
        "explanations": explanations,
        "entities": entities,
        "url_analysis": url_analysis,
        "patterns": patterns,
        "language": lang
    }

    return jsonify(response)


if __name__ == "__main__":
    app.run(debug=True)