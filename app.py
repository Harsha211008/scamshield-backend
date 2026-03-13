import os
import logging
import asyncio
from flask import Flask, request, jsonify

app = Flask(__name__)

# ------------------------------------------------------------------
# Logging
# ------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("ScamAlert")

# ------------------------------------------------------------------
# Module Imports
# ------------------------------------------------------------------
try:
    from ml_model import ScamClassifier
    from rule_engine import RuleAnalyzer
    from threat_scoring import ThreatScorer
    from entity_detector import EntityExtractor
    from reputation_checker import ReputationLookup
    from language_utils import LanguageManager
    from url_scanner import scan_urls
    from scam_pattern_detector import analyze_patterns

    ml_classifier = ScamClassifier(
        model_path="scam_model.pkl",
        vectorizer_path="vectorizer.pkl"
    )

    rule_engine = RuleAnalyzer()
    threat_scorer = ThreatScorer()
    entity_detector = EntityExtractor()
    reputation_checker = ReputationLookup()
    language_manager = LanguageManager()

    logger.info("All modules loaded successfully")

except Exception as e:
    logger.error(f"Module load failure: {e}")
    ml_classifier = None


# ------------------------------------------------------------------
# Basic Routes
# ------------------------------------------------------------------
@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "service": "ScamAlert API",
        "status": "running"
    })


@app.route("/health", methods=["GET"])
def health():

    if ml_classifier is None:
        return jsonify({"status": "error"}), 500

    return jsonify({"status": "healthy"})


# ------------------------------------------------------------------
# Prediction Endpoint
# ------------------------------------------------------------------
@app.route("/predict", methods=["POST"])
def predict():

    try:

        if not request.is_json:
            return jsonify({"error": "Request must be JSON"}), 400

        data = request.get_json()
        message = data.get("message", "")

        if not message or not isinstance(message, str):
            return jsonify({"error": "Message required"}), 400

        text = message.strip()

        if ml_classifier is None:
            return jsonify({"error": "AI modules unavailable"}), 500

        # ----------------------------------------------------------
        # Language Processing
        # ----------------------------------------------------------
        try:
            lang_data = language_manager.process(text)
            language = lang_data.get("language", "unknown")
            processed_text = lang_data.get("translated_text", text)
        except Exception as e:
            logger.error(f"Language error: {e}")
            language = "unknown"
            processed_text = text

        # ----------------------------------------------------------
        # Entity Detection
        # ----------------------------------------------------------
        try:
            entities = entity_detector.extract(processed_text)
        except Exception as e:
            logger.error(f"Entity detection error: {e}")
            entities = {"phones": [], "emails": [], "upi": []}

        # ----------------------------------------------------------
        # URL Scan
        # ----------------------------------------------------------
        try:
            url_analysis = asyncio.run(scan_urls(processed_text))
        except Exception as e:
            logger.error(f"URL scan error: {e}")
            url_analysis = []

        # ----------------------------------------------------------
        # Pattern Detection
        # ----------------------------------------------------------
        try:
            patterns = analyze_patterns(processed_text)
        except Exception as e:
            logger.error(f"Pattern detection error: {e}")
            patterns = {}

        # ----------------------------------------------------------
        # Machine Learning Prediction
        # ----------------------------------------------------------
        try:
            ml_result = ml_classifier.predict(processed_text)
            ml_prob = ml_result.get("probability", 0)
        except Exception as e:
            logger.error(f"ML error: {e}")
            ml_prob = 0.0

        # ----------------------------------------------------------
        # Reputation Check
        # ----------------------------------------------------------
        try:
            reputation = reputation_checker.check(entities, url_analysis)
        except Exception as e:
            logger.error(f"Reputation error: {e}")
            reputation = {"score": 0, "reasons": []}

        # ----------------------------------------------------------
        # Rule Engine
        # ----------------------------------------------------------
        try:
            rule_flags = rule_engine.evaluate(
                processed_text,
                entities,
                patterns
            )
        except Exception as e:
            logger.error(f"Rule engine error: {e}")
            rule_flags = []

        # ----------------------------------------------------------
        # Threat Score
        # ----------------------------------------------------------
        try:

            result = threat_scorer.score_signals(
                ml_probability=ml_prob,
                url_data=url_analysis,
                pattern_data=patterns,
                rule_data=rule_flags,
                reputation_data=reputation
            )

            threat_score = result.get("threat_score", 0)
            category = result.get("category", "SAFE")
            reasons = result.get("explanations", [])

        except Exception as e:

            logger.error(f"Threat scoring error: {e}")

            threat_score = 0
            category = "UNKNOWN"
            reasons = ["Threat scoring failed"]

        # ----------------------------------------------------------
        # Final Response
        # ----------------------------------------------------------
        return jsonify({
            "category": category,
            "threat_score": threat_score,
            "explanations": reasons,
            "entities": entities,
            "urls": url_analysis,
            "language": language
        })

    except Exception as e:

        logger.error(f"Prediction error: {e}")

        return jsonify({
            "error": "Internal error",
            "category": "UNKNOWN",
            "threat_score": 0
        }), 500


# ------------------------------------------------------------------
# Server Start
# ------------------------------------------------------------------
if __name__ == "__main__":

    port = int(os.environ.get("PORT", 10000))

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )