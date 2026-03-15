import os
import logging
import asyncio
from flask import Flask, request, jsonify

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("ScamAlert-API")

app = Flask(__name__)

# =============================================================================
# Module Imports & Instantiations
# =============================================================================
try:
    from language_utils import LanguageManager
    from entity_detector import EntityExtractor
    from url_scanner import scan_urls
    from scam_pattern_detector import analyze_patterns
    from ml_model import ScamClassifier
    from reputation_checker import ReputationLookup
    from rule_engine import RuleAnalyzer
    from threat_scoring import ThreatScorer

    # Initialize Claude's Classes
    language_manager = LanguageManager()
    entity_extractor = EntityExtractor()
    reputation_lookup = ReputationLookup()
    rule_analyzer = RuleAnalyzer()
    threat_scorer = ThreatScorer()
    
    # IMPORTANT: The model requires the paths to your pickle files
    ml_classifier = ScamClassifier(model_path="scam_model.pkl", vectorizer_path="vectorizer.pkl")

    logger.info("All modules loaded successfully.")

except ImportError as e:
    logger.critical(f"Module Import Failure: {e}")
    ml_classifier = None
    threat_scorer = None

# =============================================================================
# Async Wrapper for Gunicorn
# =============================================================================
def run_async_scanner(text):
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(scan_urls(text))
        loop.close()
        return result if isinstance(result, list) else []
    except Exception as e:
        logger.error(f"Async URL Scanner failed: {e}")
        return []

# =============================================================================
# API Routes
# =============================================================================
@app.route('/health', methods=['GET'])
def health():
    if not threat_scorer:
        return jsonify({"status": "degraded"}), 500
    return jsonify({"status": "healthy"}), 200

@app.route('/predict', methods=['POST'])
def predict():
    try:
        if not request.is_json:
            return jsonify({"error": "Expected JSON payload"}), 400
            
        data = request.get_json()
        text = data.get('message', '').strip()
        
        if not text:
            return jsonify({"error": "Valid 'message' string required"}), 400

        if threat_scorer is None:
            return jsonify({"error": "Backend modules offline"}), 500

        # =====================================================================
        # Execution Pipeline
        # =====================================================================
        
        # 1. Language Detection
        try:
            lang_data = language_manager.process(text)
            detected_lang = lang_data.get("language", "unknown")
            processed_text = lang_data.get("translated_text", text)
        except Exception as e:
            logger.error(f"Language detection failed: {e}")
            detected_lang, processed_text = "unknown", text

        # 2. Entity Extraction
        try:
            entities = entity_extractor.extract(processed_text)
        except Exception as e:
            logger.error(f"Entity extraction failed: {e}")
            entities = {}

        # 3. URL Scanning (Async)
        url_analysis = run_async_scanner(processed_text)

        # 4. Scam Patterns
        try:
            patterns = analyze_patterns(processed_text)
        except Exception as e:
            logger.error(f"Pattern detection failed: {e}")
            patterns = {}

        # 5. ML Classifier
        try:
            ml_results = ml_classifier.predict(processed_text)
            ml_prob = ml_results.get("probability", 0.0)
        except Exception as e:
            logger.error(f"ML Classifier failed: {e}")
            ml_prob = 0.0

        # 6. Reputation Checker
        try:
            reputation = reputation_lookup.check(entities, url_analysis)
        except Exception as e:
            logger.error(f"Reputation lookup failed: {e}")
            reputation = {}

        # 7. Rule Engine
        try:
            rules = rule_analyzer.evaluate(processed_text, entities, patterns)
        except Exception as e:
            logger.error(f"Rule engine failed: {e}")
            rules = []

        # 8. Threat Scoring
        try:
            scoring_result = threat_scorer.calculate(
                ml_prob=ml_prob,
                urls=url_analysis,
                patterns=patterns,
                reputation=reputation,
                rules=rules
            )
        except Exception as e:
            logger.error(f"Threat scoring crashed: {e}")
            scoring_result = {"threat_score": 0, "category": "UNKNOWN", "reasons": ["Scoring error"]}

        return jsonify({
            "category": scoring_result.get("category", "UNKNOWN"),
            "threat_score": scoring_result.get("threat_score", 0),
            "explanations": scoring_result.get("reasons", []),
            "entities": entities,
            "urls": url_analysis,
            "language": detected_lang
        }), 200

    except Exception as e:
        logger.exception("CRITICAL: Unhandled exception in /predict")
        return jsonify({"category": "UNKNOWN", "threat_score": 0, "explanations": ["Internal server error"]}), 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port, debug=False)