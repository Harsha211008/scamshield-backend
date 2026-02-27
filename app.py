from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle

app = Flask(__name__)
CORS(app)

# Load trained model
model = pickle.load(open("scam_model.pkl", "rb"))
vectorizer = pickle.load(open("vectorizer.pkl", "rb"))

@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()
    message = data.get("message")

    if not message:
        return jsonify({"error": "No message provided"}), 400

    message_vector = vectorizer.transform([message])
    probability = model.predict_proba(message_vector)[0][1]

    return jsonify({
        "scam_probability": float(probability)
    })

if __name__ == "__main__":
    app.run()