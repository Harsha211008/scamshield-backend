from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle

app = Flask(__name__)
CORS(app)

# Load trained model
model = pickle.load(open("scam_model.pkl", "rb"))
vectorizer = pickle.load(open("vectorizer.pkl", "rb"))

@app.route('/predict', methods=['POST'])
def predict():

    data = request.get_json()
    message = data['message']

    prediction = model.predict([message])[0]

    # 👇 ADD THIS PART
    text = message.lower()

    scam_keywords = [
        "prize", "gift", "claim", "winner",
        "reward", "congratulations",
        "offer", "free", "click here"
    ]

    if prediction == 0:   # model said Safe
        for word in scam_keywords:
            if word in text:
                prediction = 3   # upgrade to Scam
                break
    # 👆 ADD THIS PART

    return jsonify({"category": int(prediction)})