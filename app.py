from flask import Flask, request, jsonify@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()

        if not data or "message" not in data:
            return jsonify({"category": 0})

        message = str(data["message"]).strip()

        if message == "":
            return jsonify({"category": 0})

        # Limit extremely long text
        message = message[:500]

        # Use vectorizer properly
        vectorized = vectorizer.transform([message])
        prediction = model.predict(vectorized)[0]

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

        return jsonify({"category": int(prediction)})

    except:
        return jsonify({"category": 0})
