import pickle

class ScamClassifier:

    def __init__(self, model_path="scam_model.pkl", vectorizer_path="vectorizer.pkl"):

        with open(model_path, "rb") as f:
            self.model = pickle.load(f)

        with open(vectorizer_path, "rb") as f:
            self.vectorizer = pickle.load(f)

    def get_scam_probability(self, text):

        X = self.vectorizer.transform([text])
        prob = self.model.predict_proba(X)[0][1]

        return float(prob)