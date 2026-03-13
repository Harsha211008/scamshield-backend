import pickle

class ScamClassifier:

    def __init__(self, model_path, vectorizer_path):
        self.model = pickle.load(open(model_path, "rb"))
        self.vectorizer = pickle.load(open(vectorizer_path, "rb"))

    def predict(self, text):

        vec = self.vectorizer.transform([text])

        prob = self.model.predict_proba(vec)[0][1]

        return {
            "probability": float(prob)
        }