import pickle

def load_model():
    model = pickle.load(open("scam_model.pkl","rb"))
    vectorizer = pickle.load(open("vectorizer.pkl","rb"))
    return model,vectorizer

def predict_probability(message,model,vectorizer):

    vec = vectorizer.transform([message])

    try:
        prob=model.predict_proba(vec)[0][1]
    except:
        prob=0.5

    return prob