import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import pickle

# Load dataset
data = pd.read_csv("dataset_v3.csv")

texts = data["text"]
labels = data["label"]

# Convert text to numbers
vectorizer = TfidfVectorizer()
X = vectorizer.fit_transform(texts)

# Train model
model = LogisticRegression(max_iter=1000)
model.fit(X, labels)

# Save model
pickle.dump(model, open("scam_model.pkl", "wb"))
pickle.dump(vectorizer, open("vectorizer.pkl", "wb"))

print("Multi-class Model V3 trained successfully!")