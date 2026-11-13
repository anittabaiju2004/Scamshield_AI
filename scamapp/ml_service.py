# ml_service.py

import joblib

from functools import lru_cache
from pathlib import Path

from django.conf import settings


MODEL_PATH = Path(settings.BASE_DIR) / 'ml_models' / 'scamshield_model.joblib'


@lru_cache(maxsize=1)
def load_scam_model():

    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            f"ML model not found at: {MODEL_PATH}"
        )

    data = joblib.load(MODEL_PATH)

    vectorizer = data['vectorizer']
    model = data['model']
    labels = data['labels']

    return vectorizer, model, labels


def predict_message(message):

    vectorizer, model, labels = load_scam_model()

    # Convert text into TF-IDF features
    transformed_message = vectorizer.transform([message])

    # Predict class
    prediction = model.predict(transformed_message)[0]

    # Get prediction probabilities
    probabilities = model.predict_proba(transformed_message)[0]

    # Convert class number to readable label
    result = labels[int(prediction)]

    # Get confidence percentage
    confidence = float(max(probabilities)) * 100

    # Store probabilities for all categories
    probability_details = {
        labels[int(class_id)]: round(float(probability) * 100, 2)
        for class_id, probability in zip(model.classes_, probabilities)
    }

    return {
        'result': result,
        'confidence': round(confidence, 2),
        'probabilities': probability_details
    }