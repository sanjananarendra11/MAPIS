import json
import os
import pickle
import shutil
from datetime import datetime, timezone

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler


COLUMNS = [
    "url_length",
    "has_ip",
    "has_at",
    "dot_count",
    "https",
    "has_hyphen",
    "subdomain_depth",
    "suspicious_words",
    "double_slash",
    "entropy",
    "brand_spoof",
]

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(BASE_DIR, "dataset.csv")
LEARNING_SAMPLES_PATH = os.path.join(BASE_DIR, "learning_samples.csv")
MODEL_PATH = os.path.join(BASE_DIR, "model.pkl")
SCALER_PATH = os.path.join(BASE_DIR, "scaler.pkl")
METADATA_PATH = os.path.join(BASE_DIR, "model_metadata.json")


def load_training_data():
    dataset = pd.read_csv(DATASET_PATH).fillna(0)

    if os.path.exists(LEARNING_SAMPLES_PATH):
        learned = pd.read_csv(LEARNING_SAMPLES_PATH).fillna(0)
        learned = learned[[*COLUMNS, "label"]]
        dataset = pd.concat([dataset, learned], ignore_index=True)

    return dataset


def split_dataset(dataset):
    features = dataset[COLUMNS]
    labels = dataset["label"]
    return train_test_split(
        features,
        labels,
        test_size=0.2,
        random_state=42,
        stratify=labels,
    )


def evaluate(model, scaler, features, labels):
    scaled_features = scaler.transform(features)
    predictions = model.predict(scaled_features)
    tn, fp, fn, tp = confusion_matrix(labels, predictions, labels=[0, 1]).ravel()

    return {
        "accuracy": round(float(accuracy_score(labels, predictions)) * 100, 4),
        "balancedAccuracy": round(float(balanced_accuracy_score(labels, predictions)) * 100, 4),
        "precision": round(float(precision_score(labels, predictions, zero_division=0)) * 100, 4),
        "recall": round(float(recall_score(labels, predictions, zero_division=0)) * 100, 4),
        "f1Score": round(float(f1_score(labels, predictions, zero_division=0)) * 100, 4),
        "confusionMatrix": {
            "trueNegative": int(tn),
            "falsePositive": int(fp),
            "falseNegative": int(fn),
            "truePositive": int(tp),
        },
    }


def train_candidate(train_features, train_labels):
    scaler = StandardScaler()
    scaled_train = scaler.fit_transform(train_features)
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        random_state=42,
        n_jobs=-1,
        class_weight=None,
    )
    model.fit(scaled_train, train_labels)
    return model, scaler


def load_current_model():
    if not os.path.exists(MODEL_PATH) or not os.path.exists(SCALER_PATH):
        return None, None

    with open(MODEL_PATH, "rb") as model_file:
        current_model = pickle.load(model_file)
    with open(SCALER_PATH, "rb") as scaler_file:
        current_scaler = pickle.load(scaler_file)

    return current_model, current_scaler


def write_metadata(metadata):
    with open(METADATA_PATH, "w", encoding="utf-8") as metadata_file:
        json.dump(metadata, metadata_file, indent=2)


def main():
    dataset = load_training_data()
    train_features, test_features, train_labels, test_labels = split_dataset(dataset)

    current_model, current_scaler = load_current_model()
    current_metrics = None

    if current_model is not None and current_scaler is not None:
        current_metrics = evaluate(current_model, current_scaler, test_features, test_labels)

    candidate_model, candidate_scaler = train_candidate(train_features, train_labels)
    candidate_metrics = evaluate(candidate_model, candidate_scaler, test_features, test_labels)

    previous_accuracy = current_metrics["accuracy"] if current_metrics else None
    candidate_accuracy = candidate_metrics["accuracy"]
    should_promote = previous_accuracy is None or candidate_accuracy >= previous_accuracy

    metadata = {
        "trainedAt": datetime.now(timezone.utc).isoformat(),
        "datasetSamples": int(len(dataset)),
        "learningSamples": int(max(len(dataset) - len(pd.read_csv(DATASET_PATH)), 0)),
        "policy": "Candidate model is promoted only when held-out accuracy is not lower than the current model.",
        "promoted": bool(should_promote),
        "previousMetrics": current_metrics,
        "candidateMetrics": candidate_metrics,
        "modelParams": {
            "algorithm": "RandomForestClassifier",
            "n_estimators": 200,
            "max_depth": 20,
            "class_weight": None,
        },
    }

    if should_promote:
        if os.path.exists(MODEL_PATH):
            shutil.copy2(MODEL_PATH, os.path.join(BASE_DIR, "model.previous.pkl"))
        if os.path.exists(SCALER_PATH):
            shutil.copy2(SCALER_PATH, os.path.join(BASE_DIR, "scaler.previous.pkl"))

        with open(MODEL_PATH, "wb") as model_file:
            pickle.dump(candidate_model, model_file)
        with open(SCALER_PATH, "wb") as scaler_file:
            pickle.dump(candidate_scaler, scaler_file)

        print("Promoted candidate model.")
    else:
        print("Kept current model because candidate accuracy was lower.")

    write_metadata(metadata)
    print(json.dumps(metadata, indent=2))


if __name__ == "__main__":
    main()
