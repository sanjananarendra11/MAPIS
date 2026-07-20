from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle
import json
import pandas as pd
from feature_extractor import extract_features
import os
import hashlib
import hmac
import secrets
import re
import threading
from copy import deepcopy
from collections import deque
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse, urlunparse
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split

app = Flask(__name__)
CORS(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
print("RUNNING FILE FROM:", os.path.abspath(__file__))
print("BASE_DIR:", BASE_DIR)

# =========================================
# LOAD MODEL + SCALER
# =========================================

model = pickle.load(open(os.path.join(BASE_DIR, "model.pkl"), "rb"))
scaler = pickle.load(open(os.path.join(BASE_DIR, "scaler.pkl"), "rb"))

columns = [
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
    "brand_spoof"
]

print("DEBUG → Column count:", len(columns))

ADMIN_EMAIL = os.getenv("MAPIS_ADMIN_EMAIL", "admin@mapis.local")
ADMIN_PASSWORD = os.getenv("MAPIS_ADMIN_PASSWORD", "Admin@123")
DATA_FILE = os.getenv("MAPIS_DATA_FILE", os.path.join(BASE_DIR, "mapis_data.json"))
MAX_SCAN_HISTORY = 1000
MAX_ALERTS = 500
MAX_BLACKLIST = 500
PUBLIC_GUEST_ID = "guest-public"
DATA_LOCK = threading.Lock()
AUTH_TOKENS = {}
MODEL_METRICS_CACHE = None
TRUSTED_DOMAINS = {
    "google.com",
    "github.com",
    "microsoft.com",
    "amazon.com",
    "paypal.com",
    "apple.com",
    "facebook.com",
    "instagram.com",
    "linkedin.com",
    "openai.com",
    "figma.com",
    "nptel.ac.in",
    "swayam.gov.in",
    "swayam2.ac.in",
    "coursera.org",
    "udemy.com",
    "youtube.com",
    "wikipedia.org"
}
TRUSTED_SUFFIXES = (
    ".edu",
    ".edu.in",
    ".ac.in",
    ".gov",
    ".gov.in"
)
TRUSTED_LOCAL_HOSTS = {
    "localhost",
    "127.0.0.1",
    "::1"
}
TRUSTED_SCHEMES = {
    "about",
    "brave",
    "chrome",
    "chrome-extension",
    "edge"
}
TRUSTED_SAFE_RISK_SCORE = 5
TRUSTED_REASON = "Verified trusted domain"
TRUSTED_EXPLANATION = (
    "The URL belongs to a trusted domain or local browser page, "
    "so URL complexity alone is not treated as phishing."
)


def now_utc():
    return datetime.now(timezone.utc).isoformat()


def empty_data():
    return {
        "users": [],
        "sessions": {},
        "scanHistory": [],
        "alerts": [],
        "blacklist": [],
        "urlResultCache": {}
    }


def load_data():
    data = empty_data()

    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, "r", encoding="utf-8") as data_file:
                stored = json.load(data_file)
            if isinstance(stored, dict):
                data.update({
                    key: stored.get(key, data[key])
                    for key in data
                })
        except (OSError, json.JSONDecodeError) as error:
            print("DATA LOAD ERROR:", error)

    for key in ["users", "scanHistory", "alerts", "blacklist"]:
        if not isinstance(data.get(key), list):
            data[key] = []

    for key in ["sessions", "urlResultCache"]:
        if not isinstance(data.get(key), dict):
            data[key] = {}

    return data


def ensure_system_users(data):
    admin = next(
        (
            user for user in data["users"]
            if user.get("id") == "admin" or user.get("role") == "admin"
        ),
        None
    )

    if not admin:
        data["users"].append({
            "id": "admin",
            "name": "Administrator",
            "email": ADMIN_EMAIL,
            "role": "admin",
            "isGuest": False,
            "createdAt": now_utc()
        })
    else:
        admin.update({
            "id": "admin",
            "name": admin.get("name") or "Administrator",
            "email": ADMIN_EMAIL,
            "role": "admin",
            "isGuest": False
        })

    public_guest = next(
        (user for user in data["users"] if user.get("id") == PUBLIC_GUEST_ID),
        None
    )

    if not public_guest:
        data["users"].append({
            "id": PUBLIC_GUEST_ID,
            "name": "Guest Browser",
            "email": "",
            "role": "guest",
            "isGuest": True,
            "createdAt": now_utc()
        })


DATA = load_data()
ensure_system_users(DATA)
SCAN_HISTORY = deque(DATA["scanHistory"], maxlen=MAX_SCAN_HISTORY)
ALERTS = deque(DATA["alerts"], maxlen=MAX_ALERTS)
BLACKLIST = deque(DATA["blacklist"], maxlen=MAX_BLACKLIST)
URL_RESULT_CACHE = DATA["urlResultCache"]


def public_user(user):
    if not user:
        return None

    return {
        "id": user.get("id"),
        "name": user.get("name", "User"),
        "email": user.get("email", ""),
        "role": user.get("role", "user"),
        "isGuest": bool(user.get("isGuest", False))
    }


def find_user_by_id(user_id):
    return next(
        (user for user in DATA["users"] if user.get("id") == user_id),
        None
    )


def find_user_by_email(email):
    normalized = (email or "").strip().lower()
    return next(
        (
            user for user in DATA["users"]
            if user.get("email", "").strip().lower() == normalized
        ),
        None
    )


def claim_public_guest_scans(user):
    if (
        not user
        or user.get("role") == "admin"
        or user.get("isGuest")
    ):
        return

    registered_users = [
        existing_user for existing_user in DATA["users"]
        if existing_user.get("role") == "user" and not existing_user.get("isGuest")
    ]

    if len(registered_users) != 1 or registered_users[0].get("id") != user.get("id"):
        return

    claimed_any = False

    for scan in SCAN_HISTORY:
        owner_id = scan.get("user_id") or scan.get("ownerUserId", PUBLIC_GUEST_ID)
        if owner_id != PUBLIC_GUEST_ID:
            continue

        scan["user_id"] = user.get("id")
        scan["ownerUserId"] = user.get("id")
        scan["ownerUserName"] = user.get("name")
        claimed_any = True

    for alert in ALERTS:
        owner_id = alert.get("user_id") or alert.get("ownerUserId", PUBLIC_GUEST_ID)
        if owner_id != PUBLIC_GUEST_ID:
            continue

        alert["user_id"] = user.get("id")
        alert["ownerUserId"] = user.get("id")
        alert["ownerUserName"] = user.get("name")
        claimed_any = True

    if claimed_any:
        persist_state()


def sync_auth_tokens():
    AUTH_TOKENS.clear()

    for token, session in DATA["sessions"].items():
        user = find_user_by_id(session.get("userId"))
        if user:
            AUTH_TOKENS[token] = public_user(user)


def persist_state():
    DATA["scanHistory"] = list(SCAN_HISTORY)
    DATA["alerts"] = list(ALERTS)
    DATA["blacklist"] = list(BLACKLIST)
    DATA["urlResultCache"] = URL_RESULT_CACHE

    with DATA_LOCK:
        temp_file = f"{DATA_FILE}.tmp"
        with open(temp_file, "w", encoding="utf-8") as data_file:
            json.dump(DATA, data_file, indent=2)
        os.replace(temp_file, DATA_FILE)


def claim_public_guest_scans_for_single_user():
    registered_users = [
        existing_user for existing_user in DATA["users"]
        if existing_user.get("role") == "user" and not existing_user.get("isGuest")
    ]

    if len(registered_users) == 1:
        claim_public_guest_scans(public_user(registered_users[0]))


def hash_password(password, salt=None):
    password_salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        password_salt.encode("utf-8"),
        120000
    ).hex()
    return password_salt, digest


def password_matches(user, password):
    salt = user.get("passwordSalt")
    expected = user.get("passwordHash")

    if not salt or not expected:
        return False

    _, actual = hash_password(password, salt)
    return hmac.compare_digest(actual, expected)


def create_session(user):
    token = secrets.token_urlsafe(32)
    DATA["sessions"][token] = {
        "userId": user["id"],
        "createdAt": now_utc()
    }
    sync_auth_tokens()
    persist_state()
    return token


def get_authenticated_user():
    authorization = request.headers.get("Authorization", "")

    if not authorization.startswith("Bearer "):
        return None

    token = authorization.removeprefix("Bearer ").strip()
    session = DATA["sessions"].get(token)

    if not session:
        return None

    user = public_user(find_user_by_id(session.get("userId")))
    claim_public_guest_scans(user)
    return user


def get_scan_user():
    return get_authenticated_user() or public_user(find_user_by_id(PUBLIC_GUEST_ID))


def is_admin(user):
    return bool(user and user.get("role") == "admin")


claim_public_guest_scans_for_single_user()
sync_auth_tokens()
persist_state()


def normalize_domain(url):
    parsed = urlparse(url if "://" in url else f"https://{url}")
    domain = parsed.netloc or parsed.path
    return domain.replace("www.", "").split("/")[0]


def canonicalize_url(url):
    raw_url = (url or "").strip()

    if not raw_url:
        return ""

    parsed = urlparse(raw_url if "://" in raw_url else f"https://{raw_url}")
    scheme = (parsed.scheme or "https").lower()
    netloc = parsed.netloc.lower()
    path = parsed.path or ""

    if path == "/":
        path = ""

    return urlunparse((
        scheme,
        netloc,
        path.rstrip("/") if path != "/" else "",
        "",
        parsed.query,
        ""
    ))


def result_from_score(prediction, risk_score):
    if risk_score >= 70:
        return "Dangerous"
    if prediction == "Phishing" or risk_score >= 40:
        return "Suspicious"
    return "Safe"


def canonical_result(result, risk_score=0):
    if result in ["Dangerous", "Phishing"]:
        return "Dangerous"
    if result == "Suspicious":
        return "Suspicious"
    return "Safe"


def scan_date(scan):
    timestamp = scan.get("timestamp") or scan.get("scannedAt")

    try:
        return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return None


def scan_reason(payload):
    explanations = payload.get("layer3", {}).get("explanations", []) or []
    return (
        payload.get("layer3", {}).get("threat_type")
        or (explanations[0] if explanations else "")
        or "No strong phishing indicators detected"
    )


def ai_explanation(payload):
    explanations = payload.get("layer3", {}).get("explanations", []) or []

    if explanations:
        return ". ".join(explanations)

    if payload.get("prediction") == "Safe":
        return "No strong phishing indicators were found by the MAPIS detection layers."

    return "MAPIS detected suspicious URL, model, or page behavior signals."


def severity_from_score(risk_score):
    if risk_score >= 80:
        return "High"
    if risk_score >= 40:
        return "Medium"
    return "Low"


def record_scan(payload, user=None):
    owner = user or get_scan_user()
    risk_score = payload.get("risk_score", 0)
    result = result_from_score(
        payload.get("prediction", "Safe"),
        risk_score
    )
    scanned_at = now_utc()
    domain = normalize_domain(payload.get("url", "unknown"))
    scan_id = f"SCN-{secrets.token_hex(6)}"
    reason = scan_reason(payload)
    explanation = ai_explanation(payload)

    scan = {
        "id": scan_id,
        "type": "URL",
        "input": domain,
        "url": payload.get("url"),
        "result": result,
        "riskScore": risk_score,
        "risk_score": risk_score,
        "time": "just now",
        "scannedAt": scanned_at,
        "timestamp": scanned_at,
        "user_id": owner.get("id"),
        "ownerUserId": owner.get("id"),
        "ownerUserName": owner.get("name"),
        "reason": reason,
        "aiExplanation": explanation,
        "threatType": payload.get("layer3", {}).get("threat_type"),
        "explanations": payload.get("layer3", {}).get("explanations", [])
    }

    SCAN_HISTORY.appendleft(scan)

    if result in ["Dangerous", "Suspicious"]:
        ALERTS.appendleft({
            "id": f"ALT-{secrets.token_hex(6)}",
            "message": (
                "Malicious URL Detected"
                if result == "Dangerous"
                else "Suspicious URL Detected"
            ),
            "detail": payload.get("url"),
            "severity": severity_from_score(risk_score),
            "createdAt": scanned_at,
            "time": "just now",
            "status": "new",
            "riskScore": risk_score,
            "risk_score": risk_score,
            "ownerUserId": owner.get("id"),
            "ownerUserName": owner.get("name"),
            "reason": reason
        })

    persist_state()
    return scan


def user_owns_item(user, item):
    if not user:
        return False

    return (item.get("user_id") or item.get("ownerUserId", PUBLIC_GUEST_ID)) == user.get("id")


def sanitize_alert_for_admin(alert):
    return {
        key: value for key, value in dict(alert).items()
        if key not in ["ownerUserId", "ownerUserName", "user_id"]
    }


def sanitize_scan(scan):
    risk_score = int(scan.get("riskScore", scan.get("risk_score", 0)) or 0)
    result = canonical_result(scan.get("result"), risk_score)
    scanned_at = scan.get("timestamp") or scan.get("scannedAt") or now_utc()

    return {
        "id": scan.get("id"),
        "type": scan.get("type", "URL"),
        "input": scan.get("input") or normalize_domain(scan.get("url", "")),
        "url": scan.get("url"),
        "result": result,
        "riskScore": risk_score,
        "risk_score": risk_score,
        "reason": scan.get("reason") or scan.get("threatType") or "No strong phishing indicators detected",
        "aiExplanation": scan.get("aiExplanation") or ". ".join(scan.get("explanations", []) or []),
        "time": scan.get("time", "just now"),
        "scannedAt": scanned_at,
        "timestamp": scanned_at,
        "threatType": scan.get("threatType"),
        "explanations": scan.get("explanations", [])
    }


def url_scans(scans):
    return [
        scan for scan in scans
        if scan.get("type", "URL") == "URL"
    ]


def scan_result_counts(scans):
    counts = {
        "safe": 0,
        "suspicious": 0,
        "dangerous": 0
    }

    for scan in scans:
        risk_score = int(scan.get("riskScore", scan.get("risk_score", 0)) or 0)
        result = canonical_result(scan.get("result"), risk_score)
        key = result.lower()
        counts[key] = counts.get(key, 0) + 1

    return counts


def scans_on_date(scans, target_date):
    return [
        scan for scan in scans
        if (scan_date(scan) and scan_date(scan).date() == target_date)
    ]


def scans_since(scans, start_date):
    return [
        scan for scan in scans
        if (scan_date(scan) and scan_date(scan).date() >= start_date)
    ]


def daily_scan_counts(scans):
    today = datetime.now(timezone.utc).date()
    dates = [today - timedelta(days=offset) for offset in range(6, -1, -1)]

    return [
        {
            "day": date.strftime("%a"),
            "date": date.isoformat(),
            "scans": len(scans_on_date(scans, date)),
            "threats": len([
                scan for scan in scans_on_date(scans, date)
                if canonical_result(scan.get("result"), scan.get("riskScore", 0)) != "Safe"
            ])
        }
        for date in dates
    ]


def monthly_scan_counts(scans):
    today = datetime.now(timezone.utc).date().replace(day=1)
    months = []

    for offset in range(5, -1, -1):
        year = today.year
        month = today.month - offset
        while month <= 0:
            month += 12
            year -= 1
        months.append(datetime(year, month, 1, tzinfo=timezone.utc).date())

    rows = []
    for month_start in months:
        if month_start.month == 12:
            next_month = datetime(month_start.year + 1, 1, 1, tzinfo=timezone.utc).date()
        else:
            next_month = datetime(month_start.year, month_start.month + 1, 1, tzinfo=timezone.utc).date()

        rows.append({
            "month": month_start.strftime("%b"),
            "date": month_start.isoformat(),
            "scans": len([
                scan for scan in scans
                if scan_date(scan)
                and month_start <= scan_date(scan).date() < next_month
            ])
        })

    return rows


def detection_trends(scans):
    today = datetime.now(timezone.utc).date()
    dates = [today - timedelta(days=offset) for offset in range(6, -1, -1)]
    rows = []

    for date in dates:
        counts = scan_result_counts(scans_on_date(scans, date))
        rows.append({
            "day": date.strftime("%a"),
            "date": date.isoformat(),
            **counts
        })

    return rows


def top_phishing_domains(scans):
    counts = {}

    for scan in scans:
        result = canonical_result(scan.get("result"), scan.get("riskScore", 0))
        if result == "Safe":
            continue
        domain = normalize_domain(scan.get("url") or scan.get("input") or "")
        counts[domain] = counts.get(domain, 0) + 1

    return [
        {"name": domain, "value": count}
        for domain, count in sorted(counts.items(), key=lambda item: item[1], reverse=True)[:7]
        if domain
    ]


def user_url_counts():
    counts = {}

    for scan in SCAN_HISTORY:
        owner_id = scan.get("user_id") or scan.get("ownerUserId", PUBLIC_GUEST_ID)
        owner_name = scan.get("ownerUserName") or "Guest Browser"
        summary = counts.setdefault(
            owner_id,
            {
                "name": owner_name,
                "urlsScanned": 0,
                "totalScans": 0,
                "lastScannedAt": None
            }
        )

        user = find_user_by_id(owner_id)
        if user:
            summary.update({
                "name": user.get("name", summary["name"])
            })

        summary["totalScans"] += 1

        if scan.get("type") == "URL":
            summary["urlsScanned"] += 1

        scanned_at = scan.get("scannedAt")
        if scanned_at and (
            not summary["lastScannedAt"]
            or scanned_at > summary["lastScannedAt"]
        ):
            summary["lastScannedAt"] = scanned_at

    for user in DATA["users"]:
        if user.get("role") == "admin" or user.get("id") == PUBLIC_GUEST_ID:
            continue

        counts.setdefault(
            user.get("id"),
            {
                "name": user.get("name", "User"),
                "urlsScanned": 0,
                "totalScans": 0,
                "lastScannedAt": None
            }
        )

    sorted_counts = sorted(
        counts.values(),
        key=lambda item: (
            item["urlsScanned"],
            item["totalScans"],
            item["lastScannedAt"] or ""
        ),
        reverse=True
    )

    return [
        {
            "name": item["name"],
            "urlsScanned": item["urlsScanned"]
        }
        for item in sorted_counts
    ]


def dashboard_payload(user=None):
    viewer = user
    admin_view = is_admin(viewer)
    all_history = list(SCAN_HISTORY)
    all_alerts = list(ALERTS)
    user_history = [
        item for item in all_history
        if user_owns_item(viewer, item)
    ] if viewer and not admin_view else []
    global_url_history = url_scans(all_history)
    history = global_url_history if admin_view else user_history
    alerts = (
        [sanitize_alert_for_admin(alert) for alert in all_alerts]
        if admin_view
        else [
            alert for alert in all_alerts
            if user_owns_item(viewer, alert)
        ]
    ) if viewer else []
    visible_history = [sanitize_scan(item) for item in history[:50 if admin_view else 12]]
    result_counts = scan_result_counts(url_scans(history) if admin_view else history)
    dangerous = result_counts["dangerous"]
    suspicious = result_counts["suspicious"]
    safe = result_counts["safe"]
    emails = len([
        item for item in history
        if item["type"] == "Email"
    ])
    urls = len([
        item for item in history
        if item["type"] == "URL"
    ])

    today = datetime.now(timezone.utc).date()
    week_start = today - timedelta(days=6)
    todays_scans = len(scans_on_date(url_scans(history), today))
    weekly_scans = len(scans_since(url_scans(history), week_start))

    email_threats = len([
        item for item in history
        if item["type"] == "Email"
        and canonical_result(item.get("result"), item.get("riskScore", 0)) != "Safe"
    ])
    total_users = len([
        user for user in DATA["users"]
        if user.get("role") != "admin" and user.get("id") != PUBLIC_GUEST_ID
    ])
    daily_scans = daily_scan_counts(url_scans(history))

    return {
        "stats": {
            "totalUsers": total_users if admin_view else 0,
            "totalUrlsScanned": urls,
            "safeUrls": safe,
            "suspiciousUrls": suspicious,
            "dangerousUrls": dangerous,
            "todaysScans": todays_scans,
            "weeklyScans": weekly_scans,
            "totalThreats": dangerous + suspicious,
            "emailsScanned": emails,
            "urlsAnalyzed": urls,
            "suspiciousCases": suspicious,
            "safeResults": safe,
            "totalScans": len(history),
            "activeSessions": len(AUTH_TOKENS)
        },
        "threatsOverTime": daily_scans,
        "dailyScans": daily_scans,
        "monthlyScans": monthly_scan_counts(url_scans(history)),
        "detectionTrends": detection_trends(url_scans(history)),
        "topPhishingDomains": top_phishing_domains(url_scans(history)),
        "distribution": {
            "dangerous": dangerous,
            "phishing": dangerous,
            "suspicious": suspicious,
            "safe": safe
        },
        "attackTypes": [
            {"name": "Email", "value": email_threats},
            {"name": "Dangerous URL", "value": dangerous},
            {"name": "Suspicious URL", "value": suspicious}
        ],
        "alerts": alerts[:8],
        "history": visible_history,
        "blacklist": list(BLACKLIST) if admin_view else [],
        "userUrlCounts": user_url_counts() if admin_view else []
    }


def model_metrics_payload():
    global MODEL_METRICS_CACHE

    if MODEL_METRICS_CACHE is not None:
        return MODEL_METRICS_CACHE

    dataset_path = os.path.join(BASE_DIR, "dataset.csv")
    dataset = pd.read_csv(dataset_path).fillna(0)
    features = dataset[columns]
    labels = dataset["label"]
    scaled_features = scaler.transform(features)

    _, test_features, _, test_labels = train_test_split(
        scaled_features,
        labels,
        test_size=0.2,
        random_state=42,
        stratify=labels
    )

    predictions = model.predict(test_features)
    tn, fp, fn, tp = confusion_matrix(
        test_labels,
        predictions,
        labels=[0, 1]
    ).ravel()

    importances = sorted(
        [
            {
                "feature": feature,
                "importance": round(float(importance) * 100, 4)
            }
            for feature, importance in zip(columns, model.feature_importances_)
        ],
        key=lambda item: item["importance"],
        reverse=True
    )

    metadata_path = os.path.join(BASE_DIR, "model_metadata.json")
    training_metadata = {}

    if os.path.exists(metadata_path):
        with open(metadata_path, "r", encoding="utf-8") as metadata_file:
            training_metadata = json.load(metadata_file)

    MODEL_METRICS_CACHE = {
        "accuracy": round(float(accuracy_score(test_labels, predictions)) * 100, 4),
        "balancedAccuracy": round(float(balanced_accuracy_score(test_labels, predictions)) * 100, 4),
        "precision": round(float(precision_score(test_labels, predictions, zero_division=0)) * 100, 4),
        "recall": round(float(recall_score(test_labels, predictions, zero_division=0)) * 100, 4),
        "f1Score": round(float(f1_score(test_labels, predictions, zero_division=0)) * 100, 4),
        "datasetSamples": int(len(dataset)),
        "evaluatedSamples": int(len(test_labels)),
        "confusionMatrix": {
            "trueNegative": int(tn),
            "falsePositive": int(fp),
            "falseNegative": int(fn),
            "truePositive": int(tp)
        },
        "featureImportances": importances,
        "model": {
            "algorithm": type(model).__name__,
            "estimators": int(model.n_estimators),
            "maxDepth": model.max_depth,
            "trainedFileUpdatedAt": datetime.fromtimestamp(
                os.path.getmtime(os.path.join(BASE_DIR, "model.pkl")),
                tz=timezone.utc
            ).isoformat()
        },
        "training": training_metadata
    }

    return MODEL_METRICS_CACHE

# =========================================
# ROOT ROUTE
# =========================================

@app.route("/")
def home():
    return "PhishGuard API is running!"

# =========================================
# PREDICT ROUTE
# =========================================

@app.route("/predict", methods=["POST"])
def predict():

    try:

        data = request.json or {}

        url = canonicalize_url(data.get("url", ""))
        content_data = data.get("content_data", {})
        has_content_data = bool(content_data)

        if not url:
            return jsonify({
                "error": "No URL provided"
            }), 400

        cache_key = canonicalize_url(url)

        if not has_content_data and cache_key in URL_RESULT_CACHE:
            cached_payload = deepcopy(URL_RESULT_CACHE[cache_key])
            cached_payload["fromCache"] = True
            cached_payload["scan"] = record_scan(cached_payload)
            return jsonify(cached_payload)

        # =========================================
        # FEATURE EXTRACTION
        # =========================================

        features = extract_features(url)

        if len(features) != len(columns):

            return jsonify({
                "error": f"Feature mismatch: expected {len(columns)}, got {len(features)}"
            }), 500

        features_df = pd.DataFrame(
            [features],
            columns=columns
        )

        features_scaled = scaler.transform(features_df)

        # =========================================
        # MACHINE LEARNING PREDICTION
        # =========================================

        prediction = model.predict(features_scaled)[0]
        prob = model.predict_proba(features_scaled)[0][1]

        # =========================================
        # CONTENT ANALYSIS
        # =========================================

        has_password = content_data.get(
            "hasPasswordField",
            False
        )

        form_count = content_data.get(
            "formCount",
            0
        )

        content_words = content_data.get(
            "suspiciousWords",
            0
        )

        external_form = content_data.get(
            "hasExternalFormAction",
            False
        )

        redirect_script = content_data.get(
            "hasRedirectScript",
            False
        )

        detected_brands = content_data.get(
            "detectedBrands",
            []
        )

        # =========================================
        # TRUSTED DOMAINS
        # =========================================

        trusted_domains = [

            # Major companies
            "google.com",
            "github.com",
            "microsoft.com",
            "amazon.com",
            "paypal.com",
            "apple.com",
            "facebook.com",
            "instagram.com",
            "linkedin.com",
            "openai.com",

            # Educational
            ".edu",
            ".edu.in",
            ".ac.in",

            # Government
            ".gov",
            ".gov.in",

            # Educational platforms
            "nptel.ac.in",
            "swayam.gov.in",
            "swayam2.ac.in",
            "coursera.org",
            "udemy.com",

            # Popular trusted
            "youtube.com",
            "wikipedia.org"
        ]

        # =========================================
        # TRUST VERIFICATION
        # =========================================

        is_trusted = False

        trusted_keywords = [
            ".edu",
            ".edu.in",
            ".ac.in",
            ".gov",
            ".gov.in"
        ]

        # Educational/Gov trust
        for keyword in trusted_keywords:

            if keyword in url.lower():

                is_trusted = True

        # Exact trusted domains
        for domain in trusted_domains:

            if domain in url.lower():

                is_trusted = True

        # =========================================
        # HYBRID RISK ENGINE
        # =========================================

        phishing_score = 0

        # =====================================
        # URL FEATURES
        # =====================================

        # Raw IP address
        if features[1] == 1:
            phishing_score += 45

        # Suspicious keywords
        if features[7] > 0:
            phishing_score += 35

        # Brand spoofing
        if features[10] == 1:
            phishing_score += 60

        # No HTTPS
        if features[4] == 0:
            phishing_score += 25

        # Deep subdomains
        if features[6] > 1:
            phishing_score += 15

        # Very long URL
        if features[0] > 60:
            phishing_score += 20

        # High entropy
        if features[9] > 4:
            phishing_score += 20

        # Too many dots
        if features[3] > 5:
            phishing_score += 10

        # @ symbol
        if features[2] == 1:
            phishing_score += 25

        # Double slash attack
        if features[8] == 1:
            phishing_score += 20

        # =====================================
        # SUSPICIOUS TLD DETECTION
        # =====================================

        suspicious_tlds = [
            ".xyz",
            ".top",
            ".tk",
            ".buzz",
            ".monster",
            ".click",
            ".shop",
            ".site"
        ]

        for tld in suspicious_tlds:

            if tld in url.lower():

                phishing_score += 30

        # =====================================
        # SCAM KEYWORDS
        # =====================================

        scam_words = [
            "free",
            "offer",
            "discount",
            "cheap",
            "deal",
            "sale",
            "buy-now",
            "gift",
            "cashback",
            "win"
        ]

        for word in scam_words:

            if word in url.lower():

                phishing_score += 10

        # =====================================
        # CONTENT FEATURES
        # =====================================

        if external_form:
            phishing_score += 40

        if has_password and features[10] == 1:
            phishing_score += 40

        if redirect_script and not is_trusted:
            phishing_score += 10

        if content_words >= 3:
            phishing_score += 15

        if form_count >= 3:
            phishing_score += 10

        if len(detected_brands) > 0 and not is_trusted:
            phishing_score += 15

        # =====================================
        # HIGH RISK BRAND IMPERSONATION
        # =====================================

        high_risk_brands = [
            "icloud",
            "paypal",
            "bank",
            "google",
            "microsoft",
            "amazon",
            "facebook",
            "apple"
        ]

        for brand in high_risk_brands:

            if brand in url.lower():

                if f"{brand}.com" not in url.lower():

                    phishing_score += 60

        # =========================================
        # TRUSTED WEBSITE BOOST
        # =========================================

        if is_trusted:

            phishing_score -= 120

            phishing_score = max(
                phishing_score,
                0
            )

        # Prevent false positives
        if is_trusted and features[10] == 0:

            phishing_score = min(
                phishing_score,
                10
            )

        # =========================================
        # FINAL SCORE
        # =========================================

        risk_score = min(
            phishing_score,
            100
        )

        # =========================================
        # FINAL PREDICTION
        # =========================================

        if phishing_score >= 40:
            final_pred = "Phishing"
        else:
            final_pred = "Safe"

        # =========================================
        # CONFIDENCE SCORE
        # =========================================

        if final_pred == "Phishing":

            confidence = min(
                max(
                    85,
                    risk_score
                ),
                100
            )

        else:

            confidence = min(
                max(
                    90,
                    100 - risk_score
                ),
                99
            )

        # =========================================
        # THREAT TYPE + SEVERITY
        # =========================================

        threat_type = "Safe Browsing"
        severity = "Low"
        explanations = []

        # =====================================
        # EXPLANATIONS
        # =====================================

        if features[10] == 1:
            explanations.append(
                "Brand spoofing detected"
            )

        if features[4] == 0:
            explanations.append(
                "Website does not use HTTPS"
            )

        if features[1] == 1:
            explanations.append(
                "Website uses raw IP address"
            )

        if features[7] > 0:
            explanations.append(
                "Suspicious phishing keywords found"
            )

        if features[6] > 1:
            explanations.append(
                "Deep subdomain structure detected"
            )

        if features[9] > 4:
            explanations.append(
                "Highly random URL structure detected"
            )

        if features[2] == 1:
            explanations.append(
                "@ symbol manipulation detected"
            )

        if has_password:
            explanations.append(
                "Password input field detected"
            )

        if external_form:
            explanations.append(
                "External form submission detected"
            )

        if redirect_script and not is_trusted:
            explanations.append(
                "Suspicious redirect script detected"
            )

        if content_words >= 3:
            explanations.append(
                "Suspicious webpage content detected"
            )

        if form_count >= 3:
            explanations.append(
                "Multiple forms detected on webpage"
            )

        if len(detected_brands) > 0:
            explanations.append(
                f"Detected brands: {', '.join(detected_brands)}"
            )

        # =====================================
        # THREAT TYPE
        # =====================================

        if has_password and features[10] == 1:

            threat_type = "Credential Harvesting"

        elif (
            final_pred == "Phishing"
            and features[7] > 0
            and content_words >= 3
        ):

            threat_type = "Account Verification Scam"

        elif redirect_script and external_form:

            threat_type = "Malware / Redirect Attack"

        elif (
            "paypal" in str(detected_brands).lower()
            or "bank" in str(detected_brands).lower()
        ):

            threat_type = "Financial Phishing"

        elif final_pred == "Phishing":

            threat_type = "Suspicious Phishing Attempt"

        # =====================================
        # SEVERITY
        # =====================================

        if risk_score >= 80:
            severity = "Critical"

        elif risk_score >= 60:
            severity = "High"

        elif risk_score >= 40:
            severity = "Medium"

        else:
            severity = "Low"

        # =====================================
        # SAFE CASE
        # =====================================

        if len(explanations) == 0:

            explanations.append(
                "No strong phishing indicators detected"
            )

        # =========================================
        # LAYER 1 DISPLAY
        # =========================================

        layer1 = {
            "URL Length": features[0],
            "Uses IP Address": "Yes" if features[1] else "No",
            "@ Symbol": "Yes" if features[2] else "No",
            "Dot Count": features[3],
            "HTTPS": "Yes" if features[4] else "No",
            "Hyphens": features[5],
            "Subdomain Depth": features[6],
            "Suspicious Keywords": features[7],
            "Double Slash": features[8],
            "Entropy": round(features[9], 2),
            "Brand Spoof": "Yes" if features[10] else "No"
        }

        # =========================================
        # CONTRIBUTIONS
        # =========================================


        contributions = [

            {
                "name": "Brand Spoofing",
                "impact": "+60" if features[10] == 1 else "+0"
            },

            {
                "name": "HTTPS Security",
                "impact": "+25" if features[4] == 0 else "+0"
            },

            {
                "name": "Suspicious Keywords",
                "impact": "+35" if features[7] > 0 else "+0"
            },

            {
                "name": "Subdomain Depth",
                "impact": "+15" if features[6] > 1 else "+0"
            },

            {
                "name": "URL Entropy",
                "impact": "+20" if features[9] > 4 else "+0"
            },

            {
                "name": "External Forms",
                "impact": "+40" if external_form else "+0"
            }
        ]

        if features[10] == 1:
            contributions.append({
                "name": "Brand Spoofing Detected",
                "impact": "+60"
            })

        if features[7] > 0:
            contributions.append({
                "name": "Suspicious URL Keywords",
                "impact": "+35"
            })

        if features[1] == 1:
            contributions.append({
                "name": "Uses IP Address",
                "impact": "+45"
            })

        if features[4] == 0:
            contributions.append({
                "name": "No HTTPS",
                "impact": "+25"
            })

        if external_form:
            contributions.append({
                "name": "External Form Submission",
                "impact": "+40"
            })

        if has_password and features[10] == 1:
            contributions.append({
                "name": "Password Field on Suspicious Domain",
                "impact": "+40"
            })

        if redirect_script and not is_trusted:
            contributions.append({
                "name": "Redirect Script Found",
                "impact": "+10"
            })

        if content_words >= 3:
            contributions.append({
                "name": "Suspicious Page Content",
                "impact": "+15"
            })

        if form_count >= 3:
            contributions.append({
                "name": "Multiple Forms Detected",
                "impact": "+10"
            })

        if len(detected_brands) > 0 and not is_trusted:
            contributions.append({
                "name": "Known Brand Names Found",
                "impact": "+15"
            })

        if features[6] > 1:
            contributions.append({
                "name": "Deep Subdomain Structure",
                "impact": "+15"
            })

        # =========================================
        # FINAL RESPONSE
        # =========================================

        response_payload = {

            "url": url,

            "prediction": result_from_score(final_pred, risk_score),

            "risk_score": risk_score,

            "layer1": layer1,

            "layer2": {
                "confidence": confidence,
                "contributions": contributions
            },

            "layer3": {
                "threat_type": threat_type,
                "severity": severity,
                "explanations": explanations
            }
        }

        URL_RESULT_CACHE[cache_key] = deepcopy(response_payload)
        response_payload["scan"] = record_scan(response_payload)

        return jsonify(response_payload)

    except Exception as e:

        print("ERROR:", e)

        return jsonify({
            "error": str(e)
        }), 500


@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.json or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({
            "error": "Email and password are required"
        }), 400

    valid_admin_email = hmac.compare_digest(email, ADMIN_EMAIL.lower())
    valid_admin_password = hmac.compare_digest(password, ADMIN_PASSWORD)

    if valid_admin_email and valid_admin_password:
        user = find_user_by_id("admin")
        token = create_session(user)

        return jsonify({
            "token": token,
            "user": public_user(user)
        })

    user = find_user_by_email(email)

    if not user or user.get("role") == "admin" or not password_matches(user, password):
        return jsonify({
            "error": "Invalid email or password"
        }), 401

    token = create_session(user)

    return jsonify({
        "token": token,
        "user": public_user(user)
    })


@app.route("/api/auth/signup", methods=["POST"])
def signup():
    data = request.json or {}
    name = data.get("name", "").strip() or "MAPIS User"
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return jsonify({
            "error": "A valid email is required"
        }), 400

    if email == ADMIN_EMAIL.lower():
        return jsonify({
            "error": "This email is reserved for the administrator"
        }), 400

    if len(password) < 6:
        return jsonify({
            "error": "Password must be at least 6 characters"
        }), 400

    if find_user_by_email(email):
        return jsonify({
            "error": "An account already exists for this email"
        }), 409

    salt, password_hash = hash_password(password)
    user = {
        "id": f"usr-{secrets.token_hex(8)}",
        "name": name,
        "email": email,
        "role": "user",
        "isGuest": False,
        "passwordSalt": salt,
        "passwordHash": password_hash,
        "createdAt": now_utc()
    }
    DATA["users"].append(user)
    token = create_session(user)

    return jsonify({
        "token": token,
        "user": public_user(user)
    }), 201


@app.route("/api/auth/guest", methods=["POST"])
def guest_session():
    data = request.json or {}
    name = data.get("name", "").strip() or f"Guest {secrets.token_hex(3)}"
    user = {
        "id": f"guest-{secrets.token_hex(8)}",
        "name": name,
        "email": "",
        "role": "guest",
        "isGuest": True,
        "createdAt": now_utc()
    }
    DATA["users"].append(user)
    token = create_session(user)

    return jsonify({
        "token": token,
        "user": public_user(user)
    }), 201


@app.route("/api/auth/logout", methods=["POST"])
def logout():
    authorization = request.headers.get("Authorization", "")

    if authorization.startswith("Bearer "):
        token = authorization.removeprefix("Bearer ").strip()
        DATA["sessions"].pop(token, None)
        sync_auth_tokens()
        persist_state()

    return jsonify({
        "signedOut": True
    })


@app.route("/api/auth/profile", methods=["GET"])
def auth_profile():
    user = get_authenticated_user()

    if not user:
        return jsonify({
            "error": "Authentication required"
        }), 401

    return jsonify({
        "user": user
    })


@app.route("/api/dashboard", methods=["GET"])
def dashboard():
    return jsonify(dashboard_payload(get_authenticated_user()))


@app.route("/api/scan/url", methods=["POST"])
def scan_url():
    return predict()


@app.route("/api/scan/email", methods=["POST"])
def scan_email():
    data = request.json or {}
    owner = get_scan_user()
    sender = data.get("sender", "").strip()
    subject = data.get("subject", "").strip()
    body = data.get("body", "").strip()
    headers = data.get("headers", "").strip()

    if not sender:
        return jsonify({
            "error": "Sender address is required"
        }), 400

    sender_match = re.fullmatch(r"[^@\s]+@([^@\s]+)", sender)
    sender_domain = sender_match.group(1).lower() if sender_match else ""
    combined_text = f"{subject}\n{body}".lower()
    header_text = headers.lower()

    suspicious_terms = [
        "verify", "urgent", "password", "login", "account", "suspended",
        "payment", "bank", "gift", "prize", "wallet", "click here",
        "confirm identity", "limited time", "security alert"
    ]
    urgency_terms = [
        "urgent", "immediately", "within 24 hours", "final warning",
        "act now", "limited time", "suspended"
    ]
    found_terms = sorted({
        term for term in suspicious_terms
        if term in combined_text
    })
    found_urgency = sorted({
        term for term in urgency_terms
        if term in combined_text
    })
    links = re.findall(r"(?:https?://|www\.)[^\s<>\"']+", body, flags=re.IGNORECASE)

    def authentication_result(name):
        pass_pattern = rf"(?:{name}=pass|{name}:\s*pass|{name}\s+pass)"
        fail_pattern = rf"(?:{name}=fail|{name}:\s*fail|{name}\s+fail)"

        if re.search(pass_pattern, header_text):
            return "Pass"
        if re.search(fail_pattern, header_text):
            return "Fail"
        return "Not provided"

    spf = authentication_result("spf")
    dkim = authentication_result("dkim")
    dmarc = authentication_result("dmarc")

    trusted_domains = {
        "google.com", "microsoft.com", "apple.com", "github.com",
        "openai.com", "amazon.com", "paypal.com"
    }
    suspicious_tlds = (".xyz", ".top", ".tk", ".click", ".buzz", ".monster")
    domain_terms = ["secure", "verify", "login", "account", "support", "bank"]
    domain_risk = (
        not sender_domain
        or sender_domain.endswith(suspicious_tlds)
        or sender_domain.count("-") >= 2
        or sum(term in sender_domain for term in domain_terms) >= 2
    )

    risk_score = 0
    contributions = []
    explanations = []

    def add_risk(name, impact, explanation):
        nonlocal risk_score
        risk_score += impact
        contributions.append({
            "name": name,
            "impact": f"+{impact}"
        })
        explanations.append(explanation)

    if not sender_match:
        add_risk("Invalid Sender Format", 25, "Sender address format is invalid")
    elif domain_risk:
        add_risk("Sender Domain Pattern", 25, "Sender domain contains suspicious reputation signals")

    content_impact = min(len(found_terms) * 4, 28)
    if content_impact:
        add_risk(
            "Suspicious Content Terms",
            content_impact,
            f"Suspicious content terms found: {', '.join(found_terms)}"
        )

    urgency_impact = min(len(found_urgency) * 5, 15)
    if urgency_impact:
        add_risk(
            "Urgency Language",
            urgency_impact,
            f"Urgency language found: {', '.join(found_urgency)}"
        )

    link_impact = min(len(links) * 5, 15)
    if link_impact:
        add_risk(
            "Embedded Links",
            link_impact,
            f"Email contains {len(links)} external link(s)"
        )

    for auth_name, auth_value in [("SPF", spf), ("DKIM", dkim), ("DMARC", dmarc)]:
        if auth_value == "Fail":
            add_risk(
                f"{auth_name} Authentication",
                15,
                f"{auth_name} authentication failed"
            )

    if sender_domain in trusted_domains and all(
        value != "Fail" for value in [spf, dkim, dmarc]
    ):
        risk_score = max(risk_score - 20, 0)

    risk_score = min(risk_score, 100)

    if risk_score >= 70:
        raw_result = "Phishing"
    elif risk_score >= 35:
        raw_result = "Suspicious"
    else:
        raw_result = "Safe"
    result = result_from_score(raw_result, risk_score)

    if not explanations:
        explanations.append("No phishing indicators were found in the supplied email data")

    if result == "Dangerous" and found_terms:
        threat_type = "Content-based Phishing"
    elif result != "Safe" and domain_risk:
        threat_type = "Sender Impersonation"
    elif result != "Safe":
        threat_type = "Suspicious Email"
    else:
        threat_type = "No Email Threat Detected"

    confidence = min(max(abs(risk_score - 50) + 50, 50), 100)
    scanned_at = now_utc()
    scan = {
        "id": f"SCN-{secrets.token_hex(6)}",
        "type": "Email",
        "input": sender,
        "result": result,
        "riskScore": risk_score,
        "risk_score": risk_score,
        "time": "just now",
        "scannedAt": scanned_at,
        "timestamp": scanned_at,
        "user_id": owner.get("id"),
        "ownerUserId": owner.get("id"),
        "ownerUserName": owner.get("name"),
        "reason": threat_type,
        "aiExplanation": ". ".join(explanations),
        "subject": subject,
        "threatType": threat_type,
        "explanations": explanations
    }
    SCAN_HISTORY.appendleft(scan)

    if result != "Safe":
        ALERTS.appendleft({
            "id": f"ALT-{secrets.token_hex(6)}",
            "message": "Phishing Email Blocked",
            "detail": f"From: {sender}",
            "severity": severity_from_score(risk_score),
            "createdAt": scanned_at,
            "time": "just now",
            "status": "new",
            "riskScore": risk_score,
            "ownerUserId": owner.get("id"),
            "ownerUserName": owner.get("name")
        })

    persist_state()

    return jsonify({
        "url": sender,
        "prediction": result,
        "risk_score": risk_score,
        "layer1": {
            "Sender Address": sender,
            "Sender Domain": sender_domain or "Invalid",
            "SPF": spf,
            "DKIM": dkim,
            "DMARC": dmarc,
            "External Links": len(links),
            "Suspicious Terms": ", ".join(found_terms) if found_terms else "None"
        },
        "layer2": {
            "confidence": confidence,
            "contributions": contributions
        },
        "layer3": {
            "threat_type": threat_type,
            "severity": severity_from_score(risk_score),
            "explanations": explanations
        },
        "emailAnalysis": {
            "senderDomain": sender_domain,
            "spf": spf,
            "dkim": dkim,
            "dmarc": dmarc,
            "links": links,
            "suspiciousTerms": found_terms,
            "urgencyTerms": found_urgency
        },
        "scan": scan
    })


@app.route("/api/scan/history", methods=["GET"])
def scan_history():
    user = get_authenticated_user()
    history = list(SCAN_HISTORY)

    if is_admin(user):
        return jsonify({
            "history": [
                sanitize_scan(item)
                for item in url_scans(history)
            ][:100]
        })

    return jsonify({
        "history": [
            sanitize_scan(item) for item in history
            if user_owns_item(user, item)
        ][:50]
    })


@app.route("/api/scan/latest", methods=["GET"])
def latest_scan():
    url = canonicalize_url(request.args.get("url", ""))

    if not url:
        return jsonify({
            "error": "URL is required"
        }), 400

    cached = URL_RESULT_CACHE.get(url)

    if not cached:
        return jsonify({
            "result": None
        }), 404

    return jsonify({
        "result": cached
    })


@app.route("/api/alerts", methods=["GET", "POST"])
def alerts():
    if request.method == "POST":
        user = get_authenticated_user()

        if not is_admin(user):
            return jsonify({
                "error": "Administrator authentication required"
            }), 401

        data = request.json or {}
        alert = {
            "id": f"ALT-{secrets.token_hex(6)}",
            "message": data.get("message", "Manual threat alert"),
            "detail": data.get("detail", "Created from admin panel"),
            "severity": data.get("severity", "Medium"),
            "createdAt": now_utc(),
            "time": "just now",
            "status": data.get("status", "new"),
            "ownerUserId": user.get("id"),
            "ownerUserName": user.get("name")
        }
        ALERTS.appendleft(alert)
        persist_state()
        return jsonify(alert), 201

    user = get_authenticated_user()
    user_alerts = (
        [sanitize_alert_for_admin(alert) for alert in list(ALERTS)]
        if is_admin(user)
        else [
            alert for alert in list(ALERTS)
            if user_owns_item(user, alert)
        ]
    )

    return jsonify({
        "alerts": user_alerts[:50]
    })


@app.route("/api/model/metrics", methods=["GET"])
def model_metrics():
    return jsonify(model_metrics_payload())


@app.route("/api/blacklist", methods=["GET"])
def blacklist():
    return jsonify({
        "blacklist": list(BLACKLIST)
    })


@app.route("/api/blacklist/add", methods=["POST"])
def add_blacklist():
    user = get_authenticated_user()

    if not is_admin(user):
        return jsonify({
            "error": "Administrator authentication required"
        }), 401

    data = request.json or {}
    domain = normalize_domain(data.get("domain", ""))

    if not domain:
        return jsonify({
            "error": "Domain is required"
        }), 400

    item = {
        "id": f"BL-{secrets.token_hex(6)}",
        "domain": domain,
        "reason": data.get("reason", "Manual blacklist entry"),
        "addedBy": data.get("addedBy", "admin"),
        "createdAt": now_utc()
    }
    BLACKLIST.appendleft(item)
    persist_state()

    return jsonify(item), 201


@app.route("/api/blacklist/<blacklist_id>", methods=["DELETE"])
def delete_blacklist(blacklist_id):
    user = get_authenticated_user()

    if not is_admin(user):
        return jsonify({
            "error": "Administrator authentication required"
        }), 401

    remaining = [
        item for item in BLACKLIST
        if item["id"] != blacklist_id and item["domain"] != blacklist_id
    ]
    BLACKLIST.clear()
    BLACKLIST.extend(remaining)
    persist_state()

    return jsonify({
        "deleted": blacklist_id,
        "blacklist": list(BLACKLIST)
    })

# =========================================
# RUN APP
# =========================================

if __name__ == "__main__":
    app.run(debug=True, port=int(os.getenv("PORT", "5001")))
