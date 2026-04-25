from flask import Flask, request, jsonify, g
import sqlite3
import pandas as pd
from sklearn.ensemble import IsolationForest
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

DATABASE = "db.db"

# ---------------- DATABASE ----------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    cursor = db.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS traffic (
        user TEXT,
        size INTEGER,
        proto INTEGER
    )
    """)

    db.commit()

# Initialize once
with app.app_context():
    init_db()

# ---------------- AUTH ----------------
@app.route("/register", methods=["POST"])
def register():
    data = request.json
    db = get_db()
    cursor = db.cursor()

    if not data or "username" not in data or "password" not in data:
        return {"error": "Invalid input"}, 400

    hashed_pw = generate_password_hash(data["password"])

    try:
        cursor.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (data["username"], hashed_pw)
        )
        db.commit()
        return {"message": "User registered"}
    except sqlite3.IntegrityError:
        return {"error": "Username already exists"}, 400


@app.route("/login", methods=["POST"])
def login():
    data = request.json
    db = get_db()
    cursor = db.cursor()

    cursor.execute(
        "SELECT password FROM users WHERE username=?",
        (data["username"],)
    )
    user = cursor.fetchone()

    if user and check_password_hash(user[0], data["password"]):
        return {"success": True}
    
    return {"success": False}


# ---------------- DATA INGEST ----------------
@app.route("/ingest", methods=["POST"])
def ingest():
    data = request.json
    db = get_db()
    cursor = db.cursor()

    if not data or "size" not in data or "proto" not in data:
        return {"error": "Invalid input"}, 400

    cursor.execute(
        "INSERT INTO traffic (user, size, proto) VALUES (?, ?, ?)",
        ("default", int(data["size"]), int(data["proto"]))
    )
    db.commit()

    return {"status": "ok"}


# ---------------- IDS + AI ----------------
model_cache = None

@app.route("/analyze", methods=["GET"])
def analyze():
    global model_cache
    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT size, proto FROM traffic")
    rows = cursor.fetchall()

    if len(rows) < 10:
        return {"data": [], "alerts": ["Not enough data yet"]}

    df = pd.DataFrame(rows, columns=["size", "proto"])

    # Train model only once (basic optimization)
    if model_cache is None:
        model_cache = IsolationForest(contamination=0.1, random_state=42)
        model_cache.fit(df)

    df["anomaly"] = model_cache.predict(df)

    alerts = []

    for _, row in df.iterrows():
        if row["size"] > 1400:
            alerts.append({
                "type": "rule",
                "message": "Possible DDoS / Flood Attack"
            })

        if row["anomaly"] == -1:
            alerts.append({
                "type": "ai",
                "message": "AI detected abnormal traffic"
            })

    return {
        "total_records": len(df),
        "anomalies": int((df["anomaly"] == -1).sum()),
        "alerts": alerts
    }


# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000, debug=True)
