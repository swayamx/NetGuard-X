from flask import Flask, request, jsonify
import sqlite3
import pandas as pd
from sklearn.ensemble import IsolationForest

app = Flask(__name__)

# ---------------- DATABASE ----------------
conn = sqlite3.connect("db.db", check_same_thread=False)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
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

conn.commit()

# ---------------- AUTH ----------------
@app.route("/register", methods=["POST"])
def register():
    data = request.json
    cursor.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        (data["username"], data["password"])
    )
    conn.commit()
    return {"message": "User registered"}

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    cursor.execute(
        "SELECT * FROM users WHERE username=? AND password=?",
        (data["username"], data["password"])
    )
    user = cursor.fetchone()
    return {"success": bool(user)}

# ---------------- DATA INGEST ----------------
@app.route("/ingest", methods=["POST"])
def ingest():
    data = request.json

    cursor.execute(
        "INSERT INTO traffic (user, size, proto) VALUES (?, ?, ?)",
        ("default", data["size"], data["proto"])
    )
    conn.commit()

    return {"status": "ok"}

# ---------------- IDS + AI ----------------
@app.route("/analyze", methods=["GET"])
def analyze():
    cursor.execute("SELECT size, proto FROM traffic")
    rows = cursor.fetchall()

    if len(rows) < 10:
        return {"data": [], "alerts": []}

    df = pd.DataFrame(rows, columns=["size", "proto"])

    model = IsolationForest(contamination=0.1)
    model.fit(df)

    df["anomaly"] = model.predict(df)

    alerts = []

    for _, row in df.iterrows():
        # Rule-based detection
        if row["size"] > 1400:
            alerts.append("⚠️ Possible DDoS / Flood Attack")

        # AI anomaly detection
        if row["anomaly"] == -1:
            alerts.append("🚨 AI detected abnormal traffic")

    return {
        "data": df.values.tolist(),
        "alerts": alerts
    }

# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
