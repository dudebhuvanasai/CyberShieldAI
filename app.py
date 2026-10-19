
import os
import base64
import requests

from flask import Flask, render_template, request
from dotenv import load_dotenv

app = Flask(__name__)
load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")


def analyze_url(url):
    indicators = []

    if not url.startswith("https://"):
        indicators.append("Website does not use HTTPS.")

    suspicious_words = [
        "login", "verify", "free", "prize",
        "password", "gift", "urgent"
    ]

    if any(word in url.lower() for word in suspicious_words):
        indicators.append("URL contains suspicious keywords.")

    if "@" in url:
        indicators.append("URL contains an @ symbol.")

    if len(url) > 100:
        indicators.append("URL is unusually long.")

    risk = "LOW RISK"
    if len(indicators) >= 2:
        risk = "HIGH RISK"
    elif len(indicators) == 1:
        risk = "MEDIUM RISK"

    return {
        "url": url,
        "indicators": indicators,
        "risk": risk,
        "note": (
            "This is a basic URL heuristic result. "
            "It does not guarantee that the website is safe."
        )
    }


def check_virustotal(url):
    if not VT_API_KEY:
        return {
            "status": "API key not configured",
            "stats": None
        }

    try:
        url_id = base64.urlsafe_b64encode(
            url.encode()
        ).decode().strip("=")

        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        response = requests.get(
            endpoint,
            headers={"x-apikey": VT_API_KEY},
            timeout=15
        )

        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get(
                "attributes", {}
            ).get("last_analysis_stats", {})

            return {
                "status": "Existing report found",
                "stats": stats
            }

        if response.status_code == 404:
            return {
                "status": "No existing report found",
                "stats": None
            }

        if response.status_code == 401:
            return {
                "status": "API key invalid or unauthorized",
                "stats": None
            }

        if response.status_code == 429:
            return {
                "status": "API rate limit reached",
                "stats": None
            }

        return {
            "status": f"Report unavailable (HTTP {response.status_code})",
            "stats": None
        }

    except requests.RequestException:
        return {
            "status": "Unable to connect to VirusTotal",
            "stats": None
        }


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    url = request.form.get("url", "").strip()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    result = analyze_url(url)
    result["vt"] = check_virustotal(url)

    if result["vt"]["stats"]:
        stats = result["vt"]["stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        if malicious > 0:
            result["risk"] = "HIGH RISK"
        elif suspicious > 0 and result["risk"] == "LOW RISK":
            result["risk"] = "MEDIUM RISK"

    result["note"] = (
        "This result combines basic URL checks with an existing "
        "VirusTotal report when available. It cannot guarantee safety."
    )

    return render_template("results.html", result=result)


if __name__ == "__main__":
    app.run(debug=True)
