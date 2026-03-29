def analyze_identity(input_value):
    result = {}

    # -------------------
    # Type Detection
    # -------------------
    if "@" in input_value:
        result["type"] = "email"
        domain = input_value.split("@")[1]
    else:
        result["type"] = "username"
        domain = None

    # -------------------
    # Domain Analysis
    # -------------------
    if domain:
        if "gmail" in domain or "outlook" in domain:
            result["domain_status"] = "Trusted"
        elif "temp" in domain or "fake" in domain:
            result["domain_status"] = "Disposable"
        else:
            result["domain_status"] = "Suspicious"
    else:
        result["domain_status"] = "N/A"

    # -------------------
    # Pattern Analysis
    # -------------------
    if any(char.isdigit() for char in input_value):
        result["pattern"] = "Weak"
    else:
        result["pattern"] = "Strong"

    # -------------------
    # OSINT Simulation
    # -------------------
    username = input_value.split("@")[0]

    result["osint"] = {
        "github": "Likely Exists" if len(username) > 5 else "Unknown",
        "instagram": "Possible Match" if any(c.isdigit() for c in username) else "Unknown",
        "twitter": "Unknown"
    }

    # -------------------
    # Risk Score
    # -------------------
    risk = 0

    if result["domain_status"] == "Disposable":
        risk += 50

    if result["pattern"] == "Weak":
        risk += 30

    if len(input_value) < 6:
        risk += 20

    result["risk_score"] = min(risk, 100)

    # -------------------
    # Level
    # -------------------
    if risk >= 70:
        result["level"] = "HIGH"
    elif risk >= 40:
        result["level"] = "MEDIUM"
    else:
        result["level"] = "LOW"

    # -------------------
    # Recommendation
    # -------------------
    if result["level"] == "HIGH":
        result["recommendation"] = "🚨 High exposure! Change credentials immediately."
    elif result["level"] == "MEDIUM":
        result["recommendation"] = "⚠️ Moderate risk. Strengthen your identity."
    else:
        result["recommendation"] = "✅ Low risk. Identity looks safe."

    return result