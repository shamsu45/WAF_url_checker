from flask import Flask, request, render_template, jsonify
import re
import os
import datetime

app = Flask(_name_)

LOG_FILE = "waf_log.txt"
blocked_urls = []

# Check if URL is suspicious (simple pattern matching for demo)
def is_suspicious(url):
    patterns = [ r"\\.exe", r"\\.zip", r"unlock[-_.]code", r"login[-_.]form", r"secure[-_.]login", r"bank[-_.]account", r"credit[-_.]card", r"password[-_.]reset", r"verify[-_.]account", r"update[-_.]info", r"click[-_.]here", r"urgent[-_.]action", r"confirm[-_.]details", r"account[-_.]verification", r"security[-_.]alert", r"alert[-_.]notification", r"claim[-_.]reward", r"win[-_.]prize", r"limited[-_.]offer", r"exclusive[-_.]deal", r"urgent[-_.]message", r"invoice[-_.]payment", r"tax[-_.]refund", r"shipping[-_.]confirmation", r"order[-_.]status", r"subscription[-_.]renewal", r"account[-_.]suspension", r"service[-_.]interruption", r"technical[-_.]support", r"customer[-_.]service", r"feedback[-_.]survey", r"product[-_.]review", r"recovery[-_.]link", r"reset[-_.]password", r"account[-_.]recovery", r"security[-_.]question", r"identity[-_.]verification", r"login[-_.]attempt", r"unauthorized[-_.]access", r"data[-_.]breach", r"phishing[-_.]attempt", r"scam[-_.]alert", r"pass", r"authentication", r"support", r"paypal", r"webmail", r"banking", r"login", r"redirect",  r"account", r"secure", r"verify", r"update", r"confirm", r"alert", r"notification", r"reward", r"prize", r"offer", r"deal", r"free[-_.]gift", r"malware", r"phishing", r"@", r"bit.ly", r"login[-_.]stealer",  r"message", r"inbox", r"inbox[-_.]message", r"setup", r"hack"]
    for pattern in patterns:
        if re.search(pattern, url, re.IGNORECASE):
            return True
    return False

def log_url(url, result):
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.datetime.now()} - {url} - {result}\n")

@app.route("/", methods=["GET", "POST"])
def index():
    result = ""
    if request.method == "POST":
        url = request.form.get("url")
        if is_suspicious(url):
            result = "❌❗ Malicious URL Detected!"
            blocked_urls.append(url)
            log_url(url, "Blocked")
        else:
            result = "✅ Safe URL"
            log_url(url, "Safe")
    return render_template("index.html", result=result)

@app.route("/admin/blocked_ips")
def view_blocked():
    return jsonify(blocked_urls)

@app.route("/admin/reset_logs")
def reset_logs():
    open(LOG_FILE, "w").close()
    blocked_urls.clear()
    return "✅ Logs and blocked URLs have been reset."

if _name_ == "_main_":
    app.run(debug=True)
