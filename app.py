import os, hmac, hashlib, requests
from flask import Flask, request, abort
from dotenv import load_dotenv


load_dotenv()

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")
# store secret as bytes for HMAC
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "").encode()
DEBUG = os.getenv("DEBUG") == "1"

app = Flask(__name__)

def verify_signature(req) -> bool:

    body = req.get_data()  # raw bytes exactly as received
    sig = req.headers.get("X-Hub-Signature-256") or req.headers.get("X-Hub-Signature")
    if not sig:
        if DEBUG: print("No signature header present")
        return False

    if sig.startswith("sha256="):
        digest = hmac.new(GITHUB_WEBHOOK_SECRET, body, hashlib.sha256).hexdigest()
        expected = f"sha256={digest}"
    elif sig.startswith("sha1="):
        digest = hmac.new(GITHUB_WEBHOOK_SECRET, body, hashlib.sha1).hexdigest()
        expected = f"sha1={digest}"
    else:
        if DEBUG: print("Unknown signature algorithm:", sig.split("=", 1)[0])
        return False

    if DEBUG:
        print("Header sig:", sig)
        print("Expect  sig:", expected)

    return hmac.compare_digest(sig, expected)

def post_slack(text, blocks=None):
    payload = {"text": text}
    if blocks:
        payload["blocks"] = blocks
    r = requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=10)
    r.raise_for_status()

@app.get("/")
def root():
    return "ok", 200

@app.get("/healthz")
def healthz():
    return "ok", 200

@app.post("/github/webhook")
def github_webhook():
    if not (SLACK_WEBHOOK_URL and GITHUB_WEBHOOK_SECRET):
        abort(500, "Missing environment variables")

    if DEBUG:
        print("---- headers ----")
        for k, v in request.headers.items():
            print(f"{k}: {v}")
        print("-----------------")

    # Read event + body early
    event = request.headers.get("X-GitHub-Event", "")
    body = request.get_json(silent=True) or {}
    if DEBUG: print("Event:", event)


    if event == "ping":
        if DEBUG: print("Ping zen:", body.get("zen"))
        return "pong", 200

    # For real events, require a valid signature
    if not verify_signature(request):
        abort(401, "Invalid signature")

    try:
        if event == "push":
            repo = body["repository"]["full_name"]
            branch = body["ref"].split("/")[-1]
            pusher = body["pusher"]["name"]
            compare = body.get("compare")
            commits = body.get("commits", [])[:5]
            lines = [
                f"• `{c['id'][:7]}` {c['message'].splitlines()[0]}  <{c['url']}|view>"
                for c in commits
            ]
            text = f"📦 Push to *{repo}* on *{branch}* by *{pusher}*"
            blocks = [
                {"type": "section", "text": {"type": "mrkdwn", "text": text}},
                {"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines)}},
            ]
            if compare:
                blocks.append({
                    "type": "actions",
                    "elements": [{
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Compare"},
                        "url": compare
                    }]
                })
            post_slack(text, blocks)

        elif event == "pull_request" and body.get("action") in {
            "opened", "reopened", "closed", "ready_for_review"
        }:
            pr = body["pull_request"]
            merged = pr.get("merged", False)
            emoji = "✅" if merged else "🔃"
            text = (
                f"{emoji} PR {body['action']} in *{body['repository']['full_name']}*: "
                f"*#{pr['number']}* {pr['title']}"
            )
            subtitle = f"_by_ *{pr['user']['login']}* • `{pr['head']['ref']}` → `{pr['base']['ref']}`"
            blocks = [
                {"type": "section", "text": {"type": "mrkdwn", "text": text}},
                {"type": "section", "text": {"type": "mrkdwn", "text": subtitle}},
                {"type": "actions", "elements": [{
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Open PR"},
                    "url": pr["html_url"]
                }]}
            ]
            post_slack(text, blocks)

        # ignore other events to reduce noise
    except Exception as e:
        # Notify errors to Slack (non-fatal)
        try:
            post_slack(f"⚠️ Error handling `{event}`: `{e}`")
        except Exception:
            pass

    return "", 204

if __name__ == "__main__":
    # Dev server; for prod use Gunicorn/Uvicorn behind HTTPS
    app.run("0.0.0.0", 8000)
