import os, json, hmac, hashlib, requests
from dotenv import load_dotenv

load_dotenv()
SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "testsecret123").encode()

def sign(body_bytes: bytes) -> str:
    return "sha256=" + hmac.new(SECRET, body_bytes, hashlib.sha256).hexdigest()

def send_push():
    payload = {
        "repository": {"full_name": "demo/repo"},
        "ref": "refs/heads/main",
        "pusher": {"name": "you"},
        "compare": "https://example.com/compare",
        "commits": [
            {"id": "abcdef1234567890", "message": "test commit from local signer", "url": "https://example.com/c1"},
            {"id": "123456abcdef9876", "message": "another change", "url": "https://example.com/c2"},
        ],
    }
    body = json.dumps(payload).encode()
    headers = {
        "X-GitHub-Event": "push",
        "X-Hub-Signature-256": sign(body),
        "Content-Type": "application/json",
    }
    r = requests.post("http://127.0.0.1:8000/github/webhook", data=body, headers=headers, timeout=5)
    print("Push ->", r.status_code, r.text)

def send_pr_opened():
    payload = {
        "action": "opened",
        "repository": {"full_name": "demo/repo"},
        "pull_request": {
            "number": 42,
            "title": "Add cool feature",
            "user": {"login": "alice"},
            "head": {"ref": "feature/cool"},
            "base": {"ref": "main"},
            "html_url": "https://example.com/pr/42",
            "merged": False,
        },
    }
    body = json.dumps(payload).encode()
    headers = {
        "X-GitHub-Event": "pull_request",
        "X-Hub-Signature-256": sign(body),
        "Content-Type": "application/json",
    }
    r = requests.post("http://localhost:8000/github/webhook", data=body, headers=headers, timeout=5)
    print("PR opened ->", r.status_code, r.text)

if __name__ == "__main__":
    send_push()
    send_pr_opened()
