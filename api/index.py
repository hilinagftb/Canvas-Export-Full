"""
Canvas Course Exporter - Vercel edition.

The server does three things only:
  1. Passcode lock (with durable rate limiting when Upstash Redis is configured).
  2. Keeps the Canvas address + token in an encrypted, HttpOnly cookie.
  3. Relays read-only Canvas API calls (plus "start a content export") from the
     browser to Canvas, one short request at a time, so it fits serverless limits.

All the export work (queueing, polling, building CSVs, saving files) runs in the
browser. See README.md for deployment.

Local run:  python api/index.py   ->  http://127.0.0.1:5050
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from datetime import timedelta
from urllib.parse import parse_qs, urlencode, urlparse

import requests
from cryptography.fernet import Fernet, InvalidToken
from flask import Flask, Response, jsonify, render_template, request, session

app = Flask(__name__, template_folder=os.path.join(os.path.dirname(__file__), "templates"))


class VercelPath:
    """Vercel sends every address to this one function. vercel.json passes the
    address the visitor actually opened as ?__path=..., and this puts it back
    so Flask can route normally."""
    def __init__(self, wsgi):
        self.wsgi = wsgi

    def __call__(self, environ, start_response):
        qs = parse_qs(environ.get("QUERY_STRING", ""), keep_blank_values=True)
        if "__path" in qs:
            environ["PATH_INFO"] = "/" + qs.pop("__path")[0].lstrip("/")
            environ["QUERY_STRING"] = urlencode(qs, doseq=True)
        elif environ.get("PATH_INFO", "").rstrip("/") in ("/api/index", "/api/index.py"):
            environ["PATH_INFO"] = "/"
        return self.wsgi(environ, start_response)


app.wsgi_app = VercelPath(app.wsgi_app)

ON_VERCEL = bool(os.environ.get("VERCEL"))
SECRET = os.environ.get("SECRET_KEY") or ""
if not SECRET and not ON_VERCEL:
    SECRET = secrets.token_hex(32)  # fine for local use; sessions reset on restart
PASSCODE = os.environ.get("APP_PASSCODE", "347890")
SECURE_COOKIES = ON_VERCEL or os.environ.get("HTTPS") == "1"

app.secret_key = SECRET or "not-configured"
app.config.update(
    SESSION_COOKIE_NAME="cx_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=SECURE_COOKIES,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)
FERNET = Fernet(base64.urlsafe_b64encode(hashlib.sha256(f"canvas-creds:{SECRET}".encode()).digest()))
CREDS_COOKIE = "cx_canvas"
CREDS_MAX_AGE = 8 * 3600

MAX_TRIES = 5            # wrong tries per address before lock
LOCK_SECONDS = 15 * 60
GLOBAL_MAX = 100         # wrong tries from everyone, per hour, before all logins pause
PROXY_FILE_LIMIT = 4_000_000  # Vercel response bodies are capped at ~4.5 MB

# ---------------------------------------------------------------------------
# Rate limiting: Upstash Redis (durable across serverless instances) or memory
# ---------------------------------------------------------------------------
REDIS_URL = (os.environ.get("UPSTASH_REDIS_REST_URL") or os.environ.get("KV_REST_API_URL") or "").rstrip("/")
REDIS_TOKEN = os.environ.get("UPSTASH_REDIS_REST_TOKEN") or os.environ.get("KV_REST_API_TOKEN") or ""
_mem = {}
_mem_lock = threading.Lock()


def _redis(*cmds):
    r = requests.post(f"{REDIS_URL}/pipeline", json=[list(map(str, c)) for c in cmds],
                      headers={"Authorization": f"Bearer {REDIS_TOKEN}"}, timeout=5)
    r.raise_for_status()
    return [x.get("result") for x in r.json()]


def counter_get(key):
    if REDIS_URL:
        try:
            return int(_redis(["GET", key])[0] or 0)
        except Exception:
            return 0
    with _mem_lock:
        v, exp = _mem.get(key, (0, 0))
        return v if exp > time.time() else 0


def counter_incr(key, ttl):
    if REDIS_URL:
        try:
            n = int(_redis(["INCR", key])[0])
            if n == 1:
                _redis(["EXPIRE", key, ttl])
            return n
        except Exception:
            pass
    with _mem_lock:
        v, exp = _mem.get(key, (0, 0))
        if exp <= time.time():
            v, exp = 0, time.time() + ttl
        _mem[key] = (v + 1, exp)
        return v + 1


def counter_clear(key):
    if REDIS_URL:
        try:
            _redis(["DEL", key])
        except Exception:
            pass
    with _mem_lock:
        _mem.pop(key, None)


def client_ip():
    fwd = request.headers.get("X-Forwarded-For", "")
    return fwd.split(",")[0].strip() if fwd else (request.remote_addr or "?")


# ---------------------------------------------------------------------------
# Gatekeeping
# ---------------------------------------------------------------------------
@app.before_request
def gate():
    if not SECRET:
        return Response("Set the SECRET_KEY environment variable in Vercel, then redeploy.", 500,
                        mimetype="text/plain")
    if request.endpoint in ("index", "unlock"):
        return None
    if not session.get("unlocked"):
        if request.method == "GET" and not request.path.startswith("/api/"):
            return render_template("unlock.html")
        return jsonify(error="Locked. Enter the passcode first."), 401
    # CSRF guard: browsers won't send this custom header cross-site without CORS approval.
    if request.method != "GET" and request.headers.get("X-Requested-With") != "fetch":
        return jsonify(error="Bad request"), 400
    return None


@app.after_request
def headers(r):
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["Referrer-Policy"] = "no-referrer"
    r.headers["Cache-Control"] = "no-store"
    r.headers["X-Robots-Tag"] = "noindex, nofollow"
    if SECURE_COOKIES:
        r.headers["Strict-Transport-Security"] = "max-age=31536000"
    return r


@app.get("/")
def index():
    return render_template("index.html" if session.get("unlocked") else "unlock.html")


@app.post("/unlock")
def unlock():
    ip = client_ip()
    if counter_get(f"cx:fail:{ip}") >= MAX_TRIES:
        return jsonify(error=f"Too many wrong tries. Try again in {LOCK_SECONDS // 60} minutes."), 429
    if counter_get("cx:fail:all") >= GLOBAL_MAX:
        return jsonify(error="Too many wrong tries on this site. Try again in an hour."), 429
    code = str((request.get_json(silent=True) or {}).get("code", "")).strip()
    if hmac.compare_digest(code.encode(), PASSCODE.encode()):
        counter_clear(f"cx:fail:{ip}")
        session.clear()
        session.permanent = True
        session["unlocked"] = True
        return jsonify(ok=True)
    time.sleep(1)
    n = counter_incr(f"cx:fail:{ip}", LOCK_SECONDS)
    counter_incr("cx:fail:all", 3600)
    left = MAX_TRIES - n
    return jsonify(error=f"Wrong passcode. {left} tries left." if left > 0
                   else f"Wrong passcode. Locked for {LOCK_SECONDS // 60} minutes."), 401


@app.post("/api/lock")
def lock():
    session.clear()
    r = jsonify(ok=True)
    r.delete_cookie(CREDS_COOKIE)
    return r


# ---------------------------------------------------------------------------
# Canvas credentials (encrypted cookie)
# ---------------------------------------------------------------------------
def get_creds():
    raw = request.cookies.get(CREDS_COOKIE)
    if not raw:
        return None
    try:
        return json.loads(FERNET.decrypt(raw.encode(), ttl=CREDS_MAX_AGE))
    except (InvalidToken, ValueError):
        return None


def canvas_call(creds, method, url, params=None, data=None):
    headers = {"Authorization": f"Bearer {creds['token']}"}
    last = None
    for attempt in range(3):
        try:
            r = requests.request(method, url, headers=headers, params=params, data=data, timeout=25)
        except requests.RequestException as e:
            last = e
            time.sleep(1 + attempt)
            continue
        throttled = r.status_code == 429 or (r.status_code == 403 and "rate limit" in r.text.lower())
        if (throttled or r.status_code >= 500) and attempt < 2:
            time.sleep(1.5 * (attempt + 1))
            continue
        return r
    raise last or RuntimeError("Canvas did not respond")


@app.post("/api/connect")
def connect():
    body = request.get_json(force=True)
    base = (body.get("base_url") or "").strip().rstrip("/")
    token = (body.get("token") or "").strip()
    if not re.match(r"^https?://[^/\s]+$", base):
        return jsonify(error="Enter the Canvas address only, like https://canvas.yourorg.edu"), 400
    if ON_VERCEL and not base.startswith("https://"):
        return jsonify(error="Use an https:// address. The token must not travel unencrypted."), 400
    if not token:
        return jsonify(error="Paste an access token to connect."), 400
    creds = {"base": base, "token": token}
    try:
        r = canvas_call(creds, "GET", f"{base}/api/v1/users/self")
    except Exception:
        return jsonify(error=f"Couldn't reach {base} from the server. If Canvas is only available "
                             "inside your network, a Vercel deployment can't connect to it."), 400
    if r.status_code == 401:
        return jsonify(error="Canvas rejected this token. Check it was copied in full and hasn't expired."), 400
    if r.status_code >= 400 or "json" not in r.headers.get("Content-Type", ""):
        return jsonify(error=f"That address didn't answer like Canvas (HTTP {r.status_code})."), 400
    user = r.json()
    accounts = []
    try:
        ar = canvas_call(creds, "GET", f"{base}/api/v1/accounts", params={"per_page": 100})
        if ar.ok:
            accounts = [{"id": a["id"], "name": a.get("name", "")} for a in ar.json()]
    except Exception:
        pass
    resp = jsonify(user=user.get("name"), accounts=accounts, base_url=base)
    resp.set_cookie(CREDS_COOKIE, FERNET.encrypt(json.dumps(creds).encode()).decode(),
                    max_age=CREDS_MAX_AGE, httponly=True, secure=SECURE_COOKIES, samesite="Strict")
    return resp


@app.post("/api/disconnect")
def disconnect():
    r = jsonify(ok=True)
    r.delete_cookie(CREDS_COOKIE)
    return r


@app.get("/api/status")
def status():
    c = get_creds()
    return jsonify(connected=bool(c), base_url=c["base"] if c else None)


# ---------------------------------------------------------------------------
# Canvas relay (allowlisted, read-only except starting a content export)
# ---------------------------------------------------------------------------
GET_ALLOW = [re.compile(p) for p in (
    r"^/users/self$", r"^/accounts$", r"^/accounts/\d+/(courses|users)$", r"^/courses$",
    r"^/courses/\d+/(enrollments|users|sections|groups|assignment_groups|assignments|"
    r"students/submissions|discussion_topics|quizzes|modules|pages|files)$",
    r"^/courses/\d+/discussion_topics/\d+/view$", r"^/courses/\d+/quizzes/\d+/submissions$",
    r"^/groups/\d+/users$", r"^/courses/\d+/content_exports/\d+$", r"^/progress/\d+$",
)]
POST_ALLOW = [re.compile(r"^/courses/\d+/content_exports$")]
EXPORT_TYPES = {"common_cartridge", "zip", "qti"}


@app.post("/api/canvas")
def relay():
    creds = get_creds()
    if not creds:
        return jsonify(error="Not connected to Canvas. Connect again."), 401
    b = request.get_json(force=True)
    method = (b.get("method") or "GET").upper()
    base = creds["base"]
    params, data = None, None
    if b.get("url"):  # a "next page" or progress link returned by Canvas
        u = urlparse(b["url"])
        if f"{u.scheme}://{u.netloc}" != base or not u.path.startswith("/api/v1/"):
            return jsonify(error="Link is not on your Canvas"), 400
        path, url = u.path[len("/api/v1"):], b["url"]
    else:
        path = str(b.get("path") or "")
        url = f"{base}/api/v1{path}"
        params = [(str(k), str(v)) for k, v in (b.get("params") or [])]
    allow = GET_ALLOW if method == "GET" else POST_ALLOW if method == "POST" else []
    if not any(p.match(path) for p in allow):
        return jsonify(error=f"Not allowed: {method} {path}"), 403
    if method == "POST":
        et = (b.get("data") or {}).get("export_type")
        if et not in EXPORT_TYPES:
            return jsonify(error="Unknown export type"), 400
        data = {"export_type": et, "skip_notifications": "true"}
    try:
        r = canvas_call(creds, method, url, params=params, data=data)
    except Exception:
        return jsonify(error="Canvas did not respond. Try again."), 504
    if r.status_code >= 400:
        msg = r.text[:300]
        try:
            j = r.json()
            msg = (j.get("errors") or [{}])[0].get("message") or j.get("message") or msg
        except Exception:
            pass
        code = r.status_code if r.status_code < 500 else 502
        return jsonify(error=f"Canvas said: {msg} (HTTP {r.status_code})", status=r.status_code), code
    return jsonify(data=r.json(), next=r.links.get("next", {}).get("url"),
                   remaining=r.headers.get("X-Rate-Limit-Remaining"))


@app.post("/api/export_file")
def export_file():
    """Relay a finished content export when it is small enough for Vercel."""
    creds = get_creds()
    if not creds:
        return jsonify(error="Not connected"), 401
    b = request.get_json(force=True)
    cid, eid = int(b["course_id"]), int(b["export_id"])
    r = canvas_call(creds, "GET", f"{creds['base']}/api/v1/courses/{cid}/content_exports/{eid}")
    if not r.ok:
        return jsonify(error=f"HTTP {r.status_code}"), 502
    att = (r.json().get("attachment") or {})
    url, size = att.get("url"), att.get("size") or 0
    if not url:
        return jsonify(error="No file yet"), 404
    if size > PROXY_FILE_LIMIT:
        return jsonify(error="too_big", url=url), 413
    headers = {}
    if urlparse(url).netloc == urlparse(creds["base"]).netloc:
        headers["Authorization"] = f"Bearer {creds['token']}"
    f = requests.get(url, headers=headers, timeout=50)
    if not f.ok or "text/html" in f.headers.get("Content-Type", "") or len(f.content) > PROXY_FILE_LIMIT:
        return jsonify(error="relay_failed", url=url), 413
    return Response(f.content, mimetype="application/octet-stream")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5050"))
    print(f"\n  Canvas Course Exporter -> http://127.0.0.1:{port}\n")
    app.run(host="127.0.0.1", port=port, debug=False, threaded=True)
