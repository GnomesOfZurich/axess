#!/usr/bin/env python3
"""Run the OpenID Foundation relying-party test plans against examples/oauth.

For each plan: create it on the suite through its REST API (static client,
plain request, client_secret_basic), then for each test module of the plan
create the module, wait until the suite is waiting for the client, start a
fresh examples/oauth process against the module's issuer, drive a browser-less
login (and, for the logout plans, the logout) with cookies and manual
redirects, wait for the suite to finish the module, stop the process, and
record the suite's own verdict. Nothing here decides pass or fail: the result
and the failing or warning log lines are what the suite reports.

Standard library only. Run it through run-rp.sh, which starts the suite and
builds the example. Exit status is 0 when the run completed (whatever the
verdicts), 2 when the harness itself broke.
"""

import argparse
import base64
import datetime
import http.cookiejar
import json
import os
import re
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# The plans, in the order they are run. `key` names the entry in the results
# (a plan can be run under more than one variant). `logout` says whether the
# driver ends the session after logging in, `refresh` whether it asks for a
# token refresh after it, `private_key` whether the example authenticates by
# `private_key_jwt` with a key generated for the run, and `modules`, when
# present, limits the run to those modules of the plan.
PLANS = [
    {
        "key": "basic",
        "name": "oidcc-client-basic-certification-test-plan",
        "alias": "axess-basic",
        "logout": False,
        "variant": {"client_registration": "static_client", "request_type": "plain_http_request"},
    },
    {
        "key": "rpinit",
        "name": "oidcc-client-rp-initiated-logout-rp-basic",
        "alias": "axess-rpinit",
        "logout": True,
        "variant": {
            "client_registration": "static_client",
            "client_auth_type": "client_secret_basic",
            "request_type": "plain_http_request",
            "response_mode": "default",
        },
    },
    {
        "key": "bcl",
        "name": "oidcc-client-back-channel-logout-rp-basic",
        "alias": "axess-bcl",
        "logout": True,
        "variant": {
            "client_registration": "static_client",
            "client_auth_type": "client_secret_basic",
            "request_type": "plain_http_request",
            "response_mode": "default",
        },
    },
    {
        "key": "refresh",
        "name": "oidcc-client-refreshtoken-test-plan",
        "alias": "axess-refresh",
        "logout": False,
        "refresh": True,
        "variant": {
            "client_registration": "static_client",
            "client_auth_type": "client_secret_basic",
            "request_type": "plain_http_request",
            "response_type": "code",
            "response_mode": "default",
        },
    },
    {
        # The Basic certification plan fixes client_secret_basic and has no
        # client_auth_type variant, so the same modules are run from the
        # generic client plan, which has one.
        "key": "basic-private-key-jwt",
        "name": "oidcc-client-test-plan",
        "alias": "axess-basic-pkjwt",
        "logout": False,
        "private_key": True,
        "modules": [
            "oidcc-client-test",
            "oidcc-client-test-invalid-iss",
            "oidcc-client-test-missing-sub",
            "oidcc-client-test-invalid-aud",
            "oidcc-client-test-missing-iat",
            "oidcc-client-test-kid-absent-single-jwks",
            "oidcc-client-test-kid-absent-multiple-jwks",
            "oidcc-client-test-idtoken-sig-rs256",
            "oidcc-client-test-idtoken-sig-none",
            "oidcc-client-test-invalid-sig-rs256",
            "oidcc-client-test-userinfo-invalid-sub",
            "oidcc-client-test-nonce-invalid",
            "oidcc-client-test-scope-userinfo-claims",
            "oidcc-client-test-client-secret-basic",
        ],
        "variant": {
            "client_registration": "static_client",
            "client_auth_type": "private_key_jwt",
            "request_type": "plain_http_request",
            "response_type": "code",
            "response_mode": "default",
        },
    },
]

KEY_ID = "axess-conformance-key"

PROVIDER = "suite"
CLIENT_ID = "axess-conformance-rp"
CLIENT_SECRET = "axess-conformance-rp-secret"
RP_PORT = 9300
# The suite runs in a container; this name reaches the host from inside it.
RP_FROM_SUITE = "host.containers.internal"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Browser:
    """A cookie jar and manual redirect following, as much of a browser as the
    flow needs."""

    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar), _NoRedirect
        )
        self.trail = []

    def request(self, method, url, timeout=20):
        req = urllib.request.Request(url, method=method, data=b"" if method == "POST" else None)
        try:
            resp = self.opener.open(req, timeout=timeout)
        except urllib.error.HTTPError as e:
            resp = e
        body = resp.read().decode("utf-8", "replace")
        self.trail.append("%s %s -> %s" % (method, url, resp.status))
        return resp.status, resp.headers, body

    def follow(self, method, url, limit=12):
        status, headers, body = self.request(method, url)
        for _ in range(limit):
            if status in (301, 302, 303, 307, 308) and headers.get("Location"):
                url = urllib.parse.urljoin(url, headers["Location"])
                status, headers, body = self.request("GET", url)
            else:
                break
        return status, body


def api(suite, method, path, params=None, body=None, timeout=60):
    url = suite + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, method=method, data=data, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
    return json.loads(raw) if raw else None


def wait_for_suite(suite, seconds=240):
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            api(suite, "GET", "/api/plan/available", timeout=10)
            return
        except Exception:
            time.sleep(3)
    raise SystemExit("the suite did not answer at %s within %ds" % (suite, seconds))


def wait_status(suite, module_id, wanted, seconds):
    deadline = time.time() + seconds
    status = None
    while time.time() < deadline:
        info = api(suite, "GET", "/api/info/" + module_id)
        status = info.get("status")
        if status in wanted:
            return info
        time.sleep(0.4)
    return None


def port_open(port):
    with socket.socket() as s:
        s.settimeout(0.3)
        return s.connect_ex(("127.0.0.1", port)) == 0


def make_key(outdir):
    """A fresh RSA key for private_key_jwt: returns the PEM path and the
    public JWK the suite verifies assertions against."""
    path = os.path.join(outdir, "private-key-jwt.pem")
    subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt",
                    "rsa_keygen_bits:2048", "-out", path], check=True, capture_output=True)
    os.chmod(path, 0o600)
    out = subprocess.run(["openssl", "rsa", "-in", path, "-noout", "-modulus"],
                         check=True, capture_output=True, text=True).stdout
    modulus = bytes.fromhex(out.strip().split("=", 1)[1])
    b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    jwk = {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": KEY_ID,
           "n": b64(modulus), "e": b64((65537).to_bytes(3, "big"))}
    return path, jwk


def start_rp(binary, issuer, logfile, key_path=None):
    env = dict(os.environ)
    env.update(
        {
            "OAUTH_ISSUER": issuer,
            "OAUTH_PROVIDER_NAME": PROVIDER,
            "OAUTH_CLIENT_ID": CLIENT_ID,
            "OAUTH_BASE_URL": "http://localhost:%d" % RP_PORT,
            "OAUTH_LISTEN": "0.0.0.0:%d" % RP_PORT,
            # The registration's id_token_signed_response_alg: the OpenID
            # Connect default, which the suite's wrong-algorithm test relies on.
            "OAUTH_ID_TOKEN_ALGS": "RS256",
            # The cookie jar here is a plain-http client and the suite is
            # reached over loopback http; see the conformance chapter.
            "AXESS_DEV_INSECURE_COOKIES": "1",
            "RUST_LOG": "axess_example_oauth=debug,axess=debug",
        }
    )
    if key_path:
        env.pop("OAUTH_CLIENT_SECRET", None)
        env.update({"OAUTH_PRIVATE_KEY_FILE": key_path, "OAUTH_PRIVATE_KEY_ALG": "RS256",
                    "OAUTH_PRIVATE_KEY_KID": KEY_ID})
    else:
        env["OAUTH_CLIENT_SECRET"] = CLIENT_SECRET
        env.pop("OAUTH_PRIVATE_KEY_FILE", None)
    log = open(logfile, "wb")
    proc = subprocess.Popen([binary], env=env, stdout=log, stderr=subprocess.STDOUT)
    deadline = time.time() + 30
    while time.time() < deadline:
        if proc.poll() is not None:
            return proc, "the example exited at start (status %s)" % proc.returncode
        if port_open(RP_PORT):
            return proc, None
        time.sleep(0.2)
    return proc, "the example did not listen within 30 s"


def stop_rp(proc):
    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def drive(plan, browser):
    """Log in, and for the logout plans log out. Returns a one-line note on
    what the client saw; the suite, not this note, decides the verdict."""
    base = "http://localhost:%d" % RP_PORT
    status, body = browser.follow("GET", "%s/auth/login/%s" % (base, PROVIDER))
    note = "login ended with HTTP %d" % status
    if status == 200 and "<h1>Profile</h1>" in body:
        note += " (signed in)"
        if plan.get("refresh"):
            status, _ = browser.follow("POST", base + "/auth/refresh")
            note += "; refresh ended with HTTP %d" % status
        if plan["logout"]:
            status, _ = browser.follow("POST", base + "/auth/logout")
            note += "; logout ended with HTTP %d" % status
    else:
        note += " (not signed in)"
    return note


def summarise_log(entries):
    """The log lines that carry a verdict other than success."""
    rows = []
    for e in entries:
        res = e.get("result")
        if res in ("FAILURE", "WARNING", "INTERRUPTED", "REVIEW"):
            rows.append(
                {
                    "result": res,
                    "src": e.get("src"),
                    "msg": e.get("msg"),
                    "requirements": e.get("requirements"),
                }
            )
    return rows


def run_module(suite, plan, plan_id, module, binary, outdir, wait_seconds, key_path=None):
    name = module["testModule"]
    started = time.time()
    created = api(suite, "POST", "/api/runner", {"test": name, "plan": plan_id})
    module_id = created["id"]
    info = wait_status(suite, module_id, ("WAITING", "FINISHED", "INTERRUPTED"), 60)
    record = {"module": name, "id": module_id, "variant": module.get("variant")}
    if info is None or info["status"] != "WAITING":
        record.update(status=(info or {}).get("status"), note="the suite never waited for the client")
        return finish_record(suite, record, module_id, started)

    issuer = "%s/test/a/%s/" % (suite, plan["alias"])
    rp_log = os.path.join(outdir, "%s.%s.rp.log" % (plan["alias"], name))
    proc, problem = start_rp(binary, issuer, rp_log, key_path)
    try:
        if problem:
            record["client_note"] = problem
        else:
            browser = Browser()
            try:
                record["client_note"] = drive(plan, browser)
            except Exception as e:  # the client side broke; the suite still judges
                record["client_note"] = "driver error: %r" % (e,)
            record["client_trail"] = browser.trail
        info = wait_status(suite, module_id, ("FINISHED", "INTERRUPTED"), wait_seconds)
        if info is None:
            record["timed_out_waiting"] = True
    finally:
        stop_rp(proc)
    return finish_record(suite, record, module_id, started)


def finish_record(suite, record, module_id, started):
    info = api(suite, "GET", "/api/info/" + module_id)
    record["status"] = info.get("status")
    record["result"] = info.get("result")
    try:
        log = api(suite, "GET", "/api/log/" + module_id)
        record["findings"] = summarise_log(log)
    except Exception as e:
        record["findings"] = []
        record["log_error"] = repr(e)
    record["seconds"] = round(time.time() - started, 1)
    return record


def export_plan(suite, plan_id, path):
    url = "%s/api/plan/export/%s" % (suite, plan_id)
    try:
        with urllib.request.urlopen(url, timeout=120) as resp, open(path, "wb") as f:
            f.write(resp.read())
        return True
    except Exception:
        return False


def render_markdown(run):
    """The results section of docs/factors/conformance.md."""
    out = []
    out.append("Suite version %s, image `%s`." % (run["suite_version"], run["suite_image"]))
    out.append("")
    for p in run["plans"]:
        counts = {}
        for m in p["modules"]:
            key = m.get("result") or m.get("status") or "none"
            counts[key] = counts.get(key, 0) + 1
        summary = ", ".join("%d %s" % (n, k.lower()) for k, n in sorted(counts.items()))
        out.append("### `%s`%s" % (p["plan"], p.get("title_suffix", "")))
        out.append("")
        out.append("Run %s (UTC). Plan instance on the suite: %s. Variant: `%s`. Modules run: %d (%s)." % (
            p.get("date", run["date"]), p["plan_id"], json.dumps(p["variant"], sort_keys=True),
            len(p["modules"]), summary))
        if p.get("modules_in_plan") and p["modules_in_plan"] != len(p["modules"]):
            out.append("")
            out.append("The plan instance holds %d modules for this variant; the %d run are the ones listed." % (
                p["modules_in_plan"], len(p["modules"])))
        out.append("")
        out.append("| Module | Result | Client saw | Suite findings |")
        out.append("|---|---|---|---|")
        for m in p["modules"]:
            res = m.get("result") or m.get("status") or "none"
            finds = "; ".join(
                "%s: %s" % (f["result"], re.sub(r"\s+", " ", (f.get("msg") or "")).replace("|", "/")[:160])
                for f in m.get("findings", [])[:3]
            ) or "none"
            seen = (m.get("client_note") or "").replace("|", "/")
            out.append("| `%s` | %s | %s | %s |" % (m["module"], res, seen, finds))
        out.append("")
    return "\n".join(out)


def splice(doc_path, fragment):
    start, end = "<!-- results:start -->", "<!-- results:end -->"
    text = open(doc_path).read()
    if start not in text or end not in text:
        raise SystemExit("%s has no results markers" % doc_path)
    head, rest = text.split(start, 1)
    _, tail = rest.split(end, 1)
    open(doc_path, "w").write(head + start + "\n" + fragment + "\n" + end + tail)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--suite", default="http://localhost:9080")
    ap.add_argument("--bin", required=True, help="the axess-example-oauth binary")
    ap.add_argument("--out", required=True, help="directory for logs and exports")
    ap.add_argument("--plans", default="all", help="comma-separated plan keys (basic, rpinit, bcl, refresh, basic-private-key-jwt) or names, or all")
    ap.add_argument("--wait", type=int, default=60, help="seconds to wait for a module to finish")
    ap.add_argument("--timeout-seconds", type=int, default=20, help="the suite's own waitTimeoutSeconds")
    ap.add_argument("--image", default="", help="suite image reference, recorded in the results")
    ap.add_argument("--results-json", help="write the results here")
    ap.add_argument("--splice", help="rewrite the results section of this markdown file")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    suite = args.suite.rstrip("/")
    wait_for_suite(suite)
    chosen = PLANS if args.plans == "all" else [p for p in PLANS if p["name"] in args.plans.split(",") or p["key"] in args.plans.split(",")]
    if not chosen:
        raise SystemExit("no such plan: %s" % args.plans)

    run = {"date": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M"),
           "suite_image": args.image, "plans": []}
    key_path, jwk = (make_key(args.out) if any(p.get("private_key") for p in chosen) else (None, None))
    for plan in chosen:
        config = {
            "alias": plan["alias"],
            "description": "axess examples/oauth, %s" % plan["name"],
            "publish": "private",
            "waitTimeoutSeconds": args.timeout_seconds,
            "client": {
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "scope": "openid profile email",
                "redirect_uri": "http://localhost:%d/auth/callback/%s" % (RP_PORT, PROVIDER),
                "post_logout_redirect_uri": "http://localhost:%d/" % RP_PORT,
                "backchannel_logout_uri": "http://%s:%d/auth/backchannel-logout" % (RP_FROM_SUITE, RP_PORT),
            },
        }
        plan_key = key_path if plan.get("private_key") else None
        if plan_key:
            config["client"].pop("client_secret")
            config["client"]["jwks"] = {"keys": [jwk]}
        created = api(suite, "POST", "/api/plan",
                      {"planName": plan["name"], "variant": json.dumps(plan["variant"])}, body=config)
        plan_id = created["id"]
        print("plan %s created as %s with %d modules" % (plan["name"], plan_id, len(created["modules"])), flush=True)
        results = []
        in_plan = len(created["modules"])
        modules = [m for m in created["modules"] if m["testModule"] in plan.get("modules", [m["testModule"]])]
        for module in modules:
            rec = run_module(suite, plan, plan_id, module, args.bin, args.out, args.wait, plan_key)
            print("  %-60s %s" % (rec["module"], rec.get("result") or rec.get("status")), flush=True)
            results.append(rec)
        export_plan(suite, plan_id, os.path.join(args.out, "%s.export.zip" % plan["alias"]))
        entry = {"key": plan["key"], "plan": plan["name"], "plan_id": plan_id, "variant": plan["variant"],
                 "date": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M"),
                 "modules_in_plan": in_plan, "modules": results}
        if plan.get("private_key"):
            entry["title_suffix"] = " (client_auth_type `private_key_jwt`)"
        run["plans"].append(entry)

    try:
        first = api(suite, "GET", "/api/info/" + run["plans"][0]["modules"][0]["id"])
        run["suite_version"] = first.get("version", "")
    except Exception:
        run["suite_version"] = ""
    if args.results_json and os.path.exists(args.results_json):
        # A partial run replaces only the plans it ran; the others keep the
        # verdicts of the run that produced them.
        with open(args.results_json) as f:
            previous = json.load(f)
        ran = {p["key"] for p in run["plans"]}
        order = [p["key"] for p in PLANS]
        kept = []
        for p in previous.get("plans", []):
            p.setdefault("key", next((q["key"] for q in PLANS if q["name"] == p["plan"]), p["plan"]))
            p.setdefault("date", previous.get("date"))
            if p["key"] not in ran:
                kept.append(p)
        run["plans"] = sorted(kept + run["plans"], key=lambda p: order.index(p["key"]) if p["key"] in order else 99)
    if args.results_json:
        with open(args.results_json, "w") as f:
            json.dump(run, f, indent=2, sort_keys=True)
            f.write("\n")
    fragment = render_markdown(run)
    if args.splice:
        splice(args.splice, fragment)
    else:
        print(fragment)
    return 0


if __name__ == "__main__":
    sys.exit(main())
