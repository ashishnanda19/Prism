#!/usr/bin/env python3
# =============================================================================
# Prism - developer dashboard backend
# Author: Ashish Kumar Nanda
#
# A tiny stdlib-only web server that drives the prism binaries so every piece
# of the project is runnable and inspectable from a browser.
#
#   python3 dashboard/server.py            # http://127.0.0.1:7070
#   python3 dashboard/server.py --port 8000 --bin-dir build/bin
#
# Binds to 127.0.0.1 only. It shells out to the local prism binaries with
# arguments from the page -- it is a dev tool for your own machine.
# =============================================================================
import argparse
import json
import os
import shlex
import subprocess
import sys
import tempfile
import time
import urllib.request
import socketserver
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HERE = os.path.join(ROOT, "dashboard")
UPLOADS = os.path.join(HERE, "uploads")
OUTDIR = os.path.join(tempfile.gettempdir(), "prism-dashboard-out")
os.makedirs(UPLOADS, exist_ok=True)
os.makedirs(OUTDIR, exist_ok=True)

ENGINES = {"prism", "prism-lite", "prism-classic", "prism-dump"}
TOOLS = {"explain", "sig", "fp", "reasm", "hash"}

STATE = {"bin_dir": None, "capture": None}  # capture: {proc, log_path, port, cmd}


# --------------------------------------------------------------------------- util
def bin_path(name):
    p = os.path.join(STATE["bin_dir"], name)
    return p if os.path.isfile(p) and os.access(p, os.X_OK) else None


def run(argv, stdin_data=None, timeout=60, cwd=ROOT):
    t0 = time.time()
    try:
        r = subprocess.run(argv, input=stdin_data, capture_output=True, text=True,
                           timeout=timeout, cwd=cwd)
        return {"ok": r.returncode == 0, "exit": r.returncode, "stdout": r.stdout,
                "stderr": r.stderr, "ms": int((time.time() - t0) * 1000),
                "cmd": " ".join(shlex.quote(a) for a in argv)}
    except subprocess.TimeoutExpired as e:
        return {"ok": False, "exit": -1, "stdout": e.stdout or "", "stderr": f"timeout after {timeout}s",
                "ms": int((time.time() - t0) * 1000), "cmd": " ".join(shlex.quote(a) for a in argv)}
    except FileNotFoundError as e:
        return {"ok": False, "exit": -1, "stdout": "", "stderr": str(e), "ms": 0,
                "cmd": " ".join(argv)}


def list_pcaps():
    out = []
    for base in (ROOT, UPLOADS):
        for f in sorted(os.listdir(base)):
            if f.endswith(".pcap"):
                p = os.path.join(base, f)
                out.append({"name": f, "path": p, "bytes": os.path.getsize(p),
                            "where": "repo" if base == ROOT else "upload"})
    return out


def resolve_pcap(name):
    for base in (ROOT, UPLOADS, OUTDIR):
        p = os.path.join(base, os.path.basename(name))
        if os.path.isfile(p):
            return p
    return None


# ------------------------------------------------------------------- API handlers
def api_status(_body):
    bd = STATE["bin_dir"]
    bins = {n: bool(bin_path(n)) for n in sorted(ENGINES)}
    rev = run(["git", "rev-parse", "--short", "HEAD"]).get("stdout", "").strip()
    build_ok = all(bins.values())
    ncases = None
    tp = bin_path("prism_tests") or os.path.join(os.path.dirname(bd or ""), "bin", "prism_tests")
    if bd:
        tb = os.path.join(bd, "prism_tests")
        if os.path.isfile(tb):
            r = run([tb, "--count"], timeout=20)
            for ln in r["stdout"].splitlines():
                if "test cases" in ln:
                    ncases = ln.strip()
    return {"bin_dir": bd, "binaries": bins, "build_ok": build_ok, "git": rev,
            "test_cases": ncases, "root": ROOT}


def api_ifaces(_body):
    names = []
    if sys.platform == "darwin":
        r = run(["ifconfig", "-l"], timeout=5)
        names = r["stdout"].split()
    else:
        r = run(["sh", "-c", "ls /sys/class/net"], timeout=5)
        names = r["stdout"].split()
    return {"ifaces": names}


def api_pcaps(_body):
    return {"pcaps": list_pcaps()}


def api_upload(body):
    name = os.path.basename(body.get("name", "upload.pcap")) or "upload.pcap"
    if not name.endswith(".pcap"):
        name += ".pcap"
    data = bytes.fromhex(body["hex"])
    with open(os.path.join(UPLOADS, name), "wb") as f:
        f.write(data)
    return {"ok": True, "name": name, "bytes": len(data)}


def api_run(body):
    """Run an engine on a pcap, or a `prism <tool>` command."""
    kind = body.get("kind", "engine")
    args = list(body.get("args", []))
    stdin_data = body.get("stdin")
    timeout = min(int(body.get("timeout", 60)), 180)

    # a temp signatures file, if the page sent rule text
    sig_text = body.get("signatures")
    sig_file = None
    if sig_text:
        sig_file = os.path.join(OUTDIR, f"sig-{int(time.time()*1000)}.txt")
        with open(sig_file, "w") as f:
            f.write(sig_text)

    if kind == "engine":
        engine = body.get("engine", "prism")
        if engine not in ENGINES:
            return {"ok": False, "stderr": f"unknown engine {engine}"}
        bp = bin_path(engine)
        if not bp:
            return {"ok": False, "stderr": f"{engine} not built (bin-dir {STATE['bin_dir']})"}
        pcap = resolve_pcap(body.get("pcap", ""))
        if not pcap:
            return {"ok": False, "stderr": "pcap not found"}
        out_pcap = os.path.join(OUTDIR, f"out-{int(time.time()*1000)}.pcap")
        argv = [bp, pcap]
        if engine != "prism-dump":
            if engine == "prism-lite":
                argv.append(out_pcap)
            else:
                argv += ["-o", out_pcap]
        argv += args
        if sig_file and engine != "prism-dump":
            argv += ["--signatures", sig_file]
        res = run(argv, timeout=timeout)
        if engine != "prism-dump" and os.path.isfile(out_pcap):
            res["output_pcap"] = os.path.basename(out_pcap)
            res["output_bytes"] = os.path.getsize(out_pcap)
        return res

    if kind == "tool":
        tool = body.get("tool")
        if tool not in TOOLS:
            return {"ok": False, "stderr": f"unknown tool {tool}"}
        bp = bin_path("prism")
        if not bp:
            return {"ok": False, "stderr": "prism not built"}
        argv = [bp, tool] + args
        if sig_file and tool in ("sig", "explain"):
            argv += ["--signatures", sig_file]
        # explain / dump take a pcap as first positional
        if tool == "explain" and body.get("pcap"):
            pcap = resolve_pcap(body["pcap"])
            if not pcap:
                return {"ok": False, "stderr": "pcap not found"}
            argv.insert(2, pcap)
        return run(argv, stdin_data=stdin_data, timeout=timeout)

    return {"ok": False, "stderr": f"unknown kind {kind}"}


def api_download(qs):
    name = os.path.basename(qs.get("f", [""])[0])
    p = os.path.join(OUTDIR, name)
    return p if os.path.isfile(p) else None


def api_tests(body):
    bd = STATE["bin_dir"]
    build = os.path.dirname(bd) if bd else os.path.join(ROOT, "build")
    which = body.get("which", "ctest")
    if which == "ctest":
        return run(["ctest", "--test-dir", build, "--output-on-failure"], timeout=180)
    if which == "list":
        tb = os.path.join(bd or "", "prism_tests")
        return run([tb, "--list-test-cases"], timeout=20)
    return {"ok": False, "stderr": "unknown 'which'"}


def api_build(_body):
    build = os.path.join(ROOT, "build")
    cfg = run(["cmake", "-S", ROOT, "-B", build, "-DCMAKE_BUILD_TYPE=RelWithDebInfo"], timeout=120)
    if not cfg["ok"]:
        return cfg
    b = run(["cmake", "--build", build, "-j", "4"], timeout=300)
    b["stdout"] = cfg["stdout"] + "\n" + b["stdout"]
    STATE["bin_dir"] = os.path.join(build, "bin")
    return b


def api_proxy_metrics(qs):
    port = int(qs.get("port", ["9109"])[0])
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=3) as r:
            return {"ok": True, "text": r.read().decode("utf-8", "replace")}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}


def api_capture_start(body):
    if STATE["capture"] and STATE["capture"]["proc"].poll() is None:
        return {"ok": False, "error": "a capture is already running; stop it first"}
    engine = body.get("engine", "prism")
    if engine not in ("prism", "prism-classic"):
        return {"ok": False, "error": "engine must be prism or prism-classic"}
    bp = bin_path(engine)
    if not bp:
        return {"ok": False, "error": f"{engine} not built"}
    iface = body.get("iface", "")
    port = int(body.get("metrics_port", 9109))
    src = body.get("pcap")
    argv = [bp]
    if src:
        p = resolve_pcap(src)
        if not p:
            return {"ok": False, "error": "pcap not found"}
        argv += [p, "--loop"]
    else:
        if not iface:
            return {"ok": False, "error": "give an --iface or a pcap to loop"}
        argv += ["--iface", iface]
    argv += ["-o", os.path.join(OUTDIR, "capture-out.pcap"),
             "--metrics", f"127.0.0.1:{port}", "--log-json"]
    argv += list(body.get("args", []))
    if body.get("sudo"):
        argv = ["sudo", "-n"] + argv
    log_path = os.path.join(OUTDIR, "capture.log")
    lf = open(log_path, "w")
    proc = subprocess.Popen(argv, stdout=lf, stderr=lf, cwd=ROOT)
    STATE["capture"] = {"proc": proc, "log_path": log_path, "port": port,
                        "cmd": " ".join(shlex.quote(a) for a in argv), "lf": lf}
    time.sleep(0.6)
    return api_capture_status(None)


def api_capture_stop(_body):
    c = STATE["capture"]
    if not c:
        return {"ok": True, "running": False}
    if c["proc"].poll() is None:
        c["proc"].terminate()
        try:
            c["proc"].wait(timeout=3)
        except subprocess.TimeoutExpired:
            c["proc"].kill()
    try:
        c["lf"].close()
    except Exception:  # noqa: BLE001
        pass
    STATE["capture"] = None
    return {"ok": True, "running": False}


def api_capture_status(_body):
    c = STATE["capture"]
    if not c:
        return {"ok": True, "running": False}
    running = c["proc"].poll() is None
    log = ""
    try:
        with open(c["log_path"]) as f:
            log = "".join(f.readlines()[-40:])
    except Exception:  # noqa: BLE001
        pass
    return {"ok": True, "running": running, "port": c["port"], "cmd": c["cmd"],
            "exit": None if running else c["proc"].returncode, "log": log}


ROUTES = {
    "/api/status": api_status,
    "/api/ifaces": api_ifaces,
    "/api/pcaps": api_pcaps,
    "/api/upload": api_upload,
    "/api/run": api_run,
    "/api/tests": api_tests,
    "/api/build": api_build,
    "/api/capture/start": api_capture_start,
    "/api/capture/stop": api_capture_stop,
    "/api/capture/status": api_capture_status,
}
GET_ROUTES = {"/api/proxy_metrics": api_proxy_metrics}


# ------------------------------------------------------------------------ server
class Handler(BaseHTTPRequestHandler):
    server_version = "PrismDashboard/1.0"

    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, (bytes, bytearray)) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def log_message(self, *a):  # quieter
        pass

    def do_GET(self):
        from urllib.parse import urlparse, parse_qs
        u = urlparse(self.path)
        if u.path in ("/", "/index.html"):
            try:
                with open(os.path.join(HERE, "index.html"), "rb") as f:
                    return self._send(200, f.read(), "text/html; charset=utf-8")
            except FileNotFoundError:
                return self._send(500, {"error": "index.html missing"})
        if u.path == "/api/download":
            p = api_download(parse_qs(u.query))
            if not p:
                return self._send(404, {"error": "not found"})
            with open(p, "rb") as f:
                return self._send(200, f.read(), "application/vnd.tcpdump.pcap")
        if u.path in GET_ROUTES:
            return self._send(200, GET_ROUTES[u.path](parse_qs(u.query)))
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(n) if n else b"{}"
        try:
            body = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            return self._send(400, {"error": "bad json"})
        fn = ROUTES.get(self.path)
        if not fn:
            return self._send(404, {"error": "not found"})
        try:
            return self._send(200, fn(body))
        except Exception as e:  # noqa: BLE001
            import traceback
            return self._send(500, {"error": str(e), "trace": traceback.format_exc()})


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def server_bind(self):
        # skip HTTPServer.server_bind's socket.getfqdn() -- a reverse DNS lookup
        # on 127.0.0.1 that can hang for many seconds on some macOS setups.
        socketserver.TCPServer.server_bind(self)
        self.server_name = "localhost"
        self.server_port = self.server_address[1]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=7070)
    ap.add_argument("--bin-dir", default=os.environ.get("PRISM_BIN", os.path.join(ROOT, "build", "bin")))
    args = ap.parse_args()
    STATE["bin_dir"] = os.path.abspath(args.bin_dir)

    if not os.path.isdir(STATE["bin_dir"]):
        print(f"note: {STATE['bin_dir']} does not exist yet -- build Prism, or use the "
              f"'Build' button in the dashboard.", file=sys.stderr)

    srv = Server(("127.0.0.1", args.port), Handler)
    print(f"Prism dashboard  ->  http://127.0.0.1:{args.port}   (bin-dir: {STATE['bin_dir']})")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        api_capture_stop(None)
        print("\nbye")


if __name__ == "__main__":
    main()
