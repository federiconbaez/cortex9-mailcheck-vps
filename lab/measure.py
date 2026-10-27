"""Run the lab and print the measured score.

    python -m lab.measure            # 12 broken cases + healthy control
    python -m lab.measure --json

Pass criterion (from the idea): correct root cause in >=11/12 broken cases
and 0 broken cases reported as OK. The healthy control must report OK.
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import socket
import sys
import tempfile
import threading

from lab.cases import BROKEN_CASES, _pem, build_case, new_key
from mailcheck.cli import main as cli_main


@contextlib.contextmanager
def ports():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(16)
    stop = threading.Event()

    def accept():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                c, _ = srv.accept()
                c.close()
            except OSError:
                pass

    t = threading.Thread(target=accept, daemon=True)
    t.start()
    tmp = socket.socket()
    tmp.bind(("127.0.0.1", 0))
    closed = tmp.getsockname()[1]
    tmp.close()  # nothing listens here any more
    try:
        yield srv.getsockname()[1], closed
    finally:
        stop.set()
        t.join()
        srv.close()


def run_case(argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = cli_main(argv)
    return code, json.loads(buf.getvalue())


def run_lab():
    key, other = _pem(new_key()), _pem(new_key())
    rows = []
    with tempfile.TemporaryDirectory() as root, ports() as (open_port, closed_port):
        for name, expected in list(BROKEN_CASES.items()) + [("healthy", None)]:
            argv = build_case(name, root, key, other, open_port, closed_port)
            code, rep = run_case(argv)
            rows.append({"case": name, "expected": expected, "root_cause": rep["root_cause"],
                         "overall": rep["overall"], "all_causes": rep["ordered_causes"], "exit": code})
    broken = [r for r in rows if r["expected"]]
    correct = sum(r["root_cause"] == r["expected"] for r in broken)
    false_ok = sum(r["overall"] == "OK" for r in broken)
    healthy_ok = [r for r in rows if r["case"] == "healthy"][0]["overall"] == "OK"
    return {"rows": rows, "correct": correct, "total": len(broken), "false_ok": false_ok,
            "healthy_ok": healthy_ok,
            "pass": correct >= 11 and false_ok == 0 and healthy_ok}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    res = run_lab()
    if a.json:
        print(json.dumps(res, indent=2))
    else:
        for r in res["rows"]:
            mark = "ok " if (r["expected"] and r["root_cause"] == r["expected"]) or \
                (not r["expected"] and r["overall"] == "OK") else "BAD"
            print(f"{mark} {r['case']:24} overall={r['overall']:10} root_cause={r['root_cause']} all={r['all_causes']}")
        print(f"root cause correct: {res['correct']}/{res['total']}; false OK: {res['false_ok']}; "
              f"healthy control OK: {res['healthy_ok']}; criterion met: {res['pass']}")
    return 0 if res["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
