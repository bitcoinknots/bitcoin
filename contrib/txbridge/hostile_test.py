#!/usr/bin/env python3
"""Runs knots-txbridge against fakepeer.py in every hostile mode and reports what the bridge did.
Pass: the bridge stays up for the whole run, exits 0, its RSS stays under the cap, and it reacted (dropped/banned/counted) as expected."""
import os, re, subprocess, sys, time
HERE = os.path.dirname(os.path.abspath(__file__))
# mode -> (seconds, check on parsed stats + full log)
MODES = {
    "shortversion": (30, lambda st, out: st["banned"] >= 1 and st["malformed"] >= 1),
    "bigmsg":       (30, lambda st, out: st["banned"] >= 1 and st["oversized"] >= 1),
    "hugelen":      (30, lambda st, out: st["banned"] >= 1),
    "badchecksum":  (30, lambda st, out: st["banned"] >= 1),
    "badmagic":     (30, lambda st, out: st["banned"] >= 1),
    "invflood":     (75, lambda st, out: st["banned"] >= 1 and st["requested"] <= 500 and st["announced"] >= 1000000),
    "invbadcount":  (30, lambda st, out: st["banned"] >= 1),
    "garbagetx":    (30, lambda st, out: st["banned"] >= 1 and st["malformed"] >= 1),
    "txflood":      (30, lambda st, out: st["banned"] >= 1 and st["rate-dropped"] >= 1),
    "malleate":     (30, lambda st, out: st["banned"] >= 1 and st["received"] >= 4),
    "slowloris":    (200, lambda st, out: out.count("closed (TimeoutError)") >= 1),
    "dupversion":   (30, lambda st, out: st["banned"] >= 1),
    "ansiua":       (20, lambda st, out: "\x1b" not in out and any("INJECTED" in l and "protocol" in l for l in out.splitlines())),
    "idle":         (200, lambda st, out: out.count("closed (TimeoutError)") >= 1),
}
def run(mode, port, seconds):
    fp = subprocess.Popen([sys.executable, f"{HERE}/fakepeer.py", "--mode", mode, "--port", str(port), "--seconds", str(seconds + 10)])
    time.sleep(0.5)
    t0 = time.time()
    br = subprocess.Popen([sys.executable, f"{HERE}/txbridge.py", "--network", "regtest", "--no-dns", "--peer", f"127.0.0.1:{port}",
                           "--connections", "1", "--run-seconds", str(seconds), "--stats-interval", "3600", "-v"],
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    peak = 0
    while br.poll() is None:
        try:
            with open(f"/proc/{br.pid}/status", encoding="utf8") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        peak = max(peak, int(line.split()[1]) // 1024)
        except FileNotFoundError:
            pass
        time.sleep(0.5)
    out = br.stdout.read()
    fp.kill()
    final = [l for l in out.splitlines() if "final:" in l]
    return br.returncode, time.time() - t0, peak, final[-1] if final else out[-400:], out
def parse(stats):
    st = {}
    for k, v in re.findall(r"([a-z-]+) (\d+)", stats):
        st[k] = int(v)
    return st

if __name__ == "__main__":
    port = 28800
    allok = True
    only = sys.argv[1:]
    for mode, (seconds, check) in MODES.items():
        if only and mode not in only:
            continue
        rc, dur, peak, final, out = run(mode, port, seconds)
        port += 1
        stats = final.split("final: ", 1)[-1]
        st = parse(stats)
        try:
            ok = rc == 0 and peak < 300 and check(st, out)
        except Exception as e:
            ok = False
        keys = ["dropped", "banned", "strikes", "malformed", "oversized", "rate-dropped", "announced", "requested", "received", "undelivered"]
        short = " ".join(f"{k}={st.get(k, '?')}" for k in keys)
        print(f"{'PASS' if ok else 'FAIL'} {mode:13s} rc={rc} {dur:5.1f}s peakRSS={peak}MB {short} timeouts={out.count('closed (TimeoutError)')}")
        allok &= ok
    print("ALL PASS" if allok else "SOME FAILED")
