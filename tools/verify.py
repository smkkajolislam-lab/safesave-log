#!/usr/bin/env python3
"""
Independent audit of the Safe Save Sahittyo transparency log (standard library only; openssl optional).

  python3 tools/verify.py                       # audit the files in the current checkout
  python3 tools/verify.py --base https://raw.githubusercontent.com/OWNER/REPO/main

It re-computes every checkpoint from the published entries (consistency / append-only check)
and, if openssl is installed, verifies each checkpoint's RFC 3161 time-stamp.
Anyone can run this - no trust in the log operator is needed.
"""
import argparse, hashlib, json, os, subprocess, sys, tempfile, urllib.request


def sha(*parts):
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def mth(leaves, lo, hi):
    n = hi - lo
    if n == 0:
        return sha()
    if n == 1:
        return leaves[lo]
    k = 1
    while k * 2 < n:
        k *= 2
    return sha(b"\x01", mth(leaves, lo, lo + k), mth(leaves, lo + k, hi))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="")
    ap.add_argument("--cafile", default="")
    a = ap.parse_args()

    def get(path):
        if a.base:
            with urllib.request.urlopen(f"{a.base}/{path}", timeout=60) as r:
                return r.read()
        return open(path, "rb").read()

    entries = [l for l in get("log/entries.jsonl").decode().split("\n") if l]
    leaves = [sha(b"\x00", l.encode()) for l in entries]
    history = [json.loads(l) for l in get("checkpoints/history.jsonl").decode().split("\n") if l]
    ok = True
    last = 0
    for h in history:
        if h["size"] < last or h["size"] > len(leaves):
            print("FAIL size order/range", h); ok = False; continue
        last = h["size"]
        root = mth(leaves, 0, h["size"]).hex()
        good = root == h["root"]
        ok &= good
        print(f"checkpoint size={h['size']:>6} time={h['time']} consistent={'YES' if good else 'NO  <-- LOG WAS ALTERED'}")
        try:
            data = get(f"checkpoints/{h['file']}.json")
            tsr = get(f"checkpoints/{h['file']}.tsr")
            with tempfile.TemporaryDirectory() as d:
                open(os.path.join(d, "c.json"), "wb").write(data)
                open(os.path.join(d, "c.tsr"), "wb").write(tsr)
                cmd = ["openssl", "ts", "-verify", "-in", os.path.join(d, "c.tsr"), "-data", os.path.join(d, "c.json")]
                cmd += ["-CAfile", a.cafile] if a.cafile else ["-CApath", "/etc/ssl/certs"]
                tok = os.path.join(d, "t.tok"); chain = os.path.join(d, "chain.pem")
                subprocess.run(["openssl", "ts", "-reply", "-in", os.path.join(d, "c.tsr"), "-token_out", "-out", tok], capture_output=True)
                subprocess.run(["openssl", "pkcs7", "-inform", "DER", "-in", tok, "-print_certs", "-out", chain], capture_output=True)
                r = subprocess.run(cmd + ["-untrusted", chain], capture_output=True)
                txt = (r.stdout + r.stderr).decode(errors="replace")
                print("    time-stamp (RFC 3161):", "verified" if "Verification: OK" in txt else "NOT verified by this machine's CA list (see README)")
        except Exception as e:
            print("    time-stamp check skipped:", e)
    print("RESULT:", "log is append-only and consistent" if ok else "PROBLEM FOUND")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
