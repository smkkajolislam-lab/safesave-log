#!/usr/bin/env python3
"""
Safe Save Sahittyo - public transparency log builder (runs in GitHub Actions, standard library only).

Reads the public `ledger` collection (hash + server time + RFC 3161 token, NO author identity, NO text),
appends new entries to log/entries.jsonl (append-only), builds an RFC 6962 Merkle tree,
checks that the previous checkpoint is still a prefix of the log (consistency),
publishes a new checkpoint and gets an independent RFC 3161 time-stamp on it.
"""
import base64, hashlib, json, os, re, subprocess, sys, tempfile
import urllib.parse, urllib.request
from datetime import datetime, timezone

PROJECT = os.environ.get("FIREBASE_PROJECT", "safesaveshaittyobysk")
API_KEY = os.environ.get("FIRESTORE_API_KEY", "")
ENTRIES = "log/entries.jsonl"
CKPT_DIR = "checkpoints"
HEARTBEAT_DAYS = 25
TSAS = [
    "http://timestamp.digicert.com",
    "https://timestamp.sectigo.com",
    "https://freetsa.org/tsr",
    "https://timestamp.sigstore.dev/api/v1/timestamp",
]


# ------------------------------------------------------------------ Merkle tree (RFC 6962)
def sha(*parts):
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def leaf_hash(line_bytes):
    return sha(b"\x00", line_bytes)


def mth(leaves, lo, hi):
    """Merkle Tree Hash of leaf hashes leaves[lo:hi]."""
    n = hi - lo
    if n == 0:
        return sha()
    if n == 1:
        return leaves[lo]
    k = 1
    while k * 2 < n:
        k *= 2
    return sha(b"\x01", mth(leaves, lo, lo + k), mth(leaves, lo + k, hi))


# ------------------------------------------------------------------ OpenSSL helpers
def _ca_args():
    if os.environ.get("CA_FILE"):
        return ["-CAfile", os.environ["CA_FILE"]]
    return ["-CApath", "/etc/ssl/certs"]


def _openssl(*args, data=None):
    return subprocess.run(["openssl", *args], input=data, capture_output=True)


_MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}


def parse_tsr(tsr, expected_hash_hex):
    """Returns {'gen': ISO time, 'imprint_ok': bool} or None if the reply is not a granted token."""
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "t.tsr")
        open(p, "wb").write(tsr)
        r = _openssl("ts", "-reply", "-in", p, "-text")
        if r.returncode != 0:
            return None
        text = r.stdout.decode(errors="replace")
    if "Status: Granted" not in text and "Status: Granted with modifications" not in text:
        return None
    m = re.search(r"Time stamp:\s*([A-Z][a-z]{2})\s+(\d+)\s+(\d\d):(\d\d):(\d\d)(?:\.\d+)?\s+(\d{4})", text)
    if not m:
        return None
    gen = datetime(int(m.group(6)), _MONTHS[m.group(1)], int(m.group(2)),
                   int(m.group(3)), int(m.group(4)), int(m.group(5)), tzinfo=timezone.utc)
    imprint = ""
    in_block = False
    for line in text.splitlines():
        if line.startswith("Message data:"):
            in_block = True
            continue
        if in_block:
            if re.match(r"^\s+[0-9a-f]{4} - ", line):
                seg = line[line.index(" - ") + 3: line.index(" - ") + 3 + 48]
                imprint += "".join(re.findall(r"[0-9a-f]{2}", seg))
            else:
                break
    return {"gen": gen.strftime("%Y-%m-%dT%H:%M:%SZ"), "imprint_ok": imprint == expected_hash_hex.lower()}


def verify_tsr(tsr, hash_hex=None, data_file=None):
    """Best effort: full OpenSSL verification of signature + chain. False is not fatal."""
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "t.tsr")
        tok = os.path.join(d, "t.tok")
        chain = os.path.join(d, "chain.pem")
        open(p, "wb").write(tsr)
        if _openssl("ts", "-reply", "-in", p, "-token_out", "-out", tok).returncode != 0:
            return False
        if _openssl("pkcs7", "-inform", "DER", "-in", tok, "-print_certs", "-out", chain).returncode != 0:
            return False
        args = ["ts", "-verify", "-in", p, *_ca_args(), "-untrusted", chain]
        args += ["-data", data_file] if data_file else ["-digest", hash_hex]
        r = _openssl(*args)
        return r.returncode == 0 and b"Verification: OK" in (r.stdout + r.stderr)


def tsa_stamp(data):
    """RFC 3161 time-stamp over `data`. Returns (tsr_bytes, url). Prefers a fully verifiable one."""
    sha_hex = hashlib.sha256(data).hexdigest()
    with tempfile.TemporaryDirectory() as d:
        f = os.path.join(d, "data")
        q = os.path.join(d, "req.tsq")
        open(f, "wb").write(data)
        if _openssl("ts", "-query", "-data", f, "-sha256", "-cert", "-out", q).returncode != 0:
            raise RuntimeError("cannot build timestamp query")
        query = open(q, "rb").read()
        fallback = None
        for url in TSAS:
            try:
                req = urllib.request.Request(url, data=query, headers={
                    "Content-Type": "application/timestamp-query",
                    "Accept": "application/timestamp-reply"})
                with urllib.request.urlopen(req, timeout=40) as r:
                    tsr = r.read()
                info = parse_tsr(tsr, sha_hex)
                if not info or not info["imprint_ok"]:
                    continue
                if verify_tsr(tsr, data_file=f):
                    return tsr, url
                if fallback is None:
                    fallback = (tsr, url)
            except Exception as e:
                print("TSA failed:", url, e, file=sys.stderr)
        if fallback:
            return fallback
    raise RuntimeError("no TSA available for the checkpoint")


# ------------------------------------------------------------------ ledger
def fetch_ledger():
    base = f"https://firestore.googleapis.com/v1/projects/{PROJECT}/databases/(default)/documents/ledger"
    out, token = [], None
    while True:
        q = {"pageSize": "300"}
        if token:
            q["pageToken"] = token
        if API_KEY:
            q["key"] = API_KEY
        with urllib.request.urlopen(base + "?" + urllib.parse.urlencode(q), timeout=60) as r:
            data = json.load(r)
        for doc in data.get("documents", []):
            f = doc.get("fields", {})
            try:
                out.append({
                    "id": doc["name"].rsplit("/", 1)[1],
                    "hash": f["hash"]["stringValue"],
                    "savedAt": f["savedAt"]["timestampValue"],
                    "tsaToken": f["tsaToken"]["stringValue"],
                    "tsaUrl": f.get("tsaUrl", {}).get("stringValue", ""),
                })
            except KeyError:
                continue
        token = data.get("nextPageToken")
        if not token:
            break
    out.sort(key=lambda e: (e["savedAt"], e["id"]))
    return out


def make_leaf(e):
    if not re.fullmatch(r"[0-9a-f]{64}", e["hash"]):
        return None
    try:
        tsr = base64.b64decode(e["tsaToken"], validate=False)
    except Exception:
        return None
    info = parse_tsr(tsr, e["hash"])
    if not info or not info["imprint_ok"]:
        return None
    obj = {
        "v": 1, "id": e["id"], "hash": e["hash"], "savedAt": e["savedAt"],
        "tsaGenTime": info["gen"], "tsaUrl": e["tsaUrl"],
        "tokenSha256": hashlib.sha256(tsr).hexdigest(),
        "tsaVerified": verify_tsr(tsr, hash_hex=e["hash"]),
    }
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


# ------------------------------------------------------------------ main
def read_lines(path):
    if not os.path.exists(path):
        return []
    return [l for l in open(path, encoding="utf-8").read().split("\n") if l]


def load_json(path):
    return json.load(open(path)) if os.path.exists(path) else None


def set_output(changed):
    path = os.environ.get("GITHUB_OUTPUT")
    if path:
        open(path, "a").write(f"changed={'true' if changed else 'false'}\n")
    print("changed =", changed)


def utcnow():
    return datetime.now(timezone.utc)


def main():
    os.makedirs("log", exist_ok=True)
    os.makedirs(CKPT_DIR, exist_ok=True)
    lines = read_lines(ENTRIES)
    known = {json.loads(l)["id"] for l in lines}
    prev = load_json(f"{CKPT_DIR}/latest.json")

    # 1) the log must still contain the previous checkpoint as a prefix
    if prev:
        leaves = [leaf_hash(l.encode()) for l in lines]
        if len(leaves) < prev["size"] or mth(leaves, 0, prev["size"]).hex() != prev["root"]:
            print("CONSISTENCY FAILURE: published history no longer matches the last checkpoint!", file=sys.stderr)
            sys.exit(1)

    # 2) append new, valid entries (never reorder or remove)
    new = []
    for e in fetch_ledger():
        if e["id"] in known:
            continue
        line = make_leaf(e)
        if line:
            new.append(line)
            known.add(e["id"])
        else:
            print("skipped invalid ledger entry", e["id"], file=sys.stderr)

    now = utcnow()
    heartbeat = False
    if prev and not new:
        age = now - datetime.strptime(prev["time"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        heartbeat = age.days >= HEARTBEAT_DAYS      # keeps the schedule alive and proves liveness
    if not new and not heartbeat:
        set_output(False)
        return

    all_lines = lines + new
    leaves = [leaf_hash(l.encode()) for l in all_lines]
    root = mth(leaves, 0, len(leaves)).hex()
    ckpt = {
        "origin": "safesave-log/v1", "size": len(all_lines), "root": root,
        "time": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "prevSize": prev["size"] if prev else 0, "prevRoot": prev["root"] if prev else "",
    }
    data = (json.dumps(ckpt, sort_keys=True, separators=(",", ":")) + "\n").encode()

    # 3) independent time-stamp first: if it fails nothing is written and the next run retries
    tsr, tsa_url = tsa_stamp(data)

    open(ENTRIES, "w", encoding="utf-8").write("\n".join(all_lines) + "\n")
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    for name in (f"{stamp}", "latest"):
        open(f"{CKPT_DIR}/{name}.json", "wb").write(data)
        open(f"{CKPT_DIR}/{name}.tsr", "wb").write(tsr)
    with open(f"{CKPT_DIR}/history.jsonl", "a", encoding="utf-8") as h:
        h.write(json.dumps({"size": ckpt["size"], "root": root, "time": ckpt["time"],
                            "file": stamp, "tsa": tsa_url}, sort_keys=True, separators=(",", ":")) + "\n")
    print(f"checkpoint size={ckpt['size']} root={root} new={len(new)} tsa={tsa_url}")
    set_output(True)


if __name__ == "__main__":
    main()
