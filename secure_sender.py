# sender_tcp.py
import json, time, os, base64, hashlib, socket
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

# ----- CONFIG -----
SERVER_HOST = "10.212.78.107"   # receiver address (change if receiver is on another machine)
SERVER_PORT = 7001
SENDER_PRIV_KEY_FILE = "sender_ed25519_priv.pem"
CAR_ID = "CAR_0123"
ENC_FILE = "random_ddos_prediction.txt.enc"
META_FILE = "meta_strip.txt"   # meta without key_hex
# ------------------

def compute_sha256_hex(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def read_meta(meta_path):
    out = {}
    with open(meta_path,"r",encoding="utf-8") as f:
        for line in f:
            if ":" in line:
                k,v=line.strip().split(":",1); out[k.strip()] = v.strip()
    return out

def load_priv(path):
    with open(path,"rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def build_canonical_payload():
    if not os.path.exists(ENC_FILE):
        raise SystemExit("Missing ENC file: " + ENC_FILE)
    if not os.path.exists(META_FILE):
        raise SystemExit("Missing META file: " + META_FILE)

    enc_hash = compute_sha256_hex(ENC_FILE)
    meta = read_meta(META_FILE)
    with open(ENC_FILE,"rb") as fh:
        data = fh.read()
    # encrypt_from_file.py wrote: nonce (12) + tag (16) + ciphertext
    nonce = data[:12]; tag = data[12:28]; ciphertext = data[28:]
    payload = {
        "car_id": CAR_ID,
        "ts": int(time.time()),
        "enc_hash": enc_hash,
        "meta": meta,
        "nonce": base64.b64encode(os.urandom(12)).decode(),
        "key_id": meta.get("key_id","session-20251020-0001"),
        "enc": base64.b64encode(ciphertext).decode(),
        "enc_nonce": base64.b64encode(nonce).decode(),
        "enc_tag": base64.b64encode(tag).decode()
    }
    canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    return payload, canonical

def sign_and_send():
    if not os.path.exists(SENDER_PRIV_KEY_FILE):
        raise SystemExit("Missing sender private key: " + SENDER_PRIV_KEY_FILE)

    priv = load_priv(SENDER_PRIV_KEY_FILE)
    payload, canonical = build_canonical_payload()
    sig = priv.sign(canonical)
    payload["sig"] = base64.b64encode(sig).decode()
    raw = json.dumps(payload).encode()

    # Plain TCP send (no TLS) - demo only
    with socket.create_connection((SERVER_HOST, SERVER_PORT), timeout=10) as sock:
        sock.sendall(raw)
    print("Sent payload to", SERVER_HOST, SERVER_PORT)

if __name__ == "__main__":
    sign_and_send()
