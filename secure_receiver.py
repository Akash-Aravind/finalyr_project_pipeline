# receiver_tcp.py
import socket, json, base64, time, os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ----- CONFIG -----
HOST = "0.0.0.0"
PORT = 7001
SENDER_PUB_KEY_FILE = "sender_ed25519_pub.pem"

# Put your actual 32-byte AES key here (from original meta key_hex) using bytes.fromhex(...)
KEY_STORE = {
    "session-20251020-0001": bytes.fromhex("f4d1e145e81e0ddce3892e1bdc06622b33694c18d392a5722669268386c6fc54")
}

MAX_AGE = 60  # seconds for timestamp freshness
NONCE_CACHE = set()
# -------------------

def load_sender_pub(path):
    if not os.path.exists(path):
        raise SystemExit("Missing sender public key: " + path)
    with open(path,"rb") as f:
        return serialization.load_pem_public_key(f.read())

def verify_signature(pubkey, payload_dict):
    sig_b64 = payload_dict.get("sig")
    if not sig_b64:
        raise RuntimeError("Missing signature")
    sig = base64.b64decode(sig_b64)
    # canonicalize by removing 'sig'
    data_copy = {k:v for k,v in payload_dict.items() if k!="sig"}
    canonical = json.dumps(data_copy, separators=(",", ":"), sort_keys=True).encode()
    pubkey.verify(sig, canonical)  # raises if invalid

def check_replay_and_freshness(payload):
    ts = int(payload.get("ts",0))
    if abs(time.time() - ts) > MAX_AGE:
        raise RuntimeError("Timestamp not fresh")
    nonce = payload.get("nonce")
    if nonce in NONCE_CACHE:
        raise RuntimeError("Replay detected (nonce reused)")
    NONCE_CACHE.add(nonce)
    if len(NONCE_CACHE) > 1000:
        NONCE_CACHE.pop()

def decrypt_and_print(payload):
    key_id = payload.get("key_id")
    key = KEY_STORE.get(key_id)
    if key is None:
        raise RuntimeError("Unknown key_id; receiver has no matching key: " + str(key_id))
    aes = AESGCM(key)
    nonce = base64.b64decode(payload["enc_nonce"])
    tag = base64.b64decode(payload["enc_tag"])
    ciphertext = base64.b64decode(payload["enc"])
    plaintext = aes.decrypt(nonce, ciphertext + tag, None)
    print("---- DECRYPTED MESSAGE ----")
    print(plaintext.decode(errors="ignore"))
    print("---------------------------")

def start_server():
    if not os.path.exists(SENDER_PUB_KEY_FILE):
        raise SystemExit("Missing sender public key file: " + SENDER_PUB_KEY_FILE)
    sender_pub = load_sender_pub(SENDER_PUB_KEY_FILE)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        print(f"Listening (plain TCP) on {HOST}:{PORT}")
        conn, addr = s.accept()
        with conn:
            print("Connection from", addr)
            data = b""
            while True:
                chunk = conn.recv(8192)
                if not chunk:
                    break
                data += chunk
            try:
                payload = json.loads(data.decode())
                verify_signature(sender_pub, payload)
                check_replay_and_freshness(payload)
                decrypt_and_print(payload)
            except Exception as e:
                print("Rejected message:", e)

if __name__ == "__main__":
    start_server()
