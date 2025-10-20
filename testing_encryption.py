# encrypt_from_file.py
import os
import random
import hashlib
from typing import List
import numpy as np

# ---------- CONFIG ----------
INPUT_FILE = "random_ddos_prediction.txt"
ENC_FILE = INPUT_FILE + ".enc"
META_FILE = INPUT_FILE + ".meta.txt"
N_QUBITS = 6000
SAMPLE_FRACTION = 0.1
FINAL_KEY_LEN_BYTES = 32
QBER_THRESHOLD = 0.11
# ----------------------------

def _pack_bits_to_bytes(bit_list: List[int]) -> bytes:
    rem = len(bit_list) % 8
    if rem != 0:
        bit_list = bit_list + [0] * (8 - rem)
    arr = np.packbits(np.array(bit_list, dtype=np.uint8))
    return bytes(arr)

def privacy_amplify_from_bits(bit_list: List[int], out_len_bytes: int) -> bytes:
    base = _pack_bits_to_bytes(bit_list)
    out = b''
    counter = 0
    while len(out) < out_len_bytes:
        h = hashlib.sha256()
        h.update(base)
        h.update(counter.to_bytes(4, 'big'))
        out += h.digest()
        counter += 1
    return out[:out_len_bytes]

def bb84_keygen_robust(n_qubits=N_QUBITS, sample_fraction=SAMPLE_FRACTION,
                       final_key_len_bytes=FINAL_KEY_LEN_BYTES, qber_threshold=QBER_THRESHOLD):
    # 1) Simulate bits/bases
    alice_bits = np.random.randint(0, 2, size=n_qubits).tolist()
    alice_bases = np.random.randint(0, 2, size=n_qubits).tolist()
    bob_bases = np.random.randint(0, 2, size=n_qubits).tolist()

    bob_results = []
    for i in range(n_qubits):
        if bob_bases[i] == alice_bases[i]:
            bob_results.append(alice_bits[i])
        else:
            bob_results.append(int(np.random.randint(0, 2)))

    # 2) Sift
    sifted_a, sifted_b = [], []
    for a_bit, a_basis, b_bit, b_basis in zip(alice_bits, alice_bases, bob_results, bob_bases):
        if a_basis == b_basis:
            sifted_a.append(a_bit)
            sifted_b.append(b_bit)

    sift_len = len(sifted_a)

    # 3) Sample for QBER
    sample_size = max(1, int(sift_len * sample_fraction)) if sift_len > 0 else 0
    if sample_size > 0:
        sample_indices = random.sample(range(sift_len), sample_size)
        sample_a = [sifted_a[i] for i in sample_indices]
        sample_b = [sifted_b[i] for i in sample_indices]
        qber = sum(1 for x, y in zip(sample_a, sample_b) if x != y) / len(sample_a)
    else:
        qber = 0.0

    if qber > qber_threshold:
        raise RuntimeError(f"QBER too high ({qber:.4f}); abort key generation.")

    keep = [i for i in range(sift_len) if sample_size == 0 or i not in sample_indices]
    remaining_bits = [sifted_b[i] for i in keep]

    required_bits = final_key_len_bytes * 8
    if len(remaining_bits) < required_bits:
        raise RuntimeError(f"Not enough sifted bits ({len(remaining_bits)}) to derive {final_key_len_bytes} bytes.")

    key_bytes = privacy_amplify_from_bits(remaining_bits, final_key_len_bytes)
    return key_bytes, qber, len(remaining_bits)

def aes_gcm_encrypt(key: bytes, plaintext: bytes):
    # Try PyCryptodome -> fallback to cryptography
    try:
        from Crypto.Cipher import AES
        from Crypto.Random import get_random_bytes
        nonce = get_random_bytes(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        # We'll store as: nonce || tag || ciphertext
        return nonce, tag, ciphertext, "PyCryptodome"
    except Exception:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            nonce = os.urandom(12)
            aesgcm = AESGCM(key)
            ct_and_tag = aesgcm.encrypt(nonce, plaintext, None)
            # cryptography's AESGCM returns ciphertext||tag (tag is last 16 bytes)
            tag = ct_and_tag[-16:]
            ciphertext = ct_and_tag[:-16]
            return nonce, tag, ciphertext, "cryptography"
        except Exception as e:
            raise RuntimeError("No AES-GCM backend available (install pycryptodome or cryptography).") from e

def main():
    if not os.path.exists(INPUT_FILE):
        raise SystemExit(f"Input file not found: {INPUT_FILE}")

    # Read plaintext from file (user requested: read from text file, not hard-coded variables)
    with open(INPUT_FILE, "rb") as f:
        plaintext = f.read()

    # Generate BB84-style key
    key, qber, remaining_bits_len = bb84_keygen_robust()

    # Encrypt plaintext
    nonce, tag, ciphertext, backend = aes_gcm_encrypt(key, plaintext)

    # Save: store (nonce || tag || ciphertext) in ENC_FILE
    with open(ENC_FILE, "wb") as f:
        f.write(nonce + tag + ciphertext)

    # Save metadata (key in hex, nonce, tag, backend, qber, remaining bits)
    with open(META_FILE, "w", encoding="utf-8") as f:
        f.write(f"backend_used: {backend}\n")
        f.write(f"key_hex: {key.hex()}\n")
        f.write(f"qber: {qber:.6f}\n")
        f.write(f"remaining_sifted_bits: {remaining_bits_len}\n")
        f.write(f"nonce_hex: {nonce.hex()}\n")
        f.write(f"tag_hex: {tag.hex()}\n")
        f.write(f"enc_file: {ENC_FILE}\n")

    # Print summary (hex prints truncated ciphertext)
    print("=== KEY GENERATION ===")
    print(f"Generated key ({len(key)} bytes): {key.hex()}")
    print(f"QBER estimate: {qber:.6f}")
    print(f"Remaining sifted bits: {remaining_bits_len}")
    print("=== ENCRYPTION ===")
    print(f"Backend used: {backend}")
    print(f"Nonce (hex): {nonce.hex()}")
    print(f"Tag   (hex): {tag.hex()}")
    print(f"Ciphertext (first 256 hex chars): {ciphertext.hex()[:256]} ...")
    print(f"Encrypted file written: {ENC_FILE}")
    print(f"Metadata file written: {META_FILE}")

if __name__ == "__main__":
    main()

# -------------------------
# Optional: how to decrypt (example, not executed here)
# Use values from META_FILE (key_hex, nonce_hex, tag_hex):
#
# from Crypto.Cipher import AES
# key = bytes.fromhex(key_hex)
# nonce = bytes.fromhex(nonce_hex)
# tag = bytes.fromhex(tag_hex)
# with open(ENC_FILE, "rb") as f:
#     data = f.read()
# # if you stored nonce||tag||ciphertext, slice accordingly:
# # plaintext = AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ciphertext, tag)
#
# If using 'cryptography' backend: reconstruct AESGCM(key).decrypt(nonce, ciphertext+tag, None)
