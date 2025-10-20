# decrypt_from_meta.py
import os
import sys

META_FILE = "random_ddos_prediction.txt.meta.txt"
ENC_FILE_DEFAULT = "random_ddos_prediction.txt.enc"
OUT_FILE = "random_ddos_prediction_decrypted.txt"

def read_meta(meta_path):
    meta = {}
    with open(meta_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or ":" not in line:
                continue
            k, v = line.split(":", 1)
            meta[k.strip()] = v.strip()
    return meta

def hex_to_bytes(h):
    return bytes.fromhex(h) if h else None

def decrypt_with_pycryptodome(key, nonce, tag, ciphertext):
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext

def decrypt_with_cryptography(key, nonce, tag, ciphertext):
    # cryptography AESGCM expects ciphertext||tag when calling decrypt
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    aesgcm = AESGCM(key)
    ct_and_tag = ciphertext + tag
    plaintext = aesgcm.decrypt(nonce, ct_and_tag, None)
    return plaintext

def main():
    if not os.path.exists(META_FILE):
        print(f"Meta file not found: {META_FILE}")
        sys.exit(1)

    meta = read_meta(META_FILE)
    # determine enc file path
    enc_file = meta.get("enc_file", ENC_FILE_DEFAULT)
    if not os.path.exists(enc_file):
        print(f"Encrypted file not found: {enc_file}")
        sys.exit(1)

    # required fields in meta: key_hex, nonce_hex, tag_hex
    key_hex = meta.get("key_hex")
    nonce_hex = meta.get("nonce_hex")
    tag_hex = meta.get("tag_hex")
    backend = meta.get("backend_used", "").lower()

    if not key_hex or not nonce_hex or not tag_hex:
        print("Meta file missing key_hex/nonce_hex/tag_hex. Aborting.")
        sys.exit(1)

    key = hex_to_bytes(key_hex)
    nonce = hex_to_bytes(nonce_hex)
    tag = hex_to_bytes(tag_hex)

    # read encrypted file bytes
    data = open(enc_file, "rb").read()

    # Our storage format was: nonce || tag || ciphertext
    # If that's the case, ciphertext = data[len(nonce)+len(tag):]
    expected_prefix = (nonce + tag)
    if data.startswith(expected_prefix):
        ciphertext = data[len(nonce) + len(tag):]
    else:
        # fallback: try common slicing: first 12 bytes = nonce, next 16 = tag
        if len(data) > 28:
            nonce_guess = data[:12]
            tag_guess = data[12:28]
            ciphertext_guess = data[28:]
            # if nonce matches meta nonce, accept
            if nonce_guess == nonce and tag_guess == tag:
                ciphertext = ciphertext_guess
            else:
                # otherwise, assume file contains only ciphertext (tag stored separately in meta)
                ciphertext = data
        else:
            ciphertext = data

    # try backend indicated in meta, else try both
    plaintext = None
    errors = []
    if backend:
        if "pycryptodome" in backend.lower() or "crypto.cipher" in backend.lower():
            try:
                plaintext = decrypt_with_pycryptodome(key, nonce, tag, ciphertext)
            except Exception as e:
                errors.append(("pycryptodome", str(e)))
        elif "cryptography" in backend.lower():
            try:
                plaintext = decrypt_with_cryptography(key, nonce, tag, ciphertext)
            except Exception as e:
                errors.append(("cryptography", str(e)))
        else:
            # unknown backend label — try both
            try:
                plaintext = decrypt_with_cryptography(key, nonce, tag, ciphertext)
            except Exception as e:
                errors.append(("cryptography", str(e)))
            if plaintext is None:
                try:
                    plaintext = decrypt_with_pycryptodome(key, nonce, tag, ciphertext)
                except Exception as e:
                    errors.append(("pycryptodome", str(e)))
    else:
        # try cryptography first, then pycryptodome
        try:
            plaintext = decrypt_with_cryptography(key, nonce, tag, ciphertext)
        except Exception as e:
            errors.append(("cryptography", str(e)))
        if plaintext is None:
            try:
                plaintext = decrypt_with_pycryptodome(key, nonce, tag, ciphertext)
            except Exception as e:
                errors.append(("pycryptodome", str(e)))

    if plaintext is None:
        print("Decryption failed. Errors:")
        for b, err in errors:
            print(f"- {b}: {err}")
        sys.exit(1)

    # write plaintext to file (binary -> decode if possible)
    try:
        with open(OUT_FILE, "wb") as f:
            f.write(plaintext)
        # also try decoding to utf-8 and print first few lines
        try:
            txt = plaintext.decode("utf-8")
            print("Decryption succeeded. First 500 chars of plaintext:")
            print(txt[:500])
        except Exception:
            print("Decryption succeeded but could not decode plaintext as UTF-8. Binary written to file.")
        print(f"Plaintext written to: {OUT_FILE}")
    except Exception as e:
        print(f"Failed to write output file: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
