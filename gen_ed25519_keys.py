# gen_ed25519_keys.py  (run on sender)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

priv = Ed25519PrivateKey.generate()
priv_pem = priv.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
pub = priv.public_key()
pub_pem = pub.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

open("sender_ed25519_priv.pem","wb").write(priv_pem)
open("sender_ed25519_pub.pem","wb").write(pub_pem)
print("Created sender_ed25519_priv.pem and sender_ed25519_pub.pem")
