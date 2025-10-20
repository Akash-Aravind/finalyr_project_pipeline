# Create meta_strip.txt (no key_hex)
with open("random_ddos_prediction.txt.meta.txt","r") as f:
    lines = [l for l in f if not l.startswith("key_hex:")]
with open("meta_strip.txt","w") as f:
    f.writelines(lines)
print("meta_strip.txt created without key_hex")
