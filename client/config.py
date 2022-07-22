import rsa


public_key, private_key = rsa.newkeys(512)
with open(f"PU_client.pem", "wb") as f:
    pk = rsa.PublicKey.save_pkcs1(public_key)
    f.write(pk)

with open(f"PR_client.pem", "wb") as f:
    pk = rsa.PrivateKey.save_pkcs1(private_key)
    f.write(pk)