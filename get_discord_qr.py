import asyncio
import websockets
import json
import base64
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import requests

async def main():
    print("[*] Generating RSA key pair...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    pub_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    encoded_pub_key = base64.b64encode(pub_der).decode('utf-8')

    print("[*] Connecting to Remote Auth Gateway...")
    headers = {"Origin": "https://discord.com"}
    
    async with websockets.connect("wss://remote-auth-gateway.discord.gg/?v=2", additional_headers=headers) as ws:
        while True:
            msg = await ws.recv()
            data = json.loads(msg)
            op = data.get("op")
            
            if op == "hello":
                init_payload = {
                    "op": "init",
                    "encoded_public_key": encoded_pub_key
                }
                await ws.send(json.dumps(init_payload))
                
            elif op == "nonce_proof":
                encrypted_nonce = base64.b64decode(data["encrypted_nonce"])
                nonce = private_key.decrypt(
                    encrypted_nonce,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                proof = base64.urlsafe_b64encode(hashlib.sha256(nonce).digest()).decode('utf-8').rstrip('=')
                
                await ws.send(json.dumps({
                    "op": "nonce_proof",
                    "proof": proof
                }))
                
            elif op == "pending_remote_init":
                fingerprint = data.get("fingerprint")
                qr_url = f"https://discord.com/ra/{fingerprint}"
                print(f"\n[+] Login URL Generated: {qr_url}")
                print("[!] Please scan the QR code generated from this URL using the Discord mobile app.")
                
            elif op == "pending_finish":
                print("[*] QR code scanned. Awaiting user confirmation...")
                
            elif op == "pending_login":
                print("[*] Login confirmed. Fetching session token...")
                ticket = data.get("ticket")
                req_data = {
                    "ticket": ticket
                }
                
                headers_http = {
                    "Content-Type": "application/json",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                }
                
                resp = requests.post(
                    "https://discord.com/api/v9/users/@me/remote-auth/login", 
                    json=req_data, 
                    headers=headers_http
                )
                
                if resp.status_code == 200:
                    encrypted_token = base64.b64decode(resp.json()["encrypted_token"])
                    token = private_key.decrypt(
                        encrypted_token,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    ).decode('utf-8')
                    print(f"\n[+] Successfully extracted token: {token}")
                else:
                    print(f"[-] Failed to retrieve token. Status: {resp.status_code}, Response: {resp.text}")
                    
                break

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[-] Operation aborted.")
