# Discord Authentication Gateway Monitor

A lightweight, asynchronous Python utility for monitoring and interfacing with Discord's Remote Authentication Gateway (`wss://remote-auth-gateway.discord.gg`). This tool provides a clean, automated implementation of the cryptographic handshake required to negotiate temporary session tokens via mobile QR code authorization.

## Architecture

This script utilizes a standard Discord bot (`discord.py`) to deploy an interactive UI component (a "Fast Verify" button). When interacted with, the bot spawns an asynchronous task that:
1. Generates an ephemeral 2048-bit RSA-OAEP key pair.
2. Negotiates a secure WebSocket connection with the Remote Auth Gateway.
3. Decrypts the server's nonce challenge to establish cryptographic trust.
4. Retrieves a unique session fingerprint and presents it to the user as a login URL.
5. Monitors the WebSocket for mobile authorization (`pending_login`).
6. Exchanges the authorized ticket via Discord's HTTP API for an encrypted session token.
7. Decrypts the final token using the local private key.

## Dependencies

This tool requires Python 3.8+ and the following libraries:

```bash
pip install discord.py websockets cryptography aiohttp python-dotenv
```

## Configuration

1. Create a `.env` file in the root directory (you can copy `.env.example`):
   ```bash
   cp .env.example .env
   ```
2. Insert your bot's token into the `.env` file:
   ```env
   DISCORD_BOT_TOKEN=your_bot_token_here
   ```

## Deployment

1. Create a bot application on the [Discord Developer Portal](https://discord.com/developers/applications/).
2. Enable the **Message Content Intent** under the "Bot" tab (required to read the deployment command).
3. Run the script:
   ```bash
   python verification_bot.py
   ```
4. In your Discord server, type `!setup` in any channel. The bot will deploy the Verification UI and instantly delete your command message to maintain a clean channel state.

## Disclaimer

This project is an educational implementation of Discord's internal Remote Auth API. It is designed to demonstrate cryptographic handshakes, WebSocket lifecycle management, and asynchronous event handling. Use responsibly and only in environments where you have explicit permission to test authentication flows.
