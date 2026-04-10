# gateway-service-example
Example app running the gateway service for the decentralized XMTP network

## Setup

1. Copy `.env.example` to `.env` and fill in required values:
   - Get Alchemy URLs for the XMTP Ropsten chain (APP_CHAIN) and the Base Sepolia (SETTLEMENT_CHAIN)
   - Generate a payer private key: `xmtpd-cli keys generat
   e`
   - Set the appropriate XMTP environment for your needs

2. Start Redis:
   ```bash
   docker-compose up -d redis
   ```

3. Run the gateway service:
   - Local development: `./dev/start`
   - Docker: `./dev/up`

## Customizing

The Gateway Service is designed to subsidize publishing to the XMTP network. Before deploying publicly, you will want to customize the authorization logic to ensure that only valid requests from your users are allowed through.

Learn more about customizing your Gateway Service [here](https://docs.xmtp.org/fund-agents-apps/run-gateway).

### World Chat token auth

This repo now supports an opt-in publish authorizer that validates the existing World Chat backend token before allowing `PublishClientEnvelopes`.

Enable it with either:

- `WORLD_CHAT_GATEWAY_AUTH_MODE=enforce`
- `WORLD_CHAT_GATEWAY_AUTH_KID=<world-chat-jwt-kid>`
- `WORLD_CHAT_GATEWAY_AUTH_PUBLIC_KEY_PEM=<ES256 public key PEM>`

Optional settings:

- `WORLD_CHAT_GATEWAY_AUTH_MODE` supports `disabled`, `report_only`, and `enforce`
- `WORLD_CHAT_GATEWAY_AUTH_ENABLED=true` is still accepted as a backward-compatible alias for `enforce` when `WORLD_CHAT_GATEWAY_AUTH_MODE` is unset
- `WORLD_CHAT_GATEWAY_AUTH_ISSUER` defaults to `chat.toolsforhumanity.com`
- `WORLD_CHAT_GATEWAY_AUTH_ISSUED_AFTER` defaults to `2025-12-07T00:00:00Z` to mirror the chat backend cutoff

Notes:

- The public key env accepts literal `\n`, so it can be stored as a single env var value.
- Auth is checked only for publish requests.
- `disabled` keeps the previous allow-all behavior.
- `report_only` validates and logs failures but still allows the publish.
- `enforce` rejects invalid or missing auth.

## Installing the xmtpd-cli (optional)

### MacOS
```
brew tap xmtp/tap
brew install xmtpd-cli
```
