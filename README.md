# ZIP Decoder Bot

Telegram bot that auto-detects and decodes encoded files inside a `.zip` archive, then sends back a clean zip.

## Supported encodings

- Base64 (raw, multiline, JS `eval`/`atob` wrappers)
- Hex / `\x` escapes
- URI / percent-encoding
- HTML entities
- ROT13
- Unicode escapes (`\u1234`)
- JS string escapes
- JSON with Base64 field values
- Octal escapes
- Multi-layer / chained encodings (auto-unwrapped up to 6 passes)

Binary files (images, media, archives) are passed through untouched.

## Deploy on Render

1. Push this repo to GitHub
2. Go to [render.com](https://render.com) → New → Blueprint → connect your repo
3. Render picks up `render.yaml` automatically
4. Set `BOT_TOKEN` in the Environment tab (mark as secret)
5. Deploy

## Run locally

```bash
pip install -r requirements.txt
cp .env.example .env
# fill in BOT_TOKEN in .env
python bot.py
```

## Env vars

| Variable | Required | Default | Description |
|---|---|---|---|
| `BOT_TOKEN` | ✅ | — | BotFather token |
| `MAX_ZIP_MB` | ❌ | `50` | Max zip upload size in MB |
