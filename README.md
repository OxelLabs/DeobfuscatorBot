# ZIP Deobfuscator Bot

Production Telegram bot that accepts a `.zip`, decodes obfuscated or encoded text files inside it, and returns a clean zip while preserving folder structure.

## What was fixed

The bot now has hard per-file decoder isolation. A bad file can no longer freeze the full job for hours. Each text file is decoded in a separate process and is terminated after `FILE_TIMEOUT_SECONDS`. If one file times out, the original file is kept, the report notes it, and the bot continues to the next file.

## Supported decoding

- JavaScript `_0x` deobfuscation with external tools for safe-sized files and regex fallback
- JavaScript `eval()`, `Function()`, `atob()`, `Buffer.from(..., 'base64')`
- Python `marshal.loads`, `exec(compile(...))`, `exec('\x..')`
- Base64, chunked Base64, hex strings, `\x` escapes
- URI percent-encoding, HTML entities, Unicode escapes, octal escapes
- JavaScript string escapes
- JSON fields containing Base64
- ROT13
- JSFuck using Node.js when available
- Brainfuck with a step cap
- PHP `eval(base64_decode(...))` and `gzinflate(base64_decode(...))`
- String reversal
- Single-byte XOR

## Deploy to Render as a web service

1. Push the files to GitHub.
2. In Render, create a Blueprint or Web Service from the repo.
3. Render reads `render.yaml` and builds the Docker web service.
4. Set `BOT_TOKEN` from BotFather.
5. Deploy.

This is a Render web service, not a worker. The bot starts an `aiohttp` health server on `$PORT` and uses Telegram polling.

## Environment variables

| Name | Default | Purpose |
| --- | --- | --- |
| `BOT_TOKEN` | required | Telegram bot token from BotFather |
| `MAX_ZIP_MB` | `50` | Maximum uploaded zip size |
| `MAX_UNCOMPRESSED_MB` | `250` | Zip-bomb protection limit |
| `MAX_FILES` | `800` | Maximum files per archive |
| `FILE_TIMEOUT_SECONDS` | `18` | Hard timeout per text file |
| `TOTAL_JOB_TIMEOUT_SECONDS` | `900` | Whole job timeout |
| `MAX_CONCURRENT_JOBS` | `1` | Keeps free-tier CPU stable |
| `MAX_EXTERNAL_JS_BYTES` | `350000` | Maximum file size for external JS deobfuscators |
| `MAX_BEAUTIFY_BYTES` | `1000000` | Maximum JS size for beautifier |
| `MAX_DECODE_TEXT_BYTES` | `6000000` | Maximum text file size to decode |

## Local run

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
npm install -g @relative/synchrony deobfuscator javascript-obfuscator
export BOT_TOKEN=123456:your_token
python bot.py
```

Open the bot in Telegram, send `/start`, upload a zip, and tap **Decode it**.
