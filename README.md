# ZIP Deobfuscator Bot

A production Telegram bot that auto-detects and removes obfuscation/encoding from every text file inside a `.zip` archive, then returns a clean zip preserving the original folder structure.

## Features

- Inline-keyboard driven UX (confirm → live progress bar → report → send another)
- Live progress bar updated every 1.5 s
- Multi-layer chained decoding (up to 20 passes per file, stops via MD5 hash stability)
- Binary files (images, media, archives, fonts, compiled binaries) are passed through untouched

### Supported encodings / obfuscations

- JavaScript `_0x` obfuscation (via `synchrony` CLI + pure-regex fallback)
- JS `eval()` / `Function()` wrappers
- JS `atob()` / `Buffer.from(..., 'base64')`
- Python `marshal.loads`, `exec(compile(...))`, `exec('\\x..')`
- Base64 — single-line, multi-line, chunk-scattered
- Hex strings & `\x` escapes
- URI percent-encoding
- HTML entities
- Unicode `\uXXXX` escapes
- Octal `\NNN` escapes
- JS string escapes (`\n \t \r ...`)
- JSON objects with Base64-encoded string fields
- ROT13
- JSFuck (via `node -e`)
- Brainfuck (pure-Python interpreter, 1M step cap)
- PHP `eval(base64_decode(...))` / `eval(gzinflate(base64_decode(...)))` chains
- Java / Kotlin unicode escape strings
- String reversal
- Single-byte XOR

All JS output runs through `jsbeautifier` (2-space indent).

## Local setup

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
# Optional but recommended for JS _0x obfuscation:
npm install -g @relative/synchrony deobfuscator
cp .env.example .env
# edit .env and set BOT_TOKEN=...
export $(cat .env | xargs)
python bot.py
```

## Deploy to Render (free web service)

1. Push this folder to a GitHub repo.
2. In Render → **New +** → **Blueprint** → select the repo. Render reads `render.yaml`.
3. Set the `BOT_TOKEN` env var (from [@BotFather](https://t.me/BotFather)).
4. Optionally adjust `MAX_ZIP_MB` (default 50).
5. Click **Apply**.

`render.yaml` is configured as a **web service** (free tier requirement) and the bot runs an `aiohttp` health server on `$PORT` while doing long-polling against Telegram.

The build command installs Node.js + npm and global tools (`javascript-obfuscator`, `deobfuscator`, `@relative/synchrony`) so the JS deobfuscation pipeline works end-to-end.

## Usage

1. Open the bot in Telegram, send `/start`.
2. Send a `.zip` file.
3. Tap **✅ Decode it**.
4. Watch the live progress bar.
5. Receive the decode report + clean zip.
6. Tap **📦 Send another zip** to loop.

## Env vars

| Var          | Default | Notes                                       |
|--------------|---------|---------------------------------------------|
| `BOT_TOKEN`  | —       | Required. From @BotFather.                  |
| `MAX_ZIP_MB` | `50`    | Reject zips larger than this.               |
| `PORT`       | `8080`  | Provided by Render automatically.           |
