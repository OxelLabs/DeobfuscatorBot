# ZIP Deobfuscator Bot

Production Telegram bot for Render web service deployment. It runs as a web service, starts an aiohttp health server on `$PORT`, polls Telegram, accepts `.zip` files, decodes supported obfuscation in isolated per-file processes, and sends the decoded zip back automatically.

## Deploy on Render

1. Create a new GitHub repository and upload these files.
2. In Render, create a new Blueprint or Web Service from the repo.
3. Use Docker runtime.
4. Add environment variable `BOT_TOKEN` from BotFather.
5. Deploy.

The service exposes:

- `/`
- `/health`
- `/status`

## Important environment variables

- `BOT_TOKEN`: Telegram bot token.
- `MAX_ZIP_MB`: maximum Telegram zip input size, default `50`.
- `MAX_UNCOMPRESSED_MB`: maximum total unzipped input size, default `250`.
- `MAX_FILES`: maximum files inside a zip, default `1200`.
- `FILE_TIMEOUT_SECONDS`: hard timeout for each file decoder process, default `22`.
- `TOTAL_JOB_TIMEOUT_SECONDS`: whole job timeout, default `1200`.
- `TELEGRAM_UPLOAD_LIMIT_MB`: output zip split target, default `48`.
- `MAX_CONCURRENT_JOBS`: concurrent zip jobs, default `1`.

## Supported decoding

- JavaScript `_0x` string-array obfuscation
- JavaScript `eval`, `Function`, `setTimeout` string wrappers
- JavaScript `atob` and `Buffer.from(..., "base64")`
- Dean Edwards style packed JavaScript capture
- Optional external JavaScript deobfuscation through Node CLI tools installed in Docker
- JSFuck
- Brainfuck
- PHP `eval(base64_decode(...))`, `assert(base64_decode(...))`, `gzinflate(base64_decode(...))`, `str_rot13`
- Python marshal code object disassembly from base64 or hex payloads
- JSON base64 fields
- Raw base64 and URL-safe base64
- gzip and zlib payloads
- Hex blobs and `\x..` style strings
- Unicode, octal, and common string escapes
- URL encoding
- HTML entities
- ROT13
- Reversed code strings
- Single-byte XOR
- JavaScript beautifying

## Reliability fixes in this build

- The bot processes immediately after upload and does not depend on a callback button before starting.
- Every file decode runs in a separate process with a hard timeout.
- The final output is written to disk and sent using `FSInputFile`, not a huge in-memory Telegram upload.
- Telegram send operations have retries and long request timeouts.
- If the decoded zip is larger than the Telegram upload target, it is split into multiple zip parts.
- Every result zip includes `DECODE_REPORT.txt`.
- If processing fails, the bot still sends a failure report instead of silently hanging.
