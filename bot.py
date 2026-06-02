import asyncio
import base64
import binascii
import codecs
import hashlib
import html
import io
import json
import logging
import math
import os
import re
import struct
import urllib.parse
import zipfile
import zlib
from pathlib import Path
from typing import Optional

from aiogram import Bot, Dispatcher, F
from aiogram.enums import ParseMode
from aiogram.filters import CommandStart, Command
from aiogram.types import (
    BufferedInputFile,
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
)
from aiogram.utils.keyboard import InlineKeyboardBuilder

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

TOKEN = os.environ["BOT_TOKEN"]
MAX_ZIP_MB = int(os.environ.get("MAX_ZIP_MB", "50"))

bot = Bot(token=TOKEN)
dp = Dispatcher()

pending_jobs: dict[str, bytes] = {}

BINARY_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tiff", ".ico",
    ".mp4", ".mp3", ".wav", ".flac", ".ogg", ".avi", ".mkv", ".mov",
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
    ".exe", ".dll", ".so", ".bin", ".dat", ".class", ".pyc",
    ".pdf", ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".psd", ".ai", ".sketch",
}

TEXT_EXTS = {
    ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    ".py", ".rb", ".php", ".java", ".cs", ".go", ".rs", ".cpp", ".c", ".h",
    ".html", ".htm", ".css", ".scss", ".sass", ".less",
    ".json", ".xml", ".yaml", ".yml", ".toml", ".ini", ".env",
    ".txt", ".md", ".csv", ".sql", ".sh", ".bat", ".ps1",
    ".vue", ".svelte", ".astro",
}


def safe_decode(data: bytes) -> Optional[str]:
    for enc in ("utf-8", "latin-1", "cp1252"):
        try:
            return data.decode(enc)
        except Exception:
            pass
    return None


def is_printable_text(data: bytes) -> bool:
    if len(data) == 0:
        return False
    sample = data[:4096]
    try:
        text = sample.decode("utf-8")
    except Exception:
        return False
    non_printable = sum(1 for c in text if ord(c) < 32 and c not in "\n\r\t")
    return non_printable / max(len(text), 1) < 0.05


def strip_outer_quotes(s: str) -> str:
    s = s.strip()
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        return s[1:-1]
    return s


def detect_and_decode(data: bytes, filename: str) -> tuple[bytes, list[str]]:
    methods_applied = []
    current = data
    max_passes = 6

    for _ in range(max_passes):
        result, method = _single_pass(current, filename)
        if method is None:
            break
        methods_applied.append(method)
        current = result
        if len(methods_applied) > 10:
            break

    return current, methods_applied


def _single_pass(data: bytes, filename: str) -> tuple[bytes, Optional[str]]:
    text = safe_decode(data)

    if text is not None:
        result = _try_js_eval_unwrap(text, data)
        if result is not None:
            return result, "js_eval_unwrap"

    if text is not None:
        result = _try_pure_base64(text)
        if result is not None:
            return result, "base64"

    if text is not None:
        result = _try_hex(text)
        if result is not None:
            return result, "hex"

    if text is not None:
        result = _try_uri_encoding(text)
        if result is not None:
            return result, "uri_encoded"

    if text is not None:
        result = _try_html_entities(text)
        if result is not None:
            return result, "html_entities"

    if text is not None:
        result = _try_rot13(text)
        if result is not None:
            return result, "rot13"

    if text is not None:
        result = _try_unicode_escapes(text)
        if result is not None:
            return result, "unicode_escapes"

    if text is not None:
        result = _try_js_string_escape(text)
        if result is not None:
            return result, "js_string_escape"

    if text is not None:
        result = _try_json_base64_values(text)
        if result is not None:
            return result, "json_base64_values"

    if text is not None:
        result = _try_base64_multiline(text)
        if result is not None:
            return result, "base64_multiline"

    if text is not None:
        result = _try_octal_escape(text)
        if result is not None:
            return result, "octal_escape"

    return data, None


def _try_js_eval_unwrap(text: str, raw: bytes) -> Optional[bytes]:
    patterns = [
        r'(?:let|var|const)\s+\w*encoded\w*\s*=\s*["\'\`]([A-Za-z0-9+/=\s]{60,})["\'\`]',
        r'(?:eval|exec)\s*\(\s*(?:atob|Buffer\.from)\s*\(\s*["\']([A-Za-z0-9+/=\s]{60,})["\']',
        r'atob\s*\(\s*["\']([A-Za-z0-9+/=\s]{60,})["\']',
        r'Buffer\.from\s*\(\s*["\']([A-Za-z0-9+/=\s]{60,})["\'],\s*["\']base64["\']\s*\)',
        r'(?:decode|fromBase64|b64decode)\s*\(\s*["\']([A-Za-z0-9+/=\s]{60,})["\']',
        r'_0x[0-9a-f]+\s*\(\s*["\']([A-Za-z0-9+/=\s]{60,})["\']',
    ]
    for pat in patterns:
        m = re.search(pat, text, re.DOTALL | re.IGNORECASE)
        if m:
            b64 = re.sub(r"\s+", "", m.group(1))
            pad = b64 + "=" * ((-len(b64)) % 4)
            try:
                decoded = base64.b64decode(pad)
                if is_printable_text(decoded):
                    return decoded
            except Exception:
                pass
    return None


def _try_pure_base64(text: str) -> Optional[bytes]:
    stripped = text.strip()
    clean = re.sub(r"\s+", "", stripped)
    if len(clean) < 40:
        return None
    if not re.fullmatch(r"[A-Za-z0-9+/=]+", clean):
        return None
    if len(clean) % 4 != 0 and "=" not in clean:
        pad = clean + "=" * ((-len(clean)) % 4)
    else:
        pad = clean
    try:
        decoded = base64.b64decode(pad)
        if is_printable_text(decoded) and len(decoded) > 10:
            ratio = len(decoded) / len(clean)
            if 0.5 <= ratio <= 1.0:
                return decoded
    except Exception:
        pass
    return None


def _try_base64_multiline(text: str) -> Optional[bytes]:
    lines = [l.strip() for l in text.strip().splitlines() if l.strip()]
    if len(lines) < 2:
        return None
    combined = "".join(lines)
    if not re.fullmatch(r"[A-Za-z0-9+/=]+", combined):
        return None
    if len(combined) < 60:
        return None
    pad = combined + "=" * ((-len(combined)) % 4)
    try:
        decoded = base64.b64decode(pad)
        if is_printable_text(decoded):
            return decoded
    except Exception:
        pass
    return None


def _try_hex(text: str) -> Optional[bytes]:
    stripped = text.strip()
    clean = re.sub(r"[\s\n\r]+", "", stripped)
    clean = re.sub(r"^(0x)+", "", clean, flags=re.IGNORECASE)
    clean = re.sub(r"\\x", "", clean)
    if len(clean) < 20 or len(clean) % 2 != 0:
        return None
    if not re.fullmatch(r"[0-9a-fA-F]+", clean):
        return None
    try:
        decoded = bytes.fromhex(clean)
        if is_printable_text(decoded):
            return decoded
    except Exception:
        pass
    hex_escape_pattern = r"(?:\\x[0-9a-fA-F]{2})+"
    if re.search(hex_escape_pattern, stripped):
        try:
            result = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), stripped)
            return result.encode("utf-8")
        except Exception:
            pass
    return None


def _try_uri_encoding(text: str) -> Optional[bytes]:
    stripped = text.strip()
    if "%" not in stripped:
        return None
    pct_count = stripped.count("%")
    if pct_count < 5:
        return None
    total_chars = len(stripped.replace(" ", "").replace("\n", ""))
    if pct_count / max(total_chars, 1) < 0.05:
        return None
    try:
        decoded = urllib.parse.unquote(stripped, errors="strict")
        if decoded != stripped and is_printable_text(decoded.encode("utf-8")):
            return decoded.encode("utf-8")
    except Exception:
        pass
    try:
        decoded = urllib.parse.unquote_plus(stripped)
        if decoded != stripped and is_printable_text(decoded.encode("utf-8")):
            return decoded.encode("utf-8")
    except Exception:
        pass
    return None


def _try_html_entities(text: str) -> Optional[bytes]:
    if "&" not in text or ";" not in text:
        return None
    entity_count = len(re.findall(r"&(?:#\d+|#x[0-9a-fA-F]+|[a-zA-Z]+);", text))
    if entity_count < 3:
        return None
    decoded = html.unescape(text)
    if decoded != text:
        return decoded.encode("utf-8")
    return None


def _try_rot13(text: str) -> Optional[bytes]:
    stripped = text.strip()
    if len(stripped) < 20:
        return None
    if not re.search(r"[a-zA-Z]", stripped):
        return None
    decoded = codecs.decode(stripped, "rot_13")
    if _looks_like_real_code_or_text(decoded) and not _looks_like_real_code_or_text(stripped):
        return decoded.encode("utf-8")
    return None


def _looks_like_real_code_or_text(text: str) -> bool:
    keywords = ["function", "const", "var", "let", "return", "import", "export",
                 "class", "def ", "print", "require", "module", "if ", "for ",
                 "while", "async", "await", "the ", "and ", "this", "that"]
    lower = text.lower()
    hits = sum(1 for kw in keywords if kw in lower)
    return hits >= 2


def _try_unicode_escapes(text: str) -> Optional[bytes]:
    if "\\u" not in text and "\\U" not in text:
        return None
    count = len(re.findall(r"\\u[0-9a-fA-F]{4}", text))
    if count < 3:
        return None
    try:
        decoded = text.encode("utf-8").decode("unicode_escape")
        if is_printable_text(decoded.encode("utf-8")):
            return decoded.encode("utf-8")
    except Exception:
        pass
    try:
        decoded = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), text)
        return decoded.encode("utf-8")
    except Exception:
        pass
    return None


def _try_js_string_escape(text: str) -> Optional[bytes]:
    if "\\" not in text:
        return None
    escape_count = len(re.findall(r"\\[nrtbf\"'\\]", text))
    if escape_count < 3:
        return None
    try:
        decoded = text.encode("utf-8").decode("unicode_escape")
        if is_printable_text(decoded.encode("utf-8")) and decoded != text:
            return decoded.encode("utf-8")
    except Exception:
        pass
    return None


def _try_json_base64_values(text: str) -> Optional[bytes]:
    try:
        obj = json.loads(text)
    except Exception:
        return None

    changed = [False]

    def transform(o):
        if isinstance(o, str) and len(o) > 40:
            clean = re.sub(r"\s+", "", o)
            if re.fullmatch(r"[A-Za-z0-9+/=]+", clean) and len(clean) % 4 == 0:
                try:
                    decoded = base64.b64decode(clean).decode("utf-8")
                    changed[0] = True
                    return decoded
                except Exception:
                    pass
        if isinstance(o, dict):
            return {k: transform(v) for k, v in o.items()}
        if isinstance(o, list):
            return [transform(i) for i in o]
        return o

    result = transform(obj)
    if changed[0]:
        return json.dumps(result, indent=2, ensure_ascii=False).encode("utf-8")
    return None


def _try_octal_escape(text: str) -> Optional[bytes]:
    if "\\" not in text:
        return None
    count = len(re.findall(r"\\[0-7]{3}", text))
    if count < 3:
        return None
    try:
        decoded = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), text)
        if is_printable_text(decoded.encode("utf-8")):
            return decoded.encode("utf-8")
    except Exception:
        pass
    return None


def process_zip(raw: bytes, progress_cb=None) -> tuple[bytes, dict]:
    stats = {
        "decoded": [],
        "clean": [],
        "binary_skipped": [],
        "error": [],
    }
    method_counts: dict[str, int] = {}

    with zipfile.ZipFile(io.BytesIO(raw)) as zin:
        all_items = [i for i in zin.infolist() if not i.is_dir()]
        total = len(all_items)

    out_buf = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(raw)) as zin, zipfile.ZipFile(out_buf, "w", zipfile.ZIP_DEFLATED) as zout:
        for idx, item in enumerate(zin.infolist()):
            if item.is_dir():
                try:
                    zout.mkdir(item)
                except Exception:
                    pass
                continue

            if progress_cb:
                progress_cb(idx + 1, total, item.filename)

            try:
                data = zin.read(item.filename)
            except Exception as e:
                stats["error"].append(f"{item.filename}: read error {e}")
                continue

            ext = Path(item.filename).suffix.lower()
            if ext in BINARY_EXTS:
                zout.writestr(item, data)
                stats["binary_skipped"].append(item.filename)
                continue

            try:
                cleaned, methods = detect_and_decode(data, item.filename)
                zout.writestr(item, cleaned)
                if methods:
                    label = " → ".join(methods)
                    stats["decoded"].append({"file": item.filename, "methods": label})
                    for m in methods:
                        method_counts[m] = method_counts.get(m, 0) + 1
                else:
                    stats["clean"].append(item.filename)
            except Exception as e:
                log.exception(f"Error processing {item.filename}")
                zout.writestr(item, data)
                stats["error"].append(f"{item.filename}: {e}")

    stats["method_counts"] = method_counts
    return out_buf.getvalue(), stats


def build_confirm_kb(job_id: str) -> InlineKeyboardMarkup:
    kb = InlineKeyboardBuilder()
    kb.button(text="✅ Decode it", callback_data=f"confirm:{job_id}")
    kb.button(text="❌ Cancel", callback_data=f"cancel:{job_id}")
    kb.adjust(2)
    return kb.as_markup()


def build_done_kb() -> InlineKeyboardMarkup:
    kb = InlineKeyboardBuilder()
    kb.button(text="📦 Send another zip", callback_data="new")
    kb.button(text="✔️ Done", callback_data="done")
    kb.adjust(2)
    return kb.as_markup()


def build_report(stats: dict, original_size: int, result_size: int) -> str:
    decoded_count = len(stats["decoded"])
    clean_count = len(stats["clean"])
    skip_count = len(stats["binary_skipped"])
    err_count = len(stats["error"])
    method_counts: dict = stats.get("method_counts", {})

    lines = ["<b>🔬 Decode Report</b>\n"]
    lines.append(f"📂 Decoded files:   <b>{decoded_count}</b>")
    lines.append(f"✨ Already clean:   <b>{clean_count}</b>")
    lines.append(f"⏭ Binary skipped:  <b>{skip_count}</b>")
    if err_count:
        lines.append(f"⚠️ Errors:          <b>{err_count}</b>")
    lines.append("")

    if method_counts:
        lines.append("<b>📊 Encoding types found:</b>")
        method_labels = {
            "base64": "Base64",
            "base64_multiline": "Base64 multiline",
            "js_eval_unwrap": "JS eval/atob wrapper",
            "hex": "Hex",
            "uri_encoded": "URI / percent-encoded",
            "html_entities": "HTML entities",
            "rot13": "ROT13",
            "unicode_escapes": "Unicode escapes (\\u)",
            "js_string_escape": "JS string escapes",
            "json_base64_values": "JSON with Base64 values",
            "octal_escape": "Octal escapes (\\0)",
        }
        for method, count in sorted(method_counts.items(), key=lambda x: -x[1]):
            label = method_labels.get(method, method)
            lines.append(f"  • {label}: <b>{count}</b>")
        lines.append("")

    orig_kb = original_size / 1024
    res_kb = result_size / 1024
    lines.append(f"📦 Original size: <b>{orig_kb:.1f} KB</b>")
    lines.append(f"📦 Output size:   <b>{res_kb:.1f} KB</b>")

    if decoded_count > 0 and decoded_count <= 20:
        lines.append("\n<b>📝 Files decoded:</b>")
        for entry in stats["decoded"][:20]:
            fname = Path(entry["file"]).name
            lines.append(f"  <code>{fname}</code> → {entry['methods']}")

    if stats["error"]:
        lines.append("\n<b>⚠️ Errors:</b>")
        for e in stats["error"][:5]:
            lines.append(f"  <code>{e[:80]}</code>")

    return "\n".join(lines)


@dp.message(CommandStart())
async def cmd_start(msg: Message):
    await msg.answer(
        "🤖 <b>ZIP Decoder Bot</b>\n\n"
        "Send me any <code>.zip</code> file and I'll automatically detect and decode every encoded file inside.\n\n"
        "<b>Supported encodings:</b>\n"
        "• Base64 (raw, multiline, JS eval/atob wrappers)\n"
        "• Hex / \\x escapes\n"
        "• URI / percent-encoding\n"
        "• HTML entities\n"
        "• ROT13\n"
        "• Unicode escapes (\\u1234)\n"
        "• JS string escapes\n"
        "• JSON with Base64 field values\n"
        "• Octal escapes\n"
        "• Multi-layer/chained encodings (auto-unwrapped)\n\n"
        "Binary files are passed through untouched.\n"
        f"Max size: <b>{MAX_ZIP_MB} MB</b>",
        parse_mode=ParseMode.HTML,
    )


@dp.message(Command("help"))
async def cmd_help(msg: Message):
    await cmd_start(msg)


@dp.message(F.document)
async def handle_doc(msg: Message):
    doc = msg.document
    if not doc.file_name.lower().endswith(".zip"):
        await msg.answer("❗ Please send a <code>.zip</code> file.", parse_mode=ParseMode.HTML)
        return

    file_mb = doc.file_size / (1024 * 1024)
    if file_mb > MAX_ZIP_MB:
        await msg.answer(f"❗ File too large (<b>{file_mb:.1f} MB</b>). Max is <b>{MAX_ZIP_MB} MB</b>.", parse_mode=ParseMode.HTML)
        return

    status = await msg.answer("⬇️ Downloading...")
    buf = io.BytesIO()
    await bot.download(doc, destination=buf)
    raw = buf.getvalue()

    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            all_files = [i for i in zf.infolist() if not i.is_dir()]
            total_files = len(all_files)
            total_size = sum(i.file_size for i in all_files)
    except zipfile.BadZipFile:
        await status.edit_text("❌ Invalid zip file.")
        return

    job_id = f"{msg.from_user.id}_{msg.message_id}"
    pending_jobs[job_id] = raw

    size_kb = total_size / 1024
    await status.edit_text(
        f"📂 <b>{doc.file_name}</b>\n"
        f"📄 <b>{total_files}</b> file(s) — <b>{size_kb:.1f} KB</b> uncompressed\n\n"
        f"Start decoding?",
        parse_mode=ParseMode.HTML,
        reply_markup=build_confirm_kb(job_id),
    )


@dp.callback_query(F.data.startswith("confirm:"))
async def cb_confirm(cq: CallbackQuery):
    job_id = cq.data.split(":", 1)[1]
    raw = pending_jobs.pop(job_id, None)
    if raw is None:
        await cq.answer("Session expired. Resend the zip.", show_alert=True)
        await cq.message.edit_reply_markup(reply_markup=None)
        return

    await cq.answer()
    progress_msg = await cq.message.edit_text("⚙️ Starting...", reply_markup=None)

    last_update = [0]

    async def update_progress(current: int, total: int, filename: str):
        now = asyncio.get_event_loop().time()
        if now - last_update[0] < 1.5 and current != total:
            return
        last_update[0] = now
        pct = int(current / max(total, 1) * 100)
        bar_filled = int(pct / 10)
        bar = "█" * bar_filled + "░" * (10 - bar_filled)
        fname = Path(filename).name[:35]
        try:
            await progress_msg.edit_text(
                f"⚙️ Processing...\n"
                f"[{bar}] {pct}%\n"
                f"<code>{current}/{total}</code> — <code>{fname}</code>",
                parse_mode=ParseMode.HTML,
            )
        except Exception:
            pass

    loop = asyncio.get_event_loop()
    progress_state = {"current": 0, "total": 0, "filename": ""}

    def sync_process():
        def progress_cb(current, total, filename):
            progress_state["current"] = current
            progress_state["total"] = total
            progress_state["filename"] = filename
        return process_zip(raw, progress_cb)

    async def progress_poller(stop_event: asyncio.Event):
        last = [0.0]
        while not stop_event.is_set():
            await asyncio.sleep(1.5)
            c = progress_state["current"]
            t = progress_state["total"]
            f = progress_state["filename"]
            if t > 0 and (c != last[0]):
                last[0] = c
                await update_progress(c, t, f)

    stop_event = asyncio.Event()
    poller_task = asyncio.create_task(progress_poller(stop_event))

    try:
        result_zip, stats = await loop.run_in_executor(None, sync_process)
    finally:
        stop_event.set()
        poller_task.cancel()
        try:
            await poller_task
        except asyncio.CancelledError:
            pass

    report = build_report(stats, len(raw), len(result_zip))
    await progress_msg.edit_text(report, parse_mode=ParseMode.HTML)

    out_file = BufferedInputFile(result_zip, filename="decoded_output.zip")
    await cq.message.answer_document(
        out_file,
        caption="✅ <b>Clean zip ready.</b>",
        parse_mode=ParseMode.HTML,
        reply_markup=build_done_kb(),
    )


@dp.callback_query(F.data.startswith("cancel:"))
async def cb_cancel(cq: CallbackQuery):
    job_id = cq.data.split(":", 1)[1]
    pending_jobs.pop(job_id, None)
    await cq.answer("Cancelled.")
    await cq.message.edit_text("❌ Cancelled.", reply_markup=None)


@dp.callback_query(F.data == "new")
async def cb_new(cq: CallbackQuery):
    await cq.answer()
    await cq.message.answer("📤 Send your zip file.", parse_mode=ParseMode.HTML)


@dp.callback_query(F.data == "done")
async def cb_done(cq: CallbackQuery):
    await cq.answer("👍")
    await cq.message.edit_reply_markup(reply_markup=None)


async def health_server():
    from aiohttp import web
    port = int(os.environ.get("PORT", "8080"))
    app = web.Application()
    app.router.add_get("/", lambda r: web.Response(text="OK"))
    app.router.add_get("/health", lambda r: web.Response(text="OK"))
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", port)
    await site.start()
    log.info(f"Health server on port {port}")


async def main():
    log.info("Bot starting...")
    await health_server()
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
