import asyncio
import base64
import codecs
import hashlib
import html
import io
import json
import logging
import os
import re
import urllib.parse
import zipfile
from pathlib import Path
from typing import Optional

from aiogram import Bot, Dispatcher, F
from aiogram.enums import ParseMode
from aiogram.filters import CommandStart, Command
from aiogram.types import (
    BufferedInputFile,
    CallbackQuery,
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
    sample = data[:8192]
    try:
        text = sample.decode("utf-8")
    except Exception:
        return False
    non_printable = sum(1 for c in text if ord(c) < 32 and c not in "\n\r\t")
    return non_printable / max(len(text), 1) < 0.05


def _b64_decode_safe(s: str) -> Optional[bytes]:
    s = re.sub(r"[\s\r\n]+", "", s)
    if not re.fullmatch(r"[A-Za-z0-9+/=]+", s):
        return None
    if len(s) < 16:
        return None
    pad = s + "=" * ((-len(s)) % 4)
    try:
        return base64.b64decode(pad)
    except Exception:
        return None


def detect_and_decode(data: bytes, filename: str) -> tuple[bytes, list[str]]:
    methods_applied = []
    current = data
    seen = set()
    for _ in range(20):
        h = hashlib.md5(current).hexdigest()
        if h in seen:
            break
        seen.add(h)
        result, method = _single_pass(current, filename)
        if method is None:
            break
        methods_applied.append(method)
        current = result
    return current, methods_applied


def _single_pass(data: bytes, filename: str) -> tuple[bytes, Optional[str]]:
    text = safe_decode(data)

    if text is not None:
        r = _try_js_eval_unwrap(text)
        if r is not None:
            return r, "js_eval_unwrap"

    if text is not None:
        r = _try_any_base64(text)
        if r is not None:
            return r, "base64"

    if text is not None:
        r = _try_hex(text)
        if r is not None:
            return r, "hex"

    if text is not None:
        r = _try_uri_encoding(text)
        if r is not None:
            return r, "uri_encoded"

    if text is not None:
        r = _try_html_entities(text)
        if r is not None:
            return r, "html_entities"

    if text is not None:
        r = _try_unicode_escapes(text)
        if r is not None:
            return r, "unicode_escapes"

    if text is not None:
        r = _try_js_string_escape(text)
        if r is not None:
            return r, "js_string_escape"

    if text is not None:
        r = _try_json_base64_values(text)
        if r is not None:
            return r, "json_base64_values"

    if text is not None:
        r = _try_octal_escape(text)
        if r is not None:
            return r, "octal_escape"

    if text is not None:
        r = _try_rot13(text)
        if r is not None:
            return r, "rot13"

    return data, None


def _try_js_eval_unwrap(text: str) -> Optional[bytes]:
    patterns = [
        r'(?:let|var|const)\s+\w+\s*=\s*["\'\`]([A-Za-z0-9+/=\r\n]{40,})["\'\`]',
        r'(?:eval|exec)\s*\(\s*(?:atob|Buffer\.from)\s*\(\s*["\']([A-Za-z0-9+/=\r\n]{40,})["\']',
        r'atob\s*\(\s*["\']([A-Za-z0-9+/=\r\n]{40,})["\']',
        r'Buffer\.from\s*\(\s*["\']([A-Za-z0-9+/=\r\n]{40,})["\'],\s*["\']base64["\']\s*\)',
        r'(?:fromBase64|b64decode|decodeBase64)\s*\(\s*["\']([A-Za-z0-9+/=\r\n]{40,})["\']',
        r'_0x[0-9a-f]+\s*\(\s*["\']([A-Za-z0-9+/=\r\n]{40,})["\']',
    ]
    for pat in patterns:
        for m in re.finditer(pat, text, re.DOTALL | re.IGNORECASE):
            decoded = _b64_decode_safe(m.group(1))
            if decoded is not None and is_printable_text(decoded):
                return decoded
    return None


def _try_any_base64(text: str) -> Optional[bytes]:
    stripped = text.strip()

    clean = re.sub(r"[\s\r\n]+", "", stripped)
    if len(clean) >= 16 and re.fullmatch(r"[A-Za-z0-9+/=]+", clean):
        decoded = _b64_decode_safe(clean)
        if decoded is not None and is_printable_text(decoded):
            return decoded

    lines = [l.strip() for l in stripped.splitlines() if l.strip()]
    if len(lines) >= 2:
        joined = "".join(lines)
        if re.fullmatch(r"[A-Za-z0-9+/=]+", joined):
            decoded = _b64_decode_safe(joined)
            if decoded is not None and is_printable_text(decoded):
                return decoded

    chunks = re.findall(r"[A-Za-z0-9+/]{60,}={0,2}", stripped)
    if chunks:
        combined = "".join(chunks)
        decoded = _b64_decode_safe(combined)
        if decoded is not None and is_printable_text(decoded):
            return decoded

    return None


def _try_hex(text: str) -> Optional[bytes]:
    stripped = text.strip()
    clean = re.sub(r"[\s\r\n]+", "", stripped)
    clean = re.sub(r"^0x", "", clean, flags=re.IGNORECASE)
    if len(clean) >= 20 and len(clean) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", clean):
        try:
            decoded = bytes.fromhex(clean)
            if is_printable_text(decoded):
                return decoded
        except Exception:
            pass

    if re.search(r"(?:\\x[0-9a-fA-F]{2}){3,}", stripped):
        try:
            result = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), stripped)
            if is_printable_text(result.encode("utf-8")):
                return result.encode("utf-8")
        except Exception:
            pass

    return None


def _try_uri_encoding(text: str) -> Optional[bytes]:
    stripped = text.strip()
    if stripped.count("%") < 5:
        return None
    total = len(stripped.replace(" ", "").replace("\n", ""))
    if stripped.count("%") / max(total, 1) < 0.05:
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
    if len(re.findall(r"&(?:#\d+|#x[0-9a-fA-F]+|[a-zA-Z]+);", text)) < 3:
        return None
    decoded = html.unescape(text)
    if decoded != text:
        return decoded.encode("utf-8")
    return None


def _looks_like_code(text: str) -> bool:
    keywords = ["function", "const", "var", "let", "return", "import", "export",
                 "class", "def ", "print", "require", "module", "if ", "for ",
                 "while", "async", "await", "the ", "and ", "this", "that"]
    lower = text.lower()
    return sum(1 for kw in keywords if kw in lower) >= 2


def _try_rot13(text: str) -> Optional[bytes]:
    stripped = text.strip()
    if len(stripped) < 20 or not re.search(r"[a-zA-Z]", stripped):
        return None
    decoded = codecs.decode(stripped, "rot_13")
    if _looks_like_code(decoded) and not _looks_like_code(stripped):
        return decoded.encode("utf-8")
    return None


def _try_unicode_escapes(text: str) -> Optional[bytes]:
    if "\\u" not in text:
        return None
    if len(re.findall(r"\\u[0-9a-fA-F]{4}", text)) < 3:
        return None
    try:
        decoded = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), text)
        if is_printable_text(decoded.encode("utf-8")):
            return decoded.encode("utf-8")
    except Exception:
        pass
    return None


def _try_js_string_escape(text: str) -> Optional[bytes]:
    if "\\" not in text:
        return None
    if len(re.findall(r"\\[nrtbf\"'\\]", text)) < 3:
        return None
    try:
        decoded = text.encode("raw_unicode_escape").decode("unicode_escape")
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
            decoded = _b64_decode_safe(o)
            if decoded is not None:
                try:
                    s = decoded.decode("utf-8")
                    changed[0] = True
                    return s
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
    if len(re.findall(r"\\[0-7]{3}", text)) < 3:
        return None
    try:
        decoded = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), text)
        if is_printable_text(decoded.encode("utf-8")):
            return decoded.encode("utf-8")
    except Exception:
        pass
    return None


def process_zip(raw: bytes, progress_cb=None) -> tuple[bytes, dict]:
    stats = {"decoded": [], "clean": [], "binary_skipped": [], "error": []}
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

    method_labels = {
        "base64": "Base64",
        "js_eval_unwrap": "JS eval/atob wrapper",
        "hex": "Hex",
        "uri_encoded": "URI / percent-encoded",
        "html_entities": "HTML entities",
        "rot13": "ROT13",
        "unicode_escapes": "Unicode escapes",
        "js_string_escape": "JS string escapes",
        "json_base64_values": "JSON with Base64 values",
        "octal_escape": "Octal escapes",
    }

    lines = ["<b>🔬 Decode Report</b>\n"]
    lines.append(f"📂 Decoded files:  <b>{decoded_count}</b>")
    lines.append(f"✨ Already clean:  <b>{clean_count}</b>")
    lines.append(f"⏭ Binary skipped: <b>{skip_count}</b>")
    if err_count:
        lines.append(f"⚠️ Errors:         <b>{err_count}</b>")
    lines.append("")

    if method_counts:
        lines.append("<b>📊 Encoding types found:</b>")
        for method, count in sorted(method_counts.items(), key=lambda x: -x[1]):
            label = method_labels.get(method, method)
            lines.append(f"  • {label}: <b>{count}</b>")
        lines.append("")

    lines.append(f"📦 Original: <b>{original_size / 1024:.1f} KB</b>")
    lines.append(f"📦 Output:   <b>{result_size / 1024:.1f} KB</b>")

    if 0 < decoded_count <= 20:
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
        "Send me a <code>.zip</code> file. I'll auto-detect and fully decode every encoded file inside — including chained/multi-layer encodings.\n\n"
        "<b>Supported:</b>\n"
        "• Base64 (raw, multiline, JS eval/atob wrappers, chained)\n"
        "• Hex / \\x escapes\n"
        "• URI / percent-encoding\n"
        "• HTML entities\n"
        "• Unicode escapes (\\u1234)\n"
        "• JS string escapes\n"
        "• JSON with Base64 field values\n"
        "• Octal escapes\n"
        "• ROT13\n"
        "• Multi-layer (auto-unwrapped until real code is reached)\n\n"
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

    await status.edit_text(
        f"📂 <b>{doc.file_name}</b>\n"
        f"📄 <b>{total_files}</b> file(s) — <b>{total_size / 1024:.1f} KB</b> uncompressed\n\n"
        "Start decoding?",
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

    progress_state = {"current": 0, "total": 0, "filename": ""}

    def sync_process():
        def progress_cb(current, total, filename):
            progress_state["current"] = current
            progress_state["total"] = total
            progress_state["filename"] = filename
        return process_zip(raw, progress_cb)

    stop_event = asyncio.Event()

    async def progress_poller():
        last_current = -1
        while not stop_event.is_set():
            await asyncio.sleep(1.5)
            c = progress_state["current"]
            t = progress_state["total"]
            f = progress_state["filename"]
            if t > 0 and c != last_current:
                last_current = c
                pct = int(c / t * 100)
                bar = "█" * (pct // 10) + "░" * (10 - pct // 10)
                fname = Path(f).name[:35] if f else ""
                try:
                    await progress_msg.edit_text(
                        f"⚙️ Processing...\n[{bar}] {pct}%\n<code>{c}/{t}</code> — <code>{fname}</code>",
                        parse_mode=ParseMode.HTML,
                    )
                except Exception:
                    pass

    poller = asyncio.create_task(progress_poller())
    try:
        result_zip, stats = await asyncio.get_event_loop().run_in_executor(None, sync_process)
    finally:
        stop_event.set()
        poller.cancel()
        try:
            await poller
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
    await cq.message.answer("📤 Send your zip file.")


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
