import asyncio
import base64
import binascii
import codecs
import contextlib
import dataclasses
import dis
import hashlib
import html
import io
import json
import logging
import marshal
import multiprocessing
import os
import pathlib
import queue
import random
import re
import shutil
import string
import subprocess
import sys
import tempfile
import time
import traceback
import types
import urllib.parse
import uuid
import zipfile
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

import chardet
import jsbeautifier
from aiohttp import web
from aiogram import Bot, Dispatcher, F
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ChatAction, ParseMode
from aiogram.exceptions import TelegramAPIError, TelegramNetworkError, TelegramRetryAfter
from aiogram.filters import Command, CommandStart
from aiogram.types import CallbackQuery, Document, FSInputFile, InlineKeyboardButton, InlineKeyboardMarkup, Message

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
log = logging.getLogger("zip-deobfuscator-bot")

BOT_TOKEN = os.environ.get("BOT_TOKEN", "").strip()
PORT = int(os.environ.get("PORT", "8080"))
MAX_ZIP_MB = int(os.environ.get("MAX_ZIP_MB", "50"))
MAX_ZIP_BYTES = MAX_ZIP_MB * 1024 * 1024
MAX_UNCOMPRESSED_MB = int(os.environ.get("MAX_UNCOMPRESSED_MB", "250"))
MAX_UNCOMPRESSED_BYTES = MAX_UNCOMPRESSED_MB * 1024 * 1024
MAX_FILES = int(os.environ.get("MAX_FILES", "1200"))
MAX_PASSES = int(os.environ.get("MAX_PASSES", "14"))
FILE_TIMEOUT_SECONDS = int(os.environ.get("FILE_TIMEOUT_SECONDS", "22"))
TOTAL_JOB_TIMEOUT_SECONDS = int(os.environ.get("TOTAL_JOB_TIMEOUT_SECONDS", "1200"))
DOWNLOAD_TIMEOUT_SECONDS = int(os.environ.get("DOWNLOAD_TIMEOUT_SECONDS", "180"))
SEND_TIMEOUT_SECONDS = int(os.environ.get("SEND_TIMEOUT_SECONDS", "300"))
SUBPROC_TIMEOUT = int(os.environ.get("SUBPROC_TIMEOUT", "8"))
JSFUCK_TIMEOUT = int(os.environ.get("JSFUCK_TIMEOUT", "5"))
BF_MAX_STEPS = int(os.environ.get("BF_MAX_STEPS", "700000"))
MAX_EXTERNAL_JS_BYTES = int(os.environ.get("MAX_EXTERNAL_JS_BYTES", "650000"))
MAX_BEAUTIFY_BYTES = int(os.environ.get("MAX_BEAUTIFY_BYTES", "1600000"))
MAX_DECODE_TEXT_BYTES = int(os.environ.get("MAX_DECODE_TEXT_BYTES", "9000000"))
MAX_INLINE_STRING_BYTES = int(os.environ.get("MAX_INLINE_STRING_BYTES", "2200000"))
MAX_CONCURRENT_JOBS = int(os.environ.get("MAX_CONCURRENT_JOBS", "1"))
TELEGRAM_UPLOAD_LIMIT_MB = int(os.environ.get("TELEGRAM_UPLOAD_LIMIT_MB", "48"))
TELEGRAM_UPLOAD_LIMIT_BYTES = TELEGRAM_UPLOAD_LIMIT_MB * 1024 * 1024
WORK_ROOT = os.environ.get("WORK_ROOT", "/tmp/zip_deobfuscator_jobs")
CLEANUP_AFTER_SECONDS = int(os.environ.get("CLEANUP_AFTER_SECONDS", "3600"))
PROCESS_START_METHOD = os.environ.get("PROCESS_START_METHOD", "spawn").strip().lower()

BINARY_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tiff", ".ico", ".svgz", ".mp4", ".mp3", ".wav", ".flac", ".ogg", ".avi", ".mkv", ".mov", ".webm", ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".tgz", ".apk", ".ipa", ".exe", ".dll", ".so", ".dylib", ".bin", ".dat", ".class", ".pyc", ".pyo", ".pdf", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".db", ".sqlite", ".sqlite3", ".psd", ".ai", ".sketch", ".jar", ".wasm", ".DS_Store"
}
JS_EXTS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}
PY_EXTS = {".py", ".pyw"}
PHP_EXTS = {".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".inc"}
TEXT_EXTS = JS_EXTS | PY_EXTS | PHP_EXTS | {".json", ".txt", ".html", ".htm", ".css", ".xml", ".java", ".kt", ".kts", ".lua", ".sh", ".bash", ".env", ".md", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".go", ".rs", ".rb", ".pl", ".swift", ".dart", ".sql", ".csv", ".svg"}
CODE_KEYWORDS = ["function", "const ", "var ", "let ", "return", "import", "export", "class ", "def ", "print", "require", "module", "if ", "for ", "while ", "async", "await", "=>", "console.", "public ", "private ", "package ", "<?php", "$", "from ", "eval", "atob", "Buffer.from", "base64_decode"]

bot = Bot(token=BOT_TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.HTML)) if BOT_TOKEN else None
dp = Dispatcher()
executor = ThreadPoolExecutor(max_workers=max(1, MAX_CONCURRENT_JOBS))
job_sem = asyncio.Semaphore(max(1, MAX_CONCURRENT_JOBS))
active_jobs: Dict[str, "Job"] = {}
finished_jobs: Dict[str, "Job"] = {}

@dataclasses.dataclass
class Job:
    job_id: str
    chat_id: int
    user_id: int
    message_id: int
    source_name: str
    work_dir: str
    status_message_id: Optional[int] = None
    started_at: float = dataclasses.field(default_factory=time.time)
    finished_at: Optional[float] = None
    status: str = "queued"
    total: int = 0
    done: int = 0
    current: str = ""
    cancelled: bool = False
    error: str = ""
    report_text: str = ""
    output_paths: List[str] = dataclasses.field(default_factory=list)
    stats: Dict[str, Any] = dataclasses.field(default_factory=dict)


def now_ms() -> int:
    return int(time.time() * 1000)


def short_id() -> str:
    return uuid.uuid4().hex[:10]


def ensure_work_root() -> None:
    pathlib.Path(WORK_ROOT).mkdir(parents=True, exist_ok=True)


def size_label(n: int) -> str:
    units = ["B", "KB", "MB", "GB"]
    v = float(n)
    for u in units:
        if v < 1024 or u == units[-1]:
            return f"{v:.1f} {u}" if u != "B" else f"{int(v)} B"
        v /= 1024
    return f"{n} B"


def escape(s: Any) -> str:
    return html.escape(str(s), quote=False)


def md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def sha1(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def is_probably_utf16(data: bytes) -> bool:
    sample = data[:4096]
    if len(sample) < 4:
        return False
    zeros_even = sample[::2].count(0)
    zeros_odd = sample[1::2].count(0)
    return max(zeros_even, zeros_odd) / max(len(sample) // 2, 1) > 0.35


def detect_encoding(data: bytes) -> str:
    if data.startswith(codecs.BOM_UTF8):
        return "utf-8-sig"
    if data.startswith(codecs.BOM_UTF16_LE):
        return "utf-16-le"
    if data.startswith(codecs.BOM_UTF16_BE):
        return "utf-16-be"
    if is_probably_utf16(data):
        return "utf-16-le" if data[:4096][1::2].count(0) > data[:4096][::2].count(0) else "utf-16-be"
    try:
        data[:65536].decode("utf-8")
        return "utf-8"
    except UnicodeDecodeError:
        detected = chardet.detect(data[:131072])
        enc = detected.get("encoding") or "latin-1"
        return enc


def to_text(data: bytes) -> Optional[str]:
    if not data:
        return ""
    if len(data) > MAX_DECODE_TEXT_BYTES:
        return None
    enc = detect_encoding(data)
    try:
        return data.decode(enc, errors="replace")
    except Exception:
        try:
            return data.decode("latin-1", errors="replace")
        except Exception:
            return None


def text_to_bytes(text: str) -> bytes:
    return text.encode("utf-8", errors="replace")


def is_printable_text(data: bytes) -> bool:
    if not data:
        return False
    if b"\x00" in data[:8192] and not is_probably_utf16(data):
        return False
    text = to_text(data[:131072])
    if text is None:
        return False
    if not text:
        return True
    bad = 0
    for ch in text:
        o = ord(ch)
        if o < 32 and ch not in "\n\r\t\f\b":
            bad += 1
    return bad / max(len(text), 1) <= 0.055


def looks_like_code(text: str) -> bool:
    if not text:
        return False
    low = text.lower()
    hits = sum(1 for k in CODE_KEYWORDS if k.lower() in low)
    syntax = low.count("{") + low.count("}") + low.count(";") + low.count("(") + low.count(")") + low.count("=")
    alpha = sum(1 for ch in low[:5000] if ch.isalpha())
    return hits >= 2 or (hits >= 1 and syntax >= 5) or (hits >= 1 and alpha > 120)


def ext_of(filename: str) -> str:
    return pathlib.PurePosixPath(filename.replace("\\", "/")).suffix.lower()


def is_binary_file(filename: str, data: bytes) -> bool:
    ext = ext_of(filename)
    if ext in TEXT_EXTS:
        return False
    if ext in BINARY_EXTS:
        return True
    return not is_printable_text(data)


def run_subproc(cmd: Sequence[str], input_bytes: Optional[bytes] = None, timeout: int = SUBPROC_TIMEOUT, cwd: Optional[str] = None) -> Optional[bytes]:
    try:
        r = subprocess.run(list(cmd), input=input_bytes, capture_output=True, timeout=timeout, check=False, cwd=cwd)
        if r.returncode != 0:
            return None
        return r.stdout
    except Exception:
        return None


def js_beautify(text: str) -> str:
    if len(text.encode("utf-8", errors="ignore")) > MAX_BEAUTIFY_BYTES:
        return text
    try:
        opts = jsbeautifier.default_options()
        opts.indent_size = 2
        opts.space_in_empty_paren = True
        opts.preserve_newlines = True
        opts.max_preserve_newlines = 2
        opts.wrap_line_length = 0
        return jsbeautifier.beautify(text, opts)
    except Exception:
        return text


def b64_candidates(text: str) -> Iterable[str]:
    patterns = [
        r"(?:base64_decode|atob)\s*\(\s*(['\"])([A-Za-z0-9+/=_\-\s]{12,})\1\s*\)",
        r"Buffer\.from\s*\(\s*(['\"])([A-Za-z0-9+/=_\-\s]{12,})\1\s*,\s*(['\"])base64\3\s*\)",
        r"(?:b64decode|urlsafe_b64decode)\s*\(\s*(['\"])([A-Za-z0-9+/=_\-\s]{12,})\1\s*\)",
        r"(['\"])([A-Za-z0-9+/=_\-]{40,})\1"
    ]
    for pat in patterns:
        for m in re.finditer(pat, text, re.IGNORECASE | re.DOTALL):
            yield m.group(2)
    stripped = re.sub(r"\s+", "", text.strip())
    if 12 <= len(stripped) <= MAX_INLINE_STRING_BYTES and re.fullmatch(r"[A-Za-z0-9+/=_\-]+", stripped):
        yield stripped


def b64_decode_safe(s: str) -> Optional[bytes]:
    s2 = re.sub(r"\s+", "", s)
    if len(s2) < 8 or len(s2) > MAX_INLINE_STRING_BYTES:
        return None
    if not re.fullmatch(r"[A-Za-z0-9+/=_\-]+", s2):
        return None
    s2 = s2.replace("-", "+").replace("_", "/")
    s2 += "=" * ((-len(s2)) % 4)
    try:
        out = base64.b64decode(s2, validate=False)
    except Exception:
        return None
    if not out:
        return None
    return out


def decode_python_string_literal(raw: str) -> Optional[str]:
    try:
        return bytes(raw, "utf-8").decode("unicode_escape")
    except Exception:
        return None


def unquote_literal(raw: str) -> str:
    out = decode_python_string_literal(raw)
    return raw if out is None else out


def try_unicode_escapes(text: str) -> Optional[str]:
    if not re.search(r"\\(?:x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|[0-7]{2,3}|n|r|t)", text):
        return None
    try:
        decoded = bytes(text, "utf-8").decode("unicode_escape")
    except Exception:
        return None
    if decoded != text and (looks_like_code(decoded) or len(decoded) > len(text) * 0.35):
        return decoded
    return None


def try_html_entities(text: str) -> Optional[str]:
    if "&" not in text:
        return None
    decoded = html.unescape(text)
    if decoded != text and (looks_like_code(decoded) or decoded.count("<") + decoded.count(">") > text.count("<") + text.count(">")):
        return decoded
    return None


def try_url_decode(text: str) -> Optional[str]:
    if "%" not in text:
        return None
    decoded = urllib.parse.unquote(text)
    if decoded != text and (looks_like_code(decoded) or decoded.count("%") < text.count("%") // 2):
        return decoded
    return None


def try_hex_blob(text: str) -> Optional[str]:
    compact = re.sub(r"(?:\\x|0x|[^0-9a-fA-F])", "", text)
    if len(compact) < 24 or len(compact) % 2:
        return None
    if len(compact) > MAX_INLINE_STRING_BYTES * 2:
        return None
    try:
        out = binascii.unhexlify(compact)
    except Exception:
        return None
    if not is_printable_text(out):
        return None
    decoded = to_text(out)
    if decoded and (looks_like_code(decoded) or len(decoded) > 10):
        return decoded
    return None


def try_rot13(text: str) -> Optional[str]:
    if len(text) < 20 or looks_like_code(text):
        return None
    decoded = codecs.decode(text, "rot_13")
    return decoded if decoded != text and looks_like_code(decoded) else None


def try_reverse(text: str) -> Optional[str]:
    if len(text) < 30 or len(text) > MAX_DECODE_TEXT_BYTES or looks_like_code(text):
        return None
    decoded = text[::-1]
    return decoded if looks_like_code(decoded) else None


def try_gzip_zlib(data: bytes) -> Optional[str]:
    if len(data) < 12 or len(data) > MAX_DECODE_TEXT_BYTES:
        return None
    import gzip
    import zlib
    tries = []
    if data.startswith(b"\x1f\x8b"):
        tries.append(lambda: gzip.decompress(data))
    tries.append(lambda: zlib.decompress(data))
    tries.append(lambda: zlib.decompress(data, -15))
    for fn in tries:
        try:
            out = fn()
            if out and is_printable_text(out):
                t = to_text(out)
                if t and (looks_like_code(t) or len(t) > 20):
                    return t
        except Exception:
            continue
    return None


def try_base64_text(text: str) -> Optional[str]:
    best = None
    best_score = -1
    seen: Set[str] = set()
    for candidate in b64_candidates(text):
        c = re.sub(r"\s+", "", candidate)
        if c in seen:
            continue
        seen.add(c)
        out = b64_decode_safe(candidate)
        if not out:
            continue
        z = try_gzip_zlib(out)
        if z:
            return z
        if is_printable_text(out):
            decoded = to_text(out)
            if decoded:
                score = int(looks_like_code(decoded)) * 1000 + len(decoded)
                if score > best_score:
                    best = decoded
                    best_score = score
    if best is None:
        return None
    if looks_like_code(best) or len(best) > 20:
        return best
    return None


def try_json_base64(text: str) -> Optional[str]:
    stripped = text.strip()
    if not stripped.startswith(("{", "[")) or len(stripped) > MAX_INLINE_STRING_BYTES:
        return None
    try:
        obj = json.loads(stripped)
    except Exception:
        return None
    changed = False
    def walk(x: Any) -> Any:
        nonlocal changed
        if isinstance(x, dict):
            return {k: walk(v) for k, v in x.items()}
        if isinstance(x, list):
            return [walk(v) for v in x]
        if isinstance(x, str):
            out = b64_decode_safe(x)
            if out and is_printable_text(out):
                t = to_text(out)
                if t and (looks_like_code(t) or len(t) > 12):
                    changed = True
                    return t
        return x
    new_obj = walk(obj)
    if changed:
        return json.dumps(new_obj, ensure_ascii=False, indent=2)
    return None


def try_js_eval_unwrap(text: str) -> Optional[str]:
    patterns = [
        r"\beval\s*\(\s*(['\"])((?:\\.|(?!\1).){8,})\1\s*\)",
        r"\bFunction\s*\(\s*(['\"])((?:\\.|(?!\1).){8,})\1\s*\)\s*\(\s*\)",
        r"\bsetTimeout\s*\(\s*(['\"])((?:\\.|(?!\1).){8,})\1\s*,\s*\d+\s*\)"
    ]
    for pat in patterns:
        m = re.search(pat, text, re.DOTALL)
        if not m:
            continue
        raw = m.group(2)
        decoded = unquote_literal(raw)
        if decoded and decoded != text and (looks_like_code(decoded) or len(decoded) > 20):
            return decoded
    m = re.search(r"\beval\s*\(\s*atob\s*\(\s*(['\"])([A-Za-z0-9+/=_\-\s]{12,})\1\s*\)\s*\)", text, re.DOTALL)
    if m:
        out = b64_decode_safe(m.group(2))
        if out and is_printable_text(out):
            return to_text(out)
    return None


def try_php_unwrap(text: str) -> Optional[str]:
    patterns = [
        r"eval\s*\(\s*base64_decode\s*\(\s*(['\"])([A-Za-z0-9+/=_\-\s]{12,})\1\s*\)\s*\)",
        r"assert\s*\(\s*base64_decode\s*\(\s*(['\"])([A-Za-z0-9+/=_\-\s]{12,})\1\s*\)\s*\)",
        r"gzinflate\s*\(\s*base64_decode\s*\(\s*(['\"])([A-Za-z0-9+/=_\-\s]{12,})\1\s*\)\s*\)"
    ]
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE | re.DOTALL)
        if not m:
            continue
        out = b64_decode_safe(m.group(2))
        if not out:
            continue
        z = try_gzip_zlib(out)
        if z:
            return z
        if is_printable_text(out):
            decoded = to_text(out)
            if decoded:
                return decoded
    if "str_rot13" in text and "eval" in text:
        m = re.search(r"str_rot13\s*\(\s*(['\"])((?:\\.|(?!\1).){8,})\1\s*\)", text, re.DOTALL)
        if m:
            decoded = codecs.decode(unquote_literal(m.group(2)), "rot_13")
            if decoded and looks_like_code(decoded):
                return decoded
    return None


def parse_string_array(arr_literal: str) -> List[str]:
    out = []
    for m in re.finditer(r"(['\"])((?:\\.|(?!\1).)*?)\1", arr_literal, re.DOTALL):
        out.append(unquote_literal(m.group(2)))
    return out


def try_js_0x_fallback(text: str) -> Optional[str]:
    head = text[:850000]
    m = re.search(r"(?:var|let|const)\s+(_0x[a-fA-F0-9]+)\s*=\s*(\[(?:[^\[\]]|\\.|\n|\r){20,450000}\])\s*;", head, re.DOTALL)
    if not m:
        return None
    arr = parse_string_array(m.group(2))
    if not arr:
        return None
    fn_names: Set[str] = set()
    for f in re.finditer(r"(?:function\s+|(?:var|let|const)\s+)(_0x[a-fA-F0-9]+)\s*(?:=\s*function)?\s*\(", head):
        fn_names.add(f.group(1))
    if not fn_names:
        fn_names.add(m.group(1))
    pattern = re.compile(r"\b(" + "|".join(re.escape(n) for n in sorted(fn_names, key=len, reverse=True)) + r")\s*\(\s*(0x[0-9a-fA-F]+|\d+)\s*(?:,\s*['\"][^'\"]*['\"])?\s*\)")
    offsets = [0, 1, -1, 0x0, 0x1, 0x10, 0x20, 0x40, 0x80, 0x100, 0x120, 0x150, 0x180, 0x200]
    changed = False
    def decode_index(raw: str) -> Optional[str]:
        try:
            n = int(raw, 16) if raw.lower().startswith("0x") else int(raw)
        except Exception:
            return None
        for off in offsets:
            idx = n - off
            if 0 <= idx < len(arr):
                return arr[idx]
        return None
    def repl(match: re.Match) -> str:
        nonlocal changed
        val = decode_index(match.group(2))
        if val is None:
            return match.group(0)
        changed = True
        return json.dumps(val, ensure_ascii=False)
    new_text = pattern.sub(repl, text, count=50000)
    if changed and new_text != text:
        return js_beautify(new_text)
    return None


def try_synchrony(text: str) -> Optional[str]:
    data_len = len(text.encode("utf-8", errors="ignore"))
    if data_len > MAX_EXTERNAL_JS_BYTES:
        return None
    if not any(k in text for k in ("_0x", "javascript-obfuscator", "stringArray", "controlFlowFlattening", "selfDefending")):
        return None
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "input.js")
        out = os.path.join(td, "output.js")
        pathlib.Path(src).write_text(text, encoding="utf-8", errors="ignore")
        commands = [["synchrony", "deobfuscate", src, "-o", out], ["deobfuscator", "-s", src, "-o", out]]
        for cmd in commands:
            r = run_subproc(cmd, timeout=SUBPROC_TIMEOUT, cwd=td)
            if r is not None and os.path.exists(out):
                try:
                    decoded = pathlib.Path(out).read_text(encoding="utf-8", errors="replace")
                except Exception:
                    continue
                if decoded and decoded != text and len(decoded) > 5:
                    return js_beautify(decoded)
    return None


def try_jsfuck(text: str) -> Optional[str]:
    stripped = text.strip()
    if len(stripped) < 20 or len(stripped) > 350000:
        return None
    allowed = set("[]()+! \\n\\r\\t")
    if any(ch not in allowed for ch in stripped[:2000]):
        return None
    script = "const vm=require('vm');const s=process.argv[1];let r=vm.runInNewContext(s,{}, {timeout:" + str(JSFUCK_TIMEOUT * 1000) + "});if(typeof r!=='string')r=String(r);process.stdout.write(r);"
    out = run_subproc(["node", "-e", script, stripped], timeout=JSFUCK_TIMEOUT + 1)
    if out and is_printable_text(out):
        decoded = to_text(out)
        if decoded and decoded != text:
            return decoded
    return None


def run_brainfuck(src: str, inp: bytes = b"") -> Optional[str]:
    if len(src) < 20 or len(src) > 500000:
        return None
    code = [c for c in src if c in "><+-.,[]"]
    if len(code) < 20 or len(code) / max(len(src), 1) < 0.75:
        return None
    jumps: Dict[int, int] = {}
    stack: List[int] = []
    for i, c in enumerate(code):
        if c == "[":
            stack.append(i)
        elif c == "]":
            if not stack:
                return None
            j = stack.pop()
            jumps[i] = j
            jumps[j] = i
    if stack:
        return None
    tape = bytearray(65536)
    ptr = 0
    ip = 0
    out = bytearray()
    input_pos = 0
    steps = 0
    while ip < len(code) and steps < BF_MAX_STEPS and len(out) < MAX_DECODE_TEXT_BYTES:
        c = code[ip]
        if c == ">":
            ptr = (ptr + 1) % len(tape)
        elif c == "<":
            ptr = (ptr - 1) % len(tape)
        elif c == "+":
            tape[ptr] = (tape[ptr] + 1) & 255
        elif c == "-":
            tape[ptr] = (tape[ptr] - 1) & 255
        elif c == ".":
            out.append(tape[ptr])
        elif c == ",":
            tape[ptr] = inp[input_pos] if input_pos < len(inp) else 0
            input_pos += 1
        elif c == "[" and tape[ptr] == 0:
            ip = jumps[ip]
        elif c == "]" and tape[ptr] != 0:
            ip = jumps[ip]
        ip += 1
        steps += 1
    if not out or not is_printable_text(bytes(out)):
        return None
    decoded = to_text(bytes(out))
    if decoded and (looks_like_code(decoded) or len(decoded.strip()) > 5):
        return decoded
    return None


def try_xor_single(data: bytes) -> Optional[str]:
    if len(data) < 30 or len(data) > 350000 or is_printable_text(data):
        return None
    best_score = -1
    best: Optional[bytes] = None
    common = b" etaoinshrdlucmfwypvbgkqjETAOINSHRDLUCMFWYPVBGKQJ{}();=<>/\\\"'._-$\n\r\t"
    for key in range(1, 256):
        sample = bytes(b ^ key for b in data[:8192])
        printable = sum(1 for b in sample if 32 <= b <= 126 or b in (9, 10, 13))
        common_hits = sum(1 for b in sample if b in common)
        score = printable * 2 + common_hits
        if score > best_score:
            best_score = score
            best = bytes(b ^ key for b in data)
    if best and is_printable_text(best):
        decoded = to_text(best)
        if decoded and looks_like_code(decoded):
            return decoded
    return None


def try_marshal(text: str) -> Optional[str]:
    if "marshal.loads" not in text and "loads(" not in text:
        return None
    candidates = list(b64_candidates(text))
    hexes = re.findall(r"(['\"])([0-9a-fA-F]{40,})\1", text)
    blobs: List[bytes] = []
    for c in candidates[:6]:
        out = b64_decode_safe(c)
        if out:
            blobs.append(out)
    for _, hx in hexes[:6]:
        if len(hx) % 2 == 0:
            with contextlib.suppress(Exception):
                blobs.append(binascii.unhexlify(hx))
    for blob in blobs:
        try:
            obj = marshal.loads(blob)
        except Exception:
            continue
        if isinstance(obj, types.CodeType):
            s = io.StringIO()
            dis.dis(obj, file=s)
            return s.getvalue()
        if isinstance(obj, (str, bytes)):
            decoded = obj if isinstance(obj, str) else to_text(obj)
            if decoded:
                return decoded
        return repr(obj)
    return None


def try_packed_js_eval(text: str) -> Optional[str]:
    if "eval(function(p,a,c,k,e" not in text.replace(" ", "")[:5000]:
        return None
    script = r"""
const fs=require('fs');const vm=require('vm');const src=fs.readFileSync(0,'utf8');let captured='';const ctx={eval:(x)=>{captured=String(x);return captured;},window:{},document:{},console:{log(){}}};try{vm.runInNewContext(src,ctx,{timeout:3000});}catch(e){}process.stdout.write(captured||'');
"""
    out = run_subproc(["node", "-e", script], input_bytes=text.encode("utf-8", errors="ignore"), timeout=4)
    if out and is_printable_text(out):
        decoded = to_text(out)
        if decoded and decoded != text and looks_like_code(decoded):
            return decoded
    return None


def one_decode_pass(data: bytes, filename: str) -> Tuple[bytes, List[str]]:
    methods: List[str] = []
    ext = ext_of(filename)
    gzip_text = try_gzip_zlib(data)
    if gzip_text:
        return text_to_bytes(gzip_text), ["gzip/zlib"]
    xor_text = try_xor_single(data)
    if xor_text:
        return text_to_bytes(xor_text), ["xor-single-byte"]
    text = to_text(data)
    if text is None:
        return data, []
    attempts: List[Tuple[str, Any]] = []
    if ext in JS_EXTS or "eval" in text or "_0x" in text or "atob" in text or "Buffer.from" in text:
        attempts.extend([("synchrony", try_synchrony), ("js-0x-regex", try_js_0x_fallback), ("js-packer", try_packed_js_eval), ("js-eval-string", try_js_eval_unwrap)])
    if ext in PHP_EXTS or "base64_decode" in text:
        attempts.append(("php-wrapper", try_php_unwrap))
    if ext in PY_EXTS or "marshal.loads" in text:
        attempts.append(("python-marshal-disassemble", try_marshal))
    attempts.extend([
        ("json-base64", try_json_base64),
        ("base64", try_base64_text),
        ("hex", try_hex_blob),
        ("unicode-escape", try_unicode_escapes),
        ("url-decode", try_url_decode),
        ("html-entity", try_html_entities),
        ("rot13", try_rot13),
        ("reverse", try_reverse),
        ("jsfuck", try_jsfuck),
        ("brainfuck", run_brainfuck)
    ])
    for name, fn in attempts:
        try:
            decoded = fn(text)
        except Exception:
            decoded = None
        if decoded and decoded != text:
            b = text_to_bytes(decoded)
            if b != data:
                methods.append(name)
                return b, methods
    if ext in JS_EXTS:
        beaut = js_beautify(text)
        if beaut != text:
            return text_to_bytes(beaut), ["js-beautify"]
    return data, []


def detect_and_decode(data: bytes, filename: str) -> Tuple[bytes, List[str]]:
    current = data
    methods: List[str] = []
    seen = {sha1(current)}
    for _ in range(MAX_PASSES):
        nxt, used = one_decode_pass(current, filename)
        if not used or nxt == current:
            break
        h = sha1(nxt)
        if h in seen:
            break
        seen.add(h)
        current = nxt
        methods.extend(used)
    ext = ext_of(filename)
    if ext in JS_EXTS:
        text = to_text(current)
        if text:
            beaut = js_beautify(text)
            if beaut != text:
                current = text_to_bytes(beaut)
                if "js-beautify" not in methods:
                    methods.append("js-beautify")
    return current, methods


def decode_worker(data: bytes, filename: str, out_path: str, meta_path: str) -> None:
    try:
        decoded, methods = detect_and_decode(data, filename)
        pathlib.Path(out_path).write_bytes(decoded)
        pathlib.Path(meta_path).write_text(json.dumps({"ok": True, "methods": methods, "error": ""}), encoding="utf-8")
    except BaseException as e:
        pathlib.Path(meta_path).write_text(json.dumps({"ok": False, "methods": [], "error": f"{type(e).__name__}: {e}"}), encoding="utf-8")


def process_context() -> multiprocessing.context.BaseContext:
    wanted = PROCESS_START_METHOD if PROCESS_START_METHOD in multiprocessing.get_all_start_methods() else "spawn"
    return multiprocessing.get_context(wanted)


def decode_with_timeout(data: bytes, filename: str) -> Tuple[bytes, List[str], Optional[str]]:
    if len(data) > MAX_DECODE_TEXT_BYTES and is_printable_text(data):
        return data, [], f"skipped text over {size_label(MAX_DECODE_TEXT_BYTES)}"
    ctx = process_context()
    with tempfile.TemporaryDirectory() as td:
        out_path = os.path.join(td, "decoded.bin")
        meta_path = os.path.join(td, "meta.json")
        proc = ctx.Process(target=decode_worker, args=(data, filename, out_path, meta_path))
        proc.start()
        proc.join(FILE_TIMEOUT_SECONDS)
        if proc.is_alive():
            proc.terminate()
            proc.join(2)
            if proc.is_alive():
                proc.kill()
                proc.join(1)
            return data, [], f"decode timed out after {FILE_TIMEOUT_SECONDS}s"
        if not os.path.exists(meta_path):
            return data, [], "decoder returned no metadata"
        try:
            meta = json.loads(pathlib.Path(meta_path).read_text(encoding="utf-8"))
        except Exception as e:
            return data, [], f"decoder metadata unreadable: {e}"
        if not meta.get("ok"):
            return data, [], meta.get("error") or "decoder crashed"
        try:
            decoded = pathlib.Path(out_path).read_bytes()
        except Exception as e:
            return data, [], f"decoder output unreadable: {e}"
        return decoded, list(meta.get("methods") or []), None


def safe_zip_name(name: str) -> str:
    raw = str(name or "file").replace("\\", "/")
    parts = []
    for part in raw.split("/"):
        if not part or part in (".", ".."):
            continue
        clean = "".join(ch if ch not in "\x00\r\n" else "_" for ch in part)
        clean = clean[:120] if len(clean) > 120 else clean
        parts.append(clean)
    final = "/".join(parts) or "file"
    if len(final) > 240:
        stem, ext = os.path.splitext(final)
        final = stem[:220] + ext[:20]
    return final


def unique_name(name: str, used: Set[str]) -> str:
    base = safe_zip_name(name)
    if base not in used:
        used.add(base)
        return base
    stem, ext = os.path.splitext(base)
    i = 2
    while True:
        candidate = f"{stem}_{i}{ext}"
        if candidate not in used:
            used.add(candidate)
            return candidate
        i += 1


def zipinfo_datetime(info: zipfile.ZipInfo) -> Tuple[int, int, int, int, int, int]:
    try:
        y, mo, d, h, mi, s = info.date_time
        if y < 1980:
            return (1980, 1, 1, 0, 0, 0)
        return info.date_time
    except Exception:
        return (1980, 1, 1, 0, 0, 0)


def make_zipinfo(name: str, src: Optional[zipfile.ZipInfo] = None) -> zipfile.ZipInfo:
    zi = zipfile.ZipInfo(name)
    zi.date_time = zipinfo_datetime(src) if src else time.localtime()[:6]
    zi.compress_type = zipfile.ZIP_DEFLATED
    zi.external_attr = getattr(src, "external_attr", 0o644 << 16) if src else 0o644 << 16
    return zi


def validate_zip_file(zip_bytes: bytes) -> Tuple[int, int]:
    with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as z:
        bad = z.testzip()
        if bad:
            raise ValueError(f"corrupted entry: {bad}")
        entries = [i for i in z.infolist() if not i.is_dir()]
        if not entries:
            raise ValueError("zip has no files")
        if len(entries) > MAX_FILES:
            raise ValueError(f"too many files: {len(entries)} max {MAX_FILES}")
        total = sum(max(0, i.file_size) for i in entries)
        if total > MAX_UNCOMPRESSED_BYTES:
            raise ValueError(f"unzipped size too large: {size_label(total)} max {MAX_UNCOMPRESSED_MB} MB")
        for info in entries:
            if info.file_size < 0 or info.compress_size < 0:
                raise ValueError(f"bad zip entry: {info.filename}")
            if info.file_size > MAX_UNCOMPRESSED_BYTES:
                raise ValueError(f"single file too large: {info.filename}")
        return len(entries), total


def stats_template(original_size: int) -> Dict[str, Any]:
    return {"decoded": 0, "clean": 0, "binary": 0, "errors": [], "methods": {}, "decoded_files": [], "original_size": original_size, "output_size": 0, "timed_out": 0, "skipped": 0, "files": 0, "started_ms": now_ms(), "finished_ms": 0}


def add_method(stats: Dict[str, Any], method: str) -> None:
    stats["methods"][method] = stats["methods"].get(method, 0) + 1


def write_report_file(out_zip: zipfile.ZipFile, stats: Dict[str, Any]) -> None:
    lines = []
    lines.append("ZIP Deobfuscator Bot Decode Report")
    lines.append(f"Decoded files: {stats.get('decoded', 0)}")
    lines.append(f"Already clean: {stats.get('clean', 0)}")
    lines.append(f"Binary copied: {stats.get('binary', 0)}")
    lines.append(f"Timed out: {stats.get('timed_out', 0)}")
    lines.append(f"Skipped: {stats.get('skipped', 0)}")
    lines.append("")
    lines.append("Methods:")
    for k, v in sorted(stats.get("methods", {}).items(), key=lambda x: (-x[1], x[0])):
        lines.append(f"- {k}: {v}")
    lines.append("")
    lines.append("Decoded files:")
    for fname, methods in stats.get("decoded_files", []):
        lines.append(f"- {fname}: {' -> '.join(methods)}")
    lines.append("")
    lines.append("Notes:")
    for e in stats.get("errors", []):
        lines.append(f"- {e}")
    out_zip.writestr(make_zipinfo("DECODE_REPORT.txt"), "\n".join(lines).encode("utf-8", errors="replace"))


def process_zip_sync(zip_bytes: bytes, out_path: str, state: Dict[str, Any]) -> Dict[str, Any]:
    start = time.monotonic()
    stats = stats_template(len(zip_bytes))
    used_names: Set[str] = set()
    with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as src:
        infos = src.infolist()
        entries = [i for i in infos if not i.is_dir()]
        stats["files"] = len(entries)
        state["total"] = len(entries)
        state["done"] = 0
        state["current"] = "opening zip"
        state["status"] = "processing"
        with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as dst:
            for info in infos:
                if state.get("cancelled"):
                    stats["errors"].append("job cancelled by user")
                    break
                if time.monotonic() - start > TOTAL_JOB_TIMEOUT_SECONDS:
                    stats["errors"].append(f"job stopped after {TOTAL_JOB_TIMEOUT_SECONDS}s total timeout")
                    break
                arcname = unique_name(info.filename, used_names)
                if info.is_dir():
                    continue
                state["current"] = os.path.basename(info.filename) or info.filename
                try:
                    if info.file_size > MAX_UNCOMPRESSED_BYTES:
                        stats["skipped"] += 1
                        stats["errors"].append(f"{info.filename}: skipped oversized file")
                        state["done"] += 1
                        continue
                    raw = src.read(info.filename)
                except Exception as e:
                    stats["errors"].append(f"{info.filename}: read failed: {e}")
                    state["done"] += 1
                    continue
                try:
                    if is_binary_file(info.filename, raw):
                        dst.writestr(make_zipinfo(arcname, info), raw)
                        stats["binary"] += 1
                    else:
                        decoded, methods, err = decode_with_timeout(raw, info.filename)
                        if err:
                            dst.writestr(make_zipinfo(arcname, info), raw)
                            stats["clean"] += 1
                            if "timed out" in err:
                                stats["timed_out"] += 1
                            stats["errors"].append(f"{info.filename}: {err}")
                        elif methods:
                            dst.writestr(make_zipinfo(arcname, info), decoded)
                            stats["decoded"] += 1
                            stats["decoded_files"].append((info.filename, methods))
                            for method in methods:
                                add_method(stats, method)
                        else:
                            dst.writestr(make_zipinfo(arcname, info), raw)
                            stats["clean"] += 1
                except Exception as e:
                    stats["errors"].append(f"{info.filename}: decode failed: {type(e).__name__}: {e}")
                    with contextlib.suppress(Exception):
                        dst.writestr(make_zipinfo(arcname, info), raw)
                state["done"] += 1
            write_report_file(dst, stats)
    stats["output_size"] = os.path.getsize(out_path) if os.path.exists(out_path) else 0
    stats["finished_ms"] = now_ms()
    state["status"] = "finished"
    state["finished"] = True
    return stats


def split_zip_by_size(source_zip: str, dest_dir: str, base_name: str, limit_bytes: int) -> List[str]:
    if os.path.getsize(source_zip) <= limit_bytes:
        return [source_zip]
    paths: List[str] = []
    pathlib.Path(dest_dir).mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(source_zip, "r") as src:
        infos = [i for i in src.infolist() if not i.is_dir()]
        part_index = 1
        current_path = os.path.join(dest_dir, f"{base_name}_part_{part_index:03d}.zip")
        current = zipfile.ZipFile(current_path, "w", zipfile.ZIP_DEFLATED, compresslevel=6)
        current_count = 0
        def close_current() -> None:
            nonlocal current, current_path, current_count
            current.writestr(make_zipinfo("PART_NOTICE.txt"), f"This is part {part_index} of the decoded output. Extract all parts into the same folder.\n".encode())
            current.close()
            paths.append(current_path)
        for info in infos:
            raw = src.read(info.filename)
            projected = os.path.getsize(current_path) if os.path.exists(current_path) else 0
            projected += len(raw) + 4096
            if current_count > 0 and projected > limit_bytes:
                close_current()
                part_index += 1
                current_path = os.path.join(dest_dir, f"{base_name}_part_{part_index:03d}.zip")
                current = zipfile.ZipFile(current_path, "w", zipfile.ZIP_DEFLATED, compresslevel=6)
                current_count = 0
            if len(raw) + 4096 > limit_bytes:
                note = f"{info.filename} was too large for Telegram upload limit and was omitted from this part. Size: {size_label(len(raw))}.\n"
                current.writestr(make_zipinfo(f"OVERSIZED_{current_count + 1}.txt"), note.encode())
            else:
                current.writestr(make_zipinfo(info.filename, info), raw)
            current_count += 1
        if current_count > 0:
            close_current()
        else:
            current.close()
    return paths


def render_report(stats: Dict[str, Any], job_id: str) -> str:
    elapsed = max(0, (stats.get("finished_ms", now_ms()) - stats.get("started_ms", now_ms())) / 1000)
    lines = ["🔬 <b>Decode Report</b>", f"🆔 Job: <code>{escape(job_id)}</code>", ""]
    lines.append(f"📂 Files scanned: <b>{stats.get('files', 0)}</b>")
    lines.append(f"✅ Decoded files: <b>{stats.get('decoded', 0)}</b>")
    lines.append(f"✨ Already clean/copied: <b>{stats.get('clean', 0)}</b>")
    lines.append(f"⏭ Binary copied: <b>{stats.get('binary', 0)}</b>")
    if stats.get("timed_out"):
        lines.append(f"⏱ Timed out and kept original: <b>{stats.get('timed_out')}</b>")
    if stats.get("skipped"):
        lines.append(f"🚧 Skipped: <b>{stats.get('skipped')}</b>")
    lines.append(f"⏳ Time: <b>{elapsed:.1f}s</b>")
    lines.append(f"📦 Input: <b>{size_label(stats.get('original_size', 0))}</b>")
    lines.append(f"📦 Output: <b>{size_label(stats.get('output_size', 0))}</b>")
    methods = stats.get("methods", {})
    if methods:
        lines.append("")
        lines.append("🧩 <b>Detected methods:</b>")
        for k, v in sorted(methods.items(), key=lambda x: (-x[1], x[0]))[:20]:
            lines.append(f"• <code>{escape(k)}</code>: {v}")
    decoded_files = stats.get("decoded_files", [])
    if decoded_files:
        lines.append("")
        lines.append("📝 <b>Decoded files:</b>")
        for fname, methods2 in decoded_files[:20]:
            lines.append(f"• <code>{escape(fname)}</code> → {escape(' → '.join(methods2))}")
        if len(decoded_files) > 20:
            lines.append(f"• …and {len(decoded_files) - 20} more")
    errors = stats.get("errors", [])
    if errors:
        lines.append("")
        lines.append("⚠️ <b>Notes:</b>")
        for e in errors[:10]:
            lines.append(f"• <code>{escape(str(e)[:190])}</code>")
        if len(errors) > 10:
            lines.append(f"• …and {len(errors) - 10} more")
    text = "\n".join(lines)
    return text if len(text) <= 3900 else text[:3840] + "\n…truncated"


def progress_bar(done: int, total: int) -> str:
    if total <= 0:
        return "░" * 12
    filled = max(0, min(12, int(done * 12 / total)))
    return "█" * filled + "░" * (12 - filled)


def render_status(job: Job) -> str:
    pct = int(job.done * 100 / job.total) if job.total else 0
    cur = job.current or "waiting"
    if len(cur) > 54:
        cur = cur[:51] + "..."
    if job.status in ("done", "sent"):
        return f"✅ <b>Finished</b>\n🆔 <code>{escape(job.job_id)}</code>\n<code>[████████████]</code> 100%\n📦 Sending result zip now."
    if job.status == "failed":
        return f"❌ <b>Failed</b>\n🆔 <code>{escape(job.job_id)}</code>\n<code>{escape(job.error[:900])}</code>"
    if job.cancelled:
        return f"🛑 <b>Cancelling</b>\n🆔 <code>{escape(job.job_id)}</code>\nThe current file will stop at the hard timeout."
    return f"⚙️ <b>Decoding ZIP</b>\n🆔 <code>{escape(job.job_id)}</code>\n<code>[{progress_bar(job.done, job.total)}]</code> {pct}%\n<code>{job.done}/{job.total or '?'}</code> — <code>{escape(cur)}</code>"


def main_kb(job_id: Optional[str] = None, done: bool = False) -> InlineKeyboardMarkup:
    rows: List[List[InlineKeyboardButton]] = []
    if job_id and not done:
        rows.append([InlineKeyboardButton(text="🔄 Status", callback_data=f"status:{job_id}"), InlineKeyboardButton(text="🛑 Cancel", callback_data=f"cancel:{job_id}")])
    if job_id and done:
        rows.append([InlineKeyboardButton(text="🧾 Report", callback_data=f"report:{job_id}"), InlineKeyboardButton(text="📥 Another ZIP", callback_data="another")])
    rows.append([InlineKeyboardButton(text="ℹ️ Help", callback_data="help"), InlineKeyboardButton(text="⚙️ Limits", callback_data="limits")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


WELCOME = (
    "👋 <b>ZIP Deobfuscator Bot</b>\n\n"
    "Send a <b>.zip</b>. I process it immediately, isolate every file in its own hard-timeout decoder, then send back the decoded zip.\n\n"
    "<b>Supported decoding:</b> JavaScript _0x, eval strings, Function wrappers, atob, Buffer base64, packed JS, JSFuck, Brainfuck, PHP base64/gzinflate/rot13, Python marshal disassembly, JSON base64 fields, raw base64, gzip/zlib, hex, unicode escapes, URL encoding, HTML entities, ROT13, reverse strings, XOR, and JS beautifying.\n\n"
    f"Per-file timeout: <b>{FILE_TIMEOUT_SECONDS}s</b>. Total job timeout: <b>{TOTAL_JOB_TIMEOUT_SECONDS}s</b>."
)


def limits_text() -> str:
    return (
        "⚙️ <b>Limits</b>\n\n"
        f"Max zip upload: <b>{MAX_ZIP_MB} MB</b>\n"
        f"Max unzipped size: <b>{MAX_UNCOMPRESSED_MB} MB</b>\n"
        f"Max files: <b>{MAX_FILES}</b>\n"
        f"Telegram send chunk target: <b>{TELEGRAM_UPLOAD_LIMIT_MB} MB</b>\n"
        f"Concurrent jobs: <b>{MAX_CONCURRENT_JOBS}</b>"
    )


async def call_with_retry(action: Any, attempts: int = 4, base_delay: float = 1.2) -> Any:
    last: Optional[BaseException] = None
    for i in range(attempts):
        try:
            return await action()
        except TelegramRetryAfter as e:
            last = e
            await asyncio.sleep(float(e.retry_after) + 0.5)
        except (TelegramNetworkError, TelegramAPIError, asyncio.TimeoutError) as e:
            last = e
            await asyncio.sleep(base_delay * (2 ** i) + random.random())
    if last:
        raise last
    raise RuntimeError("telegram action failed")


async def safe_edit(chat_id: int, message_id: int, text: str, reply_markup: Optional[InlineKeyboardMarkup] = None) -> None:
    if bot is None:
        return
    async def action() -> Any:
        return await asyncio.wait_for(bot.edit_message_text(chat_id=chat_id, message_id=message_id, text=text, reply_markup=reply_markup), timeout=20)
    try:
        await call_with_retry(action, attempts=2)
    except Exception:
        pass


async def safe_answer(message: Message, text: str, reply_markup: Optional[InlineKeyboardMarkup] = None) -> Optional[Message]:
    async def action() -> Message:
        return await asyncio.wait_for(message.answer(text, reply_markup=reply_markup), timeout=30)
    try:
        return await call_with_retry(action)
    except Exception:
        log.exception("send message failed")
        return None


async def safe_send_document(chat_id: int, path: str, caption: str, reply_markup: Optional[InlineKeyboardMarkup] = None) -> None:
    if bot is None:
        return
    name = os.path.basename(path)
    async def action() -> Any:
        return await bot.send_document(chat_id=chat_id, document=FSInputFile(path, filename=name), caption=caption, reply_markup=reply_markup, request_timeout=SEND_TIMEOUT_SECONDS)
    await call_with_retry(action, attempts=5, base_delay=2.0)


async def download_document(doc: Document) -> bytes:
    if bot is None:
        raise RuntimeError("bot is not initialized")
    buf = io.BytesIO()
    async def action() -> Any:
        buf.seek(0)
        buf.truncate(0)
        return await asyncio.wait_for(bot.download(doc, destination=buf), timeout=DOWNLOAD_TIMEOUT_SECONDS)
    await call_with_retry(action, attempts=4, base_delay=2.0)
    return buf.getvalue()


async def progress_loop(job: Job) -> None:
    last = ""
    while job.status not in ("done", "failed", "sent") and not job.finished_at:
        await asyncio.sleep(1.4)
        if job.status_message_id is None:
            continue
        text = render_status(job)
        if text != last:
            await safe_edit(job.chat_id, job.status_message_id, text, reply_markup=main_kb(job.job_id))
            last = text


async def send_job_outputs(job: Job) -> None:
    if bot is None:
        return
    if job.report_text:
        with contextlib.suppress(Exception):
            await bot.send_message(job.chat_id, job.report_text, reply_markup=main_kb(job.job_id, done=True), request_timeout=30)
    if not job.output_paths:
        raise RuntimeError("no output zip was created")
    total = len(job.output_paths)
    for idx, path in enumerate(job.output_paths, 1):
        if not os.path.exists(path):
            raise RuntimeError(f"missing output file: {path}")
        suffix = f" ({idx}/{total})" if total > 1 else ""
        caption = f"✅ Decoded zip{suffix}\n🆔 <code>{escape(job.job_id)}</code>\n📦 <b>{size_label(os.path.getsize(path))}</b>"
        await safe_send_document(job.chat_id, path, caption, reply_markup=main_kb(job.job_id, done=True) if idx == total else None)


async def run_job(job: Job, zip_bytes: bytes) -> None:
    active_jobs[job.job_id] = job
    progress_task = asyncio.create_task(progress_loop(job))
    state: Dict[str, Any] = {"total": 0, "done": 0, "current": "queued", "status": "queued", "finished": False, "cancelled": False}
    try:
        async with job_sem:
            if job.cancelled:
                raise RuntimeError("job cancelled before start")
            job.status = "processing"
            out_path = os.path.join(job.work_dir, "decoded_all.zip")
            loop = asyncio.get_running_loop()
            sync_task = loop.run_in_executor(executor, process_zip_sync, zip_bytes, out_path, state)
            while not sync_task.done():
                await asyncio.sleep(0.6)
                state["cancelled"] = job.cancelled
                job.total = int(state.get("total") or 0)
                job.done = int(state.get("done") or 0)
                job.current = str(state.get("current") or "")
                if job.cancelled:
                    job.current = "cancelling"
            stats = await asyncio.wait_for(sync_task, timeout=5)
            job.total = int(state.get("total") or stats.get("files") or 0)
            job.done = int(state.get("done") or job.total)
            job.current = "packaging"
            job.stats = stats
            base_name = f"decoded_{job.job_id}"
            split_dir = os.path.join(job.work_dir, "parts")
            job.output_paths = split_zip_by_size(out_path, split_dir, base_name, TELEGRAM_UPLOAD_LIMIT_BYTES)
            job.report_text = render_report(stats, job.job_id)
            job.status = "done"
            job.finished_at = time.time()
            if job.status_message_id:
                await safe_edit(job.chat_id, job.status_message_id, render_status(job), reply_markup=main_kb(job.job_id, done=True))
            await send_job_outputs(job)
            job.status = "sent"
            if job.status_message_id:
                await safe_edit(job.chat_id, job.status_message_id, "✅ <b>Done — decoded zip sent.</b>\n🆔 <code>" + escape(job.job_id) + "</code>", reply_markup=main_kb(job.job_id, done=True))
    except Exception as e:
        job.status = "failed"
        job.error = f"{type(e).__name__}: {e}"
        job.finished_at = time.time()
        log.exception("job failed")
        if job.status_message_id:
            await safe_edit(job.chat_id, job.status_message_id, render_status(job), reply_markup=main_kb(job.job_id, done=True))
        with contextlib.suppress(Exception):
            if bot is not None:
                report_path = os.path.join(job.work_dir, "failure_report.txt")
                pathlib.Path(report_path).write_text(job.error + "\n\n" + traceback.format_exc(), encoding="utf-8")
                await safe_send_document(job.chat_id, report_path, "❌ Processing failed, but here is the failure report.", reply_markup=main_kb(job.job_id, done=True))
    finally:
        progress_task.cancel()
        with contextlib.suppress(Exception):
            await progress_task
        active_jobs.pop(job.job_id, None)
        finished_jobs[job.job_id] = job


@dp.message(CommandStart())
async def cmd_start(m: Message) -> None:
    await m.answer(WELCOME, reply_markup=main_kb())


@dp.message(Command("help"))
async def cmd_help(m: Message) -> None:
    await m.answer(WELCOME, reply_markup=main_kb())


@dp.message(Command("limits"))
async def cmd_limits(m: Message) -> None:
    await m.answer(limits_text(), reply_markup=main_kb())


@dp.message(Command("status"))
async def cmd_status(m: Message) -> None:
    user = m.from_user.id if m.from_user else m.chat.id
    jobs = [j for j in list(active_jobs.values()) + list(finished_jobs.values()) if j.user_id == user or j.chat_id == m.chat.id]
    jobs = sorted(jobs, key=lambda x: x.started_at, reverse=True)[:5]
    if not jobs:
        await m.answer("No recent jobs. Send a .zip file.", reply_markup=main_kb())
        return
    text = ["📋 <b>Recent jobs</b>"]
    for j in jobs:
        text.append(f"• <code>{escape(j.job_id)}</code> — <b>{escape(j.status)}</b> — {j.done}/{j.total or '?'}")
    await m.answer("\n".join(text), reply_markup=main_kb(jobs[0].job_id, done=jobs[0].status in ("done", "sent", "failed")))


@dp.message(F.document)
async def on_document(m: Message) -> None:
    if bot is None:
        return
    doc: Document = m.document
    fname = doc.file_name or "file.zip"
    if not fname.lower().endswith(".zip"):
        await safe_answer(m, "⚠️ Send a <b>.zip</b> file only.", reply_markup=main_kb())
        return
    if doc.file_size and doc.file_size > MAX_ZIP_BYTES:
        await safe_answer(m, f"⚠️ Zip too large: <b>{size_label(doc.file_size)}</b>. Max is <b>{MAX_ZIP_MB} MB</b>.", reply_markup=main_kb())
        return
    await bot.send_chat_action(m.chat.id, ChatAction.UPLOAD_DOCUMENT)
    status_msg = await safe_answer(m, "📥 <b>Downloading zip...</b>", reply_markup=main_kb())
    try:
        zip_bytes = await download_document(doc)
        if len(zip_bytes) > MAX_ZIP_BYTES:
            raise ValueError(f"zip too large after download: {size_label(len(zip_bytes))}")
        file_count, uncompressed = validate_zip_file(zip_bytes)
    except zipfile.BadZipFile:
        if status_msg:
            await safe_edit(m.chat.id, status_msg.message_id, "❌ Invalid or corrupted zip file.", reply_markup=main_kb())
        return
    except Exception as e:
        if status_msg:
            await safe_edit(m.chat.id, status_msg.message_id, f"❌ Zip rejected: <code>{escape(e)}</code>", reply_markup=main_kb())
        return
    ensure_work_root()
    job_id = short_id()
    work_dir = os.path.join(WORK_ROOT, job_id)
    pathlib.Path(work_dir).mkdir(parents=True, exist_ok=True)
    job = Job(job_id=job_id, chat_id=m.chat.id, user_id=m.from_user.id if m.from_user else m.chat.id, message_id=m.message_id, source_name=fname, work_dir=work_dir, status_message_id=status_msg.message_id if status_msg else None, total=file_count)
    if status_msg:
        await safe_edit(m.chat.id, status_msg.message_id, f"🚀 <b>Job started</b>\n🆔 <code>{escape(job_id)}</code>\n📦 <code>{escape(fname)}</code>\n📁 Files: <b>{file_count}</b>\n📐 Unzipped: <b>{size_label(uncompressed)}</b>\n\nI will send the decoded zip automatically.", reply_markup=main_kb(job_id))
    asyncio.create_task(run_job(job, zip_bytes))


@dp.callback_query(F.data == "help")
async def cb_help(c: CallbackQuery) -> None:
    await c.answer()
    if c.message:
        await c.message.answer(WELCOME, reply_markup=main_kb())


@dp.callback_query(F.data == "limits")
async def cb_limits(c: CallbackQuery) -> None:
    await c.answer()
    if c.message:
        await c.message.answer(limits_text(), reply_markup=main_kb())


@dp.callback_query(F.data == "another")
async def cb_another(c: CallbackQuery) -> None:
    await c.answer()
    if c.message:
        await c.message.answer("📥 Send the next <b>.zip</b> file and I’ll decode it automatically.", reply_markup=main_kb())


@dp.callback_query(F.data.startswith("status:"))
async def cb_status(c: CallbackQuery) -> None:
    job_id = c.data.split(":", 1)[1]
    job = active_jobs.get(job_id) or finished_jobs.get(job_id)
    if not job:
        await c.answer("Job not found or cleaned up.", show_alert=True)
        return
    await c.answer(f"{job.status}: {job.done}/{job.total or '?'}", show_alert=True)
    if c.message:
        await safe_edit(job.chat_id, c.message.message_id, render_status(job), reply_markup=main_kb(job_id, done=job.status in ("done", "sent", "failed")))


@dp.callback_query(F.data.startswith("cancel:"))
async def cb_cancel(c: CallbackQuery) -> None:
    job_id = c.data.split(":", 1)[1]
    job = active_jobs.get(job_id)
    if not job:
        await c.answer("Job is already finished or gone.", show_alert=True)
        return
    job.cancelled = True
    await c.answer("Cancelling. Current file stops at timeout.", show_alert=True)


@dp.callback_query(F.data.startswith("report:"))
async def cb_report(c: CallbackQuery) -> None:
    job_id = c.data.split(":", 1)[1]
    job = active_jobs.get(job_id) or finished_jobs.get(job_id)
    if not job:
        await c.answer("Report expired.", show_alert=True)
        return
    await c.answer()
    if c.message:
        await c.message.answer(job.report_text or render_status(job), reply_markup=main_kb(job_id, done=True))


async def health(_request: web.Request) -> web.Response:
    data = {"ok": True, "service": "zip-deobfuscator-bot", "active_jobs": len(active_jobs), "finished_jobs": len(finished_jobs), "time": int(time.time())}
    return web.json_response(data)


async def root(_request: web.Request) -> web.Response:
    return web.Response(text="ZIP Deobfuscator Bot is running")


async def start_health_server() -> web.AppRunner:
    app = web.Application()
    app.router.add_get("/", root)
    app.router.add_get("/health", health)
    app.router.add_get("/status", health)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", PORT)
    await site.start()
    log.info("health server listening on port %d", PORT)
    return runner


async def cleanup_loop() -> None:
    ensure_work_root()
    while True:
        await asyncio.sleep(300)
        cutoff = time.time() - CLEANUP_AFTER_SECONDS
        for jid, job in list(finished_jobs.items()):
            if job.finished_at and job.finished_at < cutoff:
                finished_jobs.pop(jid, None)
                shutil.rmtree(job.work_dir, ignore_errors=True)
        with contextlib.suppress(Exception):
            for p in pathlib.Path(WORK_ROOT).iterdir():
                if p.is_dir() and p.stat().st_mtime < cutoff and p.name not in active_jobs:
                    shutil.rmtree(str(p), ignore_errors=True)


async def main() -> None:
    if not BOT_TOKEN:
        log.error("BOT_TOKEN environment variable is required")
        sys.exit(1)
    ensure_work_root()
    await start_health_server()
    asyncio.create_task(cleanup_loop())
    log.info("starting polling max_zip_mb=%d max_files=%d file_timeout=%d", MAX_ZIP_MB, MAX_FILES, FILE_TIMEOUT_SECONDS)
    await bot.delete_webhook(drop_pending_updates=True)
    await dp.start_polling(bot, allowed_updates=dp.resolve_used_update_types())


if __name__ == "__main__":
    multiprocessing.freeze_support()
    asyncio.run(main())
