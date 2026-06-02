import asyncio
import base64
import codecs
import hashlib
import html
import io
import json
import logging
import marshal
import multiprocessing
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.parse
import zipfile
from typing import Any, Dict, List, Optional, Tuple

import chardet
import jsbeautifier
from aiohttp import web
from aiogram import Bot, Dispatcher, F
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ChatAction, ParseMode
from aiogram.filters import Command, CommandStart
from aiogram.types import BufferedInputFile, CallbackQuery, Document, InlineKeyboardButton, InlineKeyboardMarkup, Message

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
log = logging.getLogger("zipbot")

BOT_TOKEN = os.environ.get("BOT_TOKEN", "").strip()
MAX_ZIP_MB = int(os.environ.get("MAX_ZIP_MB", "50"))
MAX_ZIP_BYTES = MAX_ZIP_MB * 1024 * 1024
MAX_UNCOMPRESSED_MB = int(os.environ.get("MAX_UNCOMPRESSED_MB", "250"))
MAX_UNCOMPRESSED_BYTES = MAX_UNCOMPRESSED_MB * 1024 * 1024
MAX_FILES = int(os.environ.get("MAX_FILES", "800"))
PORT = int(os.environ.get("PORT", "8080"))
MAX_PASSES = int(os.environ.get("MAX_PASSES", "8"))
FILE_TIMEOUT_SECONDS = int(os.environ.get("FILE_TIMEOUT_SECONDS", "18"))
TOTAL_JOB_TIMEOUT_SECONDS = int(os.environ.get("TOTAL_JOB_TIMEOUT_SECONDS", "900"))
SUBPROC_TIMEOUT = int(os.environ.get("SUBPROC_TIMEOUT", "6"))
JSFUCK_TIMEOUT = int(os.environ.get("JSFUCK_TIMEOUT", "4"))
BF_MAX_STEPS = int(os.environ.get("BF_MAX_STEPS", "300000"))
MAX_EXTERNAL_JS_BYTES = int(os.environ.get("MAX_EXTERNAL_JS_BYTES", "350000"))
MAX_BEAUTIFY_BYTES = int(os.environ.get("MAX_BEAUTIFY_BYTES", "1000000"))
MAX_DECODE_TEXT_BYTES = int(os.environ.get("MAX_DECODE_TEXT_BYTES", "6000000"))
MAX_CONCURRENT_JOBS = int(os.environ.get("MAX_CONCURRENT_JOBS", "1"))

BINARY_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tiff", ".ico", ".svgz",
    ".mp4", ".mp3", ".wav", ".flac", ".ogg", ".avi", ".mkv", ".mov", ".webm",
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".tgz", ".apk", ".ipa",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".dat", ".class", ".pyc", ".pyo",
    ".pdf", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".db", ".sqlite", ".sqlite3",
    ".psd", ".ai", ".sketch", ".jar", ".wasm",
}
JS_EXTS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}
PY_EXTS = {".py", ".pyw"}
PHP_EXTS = {".php", ".phtml", ".php5", ".php7", ".inc"}
TEXT_EXTS = JS_EXTS | PY_EXTS | PHP_EXTS | {".json", ".txt", ".html", ".htm", ".css", ".xml", ".java", ".kt", ".kts", ".lua", ".sh", ".env", ".md", ".yml", ".yaml", ".go", ".rs"}
CODE_KEYWORDS = ["function", "const ", "var ", "let ", "return", "import", "export", "class ", "def ", "print", "require", "module", "if ", "for ", "while ", "async", "await", "=>", "console.", "public ", "private ", "package ", "<?php", "$", "from "]

bot = Bot(token=BOT_TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.HTML)) if BOT_TOKEN else None
dp = Dispatcher()
pending_jobs: Dict[str, bytes] = {}
job_sem = asyncio.Semaphore(MAX_CONCURRENT_JOBS)


def is_printable_text(data: bytes) -> bool:
    if not data:
        return False
    if b"\x00" in data[:8192]:
        return False
    sample = data[:32768]
    try:
        text = sample.decode("utf-8")
    except UnicodeDecodeError:
        try:
            det = chardet.detect(sample)
            enc = det.get("encoding") or "latin-1"
            text = sample.decode(enc, errors="replace")
        except Exception:
            return False
    bad = sum(1 for ch in text if ord(ch) < 32 and ch not in "\n\r\t\f\b")
    return (bad / max(len(text), 1)) <= 0.06


def _to_text(data: bytes) -> Optional[str]:
    if not data:
        return None
    if len(data) > MAX_DECODE_TEXT_BYTES:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            det = chardet.detect(data[:65536])
            enc = det.get("encoding") or "utf-8"
            return data.decode(enc, errors="replace")
        except Exception:
            return None


def _b64_decode_safe(s: str) -> Optional[bytes]:
    s2 = re.sub(r"\s+", "", s)
    if len(s2) < 8:
        return None
    if len(s2) > MAX_DECODE_TEXT_BYTES * 2:
        return None
    if not re.fullmatch(r"[A-Za-z0-9+/=_-]+", s2):
        return None
    s2 = s2.replace("-", "+").replace("_", "/")
    s2 += "=" * ((-len(s2)) % 4)
    try:
        out = base64.b64decode(s2, validate=False)
        return out if out else None
    except Exception:
        return None


def _looks_like_code(text: str) -> bool:
    if not text:
        return False
    low = text.lower()
    hits = sum(1 for k in CODE_KEYWORDS if k in low)
    braces = low.count("{") + low.count("}") + low.count(";") + low.count("(")
    return hits >= 2 or (hits >= 1 and braces >= 5)


def _md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def _run_subproc(cmd: List[str], input_bytes: Optional[bytes] = None, timeout: int = SUBPROC_TIMEOUT) -> Optional[bytes]:
    try:
        r = subprocess.run(cmd, input=input_bytes, capture_output=True, timeout=timeout, check=False)
        if r.returncode != 0:
            log.debug("subproc rc=%s stderr=%s", r.returncode, r.stderr[:300])
            return None
        return r.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError, ValueError) as e:
        log.debug("subproc fail %s: %s", cmd[0] if cmd else "cmd", e)
        return None


def _js_beautify(text: str) -> str:
    if len(text.encode("utf-8", errors="ignore")) > MAX_BEAUTIFY_BYTES:
        return text
    try:
        opts = jsbeautifier.default_options()
        opts.indent_size = 2
        opts.space_in_empty_paren = True
        opts.wrap_line_length = 0
        return jsbeautifier.beautify(text, opts)
    except Exception:
        return text


def _try_synchrony(text: str) -> Optional[str]:
    if len(text.encode("utf-8", errors="ignore")) > MAX_EXTERNAL_JS_BYTES:
        return None
    if not ("_0x" in text or "javascript-obfuscator" in text or "stringArray" in text):
        return None
    fin = tempfile.NamedTemporaryFile(suffix=".js", delete=False)
    fout_path = fin.name + ".out.js"
    try:
        fin.write(text.encode("utf-8", errors="ignore"))
        fin.close()
        commands = (["synchrony", "deobfuscate", fin.name, "-o", fout_path], ["deobfuscator", "-s", fin.name, "-o", fout_path])
        for cmd in commands:
            if _run_subproc(cmd, timeout=SUBPROC_TIMEOUT) is not None and os.path.exists(fout_path):
                try:
                    data = open(fout_path, "rb").read()
                    if data and data != text.encode("utf-8", errors="ignore"):
                        return data.decode("utf-8", errors="replace")
                except Exception:
                    continue
        return None
    finally:
        for p in (fin.name, fout_path):
            try:
                os.unlink(p)
            except OSError:
                continue


def _parse_string_array(arr_literal: str) -> List[str]:
    out = []
    for m in re.finditer(r"(['\"])((?:\\.|(?!\1).)*?)\1", arr_literal, re.DOTALL):
        try:
            out.append(m.group(2).encode("utf-8").decode("unicode_escape"))
        except Exception:
            out.append(m.group(2))
    return out


def _try_js_0x_fallback(text: str) -> Optional[str]:
    head = text[:500000]
    m = re.search(r"(?:var|let|const)\s+(_0x[a-fA-F0-9]+)\s*=\s*(\[(?:[^\[\]]|\\.|\n|\r){20,200000}\])\s*;", head, re.DOTALL)
    if not m:
        return None
    arr_name = m.group(1)
    arr = _parse_string_array(m.group(2))
    if not arr:
        return None
    fn_names = set()
    for f in re.finditer(r"(?:function\s+|(?:var|let|const)\s+)(_0x[a-fA-F0-9]+)\s*(?:=\s*function)?\s*\(\s*([A-Za-z_$][\w$]*)", head):
        fn_names.add(f.group(1))
    for f in re.finditer(r"(?:var|let|const)\s+(_0x[a-fA-F0-9]+)\s*=\s*function\s*\(", head):
        fn_names.add(f.group(1))
    if not fn_names:
        return None
    pattern = re.compile(r"\b(" + "|".join(re.escape(n) for n in sorted(fn_names, key=len, reverse=True)) + r")\s*\(\s*(0x[0-9a-fA-F]+|\d+)\s*(?:,\s*['\"][^'\"]*['\"])?\s*\)")
    changed = False

    def repl(match: re.Match) -> str:
        nonlocal changed
        try:
            idx = int(match.group(2), 16) if match.group(2).lower().startswith("0x") else int(match.group(2))
            if idx >= len(arr) and idx - 0x0 < len(arr):
                idx = idx - 0x0
            if 0 <= idx < len(arr):
                changed = True
                return json.dumps(arr[idx])
        except Exception:
            return match.group(0)
        return match.group(0)

    new_text = pattern.sub(repl, text, count=20000)
    return _js_beautify(new_text) if changed and new_text != text else None


def _try_js_eval_unwrap(text: str) -> Optional[str]:
    m = re.search(r"\beval\s*\(\s*(['\"])((?:\\.|(?!\1).){8,200000})\1\s*\)", text, re.DOTALL)
    if m:
        try:
            decoded = m.group(2).encode("utf-8").decode("unicode_escape")
            if decoded and decoded != text:
                return _js_beautify(decoded)
        except Exception:
            return None
    m2 = re.search(r"\beval\s*\(\s*atob\s*\(\s*(['\"])([A-Za-z0-9+/=_\-\s]{16,500000})\1\s*\)\s*\)", text)
    if m2:
        dec = _b64_decode_safe(m2.group(2))
        if dec:
            t = _to_text(dec)
            if t:
                return _js_beautify(t)
    m3 = re.search(r"Function\s*\(\s*(['\"])((?:\\.|(?!\1).){8,200000})\1\s*\)\s*\(\s*\)", text, re.DOTALL)
    if m3:
        try:
            decoded = m3.group(2).encode("utf-8").decode("unicode_escape")
            if decoded:
                return _js_beautify(decoded)
        except Exception:
            return None
    return None


def _try_js_atob_wrapper(text: str) -> Optional[str]:
    patterns = (r"atob\s*\(\s*(['\"])([A-Za-z0-9+/=_\-\s]{16,500000})\1\s*\)", r"Buffer\.from\s*\(\s*(['\"])([A-Za-z0-9+/=_\-\s]{16,500000})\1\s*,\s*['\"]base64['\"]\s*\)")
    for pat in patterns:
        m = re.search(pat, text)
        if m:
            dec = _b64_decode_safe(m.group(2))
            if dec:
                t = _to_text(dec)
                if t and (is_printable_text(dec) or _looks_like_code(t)):
                    return _js_beautify(t)
    return None


def _try_py_marshal(data: bytes) -> Optional[str]:
    text = _to_text(data)
    if not text or "marshal" not in text:
        return None
    m = re.search(r"marshal\.loads\s*\(\s*(?:base64\.b64decode\s*\(\s*)?b?(['\"])([A-Za-z0-9+/=_\-\\xX]{16,500000})\1", text)
    if not m:
        return None
    payload = m.group(2)
    try:
        raw = _b64_decode_safe(payload)
        if raw is None:
            raw = payload.encode("latin-1").decode("unicode_escape").encode("latin-1")
        obj = marshal.loads(raw)
        import dis
        buf = io.StringIO()
        dis.dis(obj, file=buf)
        return buf.getvalue()
    except Exception:
        return None


def _try_py_exec_compile(data: bytes) -> Optional[str]:
    text = _to_text(data)
    if not text or "exec" not in text:
        return None
    patterns = (r"exec\s*\(\s*compile\s*\(\s*(?:base64\.b64decode\s*\(\s*)?b?(['\"])([A-Za-z0-9+/=_\-]{16,500000})\1", r"exec\s*\(\s*base64\.b64decode\s*\(\s*b?(['\"])([A-Za-z0-9+/=_\-]{16,500000})\1")
    for pat in patterns:
        m = re.search(pat, text)
        if m:
            dec = _b64_decode_safe(m.group(2))
            if dec:
                t = _to_text(dec)
                if t:
                    return t
    m2 = re.search(r"exec\s*\(\s*(['\"])((?:\\x[0-9a-fA-F]{2}){8,500000})\1\s*\)", text)
    if m2:
        try:
            return m2.group(2).encode("utf-8").decode("unicode_escape")
        except Exception:
            return None
    return None


def _try_raw_base64(text: str) -> Optional[str]:
    stripped = text.strip()
    if len(stripped) < 16 or len(stripped) > MAX_DECODE_TEXT_BYTES or not re.fullmatch(r"[A-Za-z0-9+/=_\-\s]+", stripped):
        return None
    if any(ch in stripped for ch in "{}();<>\"") and "\n" not in stripped:
        return None
    dec = _b64_decode_safe(stripped)
    if dec is None or not is_printable_text(dec):
        return None
    return dec.decode("utf-8", errors="replace")


def _try_base64_chunks(text: str) -> Optional[str]:
    if len(text) > MAX_DECODE_TEXT_BYTES:
        return None
    chunks = re.findall(r"[A-Za-z0-9+/=_\-]{80,}", text)
    if len(chunks) < 2:
        return None
    joined = "".join(chunks)
    dec = _b64_decode_safe(joined)
    if dec is None or not is_printable_text(dec):
        return None
    return dec.decode("utf-8", errors="replace")


def _try_hex_string(text: str) -> Optional[str]:
    stripped = re.sub(r"\s+", "", text)
    if len(stripped) < 20 or len(stripped) > MAX_DECODE_TEXT_BYTES * 2 or len(stripped) % 2 != 0 or not re.fullmatch(r"[0-9a-fA-F]+", stripped):
        return None
    try:
        dec = bytes.fromhex(stripped)
    except ValueError:
        return None
    if not is_printable_text(dec):
        return None
    return dec.decode("utf-8", errors="replace")


def _try_hex_escapes(text: str) -> Optional[str]:
    if len(re.findall(r"\\x[0-9a-fA-F]{2}", text[:500000])) < 3:
        return None
    out = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), text)
    return out if out != text else None


def _try_percent_encoding(text: str) -> Optional[str]:
    pct = text.count("%")
    if pct < 5 or (pct / max(len(text), 1)) < 0.03:
        return None
    try:
        out = urllib.parse.unquote(text)
        return out if out != text else None
    except Exception:
        return None


def _try_html_entities(text: str) -> Optional[str]:
    if len(re.findall(r"&[#a-zA-Z0-9]+;", text[:500000])) < 3:
        return None
    out = html.unescape(text)
    return out if out != text else None


def _try_unicode_escapes(text: str) -> Optional[str]:
    if len(re.findall(r"\\u[0-9a-fA-F]{4}", text[:500000])) < 3:
        return None
    out = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), text)
    return out if out != text else None


def _try_octal_escapes(text: str) -> Optional[str]:
    if len(re.findall(r"\\[0-7]{3}", text[:500000])) < 3:
        return None
    out = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), text)
    return out if out != text else None


def _try_js_string_escapes(text: str) -> Optional[str]:
    cnt = sum(text.count(esc) for esc in ("\\n", "\\t", "\\r", "\\\"", "\\'"))
    if cnt < 3:
        return None
    try:
        out = codecs.decode(text, "unicode_escape")
        return out if out != text else None
    except Exception:
        return None


def _try_json_b64_fields(text: str) -> Optional[str]:
    if len(text) > MAX_DECODE_TEXT_BYTES or not text.lstrip().startswith(("{", "[")):
        return None
    try:
        obj = json.loads(text)
    except Exception:
        return None
    changed = False

    def walk(x: Any, depth: int = 0) -> Any:
        nonlocal changed
        if depth > 20:
            return x
        if isinstance(x, dict):
            return {k: walk(v, depth + 1) for k, v in x.items()}
        if isinstance(x, list):
            return [walk(v, depth + 1) for v in x]
        if isinstance(x, str) and 16 <= len(x) <= 500000 and re.fullmatch(r"[A-Za-z0-9+/=_\-]+", x):
            dec = _b64_decode_safe(x)
            if dec and is_printable_text(dec):
                changed = True
                return dec.decode("utf-8", errors="replace")
        return x

    new_obj = walk(obj)
    return json.dumps(new_obj, indent=2, ensure_ascii=False) if changed else None


def _try_rot13(text: str) -> Optional[str]:
    if _looks_like_code(text):
        return None
    try:
        out = codecs.decode(text, "rot_13")
    except Exception:
        return None
    return out if out != text and _looks_like_code(out) else None


def _try_jsfuck(text: str) -> Optional[str]:
    stripped = re.sub(r"\s+", "", text)
    if len(stripped) < 40 or len(stripped) > 120000:
        return None
    allowed = set("[]()!+")
    if sum(1 for ch in stripped if ch in allowed) / len(stripped) < 0.9:
        return None
    script = "let s=process.argv[1];try{let r=eval(s);if(r!=null)process.stdout.write(String(r))}catch(e){process.exit(1)}"
    out = _run_subproc(["node", "-e", script, text], timeout=JSFUCK_TIMEOUT)
    if out is None or not out:
        return None
    return out.decode("utf-8", errors="replace")


def _try_brainfuck(text: str) -> Optional[str]:
    non_ws = [c for c in text if not c.isspace()]
    if len(non_ws) < 50 or len(non_ws) > 300000:
        return None
    bf_chars = set("><+-.,[]")
    if sum(1 for c in non_ws if c in bf_chars) / len(non_ws) < 0.8:
        return None
    code = [c for c in text if c in bf_chars]
    tape = bytearray(30000)
    ptr = 0
    pc = 0
    out = bytearray()
    steps = 0
    bracket_map: Dict[int, int] = {}
    stack: List[int] = []
    for i, ch in enumerate(code):
        if ch == "[":
            stack.append(i)
        elif ch == "]":
            if not stack:
                return None
            j = stack.pop()
            bracket_map[i] = j
            bracket_map[j] = i
    if stack:
        return None
    while pc < len(code) and steps < BF_MAX_STEPS:
        ch = code[pc]
        if ch == ">":
            ptr = (ptr + 1) % 30000
        elif ch == "<":
            ptr = (ptr - 1) % 30000
        elif ch == "+":
            tape[ptr] = (tape[ptr] + 1) & 255
        elif ch == "-":
            tape[ptr] = (tape[ptr] - 1) & 255
        elif ch == ".":
            out.append(tape[ptr])
            if len(out) > 200000:
                break
        elif ch == ",":
            tape[ptr] = 0
        elif ch == "[" and tape[ptr] == 0:
            pc = bracket_map[pc]
        elif ch == "]" and tape[ptr] != 0:
            pc = bracket_map[pc]
        pc += 1
        steps += 1
    if not out:
        return None
    return out.decode("utf-8", errors="replace")


def _try_php_obfuscation(text: str) -> Optional[str]:
    m = re.search(r"eval\s*\(\s*(?:gzinflate\s*\(\s*)?base64_decode\s*\(\s*(['\"])([A-Za-z0-9+/=_\-]{16,500000})\1", text)
    if not m:
        return None
    dec = _b64_decode_safe(m.group(2))
    if dec is None:
        return None
    if not is_printable_text(dec):
        try:
            import zlib
            dec = zlib.decompress(dec, -15)
        except Exception:
            return None
    if not is_printable_text(dec):
        return None
    return dec.decode("utf-8", errors="replace")


def _try_reversed(text: str) -> Optional[str]:
    if len(text) < 30 or len(text) > MAX_DECODE_TEXT_BYTES or _looks_like_code(text):
        return None
    rev = text[::-1]
    return rev if _looks_like_code(rev) else None


def _try_xor_single_byte(data: bytes) -> Optional[str]:
    if len(data) < 30 or len(data) > 200000 or is_printable_text(data):
        return None
    best: Tuple[int, Optional[str]] = (0, None)
    for key in range(1, 256):
        dec = bytes(b ^ key for b in data[:4096])
        try:
            t = dec.decode("utf-8")
        except UnicodeDecodeError:
            continue
        printable = sum(1 for ch in t if 32 <= ord(ch) < 127 or ch in "\n\r\t")
        if printable > best[0] and _looks_like_code(t):
            full = bytes(b ^ key for b in data)
            best = (printable, full.decode("utf-8", errors="replace"))
    return best[1]


def _single_pass(data: bytes, filename: str) -> Tuple[bytes, Optional[str]]:
    ext = os.path.splitext(filename)[1].lower()
    text = _to_text(data)
    if text is None:
        return data, None
    if ext in JS_EXTS or "_0x" in text:
        if re.search(r"_0x[a-fA-F0-9]{3,}", text[:500000]):
            r = _try_synchrony(text)
            if r and r != text:
                return _js_beautify(r).encode("utf-8", errors="replace"), "js_0x_synchrony"
            r = _try_js_0x_fallback(text)
            if r and r != text:
                return r.encode("utf-8", errors="replace"), "js_0x_fallback"
    if ext in JS_EXTS or "eval(" in text or "Function(" in text:
        r = _try_js_eval_unwrap(text)
        if r and r != text:
            return r.encode("utf-8", errors="replace"), "js_eval_unwrap"
    if "atob(" in text or "Buffer.from" in text:
        r = _try_js_atob_wrapper(text)
        if r and r != text:
            return r.encode("utf-8", errors="replace"), "js_atob_wrapper"
    if ext in PY_EXTS or "marshal" in text:
        r = _try_py_marshal(data)
        if r and r != text:
            return r.encode("utf-8", errors="replace"), "py_marshal_disassembly"
    if ext in PY_EXTS or "exec(" in text:
        r = _try_py_exec_compile(data)
        if r and r != text:
            return r.encode("utf-8", errors="replace"), "py_exec_unwrap"
    tests = [
        (_try_raw_base64, "base64"), (_try_base64_chunks, "base64_chunks"), (_try_hex_string, "hex_string"),
        (_try_hex_escapes, "hex_escapes"), (_try_percent_encoding, "uri_percent"), (_try_html_entities, "html_entities"),
        (_try_unicode_escapes, "unicode_escapes"), (_try_octal_escapes, "octal_escapes"), (_try_js_string_escapes, "js_string_escapes"),
        (_try_json_b64_fields, "json_b64_fields"), (_try_rot13, "rot13"), (_try_jsfuck, "jsfuck"), (_try_brainfuck, "brainfuck"),
    ]
    for fn, name in tests:
        r = fn(text)
        if r is not None and r != text:
            return r.encode("utf-8", errors="replace"), name
    if ext in PHP_EXTS or "<?php" in text:
        r = _try_php_obfuscation(text)
        if r is not None and r != text:
            return r.encode("utf-8", errors="replace"), "php_eval_b64"
    r = _try_reversed(text)
    if r is not None and r != text:
        return r.encode("utf-8", errors="replace"), "string_reverse"
    r = _try_xor_single_byte(data)
    if r is not None:
        return r.encode("utf-8", errors="replace"), "xor_single_byte"
    return data, None


def detect_and_decode(data: bytes, filename: str) -> Tuple[bytes, List[str]]:
    methods: List[str] = []
    current = data
    seen = {_md5(current)}
    for _ in range(MAX_PASSES):
        new_data, method = _single_pass(current, filename)
        new_hash = _md5(new_data)
        if method is None or new_hash in seen:
            break
        methods.append(method)
        current = new_data
        seen.add(new_hash)
    ext = os.path.splitext(filename)[1].lower()
    if ext in JS_EXTS and methods:
        t = _to_text(current)
        if t is not None:
            beaut = _js_beautify(t)
            if beaut != t:
                current = beaut.encode("utf-8", errors="replace")
                methods.append("jsbeautify")
    return current, methods


def decode_worker(data: bytes, filename: str, out_path: str, meta_path: str) -> None:
    try:
        decoded, methods = detect_and_decode(data, filename)
        with open(out_path, "wb") as f:
            f.write(decoded)
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump({"ok": True, "methods": methods, "error": ""}, f)
    except Exception as e:
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump({"ok": False, "methods": [], "error": str(e)}, f)


def decode_with_timeout(data: bytes, filename: str) -> Tuple[bytes, List[str], Optional[str]]:
    if len(data) > MAX_DECODE_TEXT_BYTES:
        return data, [], f"skipped huge text file over {MAX_DECODE_TEXT_BYTES // 1024} KB"
    ctx = multiprocessing.get_context("fork") if sys.platform != "win32" else multiprocessing.get_context("spawn")
    with tempfile.TemporaryDirectory() as td:
        out_path = os.path.join(td, "decoded.bin")
        meta_path = os.path.join(td, "meta.json")
        proc = ctx.Process(target=decode_worker, args=(data, filename, out_path, meta_path))
        proc.daemon = True
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
            return data, [], "decoder returned no result"
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
        except Exception as e:
            return data, [], f"decoder metadata failed: {e}"
        if not meta.get("ok"):
            return data, [], meta.get("error") or "decoder failed"
        try:
            with open(out_path, "rb") as f:
                decoded = f.read()
        except Exception as e:
            return data, [], f"decoder output failed: {e}"
        return decoded, list(meta.get("methods") or []), None


def is_binary_file(filename: str, data: bytes) -> bool:
    ext = os.path.splitext(filename)[1].lower()
    if ext in TEXT_EXTS:
        return False
    if ext in BINARY_EXTS:
        return True
    return not is_printable_text(data)


def safe_zip_name(name: str) -> str:
    name = name.replace("\\", "/").lstrip("/")
    parts = [p for p in name.split("/") if p and p not in (".", "..")]
    clean = "/".join(parts) or "file"
    if len(clean) > 240:
        root, ext = os.path.splitext(clean)
        clean = root[:220] + ext[:20]
    return clean


def unique_name(name: str, used: set) -> str:
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


def add_method(stats: Dict[str, Any], method: str) -> None:
    stats["methods"][method] = stats["methods"].get(method, 0) + 1


def process_zip_sync(zip_bytes: bytes, progress_state: Dict[str, Any]) -> Tuple[bytes, Dict[str, Any]]:
    start = time.monotonic()
    stats: Dict[str, Any] = {"decoded": 0, "clean": 0, "binary": 0, "errors": [], "methods": {}, "decoded_files": [], "original_size": len(zip_bytes), "output_size": 0, "timed_out": 0, "skipped": 0}
    with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as src:
        entries = [i for i in src.infolist() if not i.is_dir()]
        total = len(entries)
        progress_state["total"] = total
        progress_state["done"] = 0
        progress_state["current"] = ""
        out_buf = io.BytesIO()
        used_names: set = set()
        with zipfile.ZipFile(out_buf, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as dst:
            for info in src.infolist():
                if time.monotonic() - start > TOTAL_JOB_TIMEOUT_SECONDS:
                    stats["errors"].append(f"job stopped after {TOTAL_JOB_TIMEOUT_SECONDS}s total timeout")
                    break
                arcname = unique_name(info.filename, used_names)
                if info.is_dir():
                    continue
                progress_state["current"] = os.path.basename(info.filename) or info.filename
                try:
                    if info.file_size > MAX_UNCOMPRESSED_BYTES:
                        stats["skipped"] += 1
                        stats["errors"].append(f"{info.filename}: skipped oversized file")
                        progress_state["done"] += 1
                        continue
                    raw = src.read(info.filename)
                except Exception as e:
                    stats["errors"].append(f"{info.filename}: read failed: {e}")
                    progress_state["done"] += 1
                    continue
                try:
                    if is_binary_file(info.filename, raw):
                        dst.writestr(arcname, raw)
                        stats["binary"] += 1
                    else:
                        decoded, methods, err = decode_with_timeout(raw, info.filename)
                        if err:
                            dst.writestr(arcname, raw)
                            stats["clean"] += 1
                            if "timed out" in err:
                                stats["timed_out"] += 1
                            stats["errors"].append(f"{info.filename}: {err}")
                        elif methods:
                            dst.writestr(arcname, decoded)
                            stats["decoded"] += 1
                            stats["decoded_files"].append((info.filename, methods))
                            for m in methods:
                                add_method(stats, m)
                        else:
                            dst.writestr(arcname, raw)
                            stats["clean"] += 1
                except Exception as e:
                    log.exception("decode failed for %s", info.filename)
                    stats["errors"].append(f"{info.filename}: {e}")
                    dst.writestr(arcname, raw)
                progress_state["done"] += 1
        out_bytes = out_buf.getvalue()
    stats["output_size"] = len(out_bytes)
    progress_state["finished"] = True
    return out_bytes, stats


def validate_zip(zip_bytes: bytes) -> Tuple[int, int]:
    with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as z:
        bad = z.testzip()
        if bad:
            raise ValueError(f"corrupted entry: {bad}")
        entries = [i for i in z.infolist() if not i.is_dir()]
        if len(entries) > MAX_FILES:
            raise ValueError(f"too many files: {len(entries)} max {MAX_FILES}")
        total = sum(i.file_size for i in entries)
        if total > MAX_UNCOMPRESSED_BYTES:
            raise ValueError(f"unzipped size too large: {total // 1024} KB max {MAX_UNCOMPRESSED_MB * 1024} KB")
        return len(entries), total


def render_progress_bar(done: int, total: int, current: str) -> str:
    pct = int((done / total) * 100) if total else 0
    filled = int((done / total) * 10) if total else 0
    bar = "█" * filled + "░" * (10 - filled)
    cur = current or "..."
    if len(cur) > 40:
        cur = cur[:37] + "..."
    return f"⚙️ <b>Processing...</b>\n<code>[{bar}]</code> {pct}%\n<code>{done}/{total}</code> — <code>{html.escape(cur)}</code>"


def render_report(stats: Dict[str, Any]) -> str:
    lines = ["🔬 <b>Decode Report</b>", ""]
    lines.append(f"📂 Decoded files: <b>{stats['decoded']}</b>")
    lines.append(f"✨ Already clean: <b>{stats['clean']}</b>")
    lines.append(f"⏭ Binary skipped: <b>{stats['binary']}</b>")
    if stats.get("timed_out"):
        lines.append(f"⏱ Timed-out files kept original: <b>{stats['timed_out']}</b>")
    if stats.get("skipped"):
        lines.append(f"🚧 Oversized files skipped: <b>{stats['skipped']}</b>")
    if stats["errors"]:
        lines.append(f"⚠️ Notes: <b>{len(stats['errors'])}</b>")
    lines.append("")
    if stats["methods"]:
        lines.append("📊 <b>Encoding/obfuscation types found:</b>")
        for k, v in sorted(stats["methods"].items(), key=lambda x: -x[1]):
            lines.append(f"  • <code>{html.escape(k)}</code>: {v}")
        lines.append("")
    lines.append(f"📦 Original: <b>{stats['original_size'] // 1024} KB</b>")
    lines.append(f"📦 Output: <b>{stats['output_size'] // 1024} KB</b>")
    if stats["decoded_files"]:
        lines.append("")
        lines.append("📝 <b>Files decoded:</b>")
        for fname, methods in stats["decoded_files"][:25]:
            lines.append(f"  <code>{html.escape(fname)}</code> → {html.escape(' → '.join(methods))}")
        if len(stats["decoded_files"]) > 25:
            lines.append(f"  …and {len(stats['decoded_files']) - 25} more")
    if stats["errors"]:
        lines.append("")
        lines.append("⚠️ <b>Notes:</b>")
        for e in stats["errors"][:12]:
            lines.append(f"  • <code>{html.escape(str(e)[:220])}</code>")
        if len(stats["errors"]) > 12:
            lines.append(f"  …and {len(stats['errors']) - 12} more")
    text = "\n".join(lines)
    return text if len(text) <= 3900 else text[:3850] + "\n…truncated"


WELCOME = (
    "👋 <b>ZIP Deobfuscator Bot</b>\n\n"
    "Send me a <b>.zip</b> file and I'll auto-detect and decode obfuscated or encoded text files inside it, then send back a clean zip with the original structure.\n\n"
    "<b>Supported types:</b>\n"
    "• JavaScript <code>_0x</code> obfuscation\n"
    "• JS <code>eval()</code>, <code>Function()</code>, <code>atob()</code>, <code>Buffer.from(...,'base64')</code>\n"
    "• Python <code>marshal</code>, <code>exec(compile(...))</code>, hex exec wrappers\n"
    "• Base64, hex strings, <code>\\x</code>, URI, HTML entities, unicode and octal escapes\n"
    "• JS string escapes, JSON Base64 fields, ROT13, JSFuck, Brainfuck, PHP base64 chains, string reversal, single-byte XOR\n\n"
    f"Max zip size: <b>{MAX_ZIP_MB} MB</b>.\n"
    f"Hard timeout: <b>{FILE_TIMEOUT_SECONDS}s per file</b>, so it cannot freeze for hours."
)


def confirm_kb(job_id: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="✅ Decode it", callback_data=f"go:{job_id}"), InlineKeyboardButton(text="❌ Cancel", callback_data=f"cancel:{job_id}")], [InlineKeyboardButton(text="ℹ️ Help", callback_data="help")]])


def done_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="📦 Send another zip", callback_data="another"), InlineKeyboardButton(text="✔️ Done", callback_data="done")], [InlineKeyboardButton(text="🧾 Show help", callback_data="help")]])


@dp.message(CommandStart())
async def cmd_start(m: Message) -> None:
    await m.answer(WELCOME)


@dp.message(Command("help"))
async def cmd_help(m: Message) -> None:
    await m.answer(WELCOME)


@dp.callback_query(F.data == "help")
async def cb_help(c: CallbackQuery) -> None:
    await c.answer()
    await c.message.answer(WELCOME)


@dp.message(F.document)
async def on_document(m: Message) -> None:
    if bot is None:
        return
    doc: Document = m.document
    fname = doc.file_name or "file"
    if not fname.lower().endswith(".zip"):
        await m.reply("⚠️ Please send a <b>.zip</b> file.")
        return
    if doc.file_size and doc.file_size > MAX_ZIP_BYTES:
        await m.reply(f"⚠️ Zip too large. Max allowed is <b>{MAX_ZIP_MB} MB</b>.")
        return
    await bot.send_chat_action(m.chat.id, ChatAction.UPLOAD_DOCUMENT)
    try:
        buf = io.BytesIO()
        await asyncio.wait_for(bot.download(doc, destination=buf), timeout=120)
        zip_bytes = buf.getvalue()
    except Exception as e:
        log.exception("download failed")
        await m.reply(f"❌ Failed to download file: <code>{html.escape(str(e))}</code>")
        return
    if len(zip_bytes) > MAX_ZIP_BYTES:
        await m.reply(f"⚠️ Zip too large after download. Max allowed is <b>{MAX_ZIP_MB} MB</b>.")
        return
    try:
        file_count, uncompressed = validate_zip(zip_bytes)
    except zipfile.BadZipFile:
        await m.reply("❌ Invalid or corrupted zip file.")
        return
    except Exception as e:
        await m.reply(f"❌ Zip rejected: <code>{html.escape(str(e))}</code>")
        return
    job_id = f"{m.from_user.id if m.from_user else m.chat.id}_{m.message_id}_{int(time.time())}"
    pending_jobs[job_id] = zip_bytes
    await m.reply(f"📦 <b>{html.escape(fname)}</b>\n📁 Files: <b>{file_count}</b>\n📐 Uncompressed: <b>{uncompressed // 1024} KB</b>\n💾 Zip: <b>{len(zip_bytes) // 1024} KB</b>\n\nReady to decode?", reply_markup=confirm_kb(job_id))


async def progress_loop(chat_id: int, msg_id: int, state: Dict[str, Any]) -> None:
    if bot is None:
        return
    last_text = ""
    while not state.get("finished"):
        await asyncio.sleep(1.2)
        total = state.get("total", 0)
        done = state.get("done", 0)
        current = state.get("current", "")
        if not total:
            continue
        text = render_progress_bar(done, total, current)
        if text != last_text:
            try:
                await asyncio.wait_for(bot.edit_message_text(chat_id=chat_id, message_id=msg_id, text=text), timeout=10)
                last_text = text
            except Exception:
                continue


@dp.callback_query(F.data.startswith("cancel:"))
async def on_cancel(c: CallbackQuery) -> None:
    job_id = c.data.split(":", 1)[1]
    pending_jobs.pop(job_id, None)
    await c.message.edit_text("❌ Cancelled.")
    await c.answer()


@dp.callback_query(F.data.startswith("go:"))
async def on_go(c: CallbackQuery) -> None:
    job_id = c.data.split(":", 1)[1]
    zip_bytes = pending_jobs.pop(job_id, None)
    if zip_bytes is None:
        await c.answer("Job expired.", show_alert=True)
        return
    if job_sem.locked():
        await c.answer("Another zip is processing. Wait a moment and try again.", show_alert=True)
        pending_jobs[job_id] = zip_bytes
        return
    await c.answer()
    async with job_sem:
        progress_msg = await c.message.edit_text("⚙️ <b>Processing...</b>\n<code>[░░░░░░░░░░]</code> 0%\nstarting...")
        state: Dict[str, Any] = {"total": 0, "done": 0, "current": "", "finished": False}
        poll_task = asyncio.create_task(progress_loop(c.message.chat.id, progress_msg.message_id, state))
        loop = asyncio.get_running_loop()
        try:
            out_bytes, stats = await asyncio.wait_for(loop.run_in_executor(None, process_zip_sync, zip_bytes, state), timeout=TOTAL_JOB_TIMEOUT_SECONDS + 30)
        except zipfile.BadZipFile:
            state["finished"] = True
            await poll_task
            await asyncio.wait_for(progress_msg.edit_text("❌ Invalid zip."), timeout=15)
            return
        except asyncio.TimeoutError:
            state["finished"] = True
            await poll_task
            await asyncio.wait_for(progress_msg.edit_text(f"❌ Job stopped after {TOTAL_JOB_TIMEOUT_SECONDS}s. Try a smaller zip or raise TOTAL_JOB_TIMEOUT_SECONDS."), timeout=15)
            return
        except Exception as e:
            log.exception("process failed")
            state["finished"] = True
            await poll_task
            await asyncio.wait_for(progress_msg.edit_text(f"❌ Processing failed: <code>{html.escape(str(e))}</code>"), timeout=15)
            return
        state["finished"] = True
        await poll_task
        try:
            total = state.get("total", 0)
            await asyncio.wait_for(progress_msg.edit_text(f"⚙️ <b>Processing...</b>\n<code>[██████████]</code> 100%\n<code>{total}/{total}</code> — done"), timeout=15)
        except Exception:
            log.debug("final progress edit failed", exc_info=True)
        await c.message.answer(render_report(stats))
        out_name = f"decoded_{int(time.time())}.zip"
        await c.message.answer_document(BufferedInputFile(out_bytes, filename=out_name), caption="✅ Done.", reply_markup=done_kb())


@dp.callback_query(F.data == "another")
async def on_another(c: CallbackQuery) -> None:
    await c.answer()
    await c.message.answer("📥 Send me the next <b>.zip</b> file.")


@dp.callback_query(F.data == "done")
async def on_done(c: CallbackQuery) -> None:
    await c.answer("👋")
    try:
        await c.message.edit_reply_markup(reply_markup=None)
    except Exception:
        log.debug("reply markup cleanup failed", exc_info=True)


async def health(_request: web.Request) -> web.Response:
    return web.Response(text="OK")


async def start_health_server() -> None:
    app = web.Application()
    app.router.add_get("/", health)
    app.router.add_get("/health", health)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", PORT)
    await site.start()
    log.info("health server listening on :%d", PORT)


async def main() -> None:
    if not BOT_TOKEN:
        log.error("BOT_TOKEN env var is required")
        sys.exit(1)
    await start_health_server()
    log.info("starting polling max_zip_mb=%d file_timeout=%ds", MAX_ZIP_MB, FILE_TIMEOUT_SECONDS)
    await bot.delete_webhook(drop_pending_updates=True)
    await dp.start_polling(bot)


if __name__ == "__main__":
    multiprocessing.freeze_support()
    asyncio.run(main())
