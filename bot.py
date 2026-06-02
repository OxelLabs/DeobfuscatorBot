import asyncio
import base64
import hashlib
import html
import io
import logging
import marshal
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.parse
import zipfile
from typing import Optional, Tuple, List, Dict, Any

import chardet
import jsbeautifier
from aiohttp import web
from aiogram import Bot, Dispatcher, F
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode, ChatAction
from aiogram.filters import CommandStart, Command
from aiogram.types import (
    Message,
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    BufferedInputFile,
    Document,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("zipbot")

BOT_TOKEN = os.environ.get("BOT_TOKEN", "").strip()
MAX_ZIP_MB = int(os.environ.get("MAX_ZIP_MB", "50"))
MAX_ZIP_BYTES = MAX_ZIP_MB * 1024 * 1024
PORT = int(os.environ.get("PORT", "8080"))
MAX_PASSES = 20
SUBPROC_TIMEOUT = 15
JSFUCK_TIMEOUT = 10
BF_MAX_STEPS = 1_000_000

BINARY_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tiff", ".ico",
    ".mp4", ".mp3", ".wav", ".flac", ".ogg", ".avi", ".mkv", ".mov",
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
    ".exe", ".dll", ".so", ".bin", ".dat", ".class", ".pyc",
    ".pdf", ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".psd", ".ai", ".sketch",
}

JS_EXTS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}
PY_EXTS = {".py", ".pyw"}
PHP_EXTS = {".php", ".phtml", ".php5", ".php7"}

CODE_KEYWORDS = [
    "function", "const ", "var ", "let ", "return", "import", "export",
    "class ", "def ", "print", "require", "module", "if ", "for ", "while ",
    "async", "await", " the ", " and ", "this", "that",
]


def is_printable_text(data: bytes) -> bool:
    if not data:
        return False
    sample = data[:8192]
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
    return (bad / max(len(text), 1)) <= 0.05


def _to_text(data: bytes) -> Optional[str]:
    if not data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            det = chardet.detect(data[:16384])
            enc = det.get("encoding") or "utf-8"
            return data.decode(enc, errors="replace")
        except Exception:
            return None


def _b64_decode_safe(s: str) -> Optional[bytes]:
    s2 = re.sub(r"\s+", "", s)
    if len(s2) < 16:
        return None
    if not re.fullmatch(r"[A-Za-z0-9+/=]+", s2):
        return None
    pad = (-len(s2)) % 4
    s2 = s2 + ("=" * pad)
    try:
        return base64.b64decode(s2, validate=False)
    except Exception:
        return None


def _looks_like_code(text: str) -> bool:
    if not text:
        return False
    low = text.lower()
    hits = sum(1 for k in CODE_KEYWORDS if k in low)
    return hits >= 2


def _md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def _run_subproc(cmd: List[str], input_bytes: Optional[bytes] = None, timeout: int = SUBPROC_TIMEOUT) -> Optional[bytes]:
    try:
        r = subprocess.run(
            cmd,
            input=input_bytes,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        if r.returncode != 0:
            log.debug("subproc rc=%s stderr=%s", r.returncode, r.stderr[:300])
            return None
        return r.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        log.debug("subproc fail %s: %s", cmd[0], e)
        return None


def _js_beautify(text: str) -> str:
    try:
        opts = jsbeautifier.default_options()
        opts.indent_size = 2
        opts.space_in_empty_paren = True
        return jsbeautifier.beautify(text, opts)
    except Exception:
        return text


def _try_synchrony(text: str) -> Optional[str]:
    fin = tempfile.NamedTemporaryFile(suffix=".js", delete=False)
    fout_path = fin.name + ".out.js"
    try:
        fin.write(text.encode("utf-8"))
        fin.close()
        for cmd in (
            ["synchrony", "deobfuscate", fin.name, "-o", fout_path],
            ["npx", "--yes", "synchrony", "deobfuscate", fin.name, "-o", fout_path],
        ):
            out = _run_subproc(cmd, timeout=SUBPROC_TIMEOUT)
            if out is not None and os.path.exists(fout_path):
                try:
                    with open(fout_path, "rb") as f:
                        data = f.read()
                    if data and data != text.encode("utf-8"):
                        return data.decode("utf-8", errors="replace")
                except Exception:
                    pass
        for cmd in (
            ["deobfuscator", "-s", fin.name, "-o", fout_path],
            ["npx", "--yes", "deobfuscator", "-s", fin.name, "-o", fout_path],
        ):
            out = _run_subproc(cmd, timeout=SUBPROC_TIMEOUT)
            if out is not None and os.path.exists(fout_path):
                try:
                    with open(fout_path, "rb") as f:
                        data = f.read()
                    if data and data != text.encode("utf-8"):
                        return data.decode("utf-8", errors="replace")
                except Exception:
                    pass
        return None
    finally:
        for p in (fin.name, fout_path):
            try:
                os.unlink(p)
            except OSError:
                pass


def _try_js_0x_fallback(text: str) -> Optional[str]:
    m = re.search(r"(var|let|const)\s+(_0x[a-f0-9]+)\s*=\s*(\[[^\]]+\])\s*;", text)
    if not m:
        return None
    arr_name = m.group(2)
    arr_literal = m.group(3)
    try:
        items = re.findall(r"(?:'((?:[^'\\]|\\.)*)'|\"((?:[^\"\\]|\\.)*)\")", arr_literal)
        arr = [a or b for a, b in items]
    except Exception:
        return None
    if not arr:
        return None

    rot_match = re.search(
        rf"\(\s*function\s*\([^)]*\)\s*\{{[^}}]*{re.escape(arr_name)}[^}}]*\}}\s*\([^)]*\)\s*\)\s*;",
        text,
        re.DOTALL,
    )
    rotated = list(arr)
    if rot_match:
        for shift in range(len(arr)):
            rotated.append(rotated.pop(0))

    accessor = re.search(
        rf"(?:var|let|const)\s+(_0x[a-f0-9]+)\s*=\s*function\s*\(\s*([a-zA-Z_$][\w$]*)\s*,\s*([a-zA-Z_$][\w$]*)\s*\)",
        text,
    )
    if not accessor:
        return None
    fn_name = accessor.group(1)

    def repl(match: "re.Match") -> str:
        idx_str = match.group(1)
        try:
            if idx_str.startswith("0x"):
                idx = int(idx_str, 16)
            else:
                idx = int(idx_str)
            if 0 <= idx < len(rotated):
                return "'" + rotated[idx].replace("\\", "\\\\").replace("'", "\\'") + "'"
        except Exception:
            pass
        return match.group(0)

    new_text = re.sub(rf"{re.escape(fn_name)}\s*\(\s*(0x[0-9a-fA-F]+|\d+)\s*(?:,\s*['\"][^'\"]*['\"])?\s*\)", repl, text)
    if new_text == text:
        return None
    return _js_beautify(new_text)


def _try_js_eval_unwrap(text: str) -> Optional[str]:
    m = re.search(r"\beval\s*\(\s*(?:function\s*\([^)]*\)\s*\{\s*return\s+)?(['\"])((?:\\.|(?!\1).)*)\1", text, re.DOTALL)
    if m:
        payload = m.group(2)
        try:
            decoded = payload.encode("utf-8").decode("unicode_escape")
            if decoded and decoded != text:
                return _js_beautify(decoded)
        except Exception:
            pass
    m2 = re.search(r"\beval\s*\(\s*atob\s*\(\s*(['\"])([A-Za-z0-9+/=\s]+)\1\s*\)\s*\)", text)
    if m2:
        dec = _b64_decode_safe(m2.group(2))
        if dec:
            t = _to_text(dec)
            if t:
                return _js_beautify(t)
    m3 = re.search(r"Function\s*\(\s*(['\"])((?:\\.|(?!\1).)*)\1\s*\)\s*\(\s*\)", text, re.DOTALL)
    if m3:
        try:
            decoded = m3.group(2).encode("utf-8").decode("unicode_escape")
            if decoded:
                return _js_beautify(decoded)
        except Exception:
            pass
    return None


def _try_js_atob_wrapper(text: str) -> Optional[str]:
    for pat in (
        r"atob\s*\(\s*(['\"])([A-Za-z0-9+/=\s]+)\1\s*\)",
        r"Buffer\.from\s*\(\s*(['\"])([A-Za-z0-9+/=\s]+)\1\s*,\s*['\"]base64['\"]\s*\)",
    ):
        m = re.search(pat, text)
        if m:
            dec = _b64_decode_safe(m.group(2))
            if dec:
                t = _to_text(dec)
                if t and _looks_like_code(t):
                    return _js_beautify(t)
    return None


def _try_py_marshal(data: bytes) -> Optional[str]:
    text = _to_text(data)
    if not text:
        return None
    m = re.search(r"marshal\.loads\s*\(\s*(?:base64\.b64decode\s*\(\s*)?b?(['\"])([A-Za-z0-9+/=\\xX]+)\1", text)
    if not m:
        return None
    payload = m.group(2)
    try:
        raw = _b64_decode_safe(payload)
        if raw is None:
            try:
                raw = payload.encode("latin-1").decode("unicode_escape").encode("latin-1")
            except Exception:
                return None
        obj = marshal.loads(raw)
        import dis
        buf = io.StringIO()
        dis.dis(obj, file=buf)
        return buf.getvalue()
    except Exception:
        return None


def _try_py_exec_compile(data: bytes) -> Optional[str]:
    text = _to_text(data)
    if not text:
        return None
    m = re.search(r"exec\s*\(\s*compile\s*\(\s*(?:base64\.b64decode\s*\(\s*)?b?(['\"])([A-Za-z0-9+/=]+)\1", text)
    if m:
        dec = _b64_decode_safe(m.group(2))
        if dec:
            t = _to_text(dec)
            if t:
                return t
    m2 = re.search(r"exec\s*\(\s*(['\"])((?:\\x[0-9a-fA-F]{2})+)\1\s*\)", text)
    if m2:
        try:
            return m2.group(2).encode("utf-8").decode("unicode_escape")
        except Exception:
            return None
    m3 = re.search(r"exec\s*\(\s*base64\.b64decode\s*\(\s*b?(['\"])([A-Za-z0-9+/=]+)\1", text)
    if m3:
        dec = _b64_decode_safe(m3.group(2))
        if dec:
            t = _to_text(dec)
            if t:
                return t
    return None


def _try_raw_base64(text: str) -> Optional[str]:
    stripped = text.strip()
    if "\n" in stripped or " " in stripped or "\t" in stripped:
        return None
    if len(stripped) < 16:
        return None
    if not re.fullmatch(r"[A-Za-z0-9+/=]+", stripped):
        return None
    dec = _b64_decode_safe(stripped)
    if dec is None:
        return None
    if not is_printable_text(dec):
        return None
    return dec.decode("utf-8", errors="replace")


def _try_multiline_base64(text: str) -> Optional[str]:
    joined = re.sub(r"\s+", "", text)
    if len(joined) < 32:
        return None
    if not re.fullmatch(r"[A-Za-z0-9+/=]+", joined):
        return None
    if "\n" not in text.strip():
        return None
    dec = _b64_decode_safe(joined)
    if dec is None or not is_printable_text(dec):
        return None
    return dec.decode("utf-8", errors="replace")


def _try_base64_chunks(text: str) -> Optional[str]:
    chunks = re.findall(r"[A-Za-z0-9+/]{60,}={0,2}", text)
    if len(chunks) < 2:
        return None
    joined = "".join(chunks)
    dec = _b64_decode_safe(joined)
    if dec is None or not is_printable_text(dec):
        return None
    return dec.decode("utf-8", errors="replace")


def _try_hex_string(text: str) -> Optional[str]:
    stripped = re.sub(r"\s+", "", text)
    if len(stripped) < 20 or len(stripped) % 2 != 0:
        return None
    if not re.fullmatch(r"[0-9a-fA-F]+", stripped):
        return None
    try:
        dec = bytes.fromhex(stripped)
    except ValueError:
        return None
    if not is_printable_text(dec):
        return None
    return dec.decode("utf-8", errors="replace")


def _try_hex_escapes(text: str) -> Optional[str]:
    if len(re.findall(r"\\x[0-9a-fA-F]{2}", text)) < 3:
        return None
    out = re.sub(
        r"\\x([0-9a-fA-F]{2})",
        lambda m: chr(int(m.group(1), 16)),
        text,
    )
    return out if out != text else None


def _try_percent_encoding(text: str) -> Optional[str]:
    pct = text.count("%")
    if pct < 5 or (pct / max(len(text), 1)) < 0.05:
        return None
    try:
        out = urllib.parse.unquote(text)
        return out if out != text else None
    except Exception:
        return None


def _try_html_entities(text: str) -> Optional[str]:
    if len(re.findall(r"&[#a-zA-Z0-9]+;", text)) < 3:
        return None
    out = html.unescape(text)
    return out if out != text else None


def _try_unicode_escapes(text: str) -> Optional[str]:
    if len(re.findall(r"\\u[0-9a-fA-F]{4}", text)) < 3:
        return None
    out = re.sub(
        r"\\u([0-9a-fA-F]{4})",
        lambda m: chr(int(m.group(1), 16)),
        text,
    )
    return out if out != text else None


def _try_octal_escapes(text: str) -> Optional[str]:
    if len(re.findall(r"\\[0-7]{3}", text)) < 3:
        return None
    out = re.sub(
        r"\\([0-7]{3})",
        lambda m: chr(int(m.group(1), 8)),
        text,
    )
    return out if out != text else None


def _try_js_string_escapes(text: str) -> Optional[str]:
    cnt = sum(text.count(esc) for esc in ("\\n", "\\t", "\\r", "\\\""))
    if cnt < 3:
        return None
    try:
        out = text.encode("utf-8").decode("raw_unicode_escape")
        return out if out != text else None
    except Exception:
        return None


def _try_json_b64_fields(text: str) -> Optional[str]:
    import json
    try:
        obj = json.loads(text)
    except Exception:
        return None
    changed = [False]

    def walk(x: Any) -> Any:
        if isinstance(x, dict):
            return {k: walk(v) for k, v in x.items()}
        if isinstance(x, list):
            return [walk(v) for v in x]
        if isinstance(x, str) and len(x) >= 16 and re.fullmatch(r"[A-Za-z0-9+/=]+", x):
            dec = _b64_decode_safe(x)
            if dec and is_printable_text(dec):
                changed[0] = True
                return dec.decode("utf-8", errors="replace")
        return x

    new_obj = walk(obj)
    if not changed[0]:
        return None
    return json.dumps(new_obj, indent=2, ensure_ascii=False)


def _try_rot13(text: str) -> Optional[str]:
    if _looks_like_code(text):
        return None
    import codecs
    try:
        out = codecs.decode(text, "rot_13")
    except Exception:
        return None
    if out == text:
        return None
    if _looks_like_code(out):
        return out
    return None


def _try_jsfuck(text: str) -> Optional[str]:
    stripped = re.sub(r"\s+", "", text)
    if len(stripped) < 40:
        return None
    allowed = set("[]()!+")
    cnt = sum(1 for ch in stripped if ch in allowed)
    if cnt / len(stripped) < 0.9:
        return None
    out = _run_subproc(
        ["node", "-e", f"try{{var r=eval({text});if(r!=null)process.stdout.write(String(r))}}catch(e){{process.exit(1)}}"],
        timeout=JSFUCK_TIMEOUT,
    )
    if out is None or not out:
        return None
    try:
        return out.decode("utf-8", errors="replace")
    except Exception:
        return None


def _try_brainfuck(text: str) -> Optional[str]:
    non_ws = [c for c in text if not c.isspace()]
    if len(non_ws) < 50:
        return None
    bf_chars = set("><+-.,[]")
    cnt = sum(1 for c in non_ws if c in bf_chars)
    if cnt / len(non_ws) < 0.8:
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
            tape[ptr] = (tape[ptr] + 1) & 0xFF
        elif ch == "-":
            tape[ptr] = (tape[ptr] - 1) & 0xFF
        elif ch == ".":
            out.append(tape[ptr])
        elif ch == ",":
            tape[ptr] = 0
        elif ch == "[":
            if tape[ptr] == 0:
                pc = bracket_map[pc]
        elif ch == "]":
            if tape[ptr] != 0:
                pc = bracket_map[pc]
        pc += 1
        steps += 1
    if not out:
        return None
    try:
        return out.decode("utf-8", errors="replace")
    except Exception:
        return None


def _try_php_obfuscation(text: str) -> Optional[str]:
    m = re.search(r"eval\s*\(\s*(?:gzinflate\s*\(\s*)?base64_decode\s*\(\s*(['\"])([A-Za-z0-9+/=]+)\1", text)
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


def _try_java_unicode(text: str) -> Optional[str]:
    if len(re.findall(r"\\u[0-9a-fA-F]{4}", text)) < 5:
        return None
    out = re.sub(
        r"\\u([0-9a-fA-F]{4})",
        lambda m: chr(int(m.group(1), 16)),
        text,
    )
    return out if out != text else None


def _try_reversed(text: str) -> Optional[str]:
    if len(text) < 30:
        return None
    if _looks_like_code(text):
        return None
    rev = text[::-1]
    if _looks_like_code(rev):
        return rev
    return None


def _try_xor_single_byte(data: bytes) -> Optional[str]:
    if len(data) < 30 or len(data) > 200000:
        return None
    if is_printable_text(data):
        return None
    best: Tuple[int, Optional[str]] = (0, None)
    for key in range(1, 256):
        dec = bytes(b ^ key for b in data[:4096])
        try:
            t = dec.decode("utf-8")
        except UnicodeDecodeError:
            continue
        printable = sum(1 for ch in t if 32 <= ord(ch) < 127 or ch in "\n\r\t")
        score = printable
        if score > best[0] and _looks_like_code(t):
            full = bytes(b ^ key for b in data)
            try:
                best = (score, full.decode("utf-8", errors="replace"))
            except Exception:
                pass
    return best[1]


def _single_pass(data: bytes, filename: str) -> Tuple[bytes, Optional[str]]:
    ext = os.path.splitext(filename)[1].lower()
    text = _to_text(data)
    if text is None:
        return data, None

    if ext in JS_EXTS or "_0x" in text:
        if re.search(r"_0x[a-f0-9]{4,}", text):
            r = _try_synchrony(text)
            if r and r != text:
                return _js_beautify(r).encode("utf-8"), "js_0x_synchrony"
            r = _try_js_0x_fallback(text)
            if r and r != text:
                return r.encode("utf-8"), "js_0x_fallback"

    if ext in JS_EXTS or "eval(" in text or "Function(" in text:
        r = _try_js_eval_unwrap(text)
        if r and r != text:
            return r.encode("utf-8"), "js_eval_unwrap"

    if "atob(" in text or "Buffer.from" in text:
        r = _try_js_atob_wrapper(text)
        if r and r != text:
            return r.encode("utf-8"), "js_atob_wrapper"

    if ext in PY_EXTS or "marshal" in text:
        r = _try_py_marshal(data)
        if r and r != text:
            return r.encode("utf-8"), "py_marshal"

    if ext in PY_EXTS or "exec(" in text:
        r = _try_py_exec_compile(data)
        if r and r != text:
            return r.encode("utf-8"), "py_exec_compile"

    r = _try_raw_base64(text)
    if r is not None and r != text:
        return r.encode("utf-8"), "base64_raw"

    r = _try_multiline_base64(text)
    if r is not None and r != text:
        return r.encode("utf-8"), "base64_multiline"

    r = _try_base64_chunks(text)
    if r is not None and r != text:
        return r.encode("utf-8"), "base64_chunks"

    r = _try_hex_string(text)
    if r is not None and r != text:
        return r.encode("utf-8"), "hex_string"

    r = _try_hex_escapes(text)
    if r is not None and r != text:
        return r.encode("utf-8"), "hex_escapes"

    r = _try_percent_encoding(text)
    if r is not None and r != text:
        return r.encode("utf-8"), "uri_percent"

    r = _try_html_entities(text)
    if r is not None and r != text:
        return r.encode("utf-8"), "html_entities"

    r = _try_unicode_escapes(text)
    if r is not None and r != text:
        return r.encode("utf-8"), "unicode_escapes"

    r = _try_octal_escapes(text)
    if r is not None and r != text:
        return r.encode("utf-8"), "octal_escapes"

    r = _try_js_string_escapes(text)
    if r is not None and r != text:
        return r.encode("utf-8"), "js_string_escapes"

    r = _try_json_b64_fields(text)
    if r is not None and r != text:
        return r.encode("utf-8"), "json_b64_fields"

    r = _try_rot13(text)
    if r is not None and r != text:
        return r.encode("utf-8"), "rot13"

    r = _try_jsfuck(text)
    if r is not None and r != text:
        return r.encode("utf-8"), "jsfuck"

    r = _try_brainfuck(text)
    if r is not None and r != text:
        return r.encode("utf-8"), "brainfuck"

    if ext in PHP_EXTS or "<?php" in text:
        r = _try_php_obfuscation(text)
        if r is not None and r != text:
            return r.encode("utf-8"), "php_eval_b64"

    if ext in {".java", ".kt", ".kts"}:
        r = _try_java_unicode(text)
        if r is not None and r != text:
            return r.encode("utf-8"), "java_unicode"

    r = _try_reversed(text)
    if r is not None and r != text:
        return r.encode("utf-8"), "string_reverse"

    r = _try_xor_single_byte(data)
    if r is not None:
        return r.encode("utf-8"), "xor_single_byte"

    return data, None


def detect_and_decode(data: bytes, filename: str) -> Tuple[bytes, List[str]]:
    methods: List[str] = []
    current = data
    prev_hash = _md5(current)
    for _ in range(MAX_PASSES):
        new_data, method = _single_pass(current, filename)
        new_hash = _md5(new_data)
        if method is None or new_hash == prev_hash:
            break
        methods.append(method)
        current = new_data
        prev_hash = new_hash
    ext = os.path.splitext(filename)[1].lower()
    if ext in JS_EXTS and methods:
        t = _to_text(current)
        if t is not None:
            beaut = _js_beautify(t)
            if beaut != t:
                current = beaut.encode("utf-8")
                methods.append("jsbeautify")
    return current, methods


def is_binary_file(filename: str, data: bytes) -> bool:
    ext = os.path.splitext(filename)[1].lower()
    if ext in BINARY_EXTS:
        return True
    if not is_printable_text(data):
        return True
    return False


def process_zip_sync(zip_bytes: bytes, progress_state: Dict[str, Any]) -> Tuple[bytes, Dict[str, Any]]:
    stats: Dict[str, Any] = {
        "decoded": 0,
        "clean": 0,
        "binary": 0,
        "errors": [],
        "methods": {},
        "decoded_files": [],
        "original_size": len(zip_bytes),
        "output_size": 0,
    }

    src = zipfile.ZipFile(io.BytesIO(zip_bytes), "r")
    names = [n for n in src.namelist() if not n.endswith("/")]
    total = len(names)
    progress_state["total"] = total
    progress_state["done"] = 0
    progress_state["current"] = ""

    out_buf = io.BytesIO()
    with zipfile.ZipFile(out_buf, "w", zipfile.ZIP_DEFLATED) as dst:
        for info in src.infolist():
            if info.is_dir():
                dst.writestr(info, b"")
                continue
            try:
                raw = src.read(info.filename)
            except Exception as e:
                stats["errors"].append(f"{info.filename}: read failed: {e}")
                progress_state["done"] += 1
                continue

            progress_state["current"] = os.path.basename(info.filename) or info.filename

            if is_binary_file(info.filename, raw):
                dst.writestr(info, raw)
                stats["binary"] += 1
            else:
                try:
                    decoded, methods = detect_and_decode(raw, info.filename)
                    if methods:
                        dst.writestr(info, decoded)
                        stats["decoded"] += 1
                        stats["decoded_files"].append((info.filename, methods))
                        for m in methods:
                            stats["methods"][m] = stats["methods"].get(m, 0) + 1
                    else:
                        dst.writestr(info, raw)
                        stats["clean"] += 1
                except Exception as e:
                    log.exception("decode failed for %s", info.filename)
                    stats["errors"].append(f"{info.filename}: {e}")
                    dst.writestr(info, raw)

            progress_state["done"] += 1

    src.close()
    out_bytes = out_buf.getvalue()
    stats["output_size"] = len(out_bytes)
    progress_state["finished"] = True
    return out_bytes, stats


def render_progress_bar(done: int, total: int, current: str) -> str:
    pct = int((done / total) * 100) if total else 0
    filled = int((done / total) * 10) if total else 0
    bar = "█" * filled + "░" * (10 - filled)
    cur = current or "..."
    if len(cur) > 40:
        cur = cur[:37] + "..."
    return (
        f"⚙️ <b>Processing...</b>\n"
        f"<code>[{bar}]</code> {pct}%\n"
        f"<code>{done}/{total}</code> — <code>{html.escape(cur)}</code>"
    )


def render_report(stats: Dict[str, Any]) -> str:
    lines = ["🔬 <b>Decode Report</b>", ""]
    lines.append(f"📂 Decoded files: <b>{stats['decoded']}</b>")
    lines.append(f"✨ Already clean: <b>{stats['clean']}</b>")
    lines.append(f"⏭ Binary skipped: <b>{stats['binary']}</b>")
    if stats["errors"]:
        lines.append(f"⚠️ Errors: <b>{len(stats['errors'])}</b>")
    lines.append("")
    if stats["methods"]:
        lines.append("📊 <b>Encoding/obfuscation types found:</b>")
        for k, v in sorted(stats["methods"].items(), key=lambda x: -x[1]):
            lines.append(f"  • <code>{html.escape(k)}</code>: {v}")
        lines.append("")
    lines.append(f"📦 Original: <b>{stats['original_size'] // 1024} KB</b>")
    lines.append(f"📦 Output: <b>{stats['output_size'] // 1024} KB</b>")
    if stats["decoded_files"] and len(stats["decoded_files"]) <= 20:
        lines.append("")
        lines.append("📝 <b>Files decoded:</b>")
        for fname, methods in stats["decoded_files"]:
            chain = " → ".join(methods)
            lines.append(f"  <code>{html.escape(fname)}</code> → {html.escape(chain)}")
    if stats["errors"] and len(stats["errors"]) <= 10:
        lines.append("")
        lines.append("⚠️ <b>Errors:</b>")
        for e in stats["errors"]:
            lines.append(f"  • <code>{html.escape(str(e)[:200])}</code>")
    return "\n".join(lines)


WELCOME = (
    "👋 <b>ZIP Deobfuscator Bot</b>\n\n"
    "Send me a <b>.zip</b> file and I'll auto-detect and decode every obfuscated "
    "or encoded file inside it, then send back a clean zip with the original structure.\n\n"
    "<b>Supported types:</b>\n"
    "• JavaScript <code>_0x</code> obfuscation (synchrony + fallback)\n"
    "• JS <code>eval()</code> / <code>Function()</code> wrappers\n"
    "• JS <code>atob()</code> / <code>Buffer.from(...,'base64')</code>\n"
    "• Python <code>marshal</code> / <code>exec(compile(...))</code>\n"
    "• Base64 (single-line, multi-line, chunked)\n"
    "• Hex strings &amp; <code>\\x</code> escapes\n"
    "• URI percent-encoding\n"
    "• HTML entities\n"
    "• Unicode <code>\\uXXXX</code> &amp; octal escapes\n"
    "• JS string escapes\n"
    "• JSON with Base64 fields\n"
    "• ROT13\n"
    "• JSFuck (via node eval)\n"
    "• Brainfuck (pure-Python interpreter)\n"
    "• PHP <code>eval(base64_decode(...))</code> chains\n"
    "• Java/Kotlin unicode escapes\n"
    "• String reversal\n"
    "• Single-byte XOR\n\n"
    f"Max zip size: <b>{MAX_ZIP_MB} MB</b>.\n"
    "Multi-layer chains are unwrapped automatically (up to 20 passes)."
)


bot = Bot(token=BOT_TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.HTML)) if BOT_TOKEN else None
dp = Dispatcher()

pending_jobs: Dict[str, bytes] = {}


def confirm_kb(job_id: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text="✅ Decode it", callback_data=f"go:{job_id}"),
        InlineKeyboardButton(text="❌ Cancel", callback_data=f"cancel:{job_id}"),
    ]])


def done_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text="📦 Send another zip", callback_data="another"),
        InlineKeyboardButton(text="✔️ Done", callback_data="done"),
    ]])


@dp.message(CommandStart())
async def cmd_start(m: Message) -> None:
    await m.answer(WELCOME)


@dp.message(Command("help"))
async def cmd_help(m: Message) -> None:
    await m.answer(WELCOME)


@dp.message(F.document)
async def on_document(m: Message) -> None:
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
        await bot.download(doc, destination=buf)
        zip_bytes = buf.getvalue()
    except Exception as e:
        log.exception("download failed")
        await m.reply(f"❌ Failed to download file: <code>{html.escape(str(e))}</code>")
        return

    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as z:
            entries = [i for i in z.infolist() if not i.is_dir()]
            file_count = len(entries)
            uncompressed = sum(i.file_size for i in entries)
    except zipfile.BadZipFile:
        await m.reply("❌ Invalid or corrupted zip file.")
        return

    job_id = f"{m.from_user.id}_{m.message_id}"
    pending_jobs[job_id] = zip_bytes

    await m.reply(
        f"📦 <b>{html.escape(fname)}</b>\n"
        f"📁 Files: <b>{file_count}</b>\n"
        f"📐 Uncompressed: <b>{uncompressed // 1024} KB</b>\n"
        f"💾 Zip: <b>{len(zip_bytes) // 1024} KB</b>\n\n"
        "Ready to decode?",
        reply_markup=confirm_kb(job_id),
    )


async def progress_loop(chat_id: int, msg_id: int, state: Dict[str, Any]) -> None:
    last_text = ""
    while not state.get("finished"):
        await asyncio.sleep(1.5)
        total = state.get("total", 0)
        done = state.get("done", 0)
        current = state.get("current", "")
        if not total:
            continue
        text = render_progress_bar(done, total, current)
        if text != last_text:
            try:
                await bot.edit_message_text(chat_id=chat_id, message_id=msg_id, text=text)
                last_text = text
            except Exception:
                pass


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

    await c.answer()
    progress_msg = await c.message.edit_text(
        "⚙️ <b>Processing...</b>\n<code>[░░░░░░░░░░]</code> 0%\nstarting..."
    )

    state: Dict[str, Any] = {"total": 0, "done": 0, "current": "", "finished": False}
    poll_task = asyncio.create_task(progress_loop(c.message.chat.id, progress_msg.message_id, state))

    loop = asyncio.get_event_loop()
    try:
        out_bytes, stats = await loop.run_in_executor(None, process_zip_sync, zip_bytes, state)
    except zipfile.BadZipFile:
        state["finished"] = True
        await poll_task
        await progress_msg.edit_text("❌ Invalid zip.")
        return
    except Exception as e:
        log.exception("process failed")
        state["finished"] = True
        await poll_task
        await progress_msg.edit_text(f"❌ Processing failed: <code>{html.escape(str(e))}</code>")
        return

    state["finished"] = True
    await poll_task

    try:
        await progress_msg.edit_text(
            f"⚙️ <b>Processing...</b>\n<code>[██████████]</code> 100%\n<code>{stats['decoded'] + stats['clean'] + stats['binary']}/{state.get('total', 0)}</code> — done"
        )
    except Exception:
        pass

    await c.message.answer(render_report(stats))

    out_name = f"decoded_{int(time.time())}.zip"
    await c.message.answer_document(
        BufferedInputFile(out_bytes, filename=out_name),
        caption="✅ Done.",
        reply_markup=done_kb(),
    )


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
        pass


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
    log.info("starting polling (max_zip_mb=%d)", MAX_ZIP_MB)
    await bot.delete_webhook(drop_pending_updates=True)
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
