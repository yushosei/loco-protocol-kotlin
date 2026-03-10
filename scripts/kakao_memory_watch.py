import argparse
import csv
import ctypes
import ctypes.wintypes as wt
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01
CHUNK = 1024 * 1024
OVERLAP = 4096

AUTH_HEADER_RE = re.compile(rb"Authorization:\s*([^\r\n]{40,260})")
HTTP_REQUEST_RE = re.compile(rb"(GET|POST) [^\r\n]{1,256} HTTP/1\.[01]\r?\n(?:[^\r\n]{0,768}\r?\n){1,60}")
LOGIN_RESPONSE_RE = re.compile(
    rb"\{[^{}]{0,800}\"access_token\":\"([^\"]{16,260})\"[^{}]{0,800}\"refresh_token\":\"([^\"]{16,260})\"[^{}]{0,800}\"autoLoginAccountId\":\"([^\"]+)\"[^{}]{0,800}\"recipe\":\"([^\"]{16,260})\"[^{}]{0,800}\}",
)
TGW_AUTH_RE = re.compile(rb"TGW-AUTH=([^;\r\n]{40,2600})")
JSON_OBJECT_RE = re.compile(r"\{.*\}", re.DOTALL)
RUNTIME_LOG_RE = re.compile(
    r"\[(?P<file>[A-Za-z0-9_]+\.cpp)\s*:\s*(?P<line>\d{3,5})\]\s+"
    r"\[(?P<clock>\d{2}:\d{2}:\d{2}\.\d{3})\]\s+"
    r"(?:(?P<level>_[A-Z]+)\s+)?"
    r"\[(?P<pid>\d+)\]\[(?P<phase>[A-Z]+)\]\s+"
    r"(?P<message>[^\r\n]{1,320})"
)
NETSTAT_TCP_RE = re.compile(r"^\s*TCP\s+(?P<local>\S+)\s+(?P<remote>\S+)\s+(?P<state>\S+)\s+(?P<pid>\d+)\s*$")
KEYWORDS = [
    b"/account/passcodeLogin/registerDevice",
    b"/account/passcodeLogin/generate",
    b"/agent/account/login.json",
    b"oauth2_token.json",
    b"request_passcode.json",
    b"register_device.json",
    b"less_settings.json",
    b"profile/list",
    b"CHECKIN",
    b"LOGINLIST",
    b"LCHATLIST",
    b"CHATONROOM",
    b"GETMEM",
    b"SYNCMSG",
    b"WRITE",
    b"SYNCREAD",
    b"NEWMEM",
    b"DELMEM",
]
LOCO_KEYWORDS = {
    "CHECKIN",
    "LOGINLIST",
    "LCHATLIST",
    "CHATONROOM",
    "GETMEM",
    "SYNCMSG",
    "WRITE",
    "SYNCREAD",
    "NEWMEM",
    "DELMEM",
}
SENSITIVE_FIELDS = {
    "access_token",
    "refresh_token",
    "password",
    "authorization",
    "oauthToken",
    "token",
    "recipe",
}
RUNTIME_EVENT_MAP = {
    "OnGETCONF_Response": "GETCONF",
    "_Send_GETCONF": "GETCONF",
    "LocoCommand_CHATONROOM_ResultHandler": "CHATONROOM",
    "_CHATONROOM(": "CHATONROOM",
    "LocoCommand_SYNCMSG_ResultHandler": "SYNCMSG",
    "OnRecvMSG_": "MSG",
    "recv MSG ": "MSG",
    "LocoCommand_WRITE_ResultHandler": "WRITE_ACK",
    "LocoCommand_WRITE_ResultHandler_v3": "WRITE_ACK",
    "OnRecvNEWMEM_": "NEWMEM",
    "recv NEWMEM ": "NEWMEM",
    "OnRecvDELMEM_": "DELMEM",
    "recv DELMEM ": "DELMEM",
    "OnRecvDECUNREAD_": "DECUNREAD",
    "recv DECUNREAD ": "DECUNREAD",
    "LocoCommand_GETMEM_ResultHandler": "GETMEM",
    "Handle_LOGINLIST_Res_": "LOGINLIST",
    "LOGIN complete.": "LOGINLIST",
    "OnCHECKIN_Response": "CHECKIN",
    "_Send_CHECKIN": "CHECKIN",
}


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", wt.LPVOID),
        ("AllocationBase", wt.LPVOID),
        ("AllocationProtect", wt.DWORD),
        ("PartitionId", wt.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
    ]


OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
OpenProcess.restype = wt.HANDLE

ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [wt.HANDLE, wt.LPCVOID, wt.LPVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
ReadProcessMemory.restype = wt.BOOL

VirtualQueryEx = kernel32.VirtualQueryEx
VirtualQueryEx.argtypes = [wt.HANDLE, wt.LPCVOID, ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
VirtualQueryEx.restype = ctypes.c_size_t

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wt.HANDLE]
CloseHandle.restype = wt.BOOL


def find_kakaotalk_pid() -> int | None:
    output = subprocess.check_output(
        ["tasklist", "/FI", "IMAGENAME eq KakaoTalk.exe", "/FO", "CSV", "/NH"],
        text=True,
        encoding="utf-8",
        errors="ignore",
    )
    rows = [row for row in csv.reader(output.splitlines()) if row and row[0].lower() == "kakaotalk.exe"]
    if not rows:
        return None
    return int(rows[0][1])


def clean_text(raw: bytes, limit: int = 1200) -> str:
    text = raw.decode("latin1", errors="ignore").replace("\x00", "")
    text = re.sub(r"[^\x09\x0a\x0d\x20-\x7e]", " ", text)
    return text[:limit]


def clean_full_text(raw: bytes) -> str:
    text = raw.decode("latin1", errors="ignore").replace("\x00", "")
    return re.sub(r"[^\x09\x0a\x0d\x20-\x7e]", " ", text)


def clean_preview(value: str, limit: int) -> str:
    value = value.replace("\x00", "")
    value = re.sub(r"[^\x20-\x7e]", "?", value)
    return value[:limit]


def compact_token(value: str, left: int = 12, right: int = 8) -> str:
    if len(value) <= left + right + 3:
        return value
    return f"{value[:left]}...{value[-right:]}"


def parse_http_request(request: str) -> dict:
    lines = request.splitlines()
    if not lines:
        return {}

    first_line = lines[0].strip()
    parts = first_line.split()
    result = {
        "first_line": first_line,
        "method": parts[0] if len(parts) >= 1 else "",
        "path": parts[1] if len(parts) >= 2 else "",
        "host": "",
        "a_header": "",
        "user_agent": "",
        "authorization": "",
        "body": "",
        "params": [],
    }

    body_started = False
    body_lines: list[str] = []
    for line in lines[1:]:
        if not body_started and not line.strip():
            body_started = True
            continue
        if body_started:
            body_lines.append(line)
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key == "host":
            result["host"] = value
        elif key == "a":
            result["a_header"] = value
        elif key == "user-agent":
            result["user_agent"] = value
        elif key == "authorization":
            result["authorization"] = value

    body = "\n".join(body_lines).strip()
    result["body"] = body
    if body and "=" in body:
        parsed = []
        for key, value in parse_qsl(body, keep_blank_values=True):
            parsed.append((key, redact_field(key, value)))
        result["params"] = parsed
    return result


def redact_field(key: str, value: str) -> str:
    if key in SENSITIVE_FIELDS:
        return compact_token(value)
    return value


def parse_json_fragment(text: str) -> dict | None:
    match = JSON_OBJECT_RE.search(text)
    if not match:
        return None
    try:
        return json.loads(match.group(0))
    except json.JSONDecodeError:
        return None


def human_summary(event: dict) -> str:
    kind = event["kind"]
    if kind == "authorization":
        parsed = parse_http_request(event.get("context", ""))
        request_label = parsed.get("first_line") or "Authorization header"
        auth = compact_token(event["token"])
        extras = []
        if parsed.get("host"):
            extras.append(f"host={parsed['host']}")
        if parsed.get("a_header"):
            extras.append(f"a={parsed['a_header']}")
        if parsed.get("user_agent"):
            extras.append(f"ua={parsed['user_agent']}")
        extras_text = " ".join(extras)
        return f"{request_label} auth={auth}" + (f" {extras_text}" if extras_text else "")

    if kind == "login_response":
        parsed = parse_json_fragment(event.get("context", "")) or {}
        user_id = parsed.get("userId") or parsed.get("user_id")
        status = parsed.get("status")
        agent = parsed.get("mainDeviceAgentName")
        app_version = parsed.get("mainDeviceAppVersion")
        return (
            f"login success account={event['account']} userId={user_id} status={status} "
            f"mainDevice={agent}/{app_version} "
            f"access={compact_token(event['access_token'])} refresh={compact_token(event['refresh_token'])}"
        )

    if kind == "tgw_auth":
        return f"TGW-AUTH cookie {compact_token(event['cookie'], left=16, right=12)}"

    if kind == "http_request":
        parsed = parse_http_request(event["request"])
        params = ", ".join(f"{key}={value}" for key, value in parsed.get("params", []))
        auth = parsed.get("authorization")
        auth_text = f" auth={compact_token(auth)}" if auth else ""
        params_text = f" params=[{params}]" if params else ""
        host_text = f" host={parsed['host']}" if parsed.get("host") else ""
        return f"{parsed.get('first_line', 'http_request')}{host_text}{auth_text}{params_text}"

    if kind == "runtime_log":
        protocol_event = event.get("protocol_event") or "RUNTIME"
        if protocol_event == "RUNTIME" and event.get("runtime_matches"):
            joined = ",".join(event["runtime_matches"][:2])
            protocol_event = f"TRACE[{joined}]"
        file_label = f"{event.get('file')}:{event.get('line')}"
        return (
            f"{protocol_event} {event.get('phase')} {file_label} "
            f"{event.get('message')}"
        )

    if kind == "tcp_connection":
        return (
            f"tcp {event['state']} "
            f"{event['remote_address']}:{event['remote_port']} "
            f"via {event['local_address']}:{event['local_port']}"
        )

    keyword = event.get("keyword", "")
    context = event.get("context", "")
    parsed = parse_http_request(context)
    request_label = parsed.get("first_line")
    if request_label:
        return f"keyword={keyword} near {request_label}"
    return f"keyword={keyword} seen in KakaoTalk memory"


def is_interesting_keyword_context(keyword: str, context: str) -> bool:
    if keyword.startswith("/") or keyword.endswith(".json"):
        return True
    if keyword not in LOCO_KEYWORDS:
        return True
    markers = (
        "TalkChat",
        "Loco",
        "chatId",
        "KakaoTalk",
        "OnRecv",
        "ResultHandler",
        "recv ",
        "sync action",
        "Authorization:",
        "/win32/",
        "katalk.kakao.com",
    )
    return any(marker in context for marker in markers)


def classify_runtime_event(message: str) -> str:
    for marker, name in RUNTIME_EVENT_MAP.items():
        if marker in message:
            return name
    return "RUNTIME"


def parse_csv_values(raw: str) -> list[str]:
    return [value.strip() for value in raw.split(",") if value.strip()]


def compile_search_keywords(extra_keywords: list[str], append_default: bool = True) -> list[bytes]:
    compiled = list(KEYWORDS) if append_default else []
    seen = set(compiled)
    for keyword in extra_keywords:
        encoded = keyword.encode("utf-8", errors="ignore")
        if encoded and encoded not in seen:
            compiled.append(encoded)
            seen.add(encoded)
    return compiled


def split_endpoint(endpoint: str) -> tuple[str, int] | None:
    if endpoint.count(":") == 0:
        return None
    host, port = endpoint.rsplit(":", 1)
    host = host.strip("[]")
    try:
        return host, int(port)
    except ValueError:
        return None


def scan_tcp_connections(pid: int) -> list[dict]:
    output = subprocess.check_output(
        ["netstat", "-ano", "-p", "tcp"],
        text=True,
        encoding="utf-8",
        errors="ignore",
    )
    events: list[dict] = []
    for line in output.splitlines():
        match = NETSTAT_TCP_RE.match(line)
        if not match:
            continue
        if int(match.group("pid")) != pid:
            continue
        local = split_endpoint(match.group("local"))
        remote = split_endpoint(match.group("remote"))
        if local is None or remote is None:
            continue
        state = match.group("state")
        if state == "LISTENING":
            continue
        events.append(
            {
                "kind": "tcp_connection",
                "pid": pid,
                "local_address": local[0],
                "local_port": local[1],
                "remote_address": remote[0],
                "remote_port": remote[1],
                "state": state,
            },
        )
    return events


def scan_process(pid: int, runtime_contains: list[str] | None = None, search_keywords: list[bytes] | None = None) -> list[dict]:
    handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        raise RuntimeError("failed to open KakaoTalk process")

    events: list[dict] = []
    runtime_filters = [value.lower() for value in (runtime_contains or [])]
    keywords = search_keywords or KEYWORDS
    try:
        mbi = MEMORY_BASIC_INFORMATION()
        addr = 0
        while VirtualQueryEx(handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            base = ctypes.cast(mbi.BaseAddress, ctypes.c_void_p).value or 0
            size = int(mbi.RegionSize)
            if mbi.State == MEM_COMMIT and not (mbi.Protect & PAGE_GUARD) and not (mbi.Protect & PAGE_NOACCESS) and size > 0:
                offset = 0
                carry = b""
                while offset < size:
                    to_read = min(CHUNK, size - offset)
                    buf = ctypes.create_string_buffer(to_read)
                    read = ctypes.c_size_t()
                    if ReadProcessMemory(handle, ctypes.c_void_p(base + offset), buf, to_read, ctypes.byref(read)) and read.value:
                        data = carry + buf.raw[: read.value]
                        data_base = base + offset - len(carry)

                        for match in AUTH_HEADER_RE.finditer(data):
                            token = match.group(1).decode("latin1", errors="ignore")
                            if "%s4-HMAC-SHA256" in token or "Credential=%s" in token:
                                continue
                            start = max(0, match.start() - 200)
                            end = min(len(data), match.end() + 500)
                            events.append(
                                {
                                    "kind": "authorization",
                                    "address": hex(data_base + match.start()),
                                    "token": token,
                                    "preview": clean_preview(token, 48),
                                    "context": clean_text(data[start:end]),
                                },
                            )

                        for match in LOGIN_RESPONSE_RE.finditer(data):
                            access_token = match.group(1).decode("latin1", errors="ignore")
                            refresh_token = match.group(2).decode("latin1", errors="ignore")
                            account = match.group(3).decode("latin1", errors="ignore")
                            recipe = match.group(4).decode("latin1", errors="ignore")
                            start = max(0, match.start() - 200)
                            end = min(len(data), match.end() + 500)
                            events.append(
                                {
                                    "kind": "login_response",
                                    "address": hex(data_base + match.start()),
                                    "access_token": access_token,
                                    "refresh_token": refresh_token,
                                    "account": account,
                                    "recipe": recipe,
                                    "context": clean_text(data[start:end], limit=1800),
                                },
                            )

                        for match in TGW_AUTH_RE.finditer(data):
                            cookie = match.group(1).decode("latin1", errors="ignore")
                            events.append(
                                {
                                    "kind": "tgw_auth",
                                    "address": hex(data_base + match.start()),
                                    "cookie": cookie,
                                    "preview": clean_preview(cookie, 64),
                                },
                            )

                        for match in HTTP_REQUEST_RE.finditer(data):
                            block = clean_text(match.group(0), limit=1800)
                            if "Authorization:" not in block and "login.json" not in block and "passcodeLogin" not in block:
                                continue
                            events.append(
                                {
                                    "kind": "http_request",
                                    "address": hex(data_base + match.start()),
                                    "request": block,
                                },
                            )

                        full_text = clean_full_text(data)
                        for match in RUNTIME_LOG_RE.finditer(full_text):
                            message = match.group("message").strip()
                            protocol_event = classify_runtime_event(message)
                            runtime_matches = [token for token in runtime_filters if token in message.lower()]
                            if protocol_event == "RUNTIME" and not runtime_matches:
                                continue
                            events.append(
                                {
                                    "kind": "runtime_log",
                                    "address": hex(data_base + match.start()),
                                    "file": match.group("file"),
                                    "line": match.group("line"),
                                    "clock": match.group("clock"),
                                    "level": match.group("level") or "",
                                    "pid": match.group("pid"),
                                    "phase": match.group("phase"),
                                    "message": message,
                                    "protocol_event": protocol_event,
                                    "runtime_matches": runtime_matches,
                                },
                            )

                        for keyword in keywords:
                            position = 0
                            while True:
                                idx = data.find(keyword, position)
                                if idx == -1:
                                    break
                                start = max(0, idx - 180)
                                end = min(len(data), idx + 1000)
                                context = clean_text(data[start:end])
                                keyword_text = keyword.decode("latin1")
                                if not is_interesting_keyword_context(keyword_text, context):
                                    position = idx + len(keyword)
                                    continue
                                events.append(
                                    {
                                        "kind": "keyword",
                                        "address": hex(data_base + idx),
                                        "keyword": keyword_text,
                                        "context": context,
                                    },
                                )
                                position = idx + len(keyword)

                        carry = data[-OVERLAP:]
                        offset += read.value
                    else:
                        offset += to_read
                        carry = b""

            next_addr = base + size
            if next_addr <= addr:
                break
            addr = next_addr
    finally:
        CloseHandle(handle)

    return events


def event_key(event: dict) -> str:
    if event["kind"] == "authorization":
        return f"authorization:{event['token']}"
    if event["kind"] == "login_response":
        return f"login_response:{event['access_token']}:{event['refresh_token']}"
    if event["kind"] == "tgw_auth":
        return f"tgw_auth:{event['cookie']}"
    if event["kind"] == "http_request":
        return f"http_request:{event['request']}"
    if event["kind"] == "runtime_log":
        return f"runtime_log:{event.get('clock')}:{event.get('file')}:{event.get('line')}:{event.get('message')}"
    if event["kind"] == "tcp_connection":
        return (
            f"tcp_connection:{event['pid']}:{event['local_address']}:{event['local_port']}:"
            f"{event['remote_address']}:{event['remote_port']}:{event['state']}"
        )
    return f"keyword:{event.get('keyword')}:{event.get('context')}"


def print_event(event: dict) -> None:
    timestamp = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    summary = human_summary(event)
    suffix = (
        f" @ {event['address']}"
        if "address" in event else
        f" @ net:{event.get('remote_address', '?')}:{event.get('remote_port', '?')}"
    )
    print(f"[{timestamp}] {event['kind']} {summary}{suffix}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Watch KakaoTalk.exe memory for auth/session changes.")
    parser.add_argument("--interval", type=float, default=2.0, help="Polling interval in seconds")
    parser.add_argument("--duration", type=float, default=0.0, help="Stop after N seconds; 0 means forever")
    parser.add_argument("--jsonl", type=Path, default=None, help="Optional JSONL output file")
    parser.add_argument(
        "--only",
        type=str,
        default="",
        help="Comma-separated event kinds to show (authorization,http_request,login_response,tgw_auth,runtime_log,keyword,tcp_connection)",
    )
    parser.add_argument(
        "--prime",
        action="store_true",
        help="Run one silent baseline scan first, then print only newly observed events",
    )
    parser.add_argument(
        "--keyword",
        type=str,
        default="",
        help="Comma-separated extra raw memory keywords to search for",
    )
    parser.add_argument(
        "--runtime-contains",
        type=str,
        default="",
        help="Comma-separated runtime-log substrings to include even if they are not in the built-in event map",
    )
    parser.add_argument(
        "--connections",
        action="store_true",
        help="Emit KakaoTalk TCP connection state changes alongside memory events",
    )
    parser.add_argument(
        "--replace-keywords",
        action="store_true",
        help="Use only the keywords passed via --keyword instead of appending them to the built-in defaults",
    )
    args = parser.parse_args()

    pid = find_kakaotalk_pid()
    if pid is None:
        print("KakaoTalk.exe is not running", file=sys.stderr)
        return 1

    print(f"Watching KakaoTalk.exe pid={pid}")
    seen: set[str] = set()
    start_time = time.time()
    allowed_kinds = set(parse_csv_values(args.only))
    runtime_contains = parse_csv_values(args.runtime_contains)
    search_keywords = compile_search_keywords(parse_csv_values(args.keyword), append_default=not args.replace_keywords)

    output_file = None
    if args.jsonl is not None:
        output_file = args.jsonl.open("a", encoding="utf-8")

    try:
        if args.prime:
            baseline_events = scan_process(pid, runtime_contains=runtime_contains, search_keywords=search_keywords)
            if args.connections:
                baseline_events.extend(scan_tcp_connections(pid))
            for event in baseline_events:
                if allowed_kinds and event["kind"] not in allowed_kinds:
                    continue
                seen.add(event_key(event))
            print(f"Primed baseline with {len(seen)} existing events")

        while True:
            events = scan_process(pid, runtime_contains=runtime_contains, search_keywords=search_keywords)
            if args.connections:
                events.extend(scan_tcp_connections(pid))
            for event in events:
                if allowed_kinds and event["kind"] not in allowed_kinds:
                    continue
                key = event_key(event)
                if key in seen:
                    continue
                seen.add(key)
                print_event(event)
                if output_file is not None:
                    record = {
                        "timestamp": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
                        "summary": human_summary(event),
                        **event,
                    }
                    output_file.write(json.dumps(record, ensure_ascii=False) + "\n")
                    output_file.flush()

            if args.duration > 0 and time.time() - start_time >= args.duration:
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        pass
    finally:
        if output_file is not None:
            output_file.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
