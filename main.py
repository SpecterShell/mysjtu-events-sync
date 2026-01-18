import argparse
from datetime import datetime, timedelta
import json
import os
import re
import threading
import time
from pathlib import Path
import sys

import caldav
import qrterm
import requests
import websocket


LOGIN_URL = "https://i.sjtu.edu.cn/jaccountlogin"
EXPRESS_LOGIN_URL = "https://jaccount.sjtu.edu.cn/jaccount/expresslogin?uuid={uuid}"
WSS_URL = "wss://jaccount.sjtu.edu.cn/jaccount/sub/{uuid}"
QR_CODE_URL = "https://jaccount.sjtu.edu.cn/jaccount/confirmscancode?uuid={uuid}&ts={ts}&sig={sig}"
CALENDAR_API = "https://calendar.sjtu.edu.cn/api/event/list?startDate={start}&endDate={end}&weekly=false&ids="
JA_COOKIE_NAME = "JAAuthCookie"


def _set_ja_cookie(session: requests.Session, value: str) -> None:
    session.cookies.set(JA_COOKIE_NAME, value, domain=".sjtu.edu.cn")


def load_cached_cookies(session: requests.Session, cache_path: Path, explicit_cookie: str | None) -> None:
    """Load JAAuthCookie from explicit arg/env or fallback file."""

    if explicit_cookie:
        _set_ja_cookie(session, explicit_cookie.strip())
        print("😎 已使用传入的 JAAuthCookie")
        return

    if not cache_path.exists():
        return
    try:
        with cache_path.open("r", encoding="utf-8") as fp:
            data = fp.read().strip()
        if data:
            _set_ja_cookie(session, data)
            print("😎 读取持久化 Cookie 成功")
    except Exception:
        print("🙃 读取持久化 Cookie 失败（可能需要重新登录）")


def persist_cookies(session: requests.Session, cache_path: Path) -> None:
    value = session.cookies.get(JA_COOKIE_NAME)
    if not value:
        return
    with cache_path.open("w", encoding="utf-8") as fp:
        fp.write(value)


def parse_uuid_from_login_page(content: bytes) -> str | None:
    match = re.search(
        r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
        content.decode("utf-8", errors="ignore"),
    )
    return match.group(1) if match else None


def monitor_wss(wss, update_qr_code_callback, login_callback):
    while True:
        try:
            msg = wss.recv()
        except websocket.WebSocketTimeoutException:
            continue
        except Exception:
            break
        if not msg:
            break
        payload = json.loads(msg)
        if payload.get("type") == "UPDATE_QR_CODE":
            sig_payload = payload.get("payload", {})
            update_qr_code_callback(sig_payload.get("ts"), sig_payload.get("sig"))
        elif payload.get("type") == "LOGIN":
            login_callback()
            return


def start_wss(uuid: str, update_qr_code_callback, login_callback):
    wss = websocket.create_connection(WSS_URL.format(uuid=uuid), timeout=30)
    wss.settimeout(30)
    thread = threading.Thread(target=monitor_wss, args=(wss, update_qr_code_callback, login_callback))
    thread.start()
    return wss, thread


def request_qr_refresh(wss) -> None:
    wss.send('{ "type": "UPDATE_QR_CODE" }')


def build_qr_updater(uuid: str):
    def _update(ts: str, sig: str) -> None:
        if not ts or not sig:
            return
        qr_data = QR_CODE_URL.format(uuid=uuid, ts=ts, sig=sig)
        qrterm.draw(qr_data, render=qrterm.render_2by1)
        print("📱 请扫码登录 (Ctrl+C 取消)")

    return _update


def login_notice() -> None:
    print("😎 扫码成功")


def ensure_login(session: requests.Session, cache_path: Path, *, allow_interactive: bool = True) -> bool:
    response = session.get(LOGIN_URL)
    if not response.url.startswith("https://jaccount.sjtu.edu.cn/jaccount/jalogin"):
        print("😋 已授权")
        return True

    if not allow_interactive:
        print("🤒 需要重新登录，但当前为非交互模式")
        return False

    uuid = parse_uuid_from_login_page(response.content)
    if not uuid:
        print("😮 错误：正则表达式未找到匹配项")
        return False

    updater = build_qr_updater(uuid)
    wss, thread = start_wss(uuid, updater, login_notice)
    time.sleep(0.2)
    request_qr_refresh(wss)
    try:
        while thread.is_alive():
            thread.join(timeout=0.5)
    except KeyboardInterrupt:
        print("❌ 已取消登录")
        try:
            wss.close()
        finally:
            return False

    confirm = session.get(EXPRESS_LOGIN_URL.format(uuid=uuid))
    if confirm.url.startswith("https://jaccount.sjtu.edu.cn/jaccount/jalogin"):
        print("🤒 错误：认证失败！又回到登录认证页面啦")
        return False
    if not (confirm.url.startswith("http://i.sjtu.edu.cn/") or confirm.url.startswith("https://i.sjtu.edu.cn/")):
        print("🤒 错误：认证失败！没有返回到指定的页面")
        return False

    persist_cookies(session, cache_path)
    print("😋 登录成功")
    return True


def date_range(days: int = 14) -> tuple[str, str]:
    now = datetime.today()
    ft_start = (now - timedelta(days=days)).strftime("%Y-%m-%d+%H:00:00")
    ft_end = (now + timedelta(days=days)).strftime("%Y-%m-%d+%H:00:00")
    return ft_start, ft_end


def fetch_events(session: requests.Session, days: int = 14) -> list[dict]:
    ft_start, ft_end = date_range(days)
    url = CALENDAR_API.format(start=ft_start, end=ft_end)
    response = session.get(url, headers={"Referer": "https://calendar.sjtu.edu.cn/ui/calendar"})
    if response.status_code != requests.codes.ok:
        print("🤒 获取日程失败，状态码：", response.status_code)
        return []
    return response.json().get("data", {}).get("events", [])


def sync_events_to_caldav(events: list[dict], *, username: str, password: str, caldav_url: str, calendar_name: str) -> None:
    if not events:
        print("🫠 没有日程可以同步")
        return

    with caldav.DAVClient(url=caldav_url, username=username, password=password) as client:
        principal = client.principal()
        calendars = principal.calendars()
        target = next((c for c in calendars if c.name == calendar_name), None)
        if target is None:
            try:
                target = principal.make_calendar(name=calendar_name)
                print(f"😗 未找到日历，已创建新日历：{calendar_name}")
            except Exception as exc:
                print(f"🤒 未找到名为 {calendar_name} 的日历，且创建失败: {exc}")
                return

        for event in events:
            print(f"🗓️  同步日程：{event['title']} ({event['startTime']} - {event['endTime']})")
            should_add = True
            for existing in target.search(
                start=datetime.strptime(event["startTime"], "%Y-%m-%d %H:%M"),
                end=datetime.strptime(event["endTime"], "%Y-%m-%d %H:%M"),
                event=True,
            ):
                if existing.icalendar_component["summary"] == event["title"]:
                    if existing.icalendar_component.get("location") != event["location"]:
                        existing.delete()
                    else:
                        should_add = False
                        break
            if should_add:
                target.add_event(
                    summary=event["title"],
                    dtstart=datetime.strptime(event["startTime"], "%Y-%m-%d %H:%M"),
                    dtend=datetime.strptime(event["endTime"], "%Y-%m-%d %H:%M"),
                    location=event["location"],
                    allDay=event["allDay"],
                )


def add_cookie_args(parser: argparse.ArgumentParser, *, include_non_interactive: bool = False) -> None:
    parser.add_argument("--cookie-file", default="cookies.txt", help="Path to JA cookie cache file")
    parser.add_argument("--ja-cookie", help="JAAuthCookie value (overrides file and env)")
    if include_non_interactive:
        parser.add_argument(
            "--non-interactive",
            action="store_true",
            help="Fail if re-login is required instead of prompting for QR code",
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Sync SJTU calendar events to CalDAV")
    subparsers = parser.add_subparsers(dest="command")

    login_parser = subparsers.add_parser("login", help="Authenticate and cache JA cookie")
    add_cookie_args(login_parser, include_non_interactive=True)

    sync_parser = subparsers.add_parser("sync", help="Sync calendar events to CalDAV")
    sync_parser.add_argument("--username", "-u", required=True, help="CalDAV username")
    sync_parser.add_argument("--password", "-p", required=True, help="CalDAV password")
    sync_parser.add_argument(
        "--caldav-url",
        default=None,
        help="CalDAV server URL (default: https://mail.sjtu.edu.cn/dav/{username}@sjtu.edu.cn/Calendar)",
    )
    sync_parser.add_argument("--calendar-name", default="交大日程", help="Target calendar name")
    sync_parser.add_argument("--days", type=int, default=14, help="Sync window in days before/after today")
    add_cookie_args(sync_parser, include_non_interactive=True)

    logout_parser = subparsers.add_parser("logout", help="Remove cached JA cookie")
    add_cookie_args(logout_parser, include_non_interactive=False)

    return parser


def run_login(args: argparse.Namespace) -> int:
    cookie_path = Path(args.cookie_file)
    explicit_cookie = args.ja_cookie or os.getenv("JA_AUTH_COOKIE")

    session = requests.session()
    load_cached_cookies(session, cookie_path, explicit_cookie)

    if not ensure_login(session, cookie_path, allow_interactive=not args.non_interactive):
        return 1
    return 0


def run_sync(args: argparse.Namespace) -> int:
    cookie_path = Path(args.cookie_file)
    explicit_cookie = args.ja_cookie or os.getenv("JA_AUTH_COOKIE")

    session = requests.session()
    load_cached_cookies(session, cookie_path, explicit_cookie)

    if not ensure_login(session, cookie_path, allow_interactive=not args.non_interactive):
        return 1

    events = fetch_events(session, args.days)
    caldav_url = args.caldav_url or f"https://mail.sjtu.edu.cn/dav/{args.username}@sjtu.edu.cn/Calendar"

    sync_events_to_caldav(
        events,
        username=args.username,
        password=args.password,
        caldav_url=caldav_url,
        calendar_name=args.calendar_name,
    )
    return 0


def run_logout(args: argparse.Namespace) -> int:
    cookie_path = Path(args.cookie_file)
    if cookie_path.exists():
        cookie_path.unlink()
        print(f"🧹 已删除缓存的 Cookie 文件: {cookie_path}")
    else:
        print(f"🤷 未找到 Cookie 文件: {cookie_path}")
    return 0


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not getattr(args, "command", None):
        parser.print_help()
        return

    if args.command == "login":
        code = run_login(args)
    elif args.command == "sync":
        code = run_sync(args)
    elif args.command == "logout":
        code = run_logout(args)
    else:
        parser.print_help()
        code = 1

    if code:
        sys.exit(code)


if __name__ == "__main__":
    main()
