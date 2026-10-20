"""IMAP for passbox, standard library only. The broker runs it as `python3 -I -c <this file> <tool>`.

The account is one passbox entry that arrives on stdin: the first line is the password and
later `key: value` lines are host, port, user, tls (`starttls` or `ssl`), and optionally cafile or
fingerprint (SHA-256 of the server certificate) to trust a self-signed certificate such as Bridge's
"""

import base64
import email
import email.errors
import email.header
import email.policy
import hashlib
import html
import imaplib
import json
import os
import re
import ssl
import sys

CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def fail(message):
    print(message, file=sys.stderr)
    sys.exit(1)


def account(raw):
    lines = raw.splitlines()
    if not lines or not lines[0]:
        raise ValueError("the account entry has no password on its first line")
    fields = {"password": lines[0]}
    for line in lines[1:]:
        key, sep, value = line.partition(":")
        if sep and key.strip() and value.strip():
            fields[key.strip().lower()] = value.strip()
    for need in ("host", "user"):
        if need not in fields:
            raise ValueError(f"the account entry has no `{need}:` line")
    return fields


def fingerprint_matches(der, pin):
    # Takes openssl's `sha256 Fingerprint=AB:CD:...` line as well as bare hex
    want = re.sub(r"[^0-9a-f]", "", pin.rsplit("=", 1)[-1].lower().removeprefix("sha256"))
    return hashlib.sha256(der).hexdigest() == want


def connect(acct):
    tls = acct.get("tls") or ("ssl" if acct.get("port") == "993" else "starttls")
    port = int(acct.get("port") or (993 if tls == "ssl" else 143))
    pin = acct.get("fingerprint")
    if pin:
        # The pin replaces CA and host name checks, and is compared before the password is sent
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx = ssl.create_default_context(cafile=acct.get("cafile"))

    if tls == "ssl":
        conn = imaplib.IMAP4_SSL(acct["host"], port, ssl_context=ctx, timeout=30)
    elif tls == "starttls":
        conn = imaplib.IMAP4(acct["host"], port, timeout=30)
        conn.starttls(ssl_context=ctx)
    else:
        raise ValueError(f"tls must be starttls or ssl, got {tls}")

    if pin and not fingerprint_matches(conn.sock.getpeercert(binary_form=True), pin):
        conn.shutdown()
        raise ssl.SSLError("the server certificate does not match the pinned fingerprint")
    conn.login(acct["user"], acct["password"])
    return conn


def quote(mailbox):
    if re.search(r"[\x00-\x1f\x7f]", mailbox):
        raise ValueError("a mailbox name cannot hold control characters")
    return '"' + mailbox.replace("\\", "\\\\").replace('"', '\\"') + '"'


def select(conn, mailbox):
    status, data = conn.select(quote(mailbox or "INBOX"), readonly=True)
    if status != "OK":
        raise ValueError(f"no mailbox {mailbox}: {data[0].decode(errors='replace')}")


def clean(text):
    """One line with no terminal control characters, since the output lands in a transcript"""
    return CONTROL.sub("", " ".join(str(text).split()))


def decode(value):
    try:
        return clean(email.header.make_header(email.header.decode_header(value)))
    except (email.errors.HeaderParseError, LookupError, UnicodeError):
        return clean(value)


def uids(conn, *criteria):
    status, data = conn.uid("SEARCH", *criteria)
    if status != "OK":
        raise ValueError("search failed")
    return data[0].split()


def summaries(conn, ids):
    if not ids:
        print("no messages")
        return
    status, data = conn.uid(
        "FETCH", b",".join(ids), "(UID BODY.PEEK[HEADER.FIELDS (DATE FROM SUBJECT)])"
    )
    if status != "OK":
        raise ValueError("fetch failed")
    rows = []
    for item in data:
        if not isinstance(item, tuple):
            continue
        uid = re.search(rb"UID (\d+)", item[0])
        headers = email.message_from_bytes(item[1])
        rows.append(
            (
                int(uid.group(1)) if uid else 0,
                decode(headers.get("Date", "")),
                decode(headers.get("From", "")),
                decode(headers.get("Subject", "")),
            )
        )
    for uid, date, sender, subject in sorted(rows, reverse=True):
        print(f"{uid} | {date} | {sender} | {subject}")


def message(conn, uid):
    if not re.fullmatch(r"\d+", uid or ""):
        raise ValueError("id must be the number recent or search printed")
    status, data = conn.uid("FETCH", uid, "(BODY.PEEK[])")
    parts = [item[1] for item in data if isinstance(item, tuple)] if status == "OK" else []
    if not parts:
        raise ValueError(f"no message with id {uid}")
    return email.message_from_bytes(parts[0], policy=email.policy.default)


def safe_name(name, index):
    """A plain file name whatever the sender wrote, so a caller that saves it stays in its directory"""
    base = re.split(r"[/\\]", name or "")[-1]
    base = CONTROL.sub("", base).strip().lstrip(".").strip()
    base = re.sub(r'[<>:"|?*]', "_", base)
    while len(base.encode()) > 200:
        base = base[:-1]
    return base or f"attachment-{index}"


def text_body(msg):
    part = msg.get_body(preferencelist=("plain", "html"))
    if part is None:
        return ""
    text = part.get_content()
    if part.get_content_type() == "text/html":
        text = re.sub(r"(?is)<(script|style).*?</\1>", "", text)
        text = html.unescape(re.sub(r"(?s)<[^>]+>", "", text))
    return CONTROL.sub("", text).strip()


def recent(conn, count="", mailbox=""):
    n = int(count or 10)
    select(conn, mailbox)
    summaries(conn, uids(conn, "ALL")[-n:] if n > 0 else [])


def search(conn, query, mailbox=""):
    select(conn, mailbox)
    # A literal carries the query as data, so quotes or CRLF in it cannot extend the command
    conn.literal = query.encode()
    summaries(conn, uids(conn, "CHARSET", "UTF-8", "TEXT")[-50:])


def read(conn, uid, mailbox=""):
    select(conn, mailbox)
    msg = message(conn, uid)
    for name in ("Date", "From", "To", "Cc", "Subject"):
        if msg[name]:
            print(f"{name}: {clean(msg[name])}")
    names = [clean(p.get_filename() or "") for p in msg.iter_attachments()]
    if names:
        print("Attachments: " + ", ".join(n or "(unnamed)" for n in names))
    print()
    print(text_body(msg))


# Attachments go back in the reply, so a cap keeps one call from flooding the socket or an agent
MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024


def attachments(conn, uid, mailbox=""):
    """Every attachment as JSON with its base64 bytes, so nothing is written on this machine"""
    select(conn, mailbox)
    msg = message(conn, uid)
    out, total = [], 0
    for index, part in enumerate(msg.iter_attachments(), 1):
        data = part.get_payload(decode=True) or b""
        item = {"name": safe_name(part.get_filename(), index), "type": part.get_content_type(), "size": len(data)}
        if total + len(data) > MAX_ATTACHMENT_BYTES:
            item["skipped"] = f"over the {MAX_ATTACHMENT_BYTES // (1024 * 1024)} MB a call returns"
        else:
            total += len(data)
            item["base64"] = base64.b64encode(data).decode()
        out.append(item)
    print(json.dumps(out))


TOOLS = {"recent": recent, "search": search, "read": read, "attachments": attachments}


def main(argv):
    if len(argv) < 2 or argv[1] not in TOOLS:
        fail(f"usage: imap.py <{'|'.join(TOOLS)}> [args]")
    raw = sys.stdin.read()
    if not raw:
        fail("no account on stdin, run this through `passbox plugin imap`")
    password = raw.splitlines()[0] if raw.splitlines() else ""
    try:
        acct = account(raw)
        conn = connect(acct)
        try:
            TOOLS[argv[1]](conn, *argv[2:])
        finally:
            try:
                conn.logout()
            except (imaplib.IMAP4.error, OSError):
                pass
    except Exception as e:  # noqa: BLE001
        # Only the message, never a traceback, and never the password even if a server echoed it
        text = f"{type(e).__name__}: {e}"
        fail(text.replace(password, "[redacted]") if password else text)


if __name__ == "__main__":
    main(sys.argv)
