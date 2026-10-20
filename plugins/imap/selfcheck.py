"""Checks the parts of imap.py that need no server. Run with `python3 -I plugins/imap/selfcheck.py`"""

import base64
import contextlib
import email.message
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import sys
import tempfile

# Loading imap.py by path would otherwise leave a __pycache__ in the plugin directory
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("imap", pathlib.Path(__file__).with_name("imap.py"))
imap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(imap)

# Attachment names cannot climb out of the directory or hide a file
assert imap.safe_name("../../.ssh/authorized_keys", 1) == "authorized_keys"
assert imap.safe_name("..\\..\\evil.exe", 1) == "evil.exe"
assert imap.safe_name("..", 2) == "attachment-2"
assert imap.safe_name("", 3) == "attachment-3"
assert imap.safe_name(None, 4) == "attachment-4"
assert imap.safe_name(".bashrc", 5) == "bashrc"
assert imap.safe_name("a\x00b\x1b[31m.pdf", 6) == "ab[31m.pdf"
assert imap.safe_name("report: Q1?.pdf", 7) == "report_ Q1_.pdf"
assert len(imap.safe_name("x" * 500 + ".pdf", 8).encode()) <= 200

# Encoded words decode, and nothing that could drive a terminal survives
assert imap.decode("=?utf-8?b?T2zDoSBtdW5kbw==?=") == "Olá mundo"
assert imap.decode("=?iso-8859-1?q?caf=E9?= time") == "café time"
assert imap.decode("plain\r\n subject") == "plain subject"
assert imap.decode("=?bogus?q?x?=") == "=?bogus?q?x?="
assert imap.clean("red\x1b[31m text") == "red[31m text"

# The account is one entry: password first, then fields
acct = imap.account("s3cret: with colon\nHost: 127.0.0.1\nport: 1143\nuser: me@example.com\n")
assert acct == {
    "password": "s3cret: with colon",
    "host": "127.0.0.1",
    "port": "1143",
    "user": "me@example.com",
}
for raw in ("", "pw\nhost: h", "pw\nuser: u"):
    try:
        imap.account(raw)
    except ValueError as e:
        assert "pw" not in str(e), e
    else:
        raise AssertionError(f"accepted {raw!r}")

der = b"certificate bytes"
digest = hashlib.sha256(der).hexdigest()
assert imap.fingerprint_matches(der, digest)
assert imap.fingerprint_matches(der, "SHA256:" + ":".join(digest[i : i + 2].upper() for i in range(0, 64, 2)))
assert imap.fingerprint_matches(der, "sha256 Fingerprint=" + digest.upper())
assert not imap.fingerprint_matches(der, "00" * 32)
assert not imap.fingerprint_matches(der, "")

assert imap.quote('Folders/a "b"') == '"Folders/a \\"b\\""'
for bad in ("INBOX\r\nA1 DELETE x", "a\x00"):
    try:
        imap.quote(bad)
    except ValueError:
        pass
    else:
        raise AssertionError(f"quoted {bad!r}")


class Conn:
    """Answers SELECT and FETCH with one canned message"""

    def __init__(self, raw):
        self.raw = raw

    def select(self, mailbox, readonly):
        assert readonly
        return "OK", [b"1"]

    def uid(self, command, *args):
        assert command == "FETCH" and args[0] == "7", args
        return "OK", [(b"7 (BODY[] {1}", self.raw), b")"]


msg = email.message.EmailMessage()
msg["From"] = "Ana <ana@example.com>"
msg["Subject"] = "=?utf-8?q?Fatura_mar=C3=A7o?="
msg.set_content("Hello\x1b[2J there")
msg.add_attachment(b"one", maintype="application", subtype="pdf", filename="../../escape.pdf")
msg.add_attachment(b"two", maintype="application", subtype="pdf", filename="escape.pdf")
msg.add_attachment(b"three", maintype="text", subtype="plain", filename="/etc/passwd")
conn = Conn(msg.as_bytes())

out = io.StringIO()
with contextlib.redirect_stdout(out):
    imap.read(conn, "7")
text = out.getvalue()
assert "Subject: Fatura março" in text, text
assert "Hello[2J there" in text and "\x1b" not in text, text
assert "Attachments: ../../escape.pdf, escape.pdf, /etc/passwd" in text, text

# Attachments come back as JSON, nothing is written, and names lose any path the sender put in
with tempfile.TemporaryDirectory() as tmp:
    before = os.getcwd()
    os.chdir(tmp)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        imap.attachments(conn, "7")
    os.chdir(before)
    assert os.listdir(tmp) == [], os.listdir(tmp)
items = json.loads(out.getvalue())
assert [i["name"] for i in items] == ["escape.pdf", "escape.pdf", "passwd"], items
assert [base64.b64decode(i["base64"]) for i in items] == [b"one", b"two", b"three"], items
assert items[0]["type"] == "application/pdf" and items[0]["size"] == 3, items[0]

# Past the cap an attachment is listed without its bytes, and the ones before it still come back
cap = imap.MAX_ATTACHMENT_BYTES
imap.MAX_ATTACHMENT_BYTES = 4
out = io.StringIO()
with contextlib.redirect_stdout(out):
    imap.attachments(conn, "7")
imap.MAX_ATTACHMENT_BYTES = cap
items = json.loads(out.getvalue())
assert "base64" in items[0] and "base64" not in items[1] and "skipped" in items[1], items

# The old dir argument is refused rather than taken as a mailbox
assert imap.attachments.__code__.co_argcount == 3

for bad in ("7 BODY[]", "", "1:*"):
    try:
        imap.message(conn, bad)
    except ValueError:
        pass
    else:
        raise AssertionError(f"accepted id {bad!r}")


# An error never repeats the password, even when the server put it in its reply
def leaky(acct):
    raise imap.imaplib.IMAP4.error(f"LOGIN failed for {acct['password']}")


imap.connect = leaky
sys.stdin = io.StringIO("hunter2-pw\nhost: h\nuser: u")
err, out = io.StringIO(), io.StringIO()
with contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
    try:
        imap.main(["-c", "recent"])
    except SystemExit as e:
        assert e.code == 1
assert "hunter2-pw" not in err.getvalue() and "[redacted]" in err.getvalue(), err.getvalue()
assert "Traceback" not in err.getvalue(), err.getvalue()
assert out.getvalue() == "", out.getvalue()

# No account on stdin is refused without connecting
sys.stdin = io.StringIO("")
with contextlib.redirect_stderr(io.StringIO()):
    try:
        imap.main(["-c", "recent"])
    except SystemExit as e:
        assert e.code == 1
    else:
        raise AssertionError("ran with no account")
sys.stdin = sys.__stdin__

print("imap selfcheck ok", file=sys.stderr)
