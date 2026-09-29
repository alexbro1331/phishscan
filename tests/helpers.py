from email.message import EmailMessage


def build_eml(*, from_="Alice <alice@example.com>", reply_to=None, return_path=None,
              subject="Hi", auth=None, text="Hello", html=None, attachments=(), received=None) -> bytes:
    m = EmailMessage()
    m["From"] = from_
    m["To"] = "bob@example.org"
    m["Subject"] = subject
    if reply_to:
        m["Reply-To"] = reply_to
    if return_path:
        m["Return-Path"] = return_path
    if auth:
        m["Authentication-Results"] = auth
    for r in received or []:
        m["Received"] = r
    if text is None:
        m.set_content(html, subtype="html")
    else:
        m.set_content(text)
        if html:
            m.add_alternative(html, subtype="html")
    for name, data in attachments:
        m.add_attachment(data, maintype="application", subtype="octet-stream", filename=name)
    return m.as_bytes()


class FakeResp:
    def __init__(self, status=200, payload=None):
        self.status_code = status
        self._p = payload or {}

    def json(self):
        return self._p


class FakeSession:
    def __init__(self, resp=None, exc=None):
        self.resp, self.exc, self.calls = resp, exc, []

    def get(self, url, **kw):
        self.calls.append((url, kw))
        if self.exc:
            raise self.exc
        return self.resp
