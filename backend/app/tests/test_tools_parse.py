"""Tool engine contracts.

Regressions guarded here:
  * every spawned engine must get stdin=DEVNULL — the ProjectDiscovery tools
    auto-read targets from stdin when it is not a TTY and otherwise block under
    the server until the hard timeout (empty result);
  * parsers must read the keys the engines actually emit (httpx `tech`,
    nuclei `matched-at`/`matcher-name`) so result columns are not silently
    always empty and distinct matchers are not collapsed into duplicate rows.
"""
import asyncio

from app.modules.tools import service as svc

HTTPX_LINE = '{"status_code":200,"url":"http://x/","title":"T","tech":["Python:3.12"]}'
NUCLEI_LINE = ('{"template-id":"redoc-api-docs","info":{"name":"ReDoc","severity":"info"},'
               '"matched-at":"http://x/redoc"}')
NAABU_LINES = ('{"ip":"127.0.0.1","port":3000}\n'
               '{"ip":"127.0.0.1","port":3000}\n'
               '{"ip":"127.0.0.1","port":8010}')


def test_httpx_parse_keeps_tech_and_title():
    rows = svc.TOOLS["httpx"]["parse"](HTTPX_LINE)
    assert rows and rows[0]["tech"] == "Python:3.12"
    assert rows[0]["title"] == "T"


def test_nuclei_parse_keeps_matched_at_id_severity():
    rows = svc.TOOLS["nuclei"]["parse"](NUCLEI_LINE)
    assert rows and rows[0]["matched"] == "http://x/redoc"
    assert rows[0]["id"] == "redoc-api-docs"
    assert rows[0]["severity"] == "info"


def test_naabu_rows_are_deduped_by_port():
    rows = svc.TOOLS["naabu"]["parse"](NAABU_LINES)
    assert [r["port"] for r in rows] == [3000, 8010]


def test_host_of_cannot_be_scoped_past_query_or_fragment():
    """Scope is checked against _host_of() but the binary receives the RAW url —
    an '@' hidden in query/fragment used to scope-match evil.com while the tool
    actually scanned good.com (silent scope drift past the warrant gate)."""
    assert svc._host_of("http://good.com?x=@evil.com") == "good.com"
    assert svc._host_of("http://good.com#/p@evil.com") == "good.com"
    # genuine userinfo keeps resolving to the real connect host
    assert svc._host_of("http://user@real.example:8080/a?b=1") == "real.example"
    assert svc._host_of("http://good.com") == "good.com"


def test_nuclei_parse_keeps_matcher_name():
    """One template can fire many matchers on the same URL (one per missing header).
    They share info.name and matched-at, so dropping matcher-name makes N genuinely
    distinct findings render as N identical rows."""
    def line(matcher):
        return ('{"template-id":"http-missing-security-headers",'
                '"info":{"name":"HTTP Missing Security Headers","severity":"info"},'
                f'"matched-at":"http://x/","matcher-name":"{matcher}"}}')

    rows = svc.TOOLS["nuclei"]["parse"](line("content-security-policy") + "\n"
                                        + line("x-frame-options"))
    assert [r["matcher"] for r in rows] == ["content-security-policy", "x-frame-options"]
    assert len({(r["item"], r["matched"], r["matcher"]) for r in rows}) == 2


def test_nuclei_parse_defaults_matcher_to_empty():
    rows = svc.TOOLS["nuclei"]["parse"](NUCLEI_LINE)
    assert rows and rows[0]["matcher"] == ""


def test_sqlmap_parse_surfaces_critical_abort():
    """A 404/unreachable target used to yield count=0 exit=1 with zero explanation rows."""
    out = "[19:56:36] [CRITICAL] page not found (404)\n[*] ending @ 19:56:36"
    rows = svc.TOOLS["sqlmap"]["parse"](out)
    assert rows and "CRITICAL" in rows[0]["item"]


async def test_exec_closes_stdin(monkeypatch):
    captured: dict = {}

    class FakeProc:
        returncode = 0

        async def communicate(self):
            return b"", b""

    async def fake_exec(*argv, **kwargs):
        captured.update(kwargs)
        return FakeProc()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    rc, out, err = await svc._exec(["true"], {}, 5)
    assert rc == 0
    assert captured["stdin"] == asyncio.subprocess.DEVNULL
