from rss_grabber import fetch_magnets_from_feed_url


def test_extract_magnets_from_xml_snippet(monkeypatch):
    xml = b"""<?xml version="1.0"?><rss><channel><item>
    <title>Test</title>
    <link>magnet:?xt=urn:btih:aaa</link>
    </item></channel></rss>"""

    def fake_open(req, timeout=30):
        class R:
            def read(self):
                return xml

            def __enter__(self):
                return self

            def __exit__(self, *a):
                pass

        return R()

    monkeypatch.setattr("rss_grabber.urllib.request.urlopen", fake_open)
    mags = fetch_magnets_from_feed_url("http://example.invalid/feed")
    assert any("magnet:?" in m for m in mags)
