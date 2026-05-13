import pytest

from magnet_util import auto_subfolder_name, btih_info_hash_v1_hex, parse_magnet, pick_unique_dir


def test_parse_magnet_btih_and_dn():
    m = parse_magnet(
        "magnet:?xt=urn:btih:ABCDEF0123456789ABCDEF0123456789ABCDEF01&dn=Hello+World"
    )
    assert m["btih"] == "abcdef0123456789abcdef0123456789abcdef01"
    assert m["dn"] == "Hello World"


def test_parse_magnet_rejects_non_magnet():
    with pytest.raises(ValueError):
        parse_magnet("https://example.com")


def test_auto_subfolder_name_btih_fallback():
    assert auto_subfolder_name(None, "a" * 40) == "torrent-aaaaaaaaaaaa"


def test_pick_unique_dir(tmp_path):
    d = pick_unique_dir(tmp_path, "foo")
    assert d.name == "foo"
    d.mkdir()
    d2 = pick_unique_dir(tmp_path, "foo")
    assert d2.name == "foo-2"


def test_btih_info_hash_v1_hex_from_hex():
    h = "ABCDEF0123456789ABCDEF0123456789ABCDEF01"
    assert btih_info_hash_v1_hex(h) == h.lower()


def test_btih_info_hash_v1_hex_from_base32():
    import base64

    hex40 = "2ccc379cbfef0f147c1e36a7910eec22b4f61ede"
    b32 = base64.b32encode(bytes.fromhex(hex40)).decode("ascii").rstrip("=")
    assert btih_info_hash_v1_hex(b32.lower()) == hex40
