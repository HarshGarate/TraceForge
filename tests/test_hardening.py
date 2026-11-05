"""Upload hardening: archives, size and shape limits, time budget."""
import gzip
import io
import json
import zipfile

import pytest

from traceforge import hardening
from traceforge.hardening import UploadRejected, expand_upload
from traceforge.ingest import normalize_file

CSV = b"timestamp,src_ip,user,event_type\n2026-03-11T10:00:00Z,203.0.113.5,a,login_failure\n"


def _zip(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for n, d in members.items():
            z.writestr(n, d)
    return buf.getvalue()


def test_plain_files_pass_through():
    assert expand_upload("a.csv", CSV) == ([("a.csv", CSV)], None)


def test_gzip_is_expanded_by_content_not_by_name():
    files, info = expand_upload("auth.log.gz", gzip.compress(CSV))
    assert files == [("auth.log", CSV)] and info["kind"] == "gzip"
    files, _ = expand_upload("renamed.csv", gzip.compress(CSV))       # wrong extension, gzip magic
    assert files[0][1] == CSV


def test_zip_members_are_flattened_to_base_names():
    files, info = expand_upload("logs.zip", _zip({"../../etc/evil.csv": CSV, "dir/sub/ok.csv": CSV, "__MACOSX/._ok.csv": b"x", "dir/": b""}))
    assert [n for n, _ in files] == ["logs.zip/evil.csv", "logs.zip/ok.csv"]
    assert all("/" not in n.split("/", 1)[1] and ".." not in n for n, _ in files) and info["kind"] == "zip"


def test_decompression_bomb_is_refused(monkeypatch):
    monkeypatch.setattr(hardening, "MAX_UPLOAD_BYTES", 10_000)
    with pytest.raises(UploadRejected, match="more than|larger than"):
        expand_upload("bomb.gz", gzip.compress(b"A" * 1_000_000))
    with pytest.raises(UploadRejected, match="larger than|more than"):
        expand_upload("bomb.zip", _zip({"big.log": b"A" * 1_000_000}))


def test_zip_total_member_and_nesting_limits(monkeypatch):
    monkeypatch.setattr(hardening, "MAX_ARCHIVE_MEMBERS", 2)
    with pytest.raises(UploadRejected, match="limit is 2"):
        expand_upload("many.zip", _zip({f"{i}.csv": CSV for i in range(3)}))
    monkeypatch.setattr(hardening, "MAX_ARCHIVE_MEMBERS", 25)
    monkeypatch.setattr(hardening, "MAX_ARCHIVE_TOTAL_BYTES", len(CSV) + 5)
    with pytest.raises(UploadRejected, match="in total"):
        expand_upload("total.zip", _zip({"a.csv": CSV, "b.csv": CSV}))


def test_nested_archives_are_refused():
    with pytest.raises(UploadRejected, match="Nested archives"):
        expand_upload("nest.zip", _zip({"inner.gz": gzip.compress(CSV)}))
    with pytest.raises(UploadRejected, match="Nested archives"):
        expand_upload("nest.gz", gzip.compress(_zip({"a.csv": CSV})))


def test_encrypted_zip_corrupt_gzip_and_tar_are_refused():
    z = bytearray(_zip({"a.csv": CSV}))
    flag_pos = z.index(b"PK\x03\x04") + 6
    z[flag_pos] |= 1                                                   # mark the local header as encrypted
    cd = z.index(b"PK\x01\x02") + 8
    z[cd] |= 1
    with pytest.raises(UploadRejected, match="password-protected"):
        expand_upload("enc.zip", bytes(z))
    with pytest.raises(UploadRejected, match="not a valid gzip"):
        expand_upload("bad.gz", b"\x1f\x8b" + b"garbage" * 5)
    with pytest.raises(UploadRejected, match="tar archives"):
        expand_upload("x.tar", b"\0" * 257 + b"ustar" + b"\0" * 300)
    with pytest.raises(UploadRejected, match="no files"):
        expand_upload("empty.zip", _zip({}))


def test_too_many_columns_are_refused():
    header = ",".join(["timestamp"] + [f"c{i}" for i in range(hardening.MAX_COLUMNS + 5)])
    row = ",".join(["2026-03-11T10:00:00Z"] + ["x"] * (hardening.MAX_COLUMNS + 5))
    with pytest.raises(ValueError, match="columns"):
        normalize_file(f"{header}\n{row}\n".encode(), "wide.csv")


def test_deeply_nested_json_is_a_clean_error():
    deep = "[" * 200_000 + "]" * 200_000
    with pytest.raises(ValueError, match="nested too deeply|JSON objects"):
        normalize_file(deep.encode(), "deep.json")


def test_json_must_hold_objects():
    with pytest.raises(ValueError, match="JSON objects"):
        normalize_file(json.dumps(["a", "b"]).encode(), "x.json")


def test_moderately_nested_json_is_flattened_to_the_limit():
    rec = {"timestamp": "2026-03-11T10:00:00Z", "a": {"b": {"c": {"d": {"e": {"f": {"g": {"h": 1}}}}}}}, "event_type": "login_failure", "user": "u"}
    df, _ = normalize_file(json.dumps([rec]).encode(), "n.json")
    assert len(df) == 1


def test_parse_time_budget_is_enforced():
    with pytest.raises(UploadRejected, match="took longer"):
        normalize_file(CSV, "slow.csv", timeout=-1)
    big = b"\n".join(b"2026-03-11T10:00:00Z Failed password for root from 203.0.113.9 port 22 ssh2" for _ in range(10_000))
    with pytest.raises(UploadRejected, match="took longer"):
        normalize_file(big, "auth.log", timeout=-1)
