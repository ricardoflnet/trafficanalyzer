from app.database import Database


def make_db(tmp_path):
    return Database(str(tmp_path / "test.db"))


def test_stats_counts_and_top5(tmp_path):
    db = make_db(tmp_path)
    sid = db.create_session("eth0", None)
    rows = []
    # 10.0.0.1 envia muitos pacotes pequenos; 10.0.0.2 envia poucos pacotes grandes.
    rows += [(1.0, "10.0.0.1", "8.8.8.8", "UDP", 60)] * 10
    rows += [(2.0, "10.0.0.2", "1.1.1.1", "TCP", 1500)] * 2
    rows += [(3.0, f"10.0.1.{i}", "1.1.1.1", "TCP", 100) for i in range(6)]
    rows += [(4.0, None, None, "OTHER", 42)]
    db.insert_packets(sid, rows)

    by_bytes = db.stats(sid, order_by="bytes")
    assert by_bytes["total_packets"] == 19
    assert by_bytes["total_bytes"] == 600 + 3000 + 600 + 42
    assert {p["protocol"]: p["packets"] for p in by_bytes["protocols"]} == {"UDP": 10, "TCP": 8, "OTHER": 1}
    assert len(by_bytes["top_sources"]) == 5
    assert by_bytes["top_sources"][0]["ip"] == "10.0.0.2"
    assert by_bytes["top_destinations"][0] == {"ip": "1.1.1.1", "packets": 8, "bytes": 3600}

    by_packets = db.stats(sid, order_by="packets")
    assert by_packets["top_sources"][0]["ip"] == "10.0.0.1"


def test_invalid_order_falls_back_to_bytes(tmp_path):
    db = make_db(tmp_path)
    sid = db.create_session("eth0", None)
    assert db.stats(sid, order_by="bytes; DROP TABLE packets")["ordered_by"] == "bytes"


def test_sessions_are_isolated_and_deletable(tmp_path):
    db = make_db(tmp_path)
    a, b = db.create_session("eth0", None), db.create_session("lo", "tcp")
    db.insert_packets(a, [(1.0, "1.1.1.1", "2.2.2.2", "TCP", 100)])
    assert db.stats(b)["total_packets"] == 0
    db.delete_session(a)
    assert db.stats(a)["total_packets"] == 0
    assert [s["id"] for s in db.list_sessions()] == [b]


def test_open_sessions_are_closed_on_restart(tmp_path):
    db = make_db(tmp_path)
    sid = db.create_session("eth0", None)
    db2 = Database(db.path)  # simula reinício do container
    assert db2.list_sessions()[0]["stopped_at"] is not None
    assert db2.list_sessions()[0]["id"] == sid
