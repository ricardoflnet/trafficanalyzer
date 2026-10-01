import pytest

pytest.importorskip("scapy.all")

from app.database import Database  # noqa: E402
from app.main import create_app  # noqa: E402


class FakeCapture:
    """Substitui a captura real: os testes da API não precisam de privilégios."""

    def __init__(self, db):
        self.db, self.session_id, self._running = db, None, False

    @property
    def running(self):
        return self._running

    def start(self, interface, bpf_filter=None):
        if self._running:
            raise RuntimeError("Já existe uma captura em andamento.")
        if interface != "eth0":
            raise ValueError("Interface desconhecida")
        self.session_id = self.db.create_session(interface, bpf_filter)
        self._running = True
        return self.session_id

    def stop(self):
        if not self._running:
            return None
        self._running = False
        self.db.close_session(self.session_id)
        return self.session_id

    def status(self):
        return {"running": self._running, "session_id": self.session_id}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("APP_PASSWORD", "segredo")
    monkeypatch.delenv("CAPTURE_INTERFACE", raising=False)
    db = Database(str(tmp_path / "api.db"))
    app = create_app(db=db, capture=FakeCapture(db))
    c = app.test_client()
    c.environ_base["HTTP_AUTHORIZATION"] = "Basic YWRtaW46c2VncmVkbw=="  # admin:segredo
    return c, db


def test_requires_auth(tmp_path, monkeypatch):
    monkeypatch.setenv("APP_PASSWORD", "segredo")
    db = Database(str(tmp_path / "a.db"))
    c = create_app(db=db, capture=FakeCapture(db)).test_client()
    assert c.get("/api/status").status_code == 401
    assert c.get("/healthz").status_code == 200


def test_start_stats_stop(client):
    c, db = client
    assert c.post("/api/capture/start", json={}).status_code == 400
    assert c.post("/api/capture/start", json={"interface": "xyz"}).status_code == 400
    res = c.post("/api/capture/start", json={"interface": "eth0"})
    assert res.status_code == 201
    sid = res.get_json()["session_id"]
    assert c.post("/api/capture/start", json={"interface": "eth0"}).status_code == 409

    db.insert_packets(sid, [(1.0, "10.0.0.1", "10.0.0.2", "TCP", 100)] * 3)
    stats = c.get("/api/stats").get_json()
    assert stats["total_packets"] == 3
    assert stats["top_sources"][0]["ip"] == "10.0.0.1"
    assert len(c.get("/api/packets?limit=2").get_json()) == 2

    assert c.post("/api/capture/stop").status_code == 200
    assert c.post("/api/capture/stop").status_code == 409
    assert c.get("/api/sessions").get_json()[0]["packets"] == 3
