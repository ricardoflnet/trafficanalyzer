"""Aplicação web: painel + API REST para controlar a captura e ler estatísticas."""
from __future__ import annotations

import atexit
import hmac
import logging
import os

from flask import Flask, Response, jsonify, render_template, request

from .capture import CaptureManager, list_interfaces
from .database import Database

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("traffic-analyzer")


def create_app(db: Database | None = None, capture: CaptureManager | None = None) -> Flask:
    app = Flask(__name__)
    db = db or Database()
    capture = capture or CaptureManager(
        db,
        batch_size=int(os.getenv("BATCH_SIZE", "500")),
        flush_interval=float(os.getenv("FLUSH_INTERVAL", "1.0")),
    )
    app.config["capture"] = capture

    user = os.getenv("APP_USER", "admin")
    password = os.getenv("APP_PASSWORD", "")
    if not password:
        log.warning("APP_PASSWORD vazio: painel SEM autenticação. Não exponha à internet assim.")

    # ------------------------------------------------------- autenticação HTTP
    @app.before_request
    def require_auth():
        if not password or request.path == "/healthz":
            return None
        auth = request.authorization
        if (
            auth
            and hmac.compare_digest(auth.username or "", user)
            and hmac.compare_digest(auth.password or "", password)
        ):
            return None
        return Response(
            "Autenticação necessária", 401, {"WWW-Authenticate": 'Basic realm="Traffic Analyzer"'}
        )

    def error(message: str, status: int = 400):
        return jsonify({"error": message}), status

    def session_param() -> int | None:
        value = request.args.get("session_id")
        if value:
            return int(value)
        return capture.session_id or db.latest_session_id()

    # ------------------------------------------------------------------ rotas
    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.get("/api/interfaces")
    def interfaces():
        return jsonify(list_interfaces())

    @app.get("/api/status")
    def status():
        return jsonify(capture.status())

    @app.post("/api/capture/start")
    def start():
        body = request.get_json(silent=True) or {}
        interface = (body.get("interface") or "").strip()
        if not interface:
            return error("Informe a interface de rede.")
        try:
            session_id = capture.start(interface, body.get("filter"))
        except RuntimeError as exc:
            return error(str(exc), 409)
        except ValueError as exc:
            return error(str(exc))
        except PermissionError:
            return error("Sem permissão para capturar. Rode com NET_RAW/NET_ADMIN (ver README).", 403)
        return jsonify({"session_id": session_id}), 201

    @app.post("/api/capture/stop")
    def stop():
        session_id = capture.stop()
        if session_id is None:
            return error("Nenhuma captura em andamento.", 409)
        return jsonify({"session_id": session_id})

    @app.get("/api/sessions")
    def sessions():
        return jsonify(db.list_sessions())

    @app.delete("/api/sessions/<int:session_id>")
    def delete_session(session_id: int):
        if capture.running and capture.session_id == session_id:
            return error("Pare a captura antes de apagar esta sessão.", 409)
        db.delete_session(session_id)
        return "", 204

    @app.get("/api/stats")
    def stats():
        try:
            session_id = session_param()
        except ValueError:
            return error("session_id inválido.")
        if session_id is None:
            return jsonify(None)
        return jsonify(db.stats(session_id, order_by=request.args.get("order", "bytes")))

    @app.get("/api/packets")
    def packets():
        try:
            session_id = session_param()
            limit = min(int(request.args.get("limit", "50")), 500)
        except ValueError:
            return error("Parâmetros inválidos.")
        if session_id is None:
            return jsonify([])
        return jsonify(db.recent_packets(session_id, limit))

    # Inicia automaticamente se a interface vier por variável de ambiente.
    auto_iface = os.getenv("CAPTURE_INTERFACE")
    if auto_iface and not capture.running:
        try:
            capture.start(auto_iface, os.getenv("CAPTURE_FILTER"))
        except Exception as exc:
            log.error("Não foi possível iniciar a captura automática em %s: %s", auto_iface, exc)

    atexit.register(capture.stop)
    return app


if __name__ == "__main__":  # modo de desenvolvimento: python -m app.main
    create_app().run(host="0.0.0.0", port=int(os.getenv("PORT", "8000")), threaded=True)
