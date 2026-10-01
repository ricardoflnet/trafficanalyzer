FROM python:3.12-slim

# tcpdump: o Scapy o usa no Linux para compilar filtros BPF.
# libpcap: suporte de captura de baixo nível.
RUN apt-get update \
    && apt-get install -y --no-install-recommends tcpdump libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt requirements-dev.txt ./
ARG INSTALL_DEV=false
RUN pip install --no-cache-dir -r requirements.txt \
    && if [ "$INSTALL_DEV" = "true" ]; then pip install --no-cache-dir -r requirements-dev.txt; fi

COPY app ./app
COPY tests ./tests

ENV PYTHONUNBUFFERED=1 \
    DB_PATH=/data/traffic.db \
    BIND_ADDRESS=0.0.0.0:8000

VOLUME ["/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD python -c "import os,urllib.request; urllib.request.urlopen('http://' + os.environ['BIND_ADDRESS'].replace('0.0.0.0','127.0.0.1') + '/healthz')" || exit 1

# Um único worker: o estado da captura (sniffer + fila) vive no processo.
# Threads atendem requisições concorrentes do painel.
CMD ["sh", "-c", "exec gunicorn --workers 1 --threads 8 --bind ${BIND_ADDRESS} --access-logfile - 'app.main:create_app()'"]
