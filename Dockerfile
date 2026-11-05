FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 MPLCONFIGDIR=/tmp/mpl
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN pip install --no-cache-dir --no-deps . && useradd --system --uid 10001 --no-create-home tf && mkdir /data && chown tf /data
USER tf
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8000/healthz', timeout=3)"
# TRACEFORGE_TOKEN must be set (see docker-compose.yml); the console is protected by it.
CMD ["traceforge", "serve", "--host", "0.0.0.0", "--no-browser", "--db", "/data/traceforge.db"]
