# AEGIS image: Go gateway + replay tool built from source, Python controller. All open source.
# gateway/go.mod pins a newer Go than this base image. The golang image sets GOTOOLCHAIN=local, which
# forbids Go from fetching it, so switch that back to auto for the build.
FROM golang:1.24-bookworm AS build
ENV GOTOOLCHAIN=auto
WORKDIR /src/gateway
COPY gateway/ ./
RUN go build -o /out/gateway . && go build -o /out/replay ./cmd/replay

FROM python:3.12-slim
WORKDIR /app
COPY --from=build /out/gateway /out/replay /app/bin/
COPY aegis.py /app/aegis.py
COPY observer/ /app/observer/
COPY deliberator/ /app/deliberator/
COPY gate/ /app/gate/
COPY ir/ /app/ir/
COPY memory/ /app/memory/
COPY controller/ /app/controller/
COPY data/idor_ceilings.json data/hard_negatives.jsonl /app/data/
COPY data/attack_corpus/ /app/data/attack_corpus/
# Run as an unprivileged user. The state directories are created and owned by it BEFORE they are declared
# VOLUMEs, so named volumes inherit that ownership.
RUN useradd --system --uid 10001 --home-dir /app --shell /usr/sbin/nologin aegis \
 && mkdir -p /app/logs /app/rules/active /app/data/learned /app/memory /app/.aegis \
 && chown -R aegis:aegis /app
USER aegis
# State that must survive restarts: learned corpus, rule store, memory DB, secrets, logs.
VOLUME ["/app/data/learned", "/app/rules/active", "/app/memory", "/app/.aegis", "/app/logs"]
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=4s --start-period=60s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8081/health', timeout=3)"]
ENV AEGIS_LISTEN=0.0.0.0:8080
ENTRYPOINT ["python", "/app/aegis.py"]
CMD ["run", "--mode", "learn"]
