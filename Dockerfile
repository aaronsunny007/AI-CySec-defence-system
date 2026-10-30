# AEGIS image: Go gateway + replay tool built from source, Python controller. All open source.
# gateway/go.mod pins a newer Go than this base image; Go fetches that toolchain itself (GOTOOLCHAIN=auto).
FROM golang:1.24-bookworm AS build
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
RUN mkdir -p /app/logs /app/rules/active /app/data/learned /app/.aegis
# State that must survive restarts: learned corpus, rule store, memory DB, secrets, logs.
VOLUME ["/app/data/learned", "/app/rules/active", "/app/memory", "/app/.aegis", "/app/logs"]
EXPOSE 8080
ENV AEGIS_LISTEN=0.0.0.0:8080
ENTRYPOINT ["python", "/app/aegis.py"]
CMD ["run", "--mode", "learn"]
