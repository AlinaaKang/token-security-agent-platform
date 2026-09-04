# mcr.microsoft.com/dotnet/runtime-deps:8.0-noble, linux/amd64 manifest resolved 2026-08-31
FROM mcr.microsoft.com/dotnet/runtime-deps:8.0-noble@sha256:5aa56f5fdf83434f14a7b877912999ee8daa69a43fa1d6106753c4adbe21dc9b

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y \
        python3 \
        tshark \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 65532 pcap \
    && useradd --uid 65532 --gid 65532 --no-create-home pcap

COPY --chown=65532:65532 scripts/pcap_preflight.py /opt/pcap/pcap_preflight.py
COPY --chown=65532:65532 pcap-inspector/inspect.py /opt/pcap/inspect.py
COPY --chown=65532:65532 pcap-inspector/detect_http.py /opt/pcap/detect_http.py

USER 65532:65532
WORKDIR /opt/pcap
ENV PYTHONPATH=/opt/pcap PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ENTRYPOINT ["python3", "/opt/pcap/inspect.py"]
