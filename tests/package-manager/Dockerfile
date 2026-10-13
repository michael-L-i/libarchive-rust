FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    pacman-package-manager python3 zstd binutils ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY transactions.py /opt/transactions.py
ENTRYPOINT ["python3", "/opt/transactions.py", "--library-dir", "/opt", "--report-dir", "/evidence"]
