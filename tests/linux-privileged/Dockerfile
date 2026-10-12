FROM rust:1.97
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    cmake pkg-config python3 util-linux zlib1g-dev libbz2-dev liblzma-dev \
    libzstd-dev liblz4-dev libb2-dev libxml2-dev libssl-dev libacl1-dev \
    libattr1-dev libext2fs-dev && rm -rf /var/lib/apt/lists/*
COPY source.tar /source.tar
RUN mkdir /suite && tar -xf /source.tar -C /suite && \
    cd /suite && cargo fetch --locked
CMD ["sleep", "infinity"]
