FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    PATH=/root/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    build-essential \
    ca-certificates \
    clang \
    cmake \
    curl \
    file \
    git \
    jq \
    libbpf-dev \
    libelf-dev \
    lld \
    linux-tools-common \
    llvm \
    llvm-dev \
    make \
    pkg-config \
    python3 \
    ripgrep \
    valgrind \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal

WORKDIR /workspace/recompile

COPY scripts/docker-setup.sh /usr/local/bin/recompile-bootstrap
RUN chmod +x /usr/local/bin/recompile-bootstrap

ENTRYPOINT ["/usr/local/bin/recompile-bootstrap"]
CMD ["bash"]
