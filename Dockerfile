# Use the latest Ubuntu image (Docker will automatically pick arm64 or amd64)
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && apt-get install -y \
    clang llvm libbpf-dev gcc git make pkg-config \
    iproute2 sudo zlib1g-dev elfutils libelf-dev \
    linux-headers-generic linux-tools-generic \
    wget tar curl iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Install Go (DYNAMICALLY detected Arch)
# We check if we are on arm64 (Apple Silicon) or amd64 (Intel)
RUN ARCH=$(dpkg --print-architecture) && \
    echo "Detected architecture: $ARCH" && \
    if [ "$ARCH" = "amd64" ]; then \
        GO_FILE="go1.24.0.linux-amd64.tar.gz"; \
    elif [ "$ARCH" = "arm64" ]; then \
        GO_FILE="go1.24.0.linux-arm64.tar.gz"; \
    else \
        echo "Unsupported architecture: $ARCH"; exit 1; \
    fi && \
    wget --no-check-certificate "https://go.dev/dl/$GO_FILE" && \
    rm -rf /usr/local/go && \
    tar -C /usr/local -xzf "$GO_FILE" && \
    rm "$GO_FILE"

RUN ARCH=$(uname -m) && \
    VER="v7.5.0" && \
    if [ "$ARCH" = "x86_64" ]; then \
        FILE="bpftool-${VER}-amd64.tar.gz"; \
    elif [ "$ARCH" = "aarch64" ]; then \
        FILE="bpftool-${VER}-arm64.tar.gz"; \
    fi && \
    URL="https://github.com/libbpf/bpftool/releases/download/${VER}/${FILE}" && \
    wget --no-check-certificate $URL -O bpftool.tar.gz && \
    tar -xzf bpftool.tar.gz -C /usr/local/sbin && \
    chmod +x /usr/local/sbin/bpftool && \
    rm bpftool.tar.gz


RUN ln -s /usr/include/$(uname -m)-linux-gnu/asm /usr/include/asm

ENV PATH=$PATH:/usr/local/go/bin:/root/go/bin
WORKDIR /code
