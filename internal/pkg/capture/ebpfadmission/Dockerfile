# Toolchain is for generation/privileged verification only, not normal builds.
FROM ubuntu:24.04@sha256:a853f94d226358a79c740cfc7bce0c289748f3fe3488d921d038ccd752c61b60
RUN apt-get update && apt-get install -y --no-install-recommends clang-18 llvm-18 libbpf-dev libpcap-dev libc6-dev linux-libc-dev ca-certificates && rm -rf /var/lib/apt/lists/*
ENV BPF2GO_CC=clang-18
