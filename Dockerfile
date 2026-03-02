FROM rust:1.93-trixie AS builder
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        wget \
        gnupg2 \
        ca-certificates \
        git \
        build-essential \
        cmake \
        libminizip-dev \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .
RUN cargo build --release

FROM debian:trixie-slim
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
        minizip \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/iosign /iosign

ENV PORT=3000
ENV OTAPROV_PATH=/ota.mobileprovision
ENV KEY_PATH=/key.p12
ENV PUBLIC_PATH=/public
ENV WORK_PATH=/work

# Expose the application's port
EXPOSE 3000

# Define the command to run the server
CMD ["/iosign"]
