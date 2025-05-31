FROM rust:1.87-bookworm AS builder
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        software-properties-common \
        wget \
        gnupg2 \
        ca-certificates \
        git \
        build-essential \
        cmake \
        zlib1g-dev \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/zhlynn/zsign.git
RUN cd zsign && \
    git reset --hard 9fd2942fa9dc5fc5ba111526686b0e4a35aff3a9 && \
    mkdir build && \
    cd build && \
    cmake .. && \
    make


COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
        zlib1g \
        zip \
        unzip \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder zsign/build/zsign /zsign
COPY --from=builder target/release/iosign /iosign

ENV PORT=3000
ENV OTAPROV_PATH=/ota.mobileprovision
ENV KEY_PATH=/key.p12
ENV PUBLIC_PATH=/public
ENV WORK_PATH=/work

# Expose the application's port
EXPOSE 3000

# Define the command to run the server
STOPSIGNAL SIGKILL
CMD ["/iosign"]
