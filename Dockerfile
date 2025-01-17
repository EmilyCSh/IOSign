FROM node:16-bookworm
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

WORKDIR /app

RUN git clone https://github.com/zhlynn/zsign.git
RUN cd zsign && \
    git reset --hard 9fd2942fa9dc5fc5ba111526686b0e4a35aff3a9 && \
    mkdir build && \
    cd build && \
    cmake .. && \
    make && \
    cp zsign /zsign

COPY package*.json ./

RUN npm install --production
COPY server.js .
COPY index.html .

ENV PORT=3000
ENV OTAPROV_PATH=/ota.mobileprovision
ENV KEY_PATH=/key.p12
ENV PUBLIC_PATH=/public
ENV WORK_PATH=/work

# Expose the application's port
EXPOSE 3000

# Define the command to run the server
STOPSIGNAL SIGKILL
CMD ["node", "server.js"]
