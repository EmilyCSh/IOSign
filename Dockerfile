FROM node:16-buster
ENV DEBIAN_FRONTEND=noninteractive

RUN dpkg --add-architecture i386 && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        software-properties-common \
        wget \
        gnupg2 \
        ca-certificates \
        libasound2 \
        libgtk-3-0 \
        libnotify4 \
        libnss3 \
        libx11-xcb1 \
        libxcomposite1 \
        libxdamage1 \
        libxrandr2 \
        libxrender1 \
        libxtst6 \
        libgbm1 \
        libfreetype6 \
        libfontconfig1 \
        fonts-liberation \
        libappindicator3-1 \
        libatk-bridge2.0-0 \
        libgtk-3-0 \
        wine \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY package*.json ./

RUN npm install --production
COPY server.js .
COPY index.html .

RUN wget https://github.com/isigner/iresign/releases/download/1.0.5/iresign_ui.windows.x86_64-1.0.5-3.zip -O iresign.zip
RUN unzip iresign.zip -d /

ENV PORT=3000
ENV IRESIGN_PATH=/iresign/iresign.exe
ENV OTAPROV_PATH=/ota.mobileprovision
ENV KEY_PATH=/key.p12
ENV PUBLIC_PATH=/public
ENV WORK_PATH=/work

# Expose the application's port
EXPOSE 3000

# Define the command to run the server
CMD ["node", "server.js"]
