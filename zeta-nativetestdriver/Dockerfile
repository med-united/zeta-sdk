ARG DOCKER_HUB="docker.io"

FROM  $DOCKER_HUB/ubuntu:24.04

RUN apt-get update && apt-get install -y \
    libstdc++6 ca-certificates \
    libunistring-dev libunistring5

RUN apt-get remove -y pebble

RUN rm -rf /var/lib/apt/lists/*

COPY zeta-nativetestdriver/build/bin/linuxX64/releaseExecutable/native-server.kexe /app/native-server

RUN chmod +x /app/native-server

EXPOSE 8091

ENTRYPOINT ["/app/native-server"]
