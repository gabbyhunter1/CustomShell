FROM debian:bullseye as builder

RUN apt-get update && apt-get install -y \
    build-essential \
    libfuse-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY main.c .

RUN gcc main.c -o customshell -D_FILE_OFFSET_BITS=64 -lfuse


FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y \
    libfuse2 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/customshell /usr/local/bin/customshell

RUN chmod +x /usr/local/bin/customshell

CMD ["/usr/local/bin/customshell"]