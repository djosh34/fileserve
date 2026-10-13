FROM scratch
ARG TARGETARCH
LABEL org.opencontainers.image.source="https://github.com/djosh34/fileserve"
COPY dist/fileserve-linux-${TARGETARCH} /fileserve
ENTRYPOINT ["/fileserve"]
