# Build on the builder's own architecture and cross-compile: no emulation needed for multi-arch images.
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.27-alpine AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/webauthnproxy . \
 && mkdir /data-skel

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.title="webauthnproxy" \
      org.opencontainers.image.description="Reverse proxy / forwardAuth protecting a site with passkeys (WebAuthn)" \
      org.opencontainers.image.source="https://github.com/coldknife2/webauthnproxy" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /out/webauthnproxy /webauthnproxy
# /data is created owned by the unprivileged user, so a named volume is writable without a chown
COPY --from=build --chown=65532:65532 /data-skel /data
VOLUME /data
ENV DATA_DIR=/data
EXPOSE 8080 8081 8082
USER nonroot
# The image has no shell or curl: the binary checks itself (GET /_wap/healthz on $LISTEN).
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 CMD ["/webauthnproxy", "healthcheck"]
ENTRYPOINT ["/webauthnproxy"]
