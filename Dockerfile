# Build on the builder's own architecture and cross-compile: no emulation needed for multi-arch images.
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.26-alpine AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/webauthnproxy .

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.title="webauthnproxy" \
      org.opencontainers.image.description="Reverse proxy / forwardAuth protecting a site with passkeys (WebAuthn)" \
      org.opencontainers.image.source="https://github.com/coldknife2/webauthnproxy" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /out/webauthnproxy /webauthnproxy
VOLUME /data
ENV DATA_DIR=/data
EXPOSE 8080 8081 8082
USER nonroot
ENTRYPOINT ["/webauthnproxy"]
