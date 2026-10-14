FROM docker.io/library/golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/webauthnproxy .

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.title="webauthnproxy" \
      org.opencontainers.image.description="Reverse proxy / forwardAuth protégeant un site par passkey (WebAuthn)" \
      org.opencontainers.image.source="https://github.com/coldknife2/webauthnproxy" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /out/webauthnproxy /webauthnproxy
VOLUME /data
ENV DATA_DIR=/data
EXPOSE 8080 8081 8082
USER nonroot
ENTRYPOINT ["/webauthnproxy"]
