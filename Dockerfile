FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/webauthnproxy .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/webauthnproxy /webauthnproxy
VOLUME /data
ENV DATA_DIR=/data
EXPOSE 8080
USER nonroot
ENTRYPOINT ["/webauthnproxy"]
