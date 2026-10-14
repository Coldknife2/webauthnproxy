FROM docker.io/library/golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /verify .
FROM scratch
COPY --from=build /verify /verify
EXPOSE 8080
ENTRYPOINT ["/verify"]
