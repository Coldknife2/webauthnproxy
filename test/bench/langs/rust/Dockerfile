FROM docker.io/library/rust:1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml ./
COPY src src
RUN cargo build --release
FROM scratch
COPY --from=build /src/target/release/verify /verify
EXPOSE 8080
ENTRYPOINT ["/verify"]
