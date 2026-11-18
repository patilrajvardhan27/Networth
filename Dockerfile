FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p natctl -p dnsfwd -p tlsprobe

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/natctl /src/target/release/dnsfwd /src/target/release/tlsprobe /usr/local/bin/
EXPOSE 8080
# Run with: docker run --cap-add=NET_ADMIN --device /dev/net/tun -p 8080:8080 <image> run --admin 0.0.0.0:8080
ENTRYPOINT ["natctl"]
