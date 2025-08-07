# Use the official Rust image
FROM rust:1.77 as builder

WORKDIR /app
COPY . .
RUN cargo build --release

# Use a minimal base image for running
FROM debian:buster-slim
WORKDIR /app
COPY --from=builder /app/target/release/ethereum-bootnode .

CMD ["./ethereum-bootnode"]
