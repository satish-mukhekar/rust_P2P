# Stage 1: Build
FROM rust:1.72 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

# Stage 2: Run
FROM debian:buster-slim
WORKDIR /app
COPY --from=builder /app/target/release/ethereum-bootnode /app/ethereum-bootnode

# Expose the port you use in the bootnode (e.g., 30333 or 4001 etc.)
EXPOSE 30333

# Run the binary
CMD ["./ethereum-bootnode"]
