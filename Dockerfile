# STAGE 1: Build the GoLogScythe binary
FROM golang:1.25-alpine3.23 AS builder

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go.mod (zero-dependency project, so go.sum might be absent)
COPY go.mod ./
RUN go mod download

# Copy the source code
# Based on the repo structure: cmd/goLogScythe contains the main.go
COPY . .

# Build the Go app as a static binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o goLogScythe ./cmd/goLogScythe/


# STAGE 2: Runtime environment with Nginx and nftables
FROM alpine:3.23

# 1. Install necessary binaries: nginx and nftables
# We need the 'nft' binary because the Go code executes it directly
RUN apk add --no-cache nginx nftables ca-certificates

# We define these as defaults.
# They are fully overridable in GitHub Actions or K8s.
ENV LOG_PATH="/var/log/nginx/access.log" \
    BAN_THRESHOLD="10" \
    BAN_WINDOW="15m" \
    PREVIEW_MODE="false" \
    NFT_SET_NAME="parasites"

# 2. Setup directory structure for GoLogScythe as defined in deployment
RUN mkdir -p /var/lib/go-log-scythe /etc/go-log-scythe /var/log/nginx && \
    touch /var/log/nginx/access.log


# 3. Copy the built binary from the builder stage
COPY --from=builder /app/goLogScythe /usr/local/bin/goLogScythe

# 4. Copy configuration files
# Note: We copy rules.conf as a base, but users can mount
# their own over it using a Docker volume (-v).
COPY deploy/go-log-scythe/rules.conf /var/lib/go-log-scythe/rules.conf
COPY deploy/nftables.conf /etc/nftables.conf


# 5. Prepare a dummy log file and whitelist
RUN touch /var/log/nginx/access.log && \
    touch /var/lib/go-log-scythe/whitelist.txt && \
    touch /var/lib/go-log-scythe/banned_ips.txt

# 6. Create an entrypoint script to manage both Nginx and GoLogScythe
# This is how we "manage the final stage" to run both processes
# exec ensures the Go app becomes PID 1, receiving Unix signals correctly
RUN echo '#!/bin/sh \n\
nft -f /etc/nftables.conf \n\
nginx \n\
exec /usr/local/bin/goLogScythe' > /entrypoint.sh && chmod +x /entrypoint.sh

# Expose Nginx ports
EXPOSE 80 443

# IMPORTANT: nftables requires CAP_NET_ADMIN.
# You must run this container with --cap-add=NET_ADMIN or --privileged.
ENTRYPOINT ["/entrypoint.sh"]