# Build stage
FROM golang:1.21-bullseye AS builder

RUN apt-get update && apt-get install -y \
    gcc \
    sqlite3 \
    libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=1 go build -o audit-server cmd/server/main.go

# Runtime stage
FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /root/

COPY --from=builder /app/audit-server .
COPY --from=builder /app/client ./client

EXPOSE 8080

ENV PORT=8080
ENV DB_PATH=/data/notifications.db

VOLUME ["/data"]

CMD ["./audit-server"]