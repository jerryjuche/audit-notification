# Build stage
FROM golang:1.21-alpine AS builder

RUN apk add --no-cache git gcc musl-dev sqlite-dev

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o audit-server cmd/server/main.go

# Runtime stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates sqlite-libs

WORKDIR /root/

COPY --from=builder /app/audit-server .
COPY --from=builder /app/client ./client

EXPOSE 8080

ENV PORT=8080
ENV MOCK_AUTH=true
ENV DB_PATH=/data/notifications.db

VOLUME ["/data"]

CMD ["./audit-server"]
