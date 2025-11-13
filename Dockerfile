# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o miit-secure-proxy .

# Final stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/miit-secure-proxy .

# Copy config and templates
COPY config.yaml ./
COPY templates ./templates/
COPY certs ./certs/

EXPOSE 8443 9443

CMD ["./miit-secure-proxy"]

