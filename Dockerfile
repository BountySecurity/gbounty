# Stage 1: Build
FROM golang:1.23-alpine AS builder

# Set working directory inside container
WORKDIR /app

# Install git (needed for go modules)
RUN apk add --no-cache git

# Copy go.mod and go.sum files first (for better caching)
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the entire project
COPY . .

# Build the Go app
RUN go build -o gbounty ./cmd/gbounty

# Stage 2: Run
FROM alpine:3.19

# Set working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/gbounty .

# Expose the API port (check your code/config; assuming 8080)
EXPOSE 6060

ENTRYPOINT ["./gbounty"]
