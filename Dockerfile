# Build stage
FROM golang:1.22-alpine AS builder
RUN apk add --no-cache git
WORKDIR /src

# Cache deps
COPY go.mod ./
RUN go mod download

# Copy the rest of the source
COPY . .

# Ensure go.sum is (re)generated even if the workspace go.sum was empty/overwritten
RUN go mod tidy

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/doh ./main.go

# Runtime stage
FROM gcr.io/distroless/base-debian12
WORKDIR /
COPY --from=builder /out/doh /doh
USER 65534:65534
ENTRYPOINT ["/doh"]
