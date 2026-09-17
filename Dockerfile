FROM golang:1.22-alpine AS builder
WORKDIR /build
COPY go.mod ./
COPY main.go ./
RUN go build -ldflags="-s -w" -o bermuda-panel main.go

FROM alpine:3.19
WORKDIR /app
RUN apk add --no-cache curl ca-certificates tzdata && \
    mkdir -p /usr/local/bin /app/data && \
    curl -L -s https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip -o xray.zip && \
    unzip xray.zip xray -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/xray && \
    rm xray.zip

COPY config.json /app/config.json
COPY --from=builder /build/bermuda-panel /app/bermuda-panel

EXPOSE 2053 443
CMD ["/app/bermuda-panel"]
