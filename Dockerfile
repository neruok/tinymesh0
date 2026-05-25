FROM golang:1.24-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /tinymesh0d ./cmd/tinymesh0d/

FROM alpine:3.19
RUN apk add --no-cache iproute2 iputils iptables nmap-ncat bind-tools curl
COPY --from=builder /tinymesh0d /usr/local/bin/tinymesh0d
ENTRYPOINT ["tinymesh0d"]
