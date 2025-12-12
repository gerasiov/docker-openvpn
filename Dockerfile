FROM golang:1.24-alpine AS builder

WORKDIR /build
COPY control.go go.mod ./
RUN go build -o control control.go

FROM alpine:latest

LABEL maintainer="Alexander Gerasiov <a@gerasiov.net>"

RUN apk add --no-cache openvpn easy-rsa dumb-init iptables
RUN ln -s /usr/share/easy-rsa/easyrsa /usr/local/bin

COPY --from=builder /build/control /control
RUN chmod +x /control

ENV OVPN_WORKDIR /data
WORKDIR ${OVPN_WORKDIR}

ENTRYPOINT ["/usr/bin/dumb-init", "--", "/control"]

CMD ["start"]