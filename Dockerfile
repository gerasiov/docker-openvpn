FROM alpine:latest

LABEL maintainer="Alexander Gerasiov <a@gerasiov.net>"

RUN apk add --no-cache openvpn easy-rsa dumb-init python3 iptables
RUN ln -s /usr/share/easy-rsa/easyrsa /usr/local/bin

COPY ./control.py /control
RUN chmod +x /control

ENV OVPN_WORKDIR /data
WORKDIR ${OVPN_WORKDIR}

ENTRYPOINT ["/usr/bin/dumb-init", "--", "/control"]

CMD ["start"]