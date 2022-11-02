FROM alpine:3.16

RUN apk add openssl

RUN mkdir -p /certfixer

ADD ./make_certs.sh /certfixer/make_certs.sh
ADD ./ssl.cnf /certfixer/ssl.cnf

WORKDIR /certfixer

CMD ["/bin/sh", "make_certs.sh"]
