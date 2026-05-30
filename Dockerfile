FROM node:18-alpine

RUN apk add --update --no-cache supervisor

WORKDIR /app
COPY challenge .
COPY flag.txt /flag.txt

RUN npm install

COPY config/supervisord.conf /etc/supervisord.conf

EXPOSE 1337

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]