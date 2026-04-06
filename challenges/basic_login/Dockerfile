FROM ubuntu:24.04

RUN apt-get update && \
    apt-get install -y socat && \
    rm -rf /var/lib/apt/lists/*

COPY prob /prob
COPY flag.txt /flag.txt

RUN chmod 755 /prob && chmod 444 /flag.txt

EXPOSE 8080

CMD ["socat", "-T", "60", "TCP-LISTEN:8080,reuseaddr,fork", "EXEC:/prob,stderr"]
