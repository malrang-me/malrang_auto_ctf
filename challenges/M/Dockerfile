FROM ubuntu@sha256:4fdf0125919d24aec972544669dcd7d6a26a8ad7e6561c73d5549bd6db258ac2

WORKDIR /app

COPY ./main /app/main
COPY ./sample.png /app/flag.png

RUN chmod 0755 /app/main

ENTRYPOINT ["/app/main"]

CMD ["/app/flag.png"]