FROM ubuntu:22.04@sha256:b6b83d3c331794420340093eb706a6f152d9c1fa51b262d9bf34594887c2c7ac

ENV USER chall

USER root
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y tzdata socat xxd && \
    ln -fs /usr/share/zoneinfo/Asia/Seoul /etc/localtime && \
    dpkg-reconfigure --frontend noninteractive tzdata && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
RUN adduser -u 1337 --disabled-password --gecos "" $USER
RUN mkdir /app && chown -R $USER:$USER /app

USER $USER
WORKDIR /app
COPY ./deploy/main /app
COPY ./deploy/flag /app
COPY --chmod=555 ./deploy/entrypoint.sh /app

EXPOSE 5000

ENTRYPOINT ["/app/entrypoint.sh"]