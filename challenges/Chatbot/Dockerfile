FROM ubuntu:20.04@sha256:fd92c36d3cb9b1d027c4d2a72c6bf0125da82425fc2ca37c414d4f010180dc19

ARG DEBIAN_FRONTEND=noninteractive

ENV user chatbot
ENV chall_port 31337

RUN apt-get update
RUN apt-get install -y \
    curl \
    tzdata

RUN ln -sf /usr/share/zoneinfo/Asia/Seoul /etc/localtime
RUN dpkg-reconfigure tzdata

RUN adduser $user

ADD ./deploy/flag /home/$user/flag
ADD ./deploy/chatbot_server /home/$user/chatbot_server
ADD ./deploy/run.sh /home/$user/run.sh
ADD ./deploy/loop.sh /home/$user/loop.sh

RUN chown -R root:root /home/$user
RUN chown root:$user /home/$user/flag
RUN chown root:$user /home/$user/chatbot_server
RUN chown root:$user /home/$user/run.sh
RUN chown root:$user /home/$user/loop.sh

RUN chmod 755 /home/$user
RUN chmod 755 /home/$user/chatbot_server
RUN chmod 440 /home/$user/flag
RUN chmod 755 /home/$user/run.sh
RUN chmod 755 /home/$user/loop.sh

WORKDIR /home/$user
USER $user
EXPOSE $chall_port
CMD ["/home/chatbot/loop.sh"]
