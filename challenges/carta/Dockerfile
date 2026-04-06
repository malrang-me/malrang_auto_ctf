FROM ubuntu:22.04@sha256:aabed3296a3d45cede1dc866a24476c4d7e093aa806263c27ddaadbdce3c1054

ENV user chall
ENV chall_port 31337

RUN apt-get update
RUN apt-get -y install socat

RUN adduser -u 1337 $user

ADD ./deploy/flag /home/$user/flag
ADD ./deploy/main /home/$user/main

RUN chown root:$user /home/$user/flag
RUN chown root:$user /home/$user/main

RUN chmod 755 /home/$user/$main
RUN chmod 440 /home/$user/flag

WORKDIR /home/$user
USER $user
EXPOSE $chall_port
CMD socat -T 25 TCP-LISTEN:$chall_port,reuseaddr,fork EXEC:/home/$user/main
