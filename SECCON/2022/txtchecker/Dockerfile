FROM ubuntu:jammy

RUN apt-get update && apt-get -y install openssh-server file procps

WORKDIR /app

RUN groupadd -r ctf && useradd -m -r -g ctf ctf
RUN echo "ctf:ctf" | chpasswd

RUN echo 'ForceCommand "/app/checker.sh"' >> /etc/ssh/sshd_config
RUN echo 'Port 2022' >> /etc/ssh/sshd_config
RUN mkdir /var/run/sshd

COPY flag.txt /
COPY checker.sh /app/

RUN chmod 444 /flag.txt
RUN chmod 555 /app/checker.sh

CMD while true; do \
        # kill long running processes for ssh
        ps -eo comm,pid,etimes | awk '/^checker.sh/ {if ($3 > 10) { print $2 }}' | xargs --no-run-if-empty kill -9; \
        sleep 5s; \
    done & \
    /sbin/sshd -D
