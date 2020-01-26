# echo 'hxp{FLAG}' > flag.txt && python3 world_generator.py 20 10 && docker build -t catch_the_flag . && docker run --cap-add=SYS_ADMIN --security-opt apparmor=unconfined -ti -p 7888:1024 catch_the_flag
# run with: ./client.py 127.0.0.1 7888

FROM debian:buster

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        python3 && \
    rm -rf /var/lib/apt/lists/

COPY ynetd /sbin/

RUN useradd --create-home --shell /bin/bash ctf
WORKDIR /home/ctf

COPY flag.txt /home/ctf/flag.txt
COPY game.py flag_char.py map /home/ctf/

RUN chmod 555 /home/ctf && \
    chown -R root:root /home/ctf && \
    chmod -R 000 /home/ctf/* && \
    chmod 500 /sbin/ynetd

RUN chown root:root /home/ctf/flag.txt && \
    chmod 004 /home/ctf/flag.txt

RUN chmod 004 map flag_char.py && \
    chmod 005 game.py

USER ctf
RUN ! find / -writable -or -user $(id -un) -or -group $(id -Gn|sed -e 's/ / -or -group  /g') 2> /dev/null | grep -Ev -m 1 '^(/dev/|/run/|/proc/|/sys/|/tmp|/var/tmp|/var/lock)'

USER root
EXPOSE 1024

CMD ynetd -lm -1 -lt 10 -t 300 -lpid 16 /home/ctf/game.py
