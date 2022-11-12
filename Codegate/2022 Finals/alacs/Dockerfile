FROM ubuntu:22.04@sha256:26c68657ccce2cb0a31b330cb0be2b5e108d467f641c62e13ab40cbec258c68d

RUN apt update
RUN apt install -y xinetd 

RUN useradd ctf

RUN mkdir /home/ctf
ADD alacs /home/ctf/alacs
ADD run.sh /home/ctf/run.sh
ADD flag /home/ctf/flag

RUN chmod 460 /home/ctf/*
RUN chown ctf:root /home/ctf/*
RUN chmod +x /home/ctf/alacs
RUN chmod +x /home/ctf/run.sh

ADD xinetd /etc/xinetd.d/
EXPOSE 3000

CMD ["/usr/sbin/xinetd","-dontfork"]