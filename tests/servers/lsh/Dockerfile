FROM ubuntu:jammy
RUN apt-get update && apt-get install -y lsh-server lsh-utils

RUN useradd -m alice && echo 'alice:alicealice' | chpasswd

RUN useradd -m ruth -p '*'
COPY ruth_rsa_1024.pub ruth_rsa_2048.pub ruth_rsa_4096.pub /home/ruth/
RUN su ruth /usr/bin/lsh-authorize /home/ruth/ruth_*.pub

RUN useradd -m queen && passwd -d queen

ENTRYPOINT ["/usr/sbin/lshd", "-v"]
