FROM ubuntu:jammy
RUN apt-get update && apt-get install -y dropbear

RUN useradd -m alice && echo 'alice:alicealice' | chpasswd

RUN useradd -m edward -p '*'
COPY edward_keys /home/edward/.ssh/authorized_keys
RUN chmod 0644 /home/edward/.ssh/authorized_keys

RUN useradd -m ruth -p '*'
COPY ruth_keys /home/ruth/.ssh/authorized_keys
RUN chmod 0644 /home/ruth/.ssh/authorized_keys

RUN useradd -m queen && passwd -d queen

ENTRYPOINT ["/usr/sbin/dropbear", "-F", "-E", "-B", "-R"]
