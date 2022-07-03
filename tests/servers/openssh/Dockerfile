FROM ubuntu:jammy
RUN apt-get update && apt-get install -y openssh-server
RUN mkdir -p /run/sshd

RUN useradd -m alice && echo 'alice:alicealice' | chpasswd

RUN useradd -m edward -p '*'
COPY edward_keys /home/edward/.ssh/authorized_keys
RUN chmod 0644 /home/edward/.ssh/authorized_keys

RUN useradd -m ruth -p '*'
COPY ruth_keys /home/ruth/.ssh/authorized_keys
RUN chmod 0644 /home/ruth/.ssh/authorized_keys

RUN useradd -m eda -p '*'
COPY eda_keys /home/eda/.ssh/authorized_keys
RUN chmod 0644 /home/eda/.ssh/authorized_keys

RUN useradd -m queen && passwd -d queen

RUN ssh-keygen -q -N "" -t ecdsa -b 384 -f /etc/ssh/ssh_host_ecdsa_384_key

COPY sshd_config /etc/ssh/sshd_config
ENTRYPOINT ["/usr/sbin/sshd", "-D", "-e"]
