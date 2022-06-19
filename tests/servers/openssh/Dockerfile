FROM ubuntu:jammy
RUN apt-get update && apt-get install -y openssh-server
COPY sshd_config /etc/ssh/sshd_config
RUN mkdir -p /run/sshd
RUN useradd -m alice && echo 'alice:alicealice' | chpasswd
RUN useradd -m queen && passwd -d queen
ENTRYPOINT ["/usr/sbin/sshd", "-D", "-e"]
