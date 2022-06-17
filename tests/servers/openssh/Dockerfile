FROM ubuntu:jammy
RUN apt-get update && apt-get install -y openssh-server
RUN mkdir -p /run/sshd
RUN useradd -m alice && echo 'alice:alicealice' | chpasswd
ENTRYPOINT ["/usr/sbin/sshd", "-D", "-e", "-ddd"]
