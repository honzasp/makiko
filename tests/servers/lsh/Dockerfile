FROM ubuntu:jammy
RUN apt-get update && apt-get install -y lsh-server
RUN useradd -m alice && echo 'alice:alicealice' | chpasswd
RUN useradd -m queen && passwd -d queen
ENTRYPOINT ["/usr/sbin/lshd", "-v"]
