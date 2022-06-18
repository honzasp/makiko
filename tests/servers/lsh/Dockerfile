FROM ubuntu:jammy
RUN apt-get update && apt-get install -y lsh-server
RUN useradd -m alice && echo 'alice:alicealice' | chpasswd
ENTRYPOINT ["/usr/sbin/lshd", "-v"]
