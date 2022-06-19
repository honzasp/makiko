FROM ubuntu:jammy
RUN apt-get update && apt-get install -y dropbear
RUN useradd -m alice && echo 'alice:alicealice' | chpasswd
RUN useradd -m queen && passwd -d queen
ENTRYPOINT ["/usr/sbin/dropbear", "-F", "-E", "-B"]
