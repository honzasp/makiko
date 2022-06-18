FROM ubuntu:jammy
RUN apt-get update && apt-get install -y dropbear
RUN useradd -m alice && echo 'alice:alicealice' | chpasswd
ENTRYPOINT ["/usr/sbin/dropbear", "-F", "-E", "-B"]
