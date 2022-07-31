FROM ubuntu:jammy
RUN apt-get update && apt-get install -y dropbear

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

RUN dropbearkey -t ecdsa -s 384 -f /etc/dropbear/dropbear_ecdsa_384_host_key

ENTRYPOINT ["/usr/sbin/dropbear", "-F", "-E", "-B", "-R", "-a", \
    "-r", "/etc/dropbear/dropbear_rsa_host_key", \
    "-r", "/etc/dropbear/dropbear_ecdsa_host_key", \
    "-r", "/etc/dropbear/dropbear_ecdsa_384_host_key", \
    "-r", "/etc/dropbear/dropbear_ed25519_host_key" \
]
