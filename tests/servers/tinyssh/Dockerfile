FROM ubuntu:jammy
RUN apt-get update && apt-get install -y tinysshd ucspi-tcp

RUN useradd -m alice
COPY alice_keys /home/alice/.ssh/authorized_keys
RUN chmod 0644 /home/alice/.ssh/authorized_keys

RUN useradd -m edward -p '*'
COPY edward_keys /home/edward/.ssh/authorized_keys
RUN chmod 0644 /home/edward/.ssh/authorized_keys

RUN tinysshd-makekey /etc/tinyssh/sshkeydir
ENTRYPOINT ["tcpserver", "-HRDl0", "0.0.0.0", "22", "/usr/sbin/tinysshd", "-v", "/etc/tinyssh/sshkeydir"]
