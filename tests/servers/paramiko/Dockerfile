FROM python:3.10-slim
RUN pip install paramiko[ed25519]
COPY server.py host_key_ed25519 /server/
WORKDIR /server
ENTRYPOINT ["/usr/local/bin/python", "server.py"]
