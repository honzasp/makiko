import logging
import paramiko
import socket
import threading

logger = logging.getLogger("server")

class Server(paramiko.ServerInterface):
    def __init__(self):
        self.exec_events = {}
        self.exec_commands = {}

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            self.exec_events[chanid] = threading.Event()
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        if (username, password) == ("alice", "alicealice"):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        allowed_keys = [
            ("edward", "ssh-ed25519", "ad215301215ca80b7083cd49b5f7be54"),
            ("ruth", "ssh-rsa", "ae86f75870515995b6726faacf8a1ac8"),
            ("ruth", "ssh-rsa", "3b18ce162d26a656a47bdd62095139f5"),
            ("ruth", "ssh-rsa", "0c3f4a5b7c25f26e11e93dd8126c6e81"),
            ("eda", "ecdsa-sha2-nistp256", "a05caef0cdf7630ffa1bf7ce4ac17bbd"),
            ("eda", "ecdsa-sha2-nistp384", "e7739d20c38730d1336a498b3e2e8dd9"),
        ]

        entry = (username, key.get_name(), key.get_fingerprint().hex())
        if entry in allowed_keys:
            return paramiko.AUTH_SUCCESSFUL

        print(entry, flush=True)
        return paramiko.AUTH_FAILED

    def check_auth_none(self, username):
        if username == "queen":
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_shell_request(self, channel):
        return True

    def check_channel_exec_request(self, channel, command):
        self.exec_commands[channel.chanid] = command
        self.exec_events[channel.chanid].set()
        return True

    def check_channel_pty_request(self, channel, *args):
        return True

    def get_allowed_auths(self, username):
        if username == "alice":
            return "password"
        return ""

def run_channel(server, channel):
    logger.info(f"opened channel {channel.chanid}")
    server.exec_events[channel.chanid].wait()
    command = server.exec_commands[channel.chanid]
    logger.info(f"received command {command!r} on channel {channel.chanid}")

    if command == b"whoami":
        channel.send(b"alice\n")
        channel.send_exit_status(0)
    elif command == b"cat":
        data_len = 0
        while data := channel.recv(1024):
            logger.info(f"received {len(data)} bytes")
            while data:
                sent_len = channel.send(data)
                logger.info(f"sent {len(data)} bytes")
                data = data[sent_len:]
            data_len += len(data)
        logger.info(f"received eof after processing {data_len} bytes")
        if not channel.closed:
            channel.send_exit_status(0)
    elif command == b"true":
        channel.send_exit_status(0)
    elif command == b"false":
        channel.send_exit_status(1)
    else:
        channel.send_stderr(b"unknown command!\n")
        channel.send_exit_status(127)

    channel.close()
    logger.info(f"closed channel {channel.chanid}")

def run_client(server_keys, client_sock, client_addr):
    logger.info(f"received connection from {client_addr!r}")

    trans = paramiko.Transport(client_sock)
    try:
        for key in server_keys:
            trans.add_server_key(key)

        server = Server()
        trans.start_server(server=server)

        threads = []
        while (channel := trans.accept(None)) is not None:
            thread = threading.Thread(target=run_channel, args=(server, channel,))
            thread.start()
            threads.append(thread)
        for thread in threads:
            thread.join()
    finally:
        trans.close()
        client_sock.close()

def run_server():
    from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, SECP384R1
    server_keys = [
        paramiko.rsakey.RSAKey.generate(1024),
        paramiko.ed25519key.Ed25519Key.from_private_key_file("host_key_ed25519"),
        paramiko.ecdsakey.ECDSAKey.generate(SECP256R1),
        paramiko.ecdsakey.ECDSAKey.generate(SECP384R1),
    ]

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", 22))
    sock.listen(100)
    logger.info("listening on port 22")

    while True:
        client_sock, client_addr = sock.accept()
        thread = threading.Thread(target=run_client, args=(server_keys, client_sock, client_addr))
        thread.start()

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    run_server()
