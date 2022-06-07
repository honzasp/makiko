import asyncio
import os
import struct

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CTR
from cryptography.hazmat.primitives.hashes import Hash, SHA256
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

LOCAL_IDENT = b"SSH-2.0-makiko"

async def main():
    reader, writer = await asyncio.open_connection("localhost", 2222)
    writer.write(LOCAL_IDENT + b"\r\n")

    while True:
        line = await reader.readline()
        if line.startswith(b"SSH-"):
            peer_ident = line[:-2]
            print("peer", peer_ident)
            break

    encryptor = None
    decryptor = None
    cipher_block_len = 8

    mac_cts = None
    mac_cts_len = 0
    mac_stc = None
    mac_stc_len = 0

    packet_seq_cts = 0
    packet_seq_stc = 0

    async def send_packet(payload):
        nonlocal packet_seq_cts

        padded_len = 5 + len(payload)
        padding_len = (-padded_len) % cipher_block_len
        if padding_len < 4:
            padding_len += cipher_block_len

        plaintext = b"".join([
            encode_uint32(1 + len(payload) + padding_len),
            encode_byte(padding_len),
            payload,
            os.urandom(padding_len),
        ])

        if encryptor is not None:
            ciphertext = encryptor.update(plaintext)
        else:
            ciphertext = plaintext

        if mac_cts is not None:
            mac = mac_cts.copy()
            mac.update(encode_uint32(packet_seq_cts) + plaintext)
            mac_sign = mac.finalize()
        else:
            mac_sign = b""

        writer.write(ciphertext + mac_sign)
        await writer.drain()

        packet_seq_cts += 1

    async def recv_packet():
        nonlocal packet_seq_stc

        first_ciphertext = await reader.read(cipher_block_len)
        if len(first_ciphertext) < cipher_block_len:
            raise RuntimeError(f"unexpected EOF, received {first_ciphertext!r} ({len(first_block)})")

        if decryptor is not None:
            first_plaintext = decryptor.update(first_ciphertext)
        else:
            first_plaintext = first_ciphertext
        packet_len, padding_len = struct.unpack("!IB", first_plaintext[:5])
        payload_len = packet_len - padding_len - 1

        if payload_len > 100_000:
            raise RuntimeError(f"payload length too large: {payload_len}")

        rest_ciphertext = await reader.read(4 + packet_len - len(first_plaintext))
        if decryptor is not None:
            rest_plaintext = decryptor.update(rest_ciphertext)
        else:
            rest_plaintext = rest_ciphertext

        plaintext = first_plaintext + rest_plaintext
        payload = plaintext[5:][:payload_len]

        mac_sign = await reader.read(mac_stc_len)
        if mac_stc is not None:
            mac = mac_stc.copy()
            mac.update(encode_uint32(packet_seq_stc) + plaintext)
            mac.verify(mac_sign)

        packet_seq_stc += 1
        return PacketDecode(payload)

    local_kex_algos = ["curve25519-sha256"]
    local_server_host_key_algos = ["ssh-ed25519"]
    local_cipher_algos = ["aes128-ctr"]
    local_mac_algos = ["hmac-sha2-256"]
    local_compress_algos = ["none"]

    local_kexinit = b"".join([
        bytes([20]), # KEXINIT
        os.urandom(16), # cookie
        encode_list(local_kex_algos), # kex_algorithms
        encode_list(local_server_host_key_algos), # server_host_key_algorithms
        encode_list(local_cipher_algos), # encryption_algorithms_client_to_server
        encode_list(local_cipher_algos), # encryption_algorithms_server_to_client
        encode_list(local_mac_algos), # mac_algorithms_client_to_server
        encode_list(local_mac_algos), # mac_algorithms_server_to_client
        encode_list(local_compress_algos), # compression_algorithms_client_to_server
        encode_list(local_compress_algos), # compression_algorithms_server_to_client
        encode_list([""]), # languages_client_to_server
        encode_list([""]), # languages_server_to_client
        bytes([0]), # first_kex_packet_follows
        bytes(4), # reserved
    ])

    async def send_kexinit():
        await send_packet(local_kexinit)

    await send_kexinit()
    while True:
        packet = await recv_packet()
        msg_id = packet.decode_byte()
        if msg_id != 20:
            raise RuntimeError(f"expected KEXINIT, received {msg_id}")

        peer_kexinit = packet.full_payload
        packet.decode_bytes(16)
        peer_kex_algos = packet.decode_name_list()
        peer_server_host_key_algos = packet.decode_name_list()
        peer_cipher_algos_cts = packet.decode_name_list()
        peer_cipher_algos_stc = packet.decode_name_list()
        peer_mac_algos_cts = packet.decode_name_list()
        peer_mac_algos_stc = packet.decode_name_list()
        peer_compress_algos_cts = packet.decode_name_list()
        peer_compress_algos_stc = packet.decode_name_list()
        packet.decode_name_list()
        packet.decode_name_list()
        first_kex_packet_follows = packet.decode_byte()

        def negotiate_algo(client_algos, server_algos):
            for algo in client_algos:
                if algo in server_algos:
                    return algo
            raise RuntimeError(f"client algos {client_algos!r} don't intersect server algos {server_algos!r}")

        if peer_kex_algos[0] == local_kex_algos[0]:
            kex_algo = peer_kex_algos[0]
        else:
            kex_algo = negotiate_algo(local_kex_algos, peer_kex_algos)
        server_host_key_algo = negotiate_algo(local_server_host_key_algos, peer_server_host_key_algos)
        cipher_algo_cts = negotiate_algo(local_cipher_algos, peer_cipher_algos_cts)
        cipher_algo_stc = negotiate_algo(local_cipher_algos, peer_cipher_algos_stc)
        mac_algo_cts = negotiate_algo(local_mac_algos, peer_mac_algos_cts)
        mac_algo_stc = negotiate_algo(local_mac_algos, peer_mac_algos_stc)
        compress_algo_cts = negotiate_algo(local_compress_algos, peer_compress_algos_cts)
        compress_algo_stc = negotiate_algo(local_compress_algos, peer_compress_algos_stc)

        print("kex", kex_algo, "server host key", server_host_key_algo)
        print("cipher", cipher_algo_cts, cipher_algo_stc)
        print("mac", mac_algo_cts, mac_algo_stc)
        print("compress", compress_algo_cts, compress_algo_stc)

        if first_kex_packet_follows:
            raise NotImplementedError()
        break

    if kex_algo == "curve25519-sha256":
        local_ephemeral_privkey = X25519PrivateKey.generate()
        local_ephemeral_pubkey = local_ephemeral_privkey.public_key()
        local_ephemeral_pubkey_bytes = local_ephemeral_pubkey.public_bytes(Encoding.Raw, PublicFormat.Raw)

        await send_packet(b"".join([
            bytes([30]),
            encode_str(local_ephemeral_pubkey_bytes),
        ]))

        packet = await recv_packet()
        msg_id = packet.decode_byte()
        if msg_id != 31:
            raise RuntimeError(f"expected KEX_ECDH_REPLY, received {msg_id}")

        server_host_pubkey_bytes = packet.decode_str()
        server_ephemeral_pubkey_bytes = packet.decode_str()
        server_exchange_hash_sig_bytes = packet.decode_str()

        server_ephemeral_pubkey = X25519PublicKey.from_public_bytes(server_ephemeral_pubkey_bytes)
        kex_key = local_ephemeral_privkey.exchange(server_ephemeral_pubkey)
        kex_key_int = int.from_bytes(kex_key, "big")
        #printhex("kex key", kex_key)

        kex_hash_algo = "sha256"
    else:
        raise NotImplementedError(f"bad kex algo {kex_algo!r}")

    if server_host_key_algo == "ssh-ed25519":
        host_pubkey_packet = PacketDecode(server_host_pubkey_bytes)
        if host_pubkey_packet.decode_str() != b"ssh-ed25519":
            raise RuntimeError("bad format of host pubkey")
        host_pubkey = host_pubkey_packet.decode_str()
        host_pubkey = Ed25519PublicKey.from_public_bytes(host_pubkey)
        print("host pubkey", host_pubkey.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH))

        server_exchange_hash_sig_packet = PacketDecode(server_exchange_hash_sig_bytes)
        if server_exchange_hash_sig_packet.decode_str() != b"ssh-ed25519":
            raise RuntimeError("bad format of host signature")
        server_exchange_hash_sig = server_exchange_hash_sig_packet.decode_str()

        exchange_hash_data = b"".join([
            encode_str(LOCAL_IDENT),
            encode_str(peer_ident),
            encode_str(local_kexinit),
            encode_str(peer_kexinit),
            encode_str(server_host_pubkey_bytes),
            encode_str(local_ephemeral_pubkey_bytes),
            encode_str(server_ephemeral_pubkey_bytes),
            encode_mpint(kex_key_int),
        ])
        #printhex("exchange hash data", exchange_hash_data)
    else:
        raise NotImplementedError(f"bad server host key algo {server_host_key_algo!r}")

    if kex_hash_algo == "sha256":
        hash_algo = SHA256()
    else:
        raise NotImplementedError(f"bad kex hash algo {kex_hash_algo!r}")

    def compute_hash(data):
        digest = Hash(hash_algo)
        digest.update(data)
        return digest.finalize()

    exchange_hash = compute_hash(exchange_hash_data)
    #printhex("exchange hash", exchange_hash)

    host_pubkey.verify(server_exchange_hash_sig, exchange_hash)
    session_id = exchange_hash

    def derive_key(x, size):
        key = compute_hash(encode_mpint(kex_key_int) + exchange_hash + x + session_id)
        while len(key) < size:
            key += compute_hash(encode_mpint(key_key_int) + exchange_hash + key)
        return key[:size]

    await send_packet(bytes([21]))

    packet = await recv_packet()
    msg_id = packet.decode_byte()
    if msg_id != 21:
        raise RuntimeError(f"expected NEWKEYS, received {msg_id}")

    if cipher_algo_cts == "aes128-ctr":
        key_iv_cts = derive_key(b"A", 16)
        key_iv_stc = derive_key(b"B", 16)
        key_cipher_cts = derive_key(b"C", 16)
        key_cipher_stc = derive_key(b"D", 16)
        #printhex("iv_cts", key_iv_cts)
        #printhex("cipher_cts", key_cipher_cts)

        cipher_cts = Cipher(AES(key_cipher_cts), CTR(key_iv_cts))
        encryptor = cipher_cts.encryptor()

        cipher_stc = Cipher(AES(key_cipher_stc), CTR(key_iv_stc))
        decryptor = cipher_stc.decryptor()

    if mac_algo_cts == "hmac-sha2-256":
        key_mac_cts = derive_key(b"E", 32)
        mac_cts = HMAC(key_mac_cts, SHA256())
        mac_cts_len = 32
    else:
        raise NotImplementedError(f"bad mac algo {mac_algo_cts|r}")

    if mac_algo_stc == "hmac-sha2-256":
        key_mac_stc = derive_key(b"F", 32)
        mac_stc = HMAC(key_mac_stc, SHA256())
        mac_stc_len = 32
    else:
        raise NotImplementedError(f"bad mac algo {mac_algo_stc!r}")

    await send_packet(b"".join([
        bytes([5]),
        encode_str(b"ssh-userauth"),
    ]))

    packet = await recv_packet()
    msg_id = packet.decode_byte()
    if msg_id != 6:
        raise RuntimeError(f"expected SERVICE_ACCEPT, got {msg_id}")
    service_name = packet.decode_str()
    if service_name != b"ssh-userauth":
        raise RuntimeError(f"unexpected accepted service {service_name}")

    await send_packet(b"".join([
        bytes([1]),
        encode_uint32(0),
        encode_str(b"goodbye"),
        encode_str(b""),
    ]))

class PacketDecode:
    def __init__(self, payload):
        self.full_payload = payload
        self.payload = payload

    def decode_byte(self):
        return self.decode_struct("!B")[0]

    def decode_uint32(self):
        return self.decode_struct("!I")[0]

    def decode_str(self):
        size = self.decode_uint32()
        data = self.decode_bytes(size)
        return data

    def decode_name_list(self):
        data = self.decode_str()
        return data.decode().split(",")

    def decode_struct(self, format):
        size = struct.calcsize(format)
        data = self.decode_bytes(size)
        return struct.unpack(format, data)

    def decode_bytes(self, size):
        data = self.payload[:size]
        self.payload = self.payload[size:]
        return data

def encode_list(names):
    return encode_str(",".join(names).encode())

def encode_str(value):
    return struct.pack("!I", len(value)) + value

def encode_byte(value):
    return struct.pack("!B", value)

def encode_uint32(value):
    return struct.pack("!I", value)

def encode_mpint(value):
    byte_len = (value.bit_length() + 7) // 8
    value_bytes = value.to_bytes(byte_len, "big")
    if value_bytes[0] >= 0x80:
        value_bytes = b"\0" + value_bytes
    return encode_str(value_bytes)

def printhex(what, data):
    print(what)
    while data:
        line, data = data[:16], data[16:]
        line_str = "".join([chr(x) if 32 <= x <= 126 else "." for x in line])
        print(line.hex(" ", 2).ljust(4, "0"), " ", line_str)

asyncio.run(main())
