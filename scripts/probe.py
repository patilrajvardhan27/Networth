#!/usr/bin/env python3
"""Tiny servers and clients used by the namespace tests."""
import socket
import sys
import threading
import time


# Printed what the server saw so tests could check the source was translated.
def tcp_whoami(host, port):
    srv = socket.create_server((host, int(port)), reuse_port=True)
    while True:
        conn, peer = srv.accept()
        conn.recv(4096)
        conn.sendall(f"HTTP/1.0 200 OK\r\n\r\npeer={peer[0]}:{peer[1]}\n".encode())
        conn.close()


# Echoed every datagram back prefixed with the address it arrived from.
def udp_echo(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, int(port)))
    while True:
        data, peer = sock.recvfrom(2048)
        sock.sendto(f"{peer[0]}:{peer[1]}|".encode() + data, peer)


# Sent one datagram and printed the reply, or exited non-zero on silence.
def udp_client(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    sock.sendto(b"ping", (host, int(port)))
    print(sock.recv(2048).decode())


# Answered any A query with 192.0.2.53 so the forwarder had something to cache.
def dns_stub(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, int(port)))
    while True:
        q, peer = sock.recvfrom(512)
        sock.sendto(q[:2] + b"\x81\x80" + q[4:6] + b"\x00\x01\x00\x00\x00\x00" + q[12:] + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xc0\x00\x02\x35", peer)


# Asked for a.test and printed the first A record that came back.
def dns_client(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    sock.sendto(b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01a\x04test\x00\x00\x01\x00\x01", (host, int(port)))
    reply = sock.recv(512)
    print(".".join(str(b) for b in reply[-4:]))


# Trickled bytes slowly so a failover could land in the middle of the stream.
def stream_server(host, port):
    srv = socket.create_server((host, int(port)), reuse_port=True)

    def serve(conn):
        for _ in range(60):
            conn.sendall(b"x" * 1000)
            time.sleep(0.1)
        conn.close()

    while True:
        threading.Thread(target=serve, args=(srv.accept()[0],), daemon=True).start()


# Read the whole slow stream and checked every byte arrived.
def stream_client(host, port):
    sock = socket.create_connection((host, int(port)), timeout=30)
    total = 0
    while chunk := sock.recv(4096):
        total += len(chunk)
    print(f"received={total}")
    sys.exit(0 if total == 60000 else 1)


if __name__ == "__main__":
    globals()[sys.argv[1].replace("-", "_")](*sys.argv[2:])
