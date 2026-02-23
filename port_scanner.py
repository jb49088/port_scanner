# ================================================================================
# =                                 PORT_SCANNER                                 =
# ================================================================================

"""
TCP Packet Structure
---------------------------------------
Header: 20+ bytes
  Source Port:              2 bytes
  Destination Port:         2 bytes
  Sequence Number:          4 bytes
  Acknowledgement Number:   4 bytes
  Data Offset:              4 bits
  Flags:                    12 bits
  Window Size:              2 bytes
  Checksum:                 2 bytes
  Urgent Pointer:           2 bytes
  Options:                  0–40 bytes

Data: 0+ bytes

Total: 20+ bytes
"""

import argparse
import asyncio
import random
import socket
import struct
import subprocess
import time


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("host", help="Host to scan.")
    args = parser.parse_args()

    return args


def is_host_reachable(address: str):
    result = subprocess.run(
        ["ping", "-c", "1", "-w", "1", address], capture_output=True
    )

    if result.returncode != 0:
        return False

    return True


def get_source_ip(destination_ip: str) -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((destination_ip, 0))
    source_ip = sock.getsockname()[0]
    sock.close()

    return source_ip


async def build_header(
    source_ip: str,
    destination_ip: str,
    destination_port: int,
) -> tuple[int, bytes]:
    source_port = random.randint(49152, 65536)
    sequence_number = random.randint(0, 4294967295)  # Initial Sequence Number (ISN)
    acknowledgement_number = 0  # Nothing to acknowledge
    header_length = 5  # Total header length in 32 bit words

    # Flags
    res = 0  # Reserved bits
    ae = 0  # Accurate ECN / Nonce sum
    cwr = 0  # Congestion Window Reduced
    ece = 0  # ECN-Echo
    urg = 0  # Urgent
    ack = 0  # Acknowledgement
    push = 0  # Push
    reset = 0  # Reset
    syn = 1  # Syn
    fin = 0  # Fin

    window_size_value = 512  # Receive buffer size
    checksum = 0  # Placeholder for calculating checksum
    urgent_pointer = 0  # Not used in SYN packets

    # Combine bit fields into bytes
    hdr_res_ae = (header_length << 4) | (res << 1) | ae
    flags = (
        (cwr << 7)
        | (ece << 6)
        | (urg << 5)
        | (ack << 4)
        | (push << 3)
        | (reset << 2)
        | (syn << 1)
        | fin
    )

    header = struct.pack(
        "!HHLLBBHHH",
        source_port,
        destination_port,
        sequence_number,
        acknowledgement_number,
        hdr_res_ae,
        flags,
        window_size_value,
        checksum,
        urgent_pointer,
    )

    # Build pseudo-header
    pseudo_header = struct.pack(
        "!4s4sBBH",
        socket.inet_aton(source_ip),  # Source IP (4 bytes)
        socket.inet_aton(destination_ip),  # Dest IP (4 bytes)
        0,  # Reserved (1 byte, always 0)
        socket.IPPROTO_TCP,  # Protocol (1 byte, 6 for TCP)
        len(header),  # TCP length (2 bytes)
    )

    checksum = calculate_checksum(header + pseudo_header)

    header = struct.pack(
        "!HHLLBBHHH",
        source_port,
        destination_port,
        sequence_number,
        acknowledgement_number,
        hdr_res_ae,
        flags,
        window_size_value,
        checksum,
        urgent_pointer,
    )

    return source_port, header


def calculate_checksum(header: bytes) -> int:
    """Calculate the 16-bit one's complement checksum of a packet."""
    total = 0
    # Sum 16 bit words
    for i in range(0, len(header), 2):
        word = (header[i] << 8) + (header[i + 1] if i + 1 < len(header) else 0)
        total += word

    # Add carry to right side
    while total >> 16:
        total = (total >> 16) + (total & 0xFFFF)

    # Perform one's complement
    total = ~total & 0xFFFF

    return total


async def sender(
    sock: socket.socket,
    source_ip: str,
    destination_ip: str,
    port_range: tuple[int, int],
    pending_ports: dict[tuple[int, int], float],
    done_sending: asyncio.Event,
) -> None:
    for destination_port in range(*port_range):
        source_port, header = await build_header(
            source_ip, destination_ip, destination_port
        )
        pending_ports[(source_port, destination_port)] = time.monotonic()
        sock.sendto(header, (destination_ip, 0))
        await asyncio.sleep(0.001)

    done_sending.set()


async def receiver(
    sock: socket.socket,
    source_ip: str,
    destination_ip: str,
    pending_ports: dict[tuple[int, int], float],
    open_ports: list[int],
    done_sending: asyncio.Event,
    timeout=2,
) -> None:
    loop = asyncio.get_running_loop()

    while pending_ports or not done_sending.is_set():
        packet = await loop.sock_recv(sock, 65535)

        src_ip, dst_ip, src_port, dst_port = parse_packet(packet)

        if (
            src_ip == destination_ip
            and dst_ip == source_ip
            and (dst_port, src_port) in pending_ports
        ):
            flags = packet[33]
            if flags & 0x12 == 0x12:  # SYN, ACK
                open_ports.append(src_port)
            del pending_ports[(dst_port, src_port)]

        now = time.monotonic()
        for k, v in list(pending_ports.items()):
            if now - v > timeout:
                del pending_ports[k]


def parse_packet(packet: bytes) -> tuple[str, str, int, int]:
    ip_header = struct.unpack("!BBHHHBBH4s4s", packet[0:20])
    src_ip, dst_ip = map(socket.inet_ntoa, ip_header[8:10])

    tcp_header = struct.unpack("!HHLLBBHHH", packet[20:40])
    src_port, dst_port = tcp_header[0:2]

    return src_ip, dst_ip, src_port, dst_port


async def port_scanner():
    args = parse_args()
    hostname = args.host
    port_range = (1, 1024)

    try:
        destination_ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        print("\nAddress resolution failed.\n")
        return

    if not is_host_reachable(destination_ip):
        print("\nHost unreachable.\n")
        return

    source_ip = get_source_ip(destination_ip)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except PermissionError:
        print("\nThis program must be run as root.\n")
        return

    sock.setblocking(False)

    open_ports = []
    pending_ports = {}
    done_sending = asyncio.Event()

    await asyncio.gather(
        sender(
            sock, source_ip, destination_ip, port_range, pending_ports, done_sending
        ),
        receiver(
            sock, source_ip, destination_ip, pending_ports, open_ports, done_sending
        ),
    )

    for port in open_ports:
        print(f"{destination_ip}:{port} is open")


if __name__ == "__main__":
    asyncio.run(port_scanner())
