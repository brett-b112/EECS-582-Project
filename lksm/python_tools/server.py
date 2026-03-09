#!/usr/bin/env python3
"""
photon_server.py — Photon Ring Remote Log Server

Responsibilities:
  1. Generate a 32-byte master key and hand it to connecting agents over mTLS.
  2. Receive length-prefixed, AES-256-GCM-encrypted frames from agents.
  3. Replicate the kernel's HKDF key derivation to decrypt each frame.
  4. Parse, validate, and log the decrypted photon_event structs.

Wire protocol (agent → server, after mTLS handshake):
  ┌─────────────────────────────────────────────────────────┐
  │ Handshake  : agent sends 4-byte magic  0x50 0x52 0x4F 0x47 ("PROG")
  │ Key push   : server sends 1-byte  0x01 (KEY_OFFER) + 32-byte master key
  │ Key ack    : agent sends  1-byte  0x02 (KEY_ACK)
  │ Log stream : agent sends frames continuously:
  │              [u32 body_len LE][body of body_len bytes]
  │   body = photon_encrypted_msg (see struct below, matches cdev_ch.h)
  └─────────────────────────────────────────────────────────┘

Crypto (must exactly mirror crypto.c):
  session_key = HKDF(IKM=master_key, salt=rotation_num_le8, info="photon-ring-v1-{rotation_num}")
  ciphertext  = AES-256-GCM(key=session_key, iv=frame.iv, plaintext=photon_event)
  tag         = frame.auth_tag   (16 bytes, appended by kernel after ciphertext)

photon_event layout (packed, matches event_manager.h):
  u64 sequence_num
  u64 timestamp_ns
  u32 event_type
  u32 detector_id
  u16 data_len
  u8  data[512]
  → total: 8+8+4+4+2+512 = 538 bytes

photon_encrypted_msg layout (packed, matches cdev_ch.h):
  u64 rotation_num
  u8  iv[12]
  u16 encrypted_len
  u8  auth_tag[16]
  u8  encrypted_data[encrypted_len]
"""

import argparse
import hashlib
import hmac
import logging
import os
import socket
import ssl
import struct
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# Constants (must match kernel headers exactly)
# ─────────────────────────────────────────────────────────────────────────────

PHOTON_KEY_SIZE   = 32          # AES-256
PHOTON_IV_SIZE    = 12          # GCM standard nonce
PHOTON_TAG_SIZE   = 16          # GCM auth tag
PHOTON_MAX_EVENT_DATA = 512

# Handshake bytes
MAGIC             = b'\x50\x52\x4f\x47'   # "PROG"
MSG_KEY_OFFER     = 0x01
MSG_KEY_ACK       = 0x02

# photon_event struct: sequence_num(8) + timestamp_ns(8) + event_type(4)
#                    + detector_id(4) + data_len(2) + data(512) = 538 bytes
PHOTON_EVENT_FMT    = '<QQIIHx512s'   # note: 1 byte implicit padding before data
# Actually packed (no padding), recompute:
PHOTON_EVENT_FMT    = '<QQIIH512s'
PHOTON_EVENT_SIZE   = struct.calcsize(PHOTON_EVENT_FMT)   # 538 bytes

# photon_encrypted_msg fixed header (matches cdev_ch.h exactly):
#   sequence_num(8) + rotation_num(8) + iv(12) + encrypted_len(2) + auth_tag(16) = 46 bytes
ENC_HDR_FMT  = '<QQ12sH16s'
ENC_HDR_SIZE = struct.calcsize(ENC_HDR_FMT)  # 46 bytes

# Event type names (mirrors event_manager.h)
EVENT_NAMES = {
    1:   "KPROBE_REG",
    2:   "SYSCALL_HOOK",
    3:   "MODULE_HIDDEN",
    4:   "PROCESS_HIDDEN",
    5:   "NETWORK_HOOK",
    100: "HEARTBEAT",
    101: "KEY_ROTATION",
}

DETECTOR_NAMES = {
    0: "SYSTEM",
    1: "KPROBE",
    2: "SYSCALL",
}

# ─────────────────────────────────────────────────────────────────────────────
# HKDF-SHA256 (RFC 5869) — must produce identical output to crypto.c
# ─────────────────────────────────────────────────────────────────────────────

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)"""
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand: OKM = first `length` bytes of T(1)||T(2)||..."""
    if length > 255 * 32:
        raise ValueError("HKDF output too long")
    okm = b""
    t   = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


def derive_session_key(master_key: bytes, rotation_num: int) -> bytes:
    """
    Mirrors photon_derive_session_key() in crypto.c exactly:

      salt = rotation_num as 8-byte little-endian
      IKM  = master_key
      PRK  = HKDF-Extract(salt, IKM)
      info = f"photon-ring-v1-{rotation_num}" as UTF-8
      OKM  = HKDF-Expand(PRK, info, 32)
    """
    salt = struct.pack('<Q', rotation_num)                       # u64 LE
    info = f"photon-ring-v1-{rotation_num}".encode('utf-8')
    prk  = hkdf_extract(salt, master_key)
    return hkdf_expand(prk, info, PHOTON_KEY_SIZE)


# ─────────────────────────────────────────────────────────────────────────────
# AES-256-GCM decryption
# ─────────────────────────────────────────────────────────────────────────────

def aes_gcm_decrypt(key: bytes, iv: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    """
    Decrypt AES-256-GCM.  The kernel appends the tag *after* the ciphertext
    in the output scatter-gather list, so we receive them separately and
    recombine here for the cryptography library.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    aesgcm = AESGCM(key)
    # cryptography lib expects ciphertext||tag concatenated
    return aesgcm.decrypt(iv, ciphertext + tag, None)


# ─────────────────────────────────────────────────────────────────────────────
# Frame parsing
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class EncryptedFrame:
    sequence_num:   int
    rotation_num:   int
    iv:             bytes
    encrypted_len:  int
    auth_tag:       bytes
    ciphertext:     bytes


@dataclass
class PhotonEvent:
    sequence_num:  int
    timestamp_ns:  int
    event_type:    int
    detector_id:   int
    data_len:      int
    data:          bytes

    @property
    def event_name(self) -> str:
        return EVENT_NAMES.get(self.event_type, f"UNKNOWN({self.event_type})")

    @property
    def detector_name(self) -> str:
        return DETECTOR_NAMES.get(self.detector_id, f"UNKNOWN({self.detector_id})")

    @property
    def timestamp_utc(self) -> str:
        ts = self.timestamp_ns / 1e9
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()

    def payload_hex(self) -> str:
        return self.data[:self.data_len].hex()


def parse_encrypted_frame(body: bytes) -> EncryptedFrame:
    """Parse photon_encrypted_msg body (after the u32 length prefix)."""
    if len(body) < ENC_HDR_SIZE:
        raise ValueError(f"Frame body too short: {len(body)} < {ENC_HDR_SIZE}")
    sequence_num, rotation_num, iv, encrypted_len, auth_tag = struct.unpack_from(ENC_HDR_FMT, body, 0)
    ciphertext_offset = ENC_HDR_SIZE
    ciphertext_end    = ciphertext_offset + encrypted_len
    if len(body) < ciphertext_end:
        raise ValueError(f"Frame truncated: need {ciphertext_end}, have {len(body)}")
    ciphertext = body[ciphertext_offset:ciphertext_end]
    return EncryptedFrame(sequence_num, rotation_num, iv, encrypted_len, auth_tag, ciphertext)


def parse_photon_event(plaintext: bytes) -> PhotonEvent:
    """Unpack a decrypted photon_event struct."""
    if len(plaintext) < PHOTON_EVENT_SIZE:
        raise ValueError(f"Plaintext too short: {len(plaintext)} < {PHOTON_EVENT_SIZE}")
    seq, ts, etype, det, dlen, data_buf = struct.unpack_from(PHOTON_EVENT_FMT, plaintext, 0)
    return PhotonEvent(seq, ts, etype, det, dlen, data_buf)


# ─────────────────────────────────────────────────────────────────────────────
# Per-agent session key cache
# ─────────────────────────────────────────────────────────────────────────────

class SessionKeyCache:
    """LRU-ish cache: derive and memoize session keys by rotation number."""
    def __init__(self, master_key: bytes, max_entries: int = 1024):
        self._master = master_key
        self._cache: dict[int, bytes] = {}
        self._max   = max_entries
        self._lock  = threading.Lock()

    def get(self, rotation_num: int) -> bytes:
        with self._lock:
            if rotation_num not in self._cache:
                if len(self._cache) >= self._max:
                    # evict oldest (lowest rotation number)
                    oldest = min(self._cache)
                    del self._cache[oldest]
                self._cache[rotation_num] = derive_session_key(self._master, rotation_num)
            return self._cache[rotation_num]


# ─────────────────────────────────────────────────────────────────────────────
# Agent handler (one thread per connected agent)
# ─────────────────────────────────────────────────────────────────────────────

def recv_exactly(sock: ssl.SSLSocket, n: int) -> Optional[bytes]:
    """Read exactly n bytes; return None on clean EOF."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def handle_agent(conn: ssl.SSLSocket, addr: tuple,
                 master_key: bytes, key_cache: SessionKeyCache,
                 log: logging.Logger) -> None:
    peer = f"{addr[0]}:{addr[1]}"
    log.info(f"[{peer}] Connection established")
    stats = {"frames": 0, "errors": 0, "bytes": 0}

    try:
        # ── Handshake ──────────────────────────────────────────────────────
        magic = recv_exactly(conn, 4)
        if magic != MAGIC:
            log.warning(f"[{peer}] Bad magic: {magic!r}, dropping")
            return

        # ── Key offer ──────────────────────────────────────────────────────
        conn.sendall(bytes([MSG_KEY_OFFER]) + master_key)
        log.info(f"[{peer}] Master key sent (32 bytes)")

        ack = recv_exactly(conn, 1)
        if not ack or ack[0] != MSG_KEY_ACK:
            log.warning(f"[{peer}] No KEY_ACK (got {ack!r}), dropping")
            return
        log.info(f"[{peer}] KEY_ACK received — session active")

        # ── Frame receive loop ─────────────────────────────────────────────
        while True:
            # Read 4-byte little-endian body length
            hdr = recv_exactly(conn, 4)
            if hdr is None:
                log.info(f"[{peer}] Connection closed by agent")
                break

            body_len = struct.unpack('<I', hdr)[0]
            if body_len == 0 or body_len > 65536:
                log.warning(f"[{peer}] Implausible body_len={body_len}, skipping")
                continue

            body = recv_exactly(conn, body_len)
            if body is None:
                log.warning(f"[{peer}] Truncated frame body, closing")
                break

            stats["bytes"] += 4 + body_len

            try:
                frame = parse_encrypted_frame(body)
            except ValueError as e:
                log.warning(f"[{peer}] Frame parse error: {e}")
                stats["errors"] += 1
                continue

            # Derive (or look up cached) session key for this rotation
            try:
                session_key = key_cache.get(frame.rotation_num)
            except Exception as e:
                log.error(f"[{peer}] Key derivation failed for rotation {frame.rotation_num}: {e}")
                stats["errors"] += 1
                continue

            # Decrypt
            try:
                plaintext = aes_gcm_decrypt(session_key, frame.iv,
                                            frame.ciphertext, frame.auth_tag)
            except Exception as e:
                log.warning(f"[{peer}] Decryption failed (rotation={frame.rotation_num}): {e}")
                stats["errors"] += 1
                continue

            # Parse event
            try:
                event = parse_photon_event(plaintext)
            except ValueError as e:
                log.warning(f"[{peer}] Event parse error: {e}")
                stats["errors"] += 1
                continue

            stats["frames"] += 1
            _log_event(event, frame, peer, log)

    except (ssl.SSLError, OSError) as e:
        log.warning(f"[{peer}] Socket error: {e}")
    finally:
        conn.close()
        log.info(f"[{peer}] Session closed — "
                 f"frames={stats['frames']} errors={stats['errors']} "
                 f"bytes={stats['bytes']}")


def _log_event(event: PhotonEvent, frame: EncryptedFrame,
               peer: str, log: logging.Logger) -> None:
    """Pretty-print a decrypted event."""
    suspicious = ""
    # Detect the "kallsyms_lookup_name" kprobe flag the kernel sets
    if event.event_type == 1 and event.data_len >= 64:
        symbol = event.data[:64].rstrip(b'\x00').decode('utf-8', errors='replace')
        if symbol == "kallsyms_lookup_name":
            suspicious = "  *** SUSPICIOUS ***"

    log.info(
        f"[{peer}] EVENT seq={frame.sequence_num} "
        f"type={event.event_name} detector={event.detector_name} "
        f"ts={event.timestamp_utc} rotation={frame.rotation_num}"
        f"{suspicious}"
    )
    if event.data_len > 0:
        log.debug(f"[{peer}]   payload({event.data_len}B): {event.payload_hex()}")


# ─────────────────────────────────────────────────────────────────────────────
# TLS server
# ─────────────────────────────────────────────────────────────────────────────

def build_ssl_context(cert: str, key: str, ca: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(cert, key)
    ctx.load_verify_locations(ca)
    ctx.verify_mode = ssl.CERT_REQUIRED   # mutual TLS — client cert required
    return ctx


def run_server(host: str, port: int, master_key: bytes,
               cert: str, key_file: str, ca: str,
               log: logging.Logger) -> None:
    ctx = build_ssl_context(cert, key_file, ca)
    key_cache = SessionKeyCache(master_key)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw_sock:
        raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw_sock.bind((host, port))
        raw_sock.listen(16)
        log.info(f"Photon Ring server listening on {host}:{port} (TLS 1.3, mTLS)")
        log.info(f"Master key (hex): {master_key.hex()}")

        while True:
            try:
                client, addr = raw_sock.accept()
                tls_conn = ctx.wrap_socket(client, server_side=True)
                t = threading.Thread(
                    target=handle_agent,
                    args=(tls_conn, addr, master_key, key_cache, log),
                    daemon=True,
                    name=f"agent-{addr[0]}-{addr[1]}"
                )
                t.start()
            except KeyboardInterrupt:
                log.info("Server shutting down")
                break
            except ssl.SSLError as e:
                log.warning(f"TLS handshake failed from {addr}: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Photon Ring Remote Log Server"
    )
    parser.add_argument("--host",     default="0.0.0.0",       help="Bind address")
    parser.add_argument("--port",     type=int, default=9443,   help="Bind port")
    parser.add_argument("--cert",     default="certs/server.crt")
    parser.add_argument("--key",      default="certs/server.key")
    parser.add_argument("--ca",       default="certs/ca.crt")
    parser.add_argument("--keyfile",  default=None,
                        help="Load master key from file (hex); generate if absent")
    parser.add_argument("--save-key", default=None,
                        help="Write generated master key (hex) to this file")
    parser.add_argument("--verbose",  action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-8s %(threadName)s  %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    log = logging.getLogger("photon_server")

    # Master key: load from file or generate fresh
    if args.keyfile and Path(args.keyfile).exists():
        master_key = bytes.fromhex(Path(args.keyfile).read_text().strip())
        log.info(f"Loaded master key from {args.keyfile}")
    else:
        master_key = os.urandom(PHOTON_KEY_SIZE)
        log.info("Generated fresh 32-byte master key")
        if args.save_key:
            Path(args.save_key).write_text(master_key.hex() + "\n")
            log.info(f"Master key saved to {args.save_key}")

    run_server(args.host, args.port, master_key,
               args.cert, args.key, args.ca, log)


if __name__ == "__main__":
    main()