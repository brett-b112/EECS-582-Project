#!/usr/bin/env python3
"""
photon_server.py — Photon Ring Remote Log Server

Responsibilities:
  1. Generate a 32-byte master key and hand it to connecting agents over mTLS.
  2. Receive length-prefixed, AES-256-GCM-encrypted frames from agents.
  3. Replicate the kernel's HKDF key derivation to decrypt each frame.
  4. Parse, validate, and log the decrypted photon_event structs.
  5. Index every decrypted event into Elasticsearch for Kibana visualization.
     Documents are written to the same index and schema used by es_writer.py
     so that dmesg-sourced and kernel-channel events appear in one dashboard.

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
from typing import Any, Dict, List, Optional

try:
    from elasticsearch import Elasticsearch
    from elasticsearch.helpers import bulk as es_bulk
    _ES_AVAILABLE = True
except ImportError:
    _ES_AVAILABLE = False

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
# Event type → severity mapping
# ─────────────────────────────────────────────────────────────────────────────

# Maps photon event_type integers to (severity, lksm_type) pairs that match
# the schema used by es_writer.py / dmesg_reader.py so all events land in the
# same Kibana index with consistent field values.
_EVENT_SEVERITY: Dict[int, str] = {
    1:   "high",      # KPROBE_REG  — any kprobe registration is noteworthy
    2:   "critical",  # SYSCALL_HOOK
    3:   "critical",  # MODULE_HIDDEN
    4:   "critical",  # PROCESS_HIDDEN
    5:   "high",      # NETWORK_HOOK
    100: "info",      # HEARTBEAT
    101: "info",      # KEY_ROTATION
}

# kprobe_event_data layout inside photon_event.data (matches kprobe_detector.h):
#   char symbol_name[64]
#   u64  addr          (8 bytes)
#   u32  flags         (4 bytes)
#   u8   is_suspicious (1 byte)
_KPROBE_DATA_FMT  = "<64sQIB"
_KPROBE_DATA_SIZE = struct.calcsize(_KPROBE_DATA_FMT)  # 77 bytes


def _parse_event_payload(event: "PhotonEvent") -> Dict[str, Any]:
    """
    Decode event.data into a structured dict that mirrors the 'data' field
    shape produced by dmesg_reader.py — allowing a single Kibana index mapping
    to cover both sources.
    """
    payload = event.data[:event.data_len]

    if event.event_type == 1 and event.data_len >= _KPROBE_DATA_SIZE:
        # KPROBE_REG — kprobe_event_data struct
        sym_raw, addr, flags, is_sus = struct.unpack_from(_KPROBE_DATA_FMT, payload, 0)
        symbol = sym_raw.rstrip(b"\x00").decode("utf-8", errors="replace")
        return {
            "detector":      "kprobe_detector",
            "symbol":        symbol,
            "target_addr":   f"0x{addr:016x}",
            "hook_mechanism": "kprobe",
            "is_suspicious": bool(is_sus),
            "flags":         flags,
        }

    if event.event_type == 100 and event.data_len >= 32:
        # HEARTBEAT — uptime_ns(8) + sequence_num(8) + events_sent(8) + events_dropped(8)
        uptime, seq, sent, dropped = struct.unpack_from("<QQQQ", payload, 0)
        return {
            "detector":       "system",
            "uptime_ns":      uptime,
            "events_sent":    sent,
            "events_dropped": dropped,
        }

    if event.event_type == 101 and event.data_len >= 16:
        # KEY_ROTATION — new_rotation_num(8) + timestamp_ns(8)
        new_rot, ts_ns = struct.unpack_from("<QQ", payload, 0)
        return {
            "detector":          "system",
            "new_rotation_num":  new_rot,
        }

    # Fallback: hex-encode the raw payload
    return {
        "detector": "photon_ring",
        "raw_hex":  payload.hex(),
    }


def _event_to_doc(event: "PhotonEvent", peer: str) -> Dict[str, Any]:
    """
    Convert a decrypted PhotonEvent to an Elasticsearch document whose shape
    matches the INDEX_MAPPING defined in es_writer.py.
    """
    severity = _EVENT_SEVERITY.get(event.event_type, "info")
    # Upgrade severity for the specific kallsyms_lookup_name probe
    payload_data = _parse_event_payload(event)
    if payload_data.get("symbol") == "kallsyms_lookup_name" or payload_data.get("is_suspicious"):
        severity = "critical"

    return {
        "seq":        event.sequence_num,
        "ts":         event.timestamp_ns / 1e9,
        "@timestamp": datetime.fromtimestamp(event.timestamp_ns / 1e9, tz=timezone.utc).isoformat(),
        "type":       event.event_name,
        "severity":   severity,
        "source":     f"photon_ring_agent:{peer}",
        "data":       payload_data,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Elasticsearch writer
# ─────────────────────────────────────────────────────────────────────────────

# Index mapping — identical to es_writer.py so both sources share one index.
_INDEX_MAPPING = {
    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
    "mappings": {
        "properties": {
            "seq":        {"type": "integer"},
            "ts":         {"type": "double"},
            "@timestamp": {"type": "date"},
            "type":       {"type": "keyword"},
            "severity":   {"type": "keyword"},
            "source":     {"type": "keyword"},
            "data": {
                "properties": {
                    "message":       {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}},
                    "symbol":        {"type": "keyword"},
                    "pid":           {"type": "integer"},
                    "process_name":  {"type": "keyword"},
                    "detector":      {"type": "keyword"},
                    "target_symbol": {"type": "keyword"},
                    "target_addr":   {"type": "keyword"},
                    "hook_mechanism":{"type": "keyword"},
                    "raw_hex":       {"type": "keyword"},
                    "uptime_ns":     {"type": "long"},
                    "events_sent":   {"type": "long"},
                    "events_dropped":{"type": "long"},
                    "new_rotation_num": {"type": "long"},
                }
            },
        }
    },
}


class PhotonESWriter:
    """
    Indexes decrypted PhotonEvents into Elasticsearch.

    Mirrors the ElasticsearchWriter interface from es_writer.py so that events
    arriving via the encrypted kernel channel land in the same index as those
    read from dmesg by KprobeReaderModule.
    """

    def __init__(self, host: str, index: str, enabled: bool,
                 log: logging.Logger) -> None:
        self._log     = log
        self._index   = index
        self._enabled = enabled and _ES_AVAILABLE

        if not _ES_AVAILABLE and enabled:
            log.warning("elasticsearch-py not installed — ES output disabled. "
                        "Run: pip install elasticsearch")
            return

        if not self._enabled:
            log.info("Elasticsearch output disabled")
            return

        try:
            self._es = Elasticsearch(hosts=[host])
            # Verify connectivity with a cheap call
            self._es.info()
            self._ensure_index()
            log.info("Connected to Elasticsearch at %s (index: %s)", host, index)
        except Exception as exc:
            # Provide a targeted hint for the most common mistakes before
            # falling back to the generic traceback-free error message.
            hint = ""
            status = getattr(getattr(exc, "meta", None), "status", None)
            if status in (301, 302, 303, 307, 308):
                hint = (
                    f" Got HTTP {status} (redirect) — you may have pointed "
                    f"--es-host at Kibana (port 5601) instead of Elasticsearch "
                    f"(port 9200). Correct usage: --es-host http://<host>:9200"
                )
            elif "Connection refused" in str(exc) or "NewConnectionError" in str(exc):
                hint = (
                    " Connection refused — is Elasticsearch running? "
                    "Try: docker-compose up -d"
                )
            log.error("Failed to connect to Elasticsearch — ES output disabled.%s", hint)
            log.debug("ES connection error detail:", exc_info=True)
            self._enabled = False

    def _ensure_index(self) -> None:
        if not self._es.indices.exists(index=self._index):
            self._es.indices.create(
                index=self._index,
                settings=_INDEX_MAPPING["settings"],
                mappings=_INDEX_MAPPING["mappings"],
            )
            self._log.info("Created Elasticsearch index '%s'", self._index)

    def index_event(self, event: "PhotonEvent", peer: str) -> None:
        """Index a single decrypted event. Called from the agent handler thread."""
        if not self._enabled:
            return
        doc = _event_to_doc(event, peer)
        try:
            self._es.index(index=self._index, document=doc)
        except Exception:
            self._log.exception("ES index failed for seq=%s", event.sequence_num)


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
                 es_writer: "PhotonESWriter", log: logging.Logger) -> None:
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
            es_writer.index_event(event, peer)

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
               es_writer: "PhotonESWriter", log: logging.Logger) -> None:
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
                    args=(tls_conn, addr, master_key, key_cache, es_writer, log),
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
    # Elasticsearch options (mirror es_writer.py config keys)
    parser.add_argument("--es-host",  default="http://localhost:9200",
                        help="Elasticsearch base URL — port 9200, not Kibana's 5601 "
                             "(default: http://localhost:9200)")
    parser.add_argument("--es-index", default="lksm_events",
                        help="Elasticsearch index name (default: lksm_events)")
    parser.add_argument("--no-es",    action="store_true",
                        help="Disable Elasticsearch output")
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

    es_writer = PhotonESWriter(
        host=args.es_host,
        index=args.es_index,
        enabled=not args.no_es,
        log=log,
    )

    run_server(args.host, args.port, master_key,
               args.cert, args.key, args.ca, es_writer, log)


if __name__ == "__main__":
    main()