"""
protocol.py
===========
Format des messages reseau partage entre client et serveur.

Chaque message TCP = [4 octets BE de longueur N][N octets JSON UTF-8].
Les valeurs binaires (cles, nonces, ciphertexts) sont encodees en hex.
"""

import json
import socket
import struct
from typing import Any, Dict


# ----------------------------------------------------------------------------
# Couche transport : envoi/reception avec prefixe de longueur
# ----------------------------------------------------------------------------

def send_msg(sock: socket.socket, msg: Dict[str, Any]) -> None:
    """Encode `msg` en JSON et l'envoie precede de sa longueur sur 4 octets."""
    payload = json.dumps(msg).encode("utf-8")
    header = struct.pack(">I", len(payload))   # big-endian uint32
    sock.sendall(header + payload)


def recv_msg(sock: socket.socket) -> Dict[str, Any]:
    """Lit la longueur (4 octets) puis le payload JSON correspondant."""
    header = recv_exact(sock, 4)
    (length,) = struct.unpack(">I", header)
    payload = recv_exact(sock, length)
    return json.loads(payload.decode("utf-8"))


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Recoit exactement `n` octets, ou leve si la connexion ferme avant."""
    chunks = []
    remaining = n
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("Connexion fermee prematurement")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


# ----------------------------------------------------------------------------
# Types de messages du protocole
# ----------------------------------------------------------------------------

# Phase 1 : enregistrement
#   client -> serveur : {"type": "register", "user_id": "...", "hp": "<hex>"}
#   serveur -> client : {"status": "ok"}  ou  {"status": "error", "msg": "..."}

# Phase 2 : authentification (3 messages)
#   client -> serveur : {"type": "auth_init", "user_id": "...", "nc": "<hex>"}
#   serveur -> client : {"ns": "<hex>"}
#   client -> serveur : {"type": "auth_proof", "ciphertext": "<hex>"}
#   serveur -> client : {"status": "ok"|"fail", "msg": "..."}
