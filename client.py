"""
client.py
=========
Client TCP qui parle au serveur d'authentification ASCON.

Modes :
    python client.py register <user_id> <password>
    python client.py auth     <user_id> <password>

Le client se connecte sur 127.0.0.1:5050.
"""

import socket
import sys

from crypto_utils import (
    hash_password,
    generate_nonce,
    build_ascon_nonce,
    ascon_encrypt,
    hexs,
    PROTO_NONCE_SIZE,
)
from protocol import send_msg, recv_msg


HOST = "127.0.0.1"
PORT = 5050

# Doit etre identique a celle du serveur (cle pre-partagee).
SHARED_KEY = bytes.fromhex("0123456789abcdef0123456789abcdef")

HASH_ALGO = "ascon"   # 'ascon' | 'blake2s' | 'sha256'


# ----------------------------------------------------------------------------
# Phase 1 : enregistrement
# ----------------------------------------------------------------------------

def do_register(user_id: str, password: str) -> None:
    print(f"[1] H(password) avec algo={HASH_ALGO}")
    hp = hash_password(password, algorithm=HASH_ALGO)
    print(f"    H(password) = {hexs(hp)}")

    with socket.create_connection((HOST, PORT)) as sock:
        send_msg(sock, {
            "type": "register",
            "user_id": user_id,
            "hp": hp.hex(),
        })
        resp = recv_msg(sock)
        print(f"[2] reponse serveur : {resp}")


# ----------------------------------------------------------------------------
# Phase 2 : authentification
# ----------------------------------------------------------------------------

def do_auth(user_id: str, password: str) -> None:
    nc = generate_nonce(PROTO_NONCE_SIZE)
    print(f"[1] Nonce client Nc = {hexs(nc)}")

    with socket.create_connection((HOST, PORT)) as sock:
        # 1er aller : (user_id, Nc)
        send_msg(sock, {
            "type": "auth_init",
            "user_id": user_id,
            "nc": nc.hex(),
        })

        # 1er retour : Ns
        resp1 = recv_msg(sock)
        if "ns" not in resp1:
            print(f"[ERREUR] {resp1}")
            return
        ns = bytes.fromhex(resp1["ns"])
        print(f"[2] Nonce serveur Ns = {hexs(ns)}")

        # Calcul du ciphertext
        hp = hash_password(password, algorithm=HASH_ALGO)
        nonce = build_ascon_nonce(nc, ns)
        ad = user_id.encode()
        ciphertext = ascon_encrypt(SHARED_KEY, nonce, hp, associated_data=ad)
        print(f"[3] Hp = {hexs(hp)}")
        print(f"    Nonce ASCON = {hexs(nonce, max_bytes=16)}")
        print(f"    AD = {ad!r}")
        print(f"    ciphertext = {hexs(ciphertext, max_bytes=12)} "
              f"({len(ciphertext)} octets)")

        # 2eme aller : ciphertext
        send_msg(sock, {
            "type": "auth_proof",
            "ciphertext": ciphertext.hex(),
        })

        # 2eme retour : OK / FAIL
        resp2 = recv_msg(sock)
        status = resp2.get("status")
        print(f"[4] reponse serveur : {resp2}")
        print()
        if status == "ok":
            print("    >>> AUTHENTIFICATION REUSSIE <<<")
        else:
            print("    >>> AUTHENTIFICATION ECHOUEE <<<")


# ----------------------------------------------------------------------------
# Entree
# ----------------------------------------------------------------------------

def usage() -> None:
    print("Usage :")
    print("    python client.py register <user_id> <password>")
    print("    python client.py auth     <user_id> <password>")
    sys.exit(1)


def main() -> None:
    if len(sys.argv) != 4:
        usage()
    cmd, user_id, password = sys.argv[1], sys.argv[2], sys.argv[3]

    if cmd == "register":
        do_register(user_id, password)
    elif cmd == "auth":
        do_auth(user_id, password)
    else:
        usage()


if __name__ == "__main__":
    main()
