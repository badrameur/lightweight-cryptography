"""
server.py
=========
Serveur TCP qui implemente le protocole d'authentification ASCON.

Lancement :
    python server.py

Le serveur ecoute sur 127.0.0.1:5050 et gere chaque client dans un thread.
La "base de donnees" est un dict en memoire (user_id -> H(password)).
"""

import json
import socket
import threading

from crypto_utils import (
    generate_nonce,
    build_ascon_nonce,
    ascon_decrypt,
    hexs,
    PROTO_NONCE_SIZE,
)
from protocol import send_msg, recv_msg


# ----------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------

HOST = "127.0.0.1"
PORT = 5050

# Cle pre-partagee entre client et serveur (16 octets pour ASCON-128).
# En production : echangee via un protocole d'echange de cle (DH, TLS, etc.).
SHARED_KEY = bytes.fromhex("0123456789abcdef0123456789abcdef")

# "Base de donnees" : user_id -> H(password)
DB = {}
DB_LOCK = threading.Lock()


# ----------------------------------------------------------------------------
# Logique du protocole
# ----------------------------------------------------------------------------

def handle_register(msg: dict) -> dict:
    """Phase 1 : enregistrement d'un nouvel utilisateur."""
    user_id = msg["user_id"]
    hp = bytes.fromhex(msg["hp"])

    with DB_LOCK:
        if user_id in DB:
            return {"status": "error", "msg": "user already registered"}
        DB[user_id] = hp

    print(f"[REGISTER] user={user_id!r}  H(password)={hexs(hp)}")
    return {"status": "ok"}


def handle_auth(conn: socket.socket) -> None:
    """
    Phase 2 : authentification en 2 echanges.
    On a deja recu le 1er message ("auth_init") -> il est passe en argument.
    """
    # --- 2.1 : reception de auth_init -------------------------------
    msg1 = recv_msg(conn)
    if msg1.get("type") != "auth_init":
        send_msg(conn, {"status": "error", "msg": "expected auth_init"})
        return

    user_id = msg1["user_id"]
    nc = bytes.fromhex(msg1["nc"])

    with DB_LOCK:
        stored_hp = DB.get(user_id)

    if stored_hp is None:
        send_msg(conn, {"status": "error", "msg": "unknown user"})
        return
    if len(nc) != PROTO_NONCE_SIZE:
        send_msg(conn, {"status": "error", "msg": "bad Nc size"})
        return

    print(f"[AUTH-INIT] user={user_id!r}  Nc={hexs(nc)}")

    # --- 2.2 : on genere Ns et on l'envoie ----------------------------
    ns = generate_nonce(PROTO_NONCE_SIZE)
    send_msg(conn, {"ns": ns.hex()})
    print(f"[AUTH-NS]   user={user_id!r}  Ns={hexs(ns)}")

    # --- 2.3 : reception du ciphertext + verification -----------------
    msg2 = recv_msg(conn)
    if msg2.get("type") != "auth_proof":
        send_msg(conn, {"status": "error", "msg": "expected auth_proof"})
        return

    ciphertext = bytes.fromhex(msg2["ciphertext"])
    nonce = build_ascon_nonce(nc, ns)
    ad = user_id.encode()

    plaintext = ascon_decrypt(SHARED_KEY, nonce, ciphertext,
                              associated_data=ad)

    if plaintext is None:
        # Tag ASCON invalide : ciphertext modifie OU nonce/AD/cle differents
        print(f"[AUTH-FAIL] user={user_id!r}  raison=tag invalide")
        send_msg(conn, {"status": "fail", "msg": "tag invalide"})
        return

    if plaintext != stored_hp:
        # Tag valide mais H(password) different : mauvais mot de passe
        print(f"[AUTH-FAIL] user={user_id!r}  raison=mauvais mot de passe")
        send_msg(conn, {"status": "fail", "msg": "mauvais mot de passe"})
        return

    print(f"[AUTH-OK]   user={user_id!r}")
    send_msg(conn, {"status": "ok", "msg": "authentication successful"})


# ----------------------------------------------------------------------------
# Boucle d'acceptation
# ----------------------------------------------------------------------------

def handle_client(conn: socket.socket, addr) -> None:
    """Traite une connexion : lit le 1er message, dispatche."""
    try:
        first = recv_msg(conn)
        msg_type = first.get("type")

        if msg_type == "register":
            response = handle_register(first)
            send_msg(conn, response)

        elif msg_type == "auth_init":
            # L'auth se fait en 2 messages : on reinjecte le 1er
            # via un buffer puis on appelle handle_auth.
            # Plus simple : on reproduit handle_auth en partant de "first".
            user_id = first["user_id"]
            nc = bytes.fromhex(first["nc"])
            with DB_LOCK:
                stored_hp = DB.get(user_id)
            if stored_hp is None:
                send_msg(conn, {"status": "error", "msg": "unknown user"})
                return

            ns = generate_nonce(PROTO_NONCE_SIZE)
            send_msg(conn, {"ns": ns.hex()})
            print(f"[AUTH-INIT] user={user_id!r}  Nc={hexs(nc)}")
            print(f"[AUTH-NS]   user={user_id!r}  Ns={hexs(ns)}")

            msg2 = recv_msg(conn)
            ciphertext = bytes.fromhex(msg2["ciphertext"])
            nonce = build_ascon_nonce(nc, ns)
            ad = user_id.encode()
            pt = ascon_decrypt(SHARED_KEY, nonce, ciphertext, associated_data=ad)

            if pt is None:
                print(f"[AUTH-FAIL] user={user_id!r}  raison=tag invalide")
                send_msg(conn, {"status": "fail", "msg": "tag invalide"})
            elif pt != stored_hp:
                print(f"[AUTH-FAIL] user={user_id!r}  raison=mauvais mot de passe")
                send_msg(conn, {"status": "fail", "msg": "mauvais mot de passe"})
            else:
                print(f"[AUTH-OK]   user={user_id!r}")
                send_msg(conn, {"status": "ok", "msg": "ok"})

        else:
            send_msg(conn, {"status": "error", "msg": f"unknown type: {msg_type}"})

    except (ConnectionError, json.JSONDecodeError) as e:
        print(f"[ERROR] {addr} : {e}")
    finally:
        conn.close()


def main() -> None:
    print("=" * 60)
    print(f"  TP2 - Serveur d'authentification ASCON")
    print(f"  Ecoute sur {HOST}:{PORT}")
    print(f"  Cle pre-partagee K = {SHARED_KEY.hex()}")
    print("=" * 60)
    print()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen()

        while True:
            conn, addr = srv.accept()
            print(f"\n[CONN] nouvelle connexion de {addr}")
            t = threading.Thread(target=handle_client, args=(conn, addr),
                                 daemon=True)
            t.start()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[STOP] serveur arrete")
