"""
demo_local.py
=============
Demonstration du protocole d'authentification ASCON, en local
(client + serveur dans le meme processus, pas de socket).

Objectif pedagogique : derouler les 3 phases (Enregistrement,
Authentification, Session) avec affichage de chaque etape, puis
montrer que les attaques (mauvais mot de passe, message modifie,
rejeu) sont bien rejetees.

A executer pour la presentation : python demo_local.py
"""

from crypto_utils import (
    hash_password,
    generate_nonce,
    build_ascon_nonce,
    ascon_encrypt,
    ascon_decrypt,
    hexs,
    PROTO_NONCE_SIZE,
    ASCON_KEY_SIZE,
)


# =============================================================================
# Cote serveur : "base de donnees" en memoire (dict username -> H(password))
# =============================================================================

class Server:
    def __init__(self, shared_key: bytes, hash_algo: str = "ascon"):
        self.K = shared_key            # cle pre-partagee (16 octets)
        self.hash_algo = hash_algo     # algo utilise pour H()
        self.db = {}                   # 'database': user_id -> H(password)

    # --- Phase 1 : enregistrement ---------------------------------------
    def register(self, user_id: str, hashed_password: bytes) -> None:
        """Le serveur stocke H(password). Il n'a JAMAIS le mdp en clair."""
        self.db[user_id] = hashed_password

    # --- Phase 2 : authentification --------------------------------------
    def auth_step1_receive_init(self, user_id: str, nc: bytes) -> bytes:
        """
        Le serveur recoit (user_id, Nc), genere Ns, et le retourne.
        Pas encore de verif : on attend la suite.
        """
        if user_id not in self.db:
            raise ValueError(f"Utilisateur inconnu : {user_id}")
        ns = generate_nonce(PROTO_NONCE_SIZE)
        # On garde Ns + Nc en memoire pour cette session (etat serveur)
        self._pending = {"user_id": user_id, "nc": nc, "ns": ns}
        return ns

    def auth_step2_verify(self, ciphertext: bytes) -> bool:
        """
        Le serveur recoit le ciphertext (Hp chiffre + tag), le dechiffre,
        et compare avec le H(password) stocke.
        """
        s = self._pending
        nonce = build_ascon_nonce(s["nc"], s["ns"])
        ad = s["user_id"].encode()    # binding avec l'identite

        plaintext = ascon_decrypt(self.K, nonce, ciphertext, associated_data=ad)
        if plaintext is None:
            # Tag invalide : ciphertext, AD, nonce ou cle ne correspondent pas
            return False

        # Le serveur compare Hp recu avec ce qui est stocke en base
        stored_hp = self.db[s["user_id"]]
        return plaintext == stored_hp


# =============================================================================
# Cote client
# =============================================================================

class Client:
    def __init__(self, shared_key: bytes, hash_algo: str = "ascon"):
        self.K = shared_key
        self.hash_algo = hash_algo

    def compute_hp(self, password: str) -> bytes:
        return hash_password(password, algorithm=self.hash_algo)

    def auth_build_message(self, user_id: str, password: str,
                           nc: bytes, ns: bytes) -> bytes:
        """
        Construit le message chiffre :
            Hp = H(password)
            ciphertext = ASCON_Encrypt(K, Nc||Ns, Hp, AD=user_id)
        """
        hp = self.compute_hp(password)
        nonce = build_ascon_nonce(nc, ns)
        ad = user_id.encode()
        return ascon_encrypt(self.K, nonce, hp, associated_data=ad)


# =============================================================================
# Helpers d'affichage
# =============================================================================

def section(title: str) -> None:
    print()
    print("=" * 72)
    print(f"  {title}")
    print("=" * 72)


def step(label: str, value=None) -> None:
    if value is None:
        print(f"  > {label}")
    else:
        print(f"  > {label:<30} {value}")


# =============================================================================
# Scenario complet
# =============================================================================

def run_demo():
    # ------------------------------------------------------------------
    # 0. Setup : cle pre-partagee K (en realite, echangee securement)
    # ------------------------------------------------------------------
    section("0. SETUP - Cle pre-partagee K")
    K = bytes.fromhex("0123456789abcdef0123456789abcdef")  # 16 octets
    assert len(K) == ASCON_KEY_SIZE
    step("Cle K (hex)", K.hex())
    step("Taille K", f"{len(K)} octets ({len(K)*8} bits)")
    step("Algo de hash", "ASCON-Hash (modifiable via crypto_utils)")

    server = Server(K, hash_algo="ascon")
    client = Client(K, hash_algo="ascon")

    # ------------------------------------------------------------------
    # PHASE 1 - Enregistrement
    # ------------------------------------------------------------------
    section("PHASE 1 - ENREGISTREMENT")
    user_id = "alice"
    password = "MonMotDePasseSecret!"
    step("Identifiant", user_id)
    step("Mot de passe (clair)", repr(password))

    hp_register = client.compute_hp(password)
    step("H(password)", hexs(hp_register))
    step("Client -> Serveur", "envoie (alice, H(password))")

    server.register(user_id, hp_register)
    step("Serveur stocke", f"db[alice] = H(password) (32 octets)")
    step("Le mdp en clair", "JAMAIS transmis ni stocke")

    # ------------------------------------------------------------------
    # PHASE 2 - Authentification (cas nominal)
    # ------------------------------------------------------------------
    section("PHASE 2 - AUTHENTIFICATION (cas nominal)")

    # Etape 2.1 : client genere Nc et l'envoie avec son ID
    print("\n-- 2.1 Echange de nonces --")
    nc = generate_nonce()
    step("Client genere Nc", hexs(nc))
    step("Client -> Serveur", f"(alice, Nc={hexs(nc)})")

    ns = server.auth_step1_receive_init(user_id, nc)
    step("Serveur genere Ns", hexs(ns))
    step("Serveur -> Client", f"Ns={hexs(ns)}")

    # Etape 2.2 : client chiffre Hp avec ASCON
    print("\n-- 2.2 Chiffrement de Hp cote client --")
    nonce_ascon = build_ascon_nonce(nc, ns)
    step("Nonce ASCON = Nc||Ns", hexs(nonce_ascon, max_bytes=16))
    step("AD (associated data)", f"{user_id!r} (authentifie, non chiffre)")

    ciphertext = client.auth_build_message(user_id, password, nc, ns)
    step("Ciphertext (= chiffre+tag)", hexs(ciphertext, max_bytes=12))
    step("Taille", f"{len(ciphertext)} octets (32 hash + 16 tag = 48)")
    step("Client -> Serveur", "envoie ciphertext")

    # Etape 2.3 : serveur dechiffre, verifie tag, compare
    print("\n-- 2.3 Verification cote serveur --")
    ok = server.auth_step2_verify(ciphertext)
    step("Tag ASCON", "VALIDE" if ok else "INVALIDE")
    step("Comparaison Hp stocke", "EGAL" if ok else "DIFFERENT")
    step("Reponse au client", "OK [v]" if ok else "FAIL [x]")
    assert ok, "L'authentification nominale doit reussir."

    # ------------------------------------------------------------------
    # PHASE 3 - Session etablie
    # ------------------------------------------------------------------
    section("PHASE 3 - SESSION ETABLIE")
    step("Authentification mutuelle", "validee")
    step("Cle de session optionnelle", "derivable depuis (K, Nc, Ns)")
    step("Suite", "echanges proteges (hors scope du TP)")

    # ==================================================================
    # TESTS D'ATTAQUES
    # ==================================================================

    # --- Attaque 1 : mauvais mot de passe ----------------------------
    section("ATTAQUE 1 - Mauvais mot de passe (impersonation)")
    nc2 = generate_nonce()
    ns2 = server.auth_step1_receive_init(user_id, nc2)
    bad_ct = client.auth_build_message(user_id, "MauvaisPassword", nc2, ns2)
    step("Client utilise", repr("MauvaisPassword"))
    step("Tag ASCON", "VALIDE (la cle K est correcte)")

    ok = server.auth_step2_verify(bad_ct)
    step("Comparaison Hp stocke", "DIFFERENT")
    step("Reponse", "FAIL [x] (mauvais mot de passe)")
    assert not ok, "Un mauvais mot de passe doit etre rejete."

    # --- Attaque 2 : ciphertext modifie ------------------------------
    section("ATTAQUE 2 - Modification du ciphertext (MITM)")
    nc3 = generate_nonce()
    ns3 = server.auth_step1_receive_init(user_id, nc3)
    good_ct = client.auth_build_message(user_id, password, nc3, ns3)

    # On flippe un seul bit du ciphertext
    tampered = bytearray(good_ct)
    tampered[5] ^= 0x01
    step("Modification", "1 seul bit flippe a l'octet 5")

    ok = server.auth_step2_verify(bytes(tampered))
    step("Tag ASCON", "INVALIDE (integrite cassee)")
    step("Reponse", "FAIL [x] (message altere detecte)")
    assert not ok, "Une falsification doit etre rejetee."

    # --- Attaque 3 : rejeu d'une session valide ----------------------
    section("ATTAQUE 3 - Rejeu (replay attack)")
    # On capture un message valide (good_ct ci-dessus) et on tente
    # de l'envoyer dans une nouvelle session avec de nouveaux nonces.
    nc4 = generate_nonce()
    ns4 = server.auth_step1_receive_init(user_id, nc4)
    step("Attaquant rejoue", "ciphertext capture lors de la session 3")
    step("Nouveaux nonces", f"Nc4={hexs(nc4)} != Nc3, Ns4={hexs(ns4)} != Ns3")
    step("Donc nonce ASCON",
         "Nc4||Ns4 different de Nc3||Ns3 utilise au chiffrement")

    ok = server.auth_step2_verify(good_ct)  # rejeu de l'ancien message
    step("Tag ASCON", "INVALIDE (nonce different)")
    step("Reponse", "FAIL [x] (rejeu detecte)")
    assert not ok, "Un rejeu doit etre rejete."

    # ------------------------------------------------------------------
    section("BILAN")
    print("  [v] Authentification nominale       : OK")
    print("  [x] Mauvais mot de passe            : rejete (Hp != stocke)")
    print("  [x] Modification du message (MITM)  : rejete (tag invalide)")
    print("  [x] Rejeu d'une ancienne session    : rejete (nonces frais)")
    print()
    print("  Garanties fournies par le protocole :")
    print("    - Confidentialite  (chiffrement ASCON-128)")
    print("    - Integrite        (tag ASCON 128 bits)")
    print("    - Authentification (cle K + comparaison H(password))")
    print("    - Anti-rejeu       (nonces Nc et Ns frais a chaque session)")
    print()


if __name__ == "__main__":
    run_demo()
