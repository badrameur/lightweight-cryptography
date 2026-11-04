"""
crypto_utils.py
================
Briques cryptographiques pour le TP2 - Lightweight Cryptography.

Contenu :
- 3 fonctions de hachage interchangeables : ASCON-Hash, BLAKE2s, SHA-256
- Wrappers pour ASCON-128 (chiffrement authentifié AEAD)
- Génération de nonces cryptographiquement aléatoires

ASCON-128 (AEAD) :
- Cle  : 16 octets (128 bits)
- Nonce: 16 octets (128 bits) — DOIT etre unique pour une meme cle !
- Sortie : ciphertext + tag de 16 octets concatenes
"""

import os
import hashlib
from typing import Optional

import ascon  # bibliotheque officielle ASCON (NIST winner 2023)


# ----------------------------------------------------------------------------
# Constantes
# ----------------------------------------------------------------------------

# Tailles ASCON-128
ASCON_KEY_SIZE = 16     # 128 bits
ASCON_NONCE_SIZE = 16   # 128 bits
ASCON_TAG_SIZE = 16     # 128 bits

# Tailles des nonces du protocole : Nc et Ns font chacun la moitie du nonce
# ASCON. Concatenes (Nc || Ns), ils donnent exactement 16 octets.
PROTO_NONCE_SIZE = 8    # 64 bits chacun

# Algorithmes de hachage supportes (interchangeables pour la phase 3 du TP)
SUPPORTED_HASHES = ("ascon", "blake2s", "sha256")


# ----------------------------------------------------------------------------
# 1. Fonctions de hachage (Phase 1 + comparaison de la Phase 3)
# ----------------------------------------------------------------------------

def hash_password(password: str, algorithm: str = "ascon") -> bytes:
    """
    Calcule H(password) avec l'algorithme choisi.

    Args:
        password : mot de passe en clair (string Unicode)
        algorithm: 'ascon' | 'blake2s' | 'sha256'

    Returns:
        Empreinte binaire (32 octets pour les 3 algos choisis ici).
    """
    pwd_bytes = password.encode("utf-8")

    if algorithm == "ascon":
        # ASCON-Hash : NIST lightweight crypto winner, 256 bits de sortie.
        return ascon.hash(pwd_bytes, variant="Ascon-Hash", hashlength=32)

    if algorithm == "blake2s":
        # BLAKE2s : optimise software 32 bits, 256 bits de sortie.
        return hashlib.blake2s(pwd_bytes).digest()

    if algorithm == "sha256":
        # SHA-256 : reference "lourde" pour comparaison.
        return hashlib.sha256(pwd_bytes).digest()

    raise ValueError(f"Algorithme inconnu : {algorithm!r}. "
                     f"Disponibles : {SUPPORTED_HASHES}")


# ----------------------------------------------------------------------------
# 2. Generation de nonces (Phase 2)
# ----------------------------------------------------------------------------

def generate_nonce(length: int = PROTO_NONCE_SIZE) -> bytes:
    """
    Genere un nonce cryptographiquement aleatoire via os.urandom.

    `os.urandom` puise dans le PRNG du systeme d'exploitation
    (CryptGenRandom sur Windows, /dev/urandom sur Linux).
    Les nonces NE DOIVENT JAMAIS etre re-utilises avec la meme cle ASCON.
    """
    return os.urandom(length)


def build_ascon_nonce(nc: bytes, ns: bytes) -> bytes:
    """
    Construit le nonce ASCON par concatenation Nc || Ns.

    - 8 octets (client) + 8 octets (serveur) = 16 octets
    - Les deux parties contribuent : aucun cote seul ne controle le nonce
    - Cela garantit la fraicheur mutuelle => protection contre le rejeu
    """
    if len(nc) != PROTO_NONCE_SIZE or len(ns) != PROTO_NONCE_SIZE:
        raise ValueError(f"Nc et Ns doivent faire {PROTO_NONCE_SIZE} octets chacun.")
    return nc + ns


# ----------------------------------------------------------------------------
# 3. Chiffrement / dechiffrement authentifie ASCON-128
# ----------------------------------------------------------------------------

def ascon_encrypt(key: bytes, nonce: bytes, plaintext: bytes,
                  associated_data: bytes = b"") -> bytes:
    """
    Chiffrement authentifie ASCON-128.

    Args:
        key            : cle pre-partagee K (16 octets)
        nonce          : nonce unique pour cette session (16 octets)
        plaintext      : donnees a chiffrer
        associated_data: donnees authentifiees mais NON chiffrees (ex: ID)

    Returns:
        ciphertext || tag    (les 16 derniers octets sont le tag d'integrite)
    """
    if len(key) != ASCON_KEY_SIZE:
        raise ValueError(f"Cle de {ASCON_KEY_SIZE} octets requise.")
    if len(nonce) != ASCON_NONCE_SIZE:
        raise ValueError(f"Nonce de {ASCON_NONCE_SIZE} octets requis.")

    return ascon.encrypt(key, nonce, associated_data, plaintext,
                         variant="Ascon-128")


def ascon_decrypt(key: bytes, nonce: bytes, ciphertext: bytes,
                  associated_data: bytes = b"") -> Optional[bytes]:
    """
    Dechiffrement authentifie ASCON-128.

    Verifie le tag AVANT de retourner le plaintext.
    Si une seule modification est detectee (ciphertext, AD, ou nonce),
    la fonction renvoie None : on rejette le message.

    Returns:
        plaintext si le tag est valide, None sinon.
    """
    if len(key) != ASCON_KEY_SIZE:
        raise ValueError(f"Cle de {ASCON_KEY_SIZE} octets requise.")
    if len(nonce) != ASCON_NONCE_SIZE:
        raise ValueError(f"Nonce de {ASCON_NONCE_SIZE} octets requis.")

    return ascon.decrypt(key, nonce, associated_data, ciphertext,
                         variant="Ascon-128")


# ----------------------------------------------------------------------------
# 4. Helpers d'affichage (utilises par les demos)
# ----------------------------------------------------------------------------

def hexs(b: bytes, max_bytes: int = 8) -> str:
    """Formate des octets en hex tronque pour affichage propre."""
    h = b.hex()
    if len(b) > max_bytes:
        return h[: max_bytes * 2] + f"...({len(b)} octets)"
    return h
