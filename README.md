# TP2 — Lightweight Cryptography (ASCON + Lightweight Hashes)

Implémentation pédagogique d’un protocole d’authentification utilisant ASCON-AEAD et des fonctions de hachage légères. Le projet comprend une démonstration locale, un client et un serveur TCP, ainsi qu’un benchmark.

## Contenu du dossier

| Fichier | Rôle |
|---|---|
| `crypto_utils.py` | Briques crypto : hash, ASCON-AEAD, nonces |
| `protocol.py` | Format des messages réseau (longueur + JSON) |
| `demo_local.py` | **Démo principale** — protocole pas-à-pas + 3 attaques |
| `server.py` | Serveur TCP (port 5050) |
| `client.py` | Client TCP CLI |
| `benchmark.py` | Comparaison ASCON-Hash / BLAKE2s / SHA-256 |
| `requirements.txt` | Dépendance : `ascon` |

## Installation

```bash
pip install -r requirements.txt
```

## Comment lancer chaque démo

### 1. Démo locale (la plus claire pour la présentation)

```bash
python demo_local.py
```

Affiche les 3 phases du protocole + 3 tests d'attaques (mauvais mdp,
modification du ciphertext, rejeu).

### 2. Démo réseau client/serveur (2 terminaux)

**Terminal 1** :
```bash
python server.py
```

**Terminal 2** :
```bash
# Phase 1 - enregistrement
python client.py register alice "MonMotDePasseSecret!"

# Phase 2 - authentification réussie
python client.py auth alice "MonMotDePasseSecret!"

# Phase 2 - authentification échouée
python client.py auth alice "MauvaisMotDePasse"
```

### 3. Benchmark des fonctions de hachage (Phase 3 du TP)

```bash
python benchmark.py
```

## Paramètres cryptographiques

| Paramètre | Valeur |
|---|---|
| AEAD | ASCON-128 (NIST lightweight winner 2023) |
| Clé K | 16 octets (128 bits), pré-partagée |
| Nonce ASCON | 16 octets = `Nc` (8 octets, client) ‖ `Ns` (8 octets, serveur) |
| Tag | 16 octets (128 bits d'intégrité) |
| Hash par défaut | ASCON-Hash (256 bits) |
| Hashs comparés | ASCON-Hash, BLAKE2s, SHA-256 |
| Associated Data | `user_id` (binding identité) |

## Sécurité — comment chaque attaque est mitigée

| Attaque | Mitigation dans le code |
|---|---|
| Eavesdropping | `Hp` est chiffré par ASCON (`ascon_encrypt`) |
| Impersonation | Sans `K` ni `H(password)`, l'attaquant ne peut produire un Hp valide |
| Replay | Nonces frais à chaque session → nonce ASCON `Nc‖Ns` toujours nouveau |
| MITM/altération | Tag ASCON 128 bits sur (ciphertext + AD) |

## Choix d'implémentation à mentionner en présentation

1. **`Nc ‖ Ns` comme nonce ASCON** : 8 + 8 = 16 octets, exactement la taille
   requise. Les deux parties contribuent à la fraîcheur ; aucune ne peut
   forcer un nonce répété.
2. **AD = `user_id`** : le tag lie le message à l'identité revendiquée.
3. **`hash_password(pwd, algo)`** factorise les 3 hashs derrière la même
   API → le swap d'algo est trivial pour le benchmark.
4. **`ascon_decrypt` retourne `None` si le tag est invalide** → le serveur
   distingue "tag cassé" (MITM) de "Hp différent" (mauvais mdp).
5. **Stockage côté serveur = `H(password)`** : le mot de passe en clair
   ne quitte jamais le client.

## Ce qu'on ne fait pas (et pourquoi)

- **Pas de salage du hash** : le TP demande un hash simple. En production,
  on ajouterait Argon2/scrypt avec sel.
- **Pas de PFS (forward secrecy)** : la session est fermée à la fin. On
  pourrait dériver une clé de session via HKDF(K, Nc‖Ns).
- **Pas de protection contre l'attaque de la base** : si l'adversaire
  vole la DB serveur, il a `H(password)` et peut s'authentifier (vu que
  c'est exactement ce que le client envoie chiffré). Solution : PAKE.
