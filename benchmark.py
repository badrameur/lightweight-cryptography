"""
benchmark.py
============
Phase 3 du TP : comparaison de performances de 3 fonctions de hachage.

Algorithmes testes :
  1. ASCON-Hash (NIST lightweight crypto winner, 2023)
  2. BLAKE2s    (lightweight modern, optimise CPU 32 bits)
  3. SHA-256    (reference 'lourde' pour comparaison)

Mesures :
  - Temps moyen pour hacher un mot de passe
  - Debit pour hacher 1 Mio de donnees
  - Taille de sortie

Lancement : python benchmark.py
"""

import os
import time
import statistics
from typing import Callable, List

from crypto_utils import hash_password, SUPPORTED_HASHES


# ----------------------------------------------------------------------------
# Mesures
# ----------------------------------------------------------------------------

def time_password_hash(algo: str, password: str, n_iter: int) -> float:
    """Temps moyen (en microsecondes) pour hacher un mot de passe."""
    times = []
    for _ in range(n_iter):
        t0 = time.perf_counter_ns()
        _ = hash_password(password, algorithm=algo)
        t1 = time.perf_counter_ns()
        times.append((t1 - t0) / 1000.0)   # ns -> us
    return statistics.median(times)


def time_throughput(hash_func: Callable[[bytes], bytes], data_size: int) -> float:
    """Debit en MiB/s pour hacher `data_size` octets."""
    data = os.urandom(data_size)
    t0 = time.perf_counter()
    _ = hash_func(data)
    t1 = time.perf_counter()
    elapsed = t1 - t0
    return (data_size / (1024 * 1024)) / elapsed if elapsed > 0 else float("inf")


def make_hash_func(algo: str) -> Callable[[bytes], bytes]:
    """Retourne une fonction qui prend des bytes et renvoie le digest."""
    import hashlib
    import ascon
    if algo == "ascon":
        return lambda d: ascon.hash(d, variant="Ascon-Hash", hashlength=32)
    if algo == "blake2s":
        return lambda d: hashlib.blake2s(d).digest()
    if algo == "sha256":
        return lambda d: hashlib.sha256(d).digest()
    raise ValueError(algo)


# ----------------------------------------------------------------------------
# Affichage
# ----------------------------------------------------------------------------

def fmt_table(rows: List[List[str]]) -> str:
    """Formate une liste de lignes en tableau ASCII."""
    if not rows:
        return ""
    widths = [max(len(c) for c in col) for col in zip(*rows)]
    sep = "+".join("-" * (w + 2) for w in widths)
    sep = f"+{sep}+"
    out = [sep]
    for i, row in enumerate(rows):
        line = "| " + " | ".join(c.ljust(w) for c, w in zip(row, widths)) + " |"
        out.append(line)
        if i == 0:
            out.append(sep)
    out.append(sep)
    return "\n".join(out)


# ----------------------------------------------------------------------------
# Scenario
# ----------------------------------------------------------------------------

def main() -> None:
    print("=" * 72)
    print("  BENCHMARK : ASCON-Hash vs BLAKE2s vs SHA-256")
    print("=" * 72)
    print()

    password = "MonMotDePasseSecret!"
    n_pwd = 5000
    data_mb_size = 1 * 1024 * 1024   # 1 MiB

    rows = [["Algorithme", "Sortie", f"Hash mdp (us, mediane sur {n_pwd})",
             f"Debit (MiB/s, sur {data_mb_size//1024} KiB)"]]

    print(f"  Mot de passe teste : {password!r}")
    print(f"  Iterations         : {n_pwd}")
    print(f"  Test debit         : 1 MiB de donnees aleatoires")
    print()

    for algo in SUPPORTED_HASHES:
        print(f"  Mesure de {algo}...")
        # 1) temps de hash d'un mot de passe (court : ~20 octets)
        t_pwd_us = time_password_hash(algo, password, n_pwd)

        # 2) debit sur 1 MiB
        hf = make_hash_func(algo)
        # On chauffe avec quelques iterations
        for _ in range(3):
            hf(b"warmup" * 1000)
        # On moyenne sur 5 mesures
        debits = [time_throughput(hf, data_mb_size) for _ in range(5)]
        debit_med = statistics.median(debits)

        # 3) taille de sortie
        digest = hf(b"x")
        out_bits = len(digest) * 8

        rows.append([
            algo.upper(),
            f"{len(digest)} o ({out_bits} bits)",
            f"{t_pwd_us:7.2f}",
            f"{debit_med:7.1f}",
        ])

    print()
    print(fmt_table(rows))
    print()

    # ------------------------------------------------------------------
    # Analyse qualitative pour la presentation
    # ------------------------------------------------------------------
    print("Analyse :")
    print("  - ASCON-Hash : optimise pour les contraintes hardware (IoT, RFID)")
    print("                 -> en pure Python, plus lent, mais c'est attendu :")
    print("                    son avantage est en silicium (faible empreinte gates).")
    print("  - BLAKE2s    : concu pour le software 32 bits, tres rapide en Python.")
    print("  - SHA-256    : reference universelle, tres optimisee, mais 'lourd'")
    print("                 en hardware compare a ASCON.")
    print()
    print("  Conclusion :")
    print("    -> En Python pur, BLAKE2s/SHA-256 dominent l'execution.")
    print("    -> En IoT/embarque, ASCON gagne sur l'empreinte hardware,")
    print("       la consommation, et le code size.")
    print("    -> ASCON reste le meilleur choix pour l'objectif du TP")
    print("       (cryptographie legere) malgre des chiffres Python defavorables.")
    print()


if __name__ == "__main__":
    main()
