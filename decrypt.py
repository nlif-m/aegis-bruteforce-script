#!/usr/bin/env python3

# this depends on the 'cryptography' package
# pip install cryptography

import argparse
import base64
import getpass
import io
import json
import sys
import multiprocessing as mp

import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


backend = default_backend()

already_decrypted_passwords = set()
data = None
header = None
slots = None

log = None


def passwords_gen(start=0, stop=10**16):
    for x in range(start, stop, 1):
        if x in already_decrypted_passwords:
            continue
        yield x


def decrypt(password: int) -> None:
    print(f"trying with password: {password}", file=log)
    password_bytes = str(password).encode("utf-8")
    # try the given password on every slot until one succeeds
    master_key = None
    for slot in slots:
        # derive a key from the given password
        kdf = Scrypt(
            salt=bytes.fromhex(slot["salt"]),
            length=32,
            n=slot["n"],
            r=slot["r"],
            p=slot["p"],
            backend=backend,
        )
        key = kdf.derive(password_bytes)

        # try to use the derived key to decrypt the master key
        cipher = AESGCM(key)
        params = slot["key_params"]
        try:
            master_key = cipher.decrypt(
                nonce=bytes.fromhex(params["nonce"]),
                data=bytes.fromhex(slot["key"]) + bytes.fromhex(params["tag"]),
                associated_data=None,
            )
            break
        except cryptography.exceptions.InvalidTag:
            pass
    if master_key:
        print(f"password: {password}")
        with open("password.txt", "w") as f:
            f.write(str(password))
    return master_key


def main():
    parser = argparse.ArgumentParser(description="Decrypt an Aegis vault")
    parser.add_argument(
        "--input", dest="input", required=True, help="encrypted Aegis vault file"
    )
    parser.add_argument(
        "--output", dest="output", default="-", help="output file ('-' for stdout)"
    )
    parser.add_argument(
        "--start", dest="start", type=int, default=0, help="start range"
    )
    parser.add_argument(
        "--stop", dest="stop", type=int, default=10**8, help="stop range"
    )
    parser.add_argument(
        "--cpu-count", dest="cpu_count", type=int, default=mp.cpu_count(), help="cpu to use for bruteforce"
    )
    args = parser.parse_args()
    try:
        with io.open("passwords.log", "r") as f:
            print("Start reading passwords.log")
            for line in f:
                line = line.removeprefix("trying with password: ").rstrip()
                already_decrypted_passwords.add(int(line))
    except FileNotFoundError as e:
        print("Not have passwords.log yet")
    else:
        print("Finished reading passwords.log")
    
    # parse the Aegis vault file
    with io.open(args.input, "r") as f:
        global data
        data = json.load(f)

    global header
    global slots
    global log
    log = open("passwords.log", "a")
    # extract all password slots from the header
    header = data["header"]
    slots = [slot for slot in header["slots"] if slot["type"] == 1]

    passwords = passwords_gen(args.start, args.stop)
    with mp.Pool(args.cpu_count) as p:
        for master_key in p.imap_unordered(
            decrypt, passwords, int(args.stop / (args.cpu_count) / 4)
        ):
            if not master_key:
                continue
            print(f"Right: {master_key}")
            # decode the base64 vault contents
            content = base64.b64decode(data["db"])

            # decrypt the vault contents using the master key
            params = header["params"]
            cipher = AESGCM(master_key)
            db = cipher.decrypt(
                nonce=bytes.fromhex(params["nonce"]),
                data=content + bytes.fromhex(params["tag"]),
                associated_data=None,
            )

            db = db.decode("utf-8")
            if args.output != "-":
                with io.open(args.output, "w") as f:
                    f.write(db)
            else:
                print(db)
            log.close()
            sys.exit(0)


if __name__ == "__main__":
    main()
