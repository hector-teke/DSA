import os
import hashlib
from RSAcipher import encryption, decryption, generate_keys
import tkinter as tk
from tkinter import filedialog
import base64
import sys

def select_file(extension):
    root = tk.Tk()
    root.withdraw()

    file_path = filedialog.askopenfilename(
        title="Select file",
        filetypes=[("Public key file", "*." + extension)]
    )

    return file_path

def read_key_file(path):            # * for any file
    with open(path, 'r') as file:
        content_base64 = file.read()

    content = base64.b64decode(content_base64).decode('utf-8')

    module, key = content[1:-1].split(',')

    return module, key

def export_keys(modulo, pubkey, privkey):
    content = f'({modulo},{pubkey})'
    content_bytes = content.encode('utf-8')
    content_base64 = base64.b64encode(content_bytes).decode('utf-8')

    root = tk.Tk()
    root.withdraw()

    file1_path = filedialog.asksaveasfilename(
        defaultextension=".pub",
        filetypes=[("Public key file", "*.pub")],
    )

    with open(file1_path, 'w') as file:
        file.write(content_base64)
    print(f"File saved at {file1_path}")

    file2_path = filedialog.asksaveasfilename(
        defaultextension=".pub",
        filetypes=[("Private key file", "*.priv")],
    )

    with open(file2_path, 'w') as file:
        file.write(content_base64)
    print(f"File saved at {file2_path}")


def file_description(path):
    info = os.stat(path)
    print(f'Name: {os.path.basename(path)}\nPath: {path}\nSize: {info.st_size} bytes')


def file_hash(path):  # Compute hash of a given file
    with open(path, 'rb') as file:
        sha_hash = hashlib.sha512()

        # Processing in blocks enhances efficiency
        block = file.read(4096)
        while len(block) > 0:
            sha_hash.update(block)  # Process the current block
            block = file.read(4096)

        return sha_hash.hexdigest()     # Return hexadecimal value of hash

if __name__ == '__main__':

    pub, priv, mod = generate_keys(112)

    print(f'Pubkey: {pub}, Module: {mod}')
    print(f'Privkey: {priv}, Module: {mod}')

    export_keys(mod, pub, priv)

    file = select_file("pub")

    file_description(file)

    module, pubkey = read_key_file(file)

    print(f'Pubkey: {pubkey}, Module: {module}')









