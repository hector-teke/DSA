import os
import hashlib
from RSAcipher import encryption, decryption, generate_keys
import tkinter as tk
from tkinter import filedialog
import base64
from PyQt6.QtGui import QFont, QPixmap, QIcon
from PyQt6.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QPushButton, QMessageBox, QSpinBox
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

def export_keys(module, pubkey, privkey):
    pub_content = f'({module},{pubkey})'
    pub_content_bytes = pub_content.encode('utf-8')
    pub_content_base64 = base64.b64encode(pub_content_bytes).decode('utf-8')

    priv_content = f'({module},{privkey})'
    priv_content_bytes = priv_content.encode('utf-8')
    priv_content_base64 = base64.b64encode(priv_content_bytes).decode('utf-8')

    root = tk.Tk()
    root.withdraw()

    # Export the public key
    file1_path = filedialog.asksaveasfilename(
        defaultextension=".pub",
        filetypes=[("Public key file", "*.pub")],
    )

    with open(file1_path, 'w') as file:
        file.write(pub_content_base64)
    print(f"File saved at {file1_path}")

    # Export the private key
    file2_path = filedialog.asksaveasfilename(
        defaultextension=".pub",
        filetypes=[("Private key file", "*.priv")],
    )

    with open(file2_path, 'w') as file:
        file.write(priv_content_base64)
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

def export_signature(signature):
    content_bytes = signature.encode('utf-8')
    content_base64 = base64.b64encode(content_bytes).decode('utf-8')

    root = tk.Tk()
    root.withdraw()

    file_path = filedialog.asksaveasfilename(
        defaultextension=".sign",
        filetypes=[("Signature file", "*.sign")],
    )

    with open(file_path, 'w') as file:
        file.write(content_base64)
    print(f"File saved at {file_path}")


# USER INTERFACE ################################################################################

class Window(QWidget):

    pubkey = None
    privkey = None
    module = None
    file = None

    def __init__(self):
        super().__init__()
        self.initializeUI()

    def initializeUI(self):
        self.setGeometry(100, 100, 680, 350)  # PosX, PosY, Width, Height
        self.setWindowTitle("Digital Signature Algorithm")
        self.setWindowIcon(QIcon('resources/sign.png'))
        self.generate_layout()
        self.show()

    def generate_layout(self):
        keys_height = 20

        bits_hint = QLabel(self)
        bits_hint.setText("Bit length for the keys:")
        bits_hint.setFont(QFont('Arial', 10))
        bits_hint.move(240, keys_height + 5)

        self.bits_input = QSpinBox(self)
        self.bits_input.setRange(30, 1024)
        self.bits_input.setValue(112)
        self.bits_input.resize(50, 24)  # Width x Height
        self.bits_input.move(380, keys_height)

        # Buttons

        generate_keys_button = QPushButton(self)
        generate_keys_button.setText("Generate Keys")
        generate_keys_button.resize(160, 30)
        generate_keys_button.move(20, keys_height + 40)
        generate_keys_button.clicked.connect(self.generateKeys)

        import_public_button = QPushButton(self)
        import_public_button.setText("Import Public Key")
        import_public_button.resize(160, 30)
        import_public_button.move(180, keys_height + 40)
        import_public_button.clicked.connect(self.import_public)

        import_private_button = QPushButton(self)
        import_private_button.setText("Import Private Key")
        import_private_button.resize(160, 30)
        import_private_button.move(340, keys_height + 40)
        import_private_button.clicked.connect(self.import_private)

        import_file_button = QPushButton(self)
        import_file_button.setText("Import File")
        import_file_button.resize(160, 30)
        import_file_button.move(500, keys_height + 40)
        import_file_button.clicked.connect(self.import_file)

        # File Information

        info_height = 110

        self.icon = QLabel(self)
        self.icon.setPixmap(QPixmap("resources/file.png").scaled(120, 120))
        self.icon.move(40, info_height)

        self.name = QLineEdit(self)
        self.name.setReadOnly(True)
        self.name.setPlaceholderText("Name")
        self.name.resize(400, 24)  # Width x Height
        self.name.move(200, info_height + 10)

        self.path = QLineEdit(self)
        self.path.setReadOnly(True)
        self.path.setPlaceholderText("Path")
        self.path.resize(400, 24)  # Width x Height
        self.path.move(200, info_height + 50)

        self.size = QLineEdit(self)
        self.size.setReadOnly(True)
        self.size.setPlaceholderText("Size")
        self.size.resize(100, 24)  # Width x Height
        self.size.move(200, info_height + 90)

        self.type = QLineEdit(self)
        self.type.setReadOnly(True)
        self.type.setPlaceholderText("Type")
        self.type.resize(280, 24)  # Width x Height
        self.type.move(320, info_height + 90)

        # Signature

        sign_height = 250

        sign_button = QPushButton(self)
        sign_button.setText("Sign Document")
        sign_button.resize(320, 80)
        sign_button.move(20, sign_height)
        sign_button.clicked.connect(self.sign_document)

        verify_button = QPushButton(self)
        verify_button.setText("Verify Signature")
        verify_button.resize(320, 80)
        verify_button.move(340, sign_height)
        verify_button.clicked.connect(self.verify_signature)


    def generateKeys(self):
        self.pubkey, self.privkey, self.module = generate_keys(self.bits_input.value())
        export_keys(self.module, self.pubkey, self.privkey)

    def import_public(self):
        file = select_file("pub")
        self.module, self.pubkey = read_key_file(file)

    def import_private(self):
        file = select_file("priv")
        self.module, self.privkey = read_key_file(file)

    def import_file(self):
        self.file = select_file("*")
        info = os.stat(self.file)

        self.path.setText(self.file)
        self.name.setText(os.path.basename(self.file))
        self.size.setText(f'{info.st_size} bytes')

        ext = os.path.splitext(self.file)[-1]

        if ext == ".pdf":
            self.icon.setPixmap(QPixmap("resources/pdf.png").scaled(120, 120))
            self.type.setText(f'Portable Document File ({ext})')
        elif ext == ".docx":
            self.icon.setPixmap(QPixmap("resources/docx.png").scaled(120, 120))
            self.type.setText(f'Microsoft Word Document ({ext})')
        elif ext == ".rar":
            self.icon.setPixmap(QPixmap("resources/rar.png").scaled(120, 120))
            self.type.setText(f'Compressed file ({ext})')
        elif ext == ".txt":
            self.icon.setPixmap(QPixmap("resources/txt.png").scaled(120, 120))
            self.type.setText(f'Plain text ({ext})')
        elif ext == ".xml":
            self.icon.setPixmap(QPixmap("resources/xml.png").scaled(120, 120))
            self.type.setText(f'Extensible Markup Language document ({ext})')
        elif ext == ".zip":
            self.icon.setPixmap(QPixmap("resources/zip.png").scaled(120, 120))
            self.type.setText(f'Compressed file ({ext})')
        else:
            self.icon.setPixmap(QPixmap("resources/file.png").scaled(120, 120))
            self.type.setText(ext)


    def sign_document(self):
        hashed_document = file_hash(self.file)
        signature = encryption(hashed_document, self.privkey, self.module)
        export_signature(signature)

        message = QMessageBox()
        message.setWindowTitle("Information")
        message.setText("Signature was exported succesfully")
        message.setIcon(QMessageBox.Icon.Information)
        message.addButton(QPushButton("Ok"), QMessageBox.ButtonRole.AcceptRole)
        message.exec()

    def verify_signature(self):








if __name__ == '__main__':

    """pub, priv, mod = generate_keys(112)

    print(f'Pubkey: {pub}, Module: {mod}')
    print(f'Privkey: {priv}, Module: {mod}')

    export_keys(mod, pub, priv)

    file = select_file("pub")

    file_description(file)

    module, pubkey = read_key_file(file)

    print(f'Pubkey: {pubkey}, Module: {module}')"""

    app = QApplication(sys.argv)
    window = Window()
    sys.exit(app.exec())







