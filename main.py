import os
import sys
import tkinter as tk
import psutil
from tkinter import messagebox, filedialog

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import hashlib
from PyPDF2 import PdfReader, PdfWriter

# Znajdowanie pendrive
def find_pendrive():
    usb_drives = []
    partitions = psutil.disk_partitions()
    for p in partitions:
        if 'removable' in p.opts or 'media' in p.mountpoint.lower():
            usb_drives.append(p.device)
    return usb_drives

def read_public_key(pendrive_path):
    file_path = os.path.join(pendrive_path, "public.pem")
    with open(file_path, "rb") as f:
        data = f.read()
    public_key = serialization.load_pem_public_key(data)
    return public_key

# Odczytywanie zaszyfrowanego klucza RSA
def read_encrypted_rsa_key(pendrive_path):
    file_path = os.path.join(pendrive_path, "private_encrypted.bin")
    with open(file_path, "rb") as f:
        data = f.read()

    salt = data[:16]
    iv = data[16:32]
    encrypted_key = data[32:]
    return salt, iv, encrypted_key


# Odszyfrowywanie klucza
def decrypt_rsa_key(encrypted_rsa_key, pin, salt, iv):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    aes_key = kdf.derive(pin.encode())

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(encrypted_rsa_key) + decryptor.finalize()

    try:
        priv_key = serialization.load_pem_private_key(decrypted, password=None)
    except ValueError as e:
        raise ValueError("Nieprawidłowy PIN lub uszkodzony plik RSA") from e

    return priv_key


def sign_pfd(pdf_path, priv_key, output_path):
    # Read PDF bytes
    with open(pdf_path, "rb") as f:
        pdf_bytes = f.read()

    # Hash PDF content
    digest = hashlib.sha256(pdf_bytes).digest()

    # Sign hash with RSA private key (PKCS1v15)
    signature = priv_key.sign(
        digest,
        padding=padding.PKCS1v15(),
        algorithm=hashes.SHA256()
    )

    # Save signature alongside PDF (simple approach)
    with open(output_path, "wb") as f_out:
        f_out.write(pdf_bytes)
        f_out.write(b"\n%%SIGNATURE%%\n")
        f_out.write(signature)



def signed_output_path(input_path):
    base, ext = os.path.splitext(input_path)
    return base + "_signed" + ext

def validate_pdf(pdf_path, public_key):
    with open(pdf_path, "rb") as f:
        content = f.read()

    if b"\n%%SIGNATURE%%\n" not in content:
        raise ValueError("PDF not signed")

    pdf_bytes, signature = content.split(b"\n%%SIGNATURE%%\n")
    digest = hashlib.sha256(pdf_bytes).digest()

    # Verify signature
    try:
        public_key.verify(
            signature,
            digest,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

class RSAApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.mode = tk.StringVar(value="")
        self.mode.set(' ')

        self.title("PDF TESTER")
        self.geometry("400x400")
        self.pendrive_path = None
        self.create_widgets()
        self.selected_pdf = None

    def create_widgets(self):
        self.label = tk.Label(self, text="Wybierz pendrive i wprowadź PIN aby odszyfrować klucz")
        self.label2 = tk.Label(self, text="Wybierz tryb działania programu:")

        self.pendrive_button = tk.Button(self, text="Wykryj pendrive", command=self.execute_app)
        self.pin_label = tk.Label(self, text="Wprowadź pin:")
        self.pin_entry = tk.Entry(self, show="*")
        self.pdf_button = tk.Button(self, text="Podaj sciezke do pdf", command=self.select_pdf)
        self.pdf_path_label = tk.Label(self, text="No pdf selected...", wraplength=400)
        self.validate_or_sign1 = tk.Radiobutton(self, text="Validate", value="Validate", variable=self.mode)
        self.validate_or_sign2 = tk.Radiobutton(self, text="Sign", value="Sign", variable=self.mode)

        self.label.pack(pady=20)
        self.pendrive_button.pack(pady=10)
        self.pin_label.pack(pady=5)
        self.pin_entry.pack(pady=5)
        self.pdf_button.pack(pady=10)
        self.pdf_path_label.pack(pady=5)
        self.label2.pack(pady=20)
        self.validate_or_sign1.pack(pady=5)
        self.validate_or_sign2.pack(pady=5)

    def select_pdf(self):
        file_path = filedialog.askopenfilename(
            title="Wybierz plik PDF",
            filetypes=[("PDF files", "*.pdf")],
        )
        if file_path:
            self.selected_pdf = file_path
            self.pdf_path_label.config(text=f"Wybrany pdf: {file_path}")
        else:
            messagebox.showwarning("Nie wybrano pliku", "Nie wybrano żadnego pliku PDF.")

    def execute_app(self):
        self.pendrive_path = find_pendrive()
        if self.pendrive_path:
            messagebox.showinfo("Znaleziono pendrive: ", f"Pendrive found at {self.pendrive_path}")

            public_key = read_public_key(self.pendrive_path[0])
            salt, iv, encrypted_key = read_encrypted_rsa_key(self.pendrive_path[0])
            pin = self.pin_entry.get()
            try:
                priv_key = decrypt_rsa_key(encrypted_key, pin, salt, iv)
            except ValueError as e:
                messagebox.showerror("Error", "invalid pin or private key")
                return


            if(self.mode.get() == "Validate"):
                try:
                    result = validate_pdf(self.selected_pdf, public_key)
                except ValueError as e:
                    messagebox.showerror("Error", f"PDF is not signed")
                    return
                if(result):
                    messagebox.showinfo("Success!","PDF file is valid!")
                else:
                    messagebox.showinfo("Fail!","PDF file is invalid/modified!")
            if(self.mode.get() == "Sign"):
                sign_pfd(self.selected_pdf, priv_key, signed_output_path(self.selected_pdf))

        else:
            messagebox.showwarning("Nie znaleziono pendrive: ", "Nie znaleziono pendrive'a w oczekiwanej lokalizacji.")


if __name__ == "__main__":
    app = RSAApp()
    app.mainloop()
