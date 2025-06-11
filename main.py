## @file rsa_pdf_signer.py
#  @brief Aplikacja GUI do podpisywania i weryfikacji podpisów PDF przy użyciu kluczy RSA zapisanych na pendrive.

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


## @brief Znajduje podłączone pendrive'y.
#  @return Lista ścieżek do wykrytych pendrive'ów.
def find_pendrive():
    usb_drives = []
    partitions = psutil.disk_partitions()
    for p in partitions:
        if 'removable' in p.opts or 'media' in p.mountpoint.lower():
            usb_drives.append(p.device)
    return usb_drives


## @brief Odczytuje klucz publiczny z pendrive'a.
#  @param pendrive_path Ścieżka do pendrive'a.
#  @return Załadowany klucz publiczny.
def read_public_key(pendrive_path):
    file_path = os.path.join(pendrive_path, "public.pem")
    with open(file_path, "rb") as f:
        data = f.read()
    public_key = serialization.load_pem_public_key(data)
    return public_key


## @brief Odczytuje zaszyfrowany klucz prywatny RSA z pendrive'a.
#  @param pendrive_path Ścieżka do pendrive'a.
#  @return Salt, IV i zaszyfrowany klucz prywatny.
def read_encrypted_rsa_key(pendrive_path):
    file_path = os.path.join(pendrive_path, "private_encrypted.bin")
    with open(file_path, "rb") as f:
        data = f.read()

    salt = data[:16]
    iv = data[16:32]
    encrypted_key = data[32:]
    return salt, iv, encrypted_key


## @brief Odszyfrowuje klucz prywatny RSA z użyciem PINu.
#  @param encrypted_rsa_key Zaszyfrowany klucz.
#  @param pin PIN wprowadzony przez użytkownika.
#  @param salt Salt użyty do KDF.
#  @param iv Wektor inicjalizacyjny do AES.
#  @return Odszyfrowany klucz prywatny RSA.
#  @throws ValueError jeśli PIN jest nieprawidłowy lub plik RSA uszkodzony.
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

## @brief Podpisuje plik PDF kluczem prywatnym.
#  @param pdf_path Ścieżka do pliku PDF.
#  @param priv_key Klucz prywatny RSA.
#  @param output_path Ścieżka do zapisania podpisanego pliku PDF.
def sign_pfd(pdf_path, priv_key, output_path):
    # Read PDF bytes
    with open(pdf_path, "rb") as f:
        pdf_bytes = f.read()

    digest = hashlib.sha256(pdf_bytes).digest()

    signature = priv_key.sign(
        digest,
        padding=padding.PKCS1v15(),
        algorithm=hashes.SHA256()
    )

    with open(output_path, "wb") as f_out:
        f_out.write(pdf_bytes)
        f_out.write(b"\n%%SIGNATURE%%\n")
        f_out.write(signature)

## @brief Generuje ścieżkę do podpisanego pliku PDF.
#  @param input_path Ścieżka do wejściowego pliku PDF.
#  @return Nowa ścieżka do podpisanego pliku PDF.
def signed_output_path(input_path):
    base, ext = os.path.splitext(input_path)
    return base + "_signed" + ext

## @brief Weryfikuje podpis pliku PDF.
#  @param pdf_path Ścieżka do pliku PDF.
#  @param public_key Klucz publiczny do weryfikacji podpisu.
#  @return True jeśli podpis poprawny, False w przeciwnym razie.
#  @throws ValueError jeśli PDF nie zawiera podpisu.
def validate_pdf(pdf_path, public_key):
    with open(pdf_path, "rb") as f:
        content = f.read()

    if b"\n%%SIGNATURE%%\n" not in content:
        raise ValueError("PDF nie jest podpisany")

    pdf_bytes, signature = content.split(b"\n%%SIGNATURE%%\n")
    digest = hashlib.sha256(pdf_bytes).digest()

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

## @class RSAApp
#  @brief Klasa GUI aplikacji.
class RSAApp(tk.Tk):
    ## @brief Konstruktor GUI aplikacji.
    def __init__(self):
        super().__init__()
        self.mode = tk.StringVar(value="")
        self.mode.set(' ')

        self.title("PDF TESTER")
        self.geometry("400x400")
        self.pendrive_path = None
        self.create_widgets()
        self.selected_pdf = None

    ## @brief Tworzy elementy GUI.
    def create_widgets(self):
        self.label = tk.Label(self, text="Wybierz pendrive i wprowadź PIN aby odszyfrować klucz")
        self.label2 = tk.Label(self, text="Wybierz tryb działania programu:")


        self.pin_label = tk.Label(self, text="Wprowadź pin:")
        self.pin_entry = tk.Entry(self, show="*")
        self.pdf_button = tk.Button(self, text="Podaj sciezke do pdf", command=self.select_pdf)
        self.pdf_path_label = tk.Label(self, text="Brak wybranego pdfa...", wraplength=400)
        self.validate_or_sign1 = tk.Radiobutton(self, text="Sprawdź poprawność", value="Validate",variable=self.mode)
        self.validate_or_sign2 = tk.Radiobutton(self, text="Podpisz", value="Sign", variable=self.mode)
        self.pendrive_button = tk.Button(self, text="Zatwierdź i rozpocznij", command=self.execute_app)

        self.label.pack(pady=20)
        self.pdf_button.pack(pady=10)
        self.pdf_path_label.pack(pady=5)
        self.pin_label.pack(pady=5)
        self.pin_entry.pack(pady=5)
        self.label2.pack(pady=20)
        self.validate_or_sign1.pack(pady=5)
        self.validate_or_sign2.pack(pady=5)
        self.pendrive_button.pack(pady=10)

    ## @brief Umożliwia wybór pliku PDF przez użytkownika.
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

    ## @brief Główna logika aplikacji: wykrywa pendrive, wczytuje klucze i wykonuje podpis lub weryfikację.
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
                messagebox.showerror("Błąd", "Niepoprawny klucz prywatny lub niepoprawny pin")
                return

            if self.mode.get() == "Validate":
                try:
                    result = validate_pdf(self.selected_pdf, public_key)
                except ValueError as e:
                    messagebox.showerror("Błąd", "PDF nie jest podpisany")
                    return
                if (result):
                    messagebox.showinfo("Sukces!", "PDF podpisany poprawnie!")
                else:
                    messagebox.showinfo("Błąd!", "PDF podpisany niepoprawnie lub zmodyfikowany!")
            if self.mode.get() == "Sign":
                sign_pfd(self.selected_pdf, priv_key, signed_output_path(self.selected_pdf))

        else:
            messagebox.showwarning("Nie znaleziono pendrive: ", "Nie znaleziono pendrive'a w oczekiwanej lokalizacji.")


if __name__ == "__main__":
    app = RSAApp()
    app.mainloop()
