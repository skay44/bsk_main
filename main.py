import sys
import tkinter as tk
from tkinter import messagebox, filedialog


# Znajdowanie pendrive
def find_pendrive():
    pass #TODO


# Odczytywanie zaszyfrowanego klucza RSA
def read_encrypted_rsa_key(pendrive_path):
    pass #TODO


# Odszyfrowywanie klucza
def decrypt_rsa_key(encrypted_rsa_key, pin):
    pass #TODO


# Odczytywanie odszyfrowanego klucza
def load_rsa_key_from_memory(decrypted_rsa_key):
    pass #TODO


class RSAApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.mode = tk.StringVar(value="")
        self.mode.set(' ')

        self.title("PDF TESTER")
        self.geometry("400x400")
        self.pendrive_path = None
        self.create_widgets()

    def create_widgets(self):
        self.label = tk.Label(self, text="Wybierz pendrive i wprowadź PIN aby odszyfrować klucz")
        self.label2 = tk.Label(self, text="Wybierz tryb działania programu:")

        self.pendrive_button = tk.Button(self, text="Wykryj pendrive", command=self.auto_detect_pendrive)
        self.pin_label = tk.Label(self, text="Wprowadź pin:")
        self.pin_entry = tk.Entry(self, show="*")
        self.pdf_button = tk.Button(self, text="Podaj sciezke do pdf", command=self.select_pdf)
        self.validate_or_sign1 = tk.Radiobutton(self, text="Validate", value="Validate", variable=self.mode)
        self.validate_or_sign2 = tk.Radiobutton(self, text="Sign", value="Sign", variable=self.mode)

        self.label.pack(pady=20)
        self.pendrive_button.pack(pady=10)
        self.pin_label.pack(pady=5)
        self.pin_entry.pack(pady=5)
        self.pdf_button.pack(pady=10)
        self.label2.pack(pady=20)
        self.validate_or_sign1.pack(pady=5)
        self.validate_or_sign2.pack(pady=5)

    def select_pdf(self):
        pass #TODO

    def auto_detect_pendrive(self):
        self.pendrive_path = find_pendrive()
        if self.pendrive_path:
            messagebox.showinfo("Znaleziono pendrive: ", f"Pendrive found at {self.pendrive_path}")
        else:
            messagebox.showwarning("Nie znaleziono pendrive: ", "Nie znaleziono pendrive'a w oczekiwanej lokalizacji.")


if __name__ == "__main__":
    app = RSAApp()
    app.mainloop()
