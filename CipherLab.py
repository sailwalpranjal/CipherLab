import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from Crypto.Cipher import AES, Blowfish, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib
import threading
import time
import pyttsx3
import langid


class CipherLab(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CipherLab")
        self.geometry("800x600")

        self.master_password_var = tk.StringVar()
        self.bg_color = tk.StringVar(value="white")
        self.text_color = tk.StringVar(value="black")
        self.rsa_key_size = tk.IntVar(value=2048)

        self.rsa_private_key = None
        self.rsa_public_key = None

        self.logs = []

        self.create_widgets()
        self.setup_menu()

    def create_widgets(self):
        # Input and Output text widgets
        self.input_text_widget = tk.Text(self, height=10)
        self.input_text_widget.pack(
            fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.output_text_widget = tk.Text(self, height=10)
        self.output_text_widget.pack(
            fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Log text widget
        self.log_text = tk.Text(self, height=5, state=tk.DISABLED)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Theme settings
        self.create_theme_frame()

        # Encryption and Decryption options
        self.create_encryption_frame()

        # Language Detection and Speech Synthesis
        self.create_language_synthesis_frame()

        # Progress Bar
        self.create_progress_bar()

    def create_theme_frame(self):
        theme_frame = tk.Frame(self)
        theme_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(theme_frame, text="Background Color:").pack(
            side=tk.LEFT, padx=5)
        ttk.Entry(theme_frame, textvariable=self.bg_color).pack(
            side=tk.LEFT, padx=5)
        ttk.Label(theme_frame, text="Text Color:").pack(side=tk.LEFT, padx=5)
        ttk.Entry(theme_frame, textvariable=self.text_color).pack(
            side=tk.LEFT, padx=5)
        ttk.Button(theme_frame, text="Apply Theme",
                   command=self.apply_theme).pack(side=tk.LEFT, padx=5)

    def create_encryption_frame(self):
        encryption_frame = tk.Frame(self)
        encryption_frame.pack(fill=tk.X, padx=10, pady=5)

        self.encryption_method = tk.StringVar(value="AES")
        ttk.Radiobutton(encryption_frame, text="AES",
                        variable=self.encryption_method, value="AES").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(encryption_frame, text="RSA",
                        variable=self.encryption_method, value="RSA").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(encryption_frame, text="Blowfish",
                        variable=self.encryption_method, value="Blowfish").pack(side=tk.LEFT, padx=5)

        self.encryption_key_var = tk.StringVar()
        ttk.Label(encryption_frame, text="Encryption Key:").pack(
            side=tk.LEFT, padx=5)
        ttk.Entry(encryption_frame, textvariable=self.encryption_key_var,
                  show="*").pack(side=tk.LEFT, padx=5)

        ttk.Button(encryption_frame, text="Encrypt",
                   command=self.encrypt_text).pack(side=tk.LEFT, padx=5)
        ttk.Button(encryption_frame, text="Decrypt",
                   command=self.decrypt_text).pack(side=tk.LEFT, padx=5)

    def create_language_synthesis_frame(self):
        lang_frame = tk.Frame(self)
        lang_frame.pack(fill=tk.X, padx=10, pady=5)

        self.language_detect_button = ttk.Button(
            lang_frame, text="Detect Language", command=self.detect_language)
        self.language_detect_button.pack(side=tk.LEFT, padx=5)

        self.speak_text_button = ttk.Button(
            lang_frame, text="Speak Text", command=self.speak_text)
        self.speak_text_button.pack(side=tk.LEFT, padx=5)

    def create_progress_bar(self):
        self.progress = ttk.Progressbar(
            self, orient="horizontal", length=200, mode="determinate")
        self.progress.pack(pady=5)

    def setup_menu(self):
        menubar = tk.Menu(self)
        self.config(menu=menubar)

        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Open", command=self.open_file)
        file_menu.add_command(label="Save", command=self.save_file)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.quit)

        edit_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Edit", menu=edit_menu)
        edit_menu.add_command(label="Undo", command=self.undo)
        edit_menu.add_command(label="Redo", command=self.redo)
        edit_menu.add_command(label="Clear", command=self.clear_text)

        settings_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Settings", menu=settings_menu)
        settings_menu.add_command(
            label="Set Password", command=self.set_master_password)
        settings_menu.add_command(
            label="Dark Mode", command=self.toggle_dark_mode)

        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="User Guide", command=self.show_user_guide)
        help_menu.add_command(label="About", command=self.show_about)

    def toggle_dark_mode(self):
        if self.bg_color.get() == "white":
            self.bg_color.set("black")
            self.text_color.set("white")
        else:
            self.bg_color.set("white")
            self.text_color.set("black")
        self.apply_theme()

    def apply_theme(self):
        bg_color = self.bg_color.get()
        text_color = self.text_color.get()
        self.configure(bg=bg_color)
        self.input_text_widget.configure(bg=bg_color, fg=text_color)
        self.output_text_widget.configure(bg=bg_color, fg=text_color)
        self.log_text.configure(bg=bg_color, fg=text_color)

    def open_file(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            with open(file_path, "r") as file:
                self.input_text_widget.delete("1.0", tk.END)
                self.input_text_widget.insert(tk.END, file.read())
            self.log(f"File opened: {file_path}")

    def save_file(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[
                                                 ("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            with open(file_path, "w") as file:
                file.write(self.input_text_widget.get("1.0", tk.END))
            self.log(f"File saved: {file_path}")

    def undo(self):
        try:
            self.input_text_widget.edit_undo()
        except:
            pass

    def redo(self):
        try:
            self.input_text_widget.edit_redo()
        except:
            pass

    def clear_text(self):
        self.input_text_widget.delete("1.0", tk.END)

    def encrypt_text(self):
        method = self.encryption_method.get()
        if method == "AES":
            self.encrypt_aes()
        elif method == "RSA":
            self.encrypt_rsa()
        elif method == "Blowfish":
            self.encrypt_blowfish()

    def decrypt_text(self):
        method = self.encryption_method.get()
        if method == "AES":
            self.decrypt_aes()
        elif method == "RSA":
            self.decrypt_rsa()
        elif method == "Blowfish":
            self.decrypt_blowfish()

    def encrypt_aes(self):
        text = self.input_text_widget.get("1.0", tk.END).encode()
        password = self.encryption_key_var.get().encode()

        try:
            salt = get_random_bytes(16)
            key = hashlib.pbkdf2_hmac("sha256", password, salt, 100000, 32)
            cipher = AES.new(key, AES.MODE_CBC)
            ct_bytes = cipher.encrypt(pad(text, AES.block_size))
            iv = cipher.iv
            ct = base64.b64encode(salt + iv + ct_bytes).decode("utf-8")
            self.output_text_widget.delete("1.0", tk.END)
            self.output_text_widget.insert(tk.END, ct)
            self.log("Text encrypted with AES")
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))

    def decrypt_aes(self):
        encrypted_text = self.output_text_widget.get("1.0", tk.END).encode()
        password = self.encryption_key_var.get().encode()

        try:
            encrypted_data = base64.b64decode(encrypted_text)
            salt = encrypted_data[:16]
            iv = encrypted_data[16:32]
            ct = encrypted_data[32:]
            key = hashlib.pbkdf2_hmac("sha256", password, salt, 100000, 32)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), AES.block_size).decode("utf-8")
            self.input_text_widget.delete("1.0", tk.END)
            self.input_text_widget.insert(tk.END, pt)
            self.log("Text decrypted with AES")
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))

    def generate_rsa_keys(self):
        try:
            key = RSA.generate(self.rsa_key_size.get())
            self.rsa_private_key = key.export_key()
            self.rsa_public_key = key.publickey().export_key()
            self.log("RSA keys generated")
        except Exception as e:
            messagebox.showerror("Key Generation Error", str(e))

    def encrypt_rsa(self):
        text = self.input_text_widget.get("1.0", tk.END).encode()

        try:
            if not self.rsa_public_key:
                self.generate_rsa_keys()
            rsa_key = RSA.import_key(self.rsa_public_key)
            cipher = PKCS1_OAEP.new(rsa_key)
            ct_bytes = cipher.encrypt(text)
            ct = base64.b64encode(ct_bytes).decode("utf-8")
            self.output_text_widget.delete("1.0", tk.END)
            self.output_text_widget.insert(tk.END, ct)
            self.log("Text encrypted with RSA")
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))

    def decrypt_rsa(self):
        encrypted_text = self.output_text_widget.get("1.0", tk.END).encode()

        try:
            if not self.rsa_private_key:
                raise ValueError("Private key not found")
            rsa_key = RSA.import_key(self.rsa_private_key)
            cipher = PKCS1_OAEP.new(rsa_key)
            encrypted_data = base64.b64decode(encrypted_text)
            pt = cipher.decrypt(encrypted_data).decode("utf-8")
            self.input_text_widget.delete("1.0", tk.END)
            self.input_text_widget.insert(tk.END, pt)
            self.log("Text decrypted with RSA")
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))

    def encrypt_blowfish(self):
        text = self.input_text_widget.get("1.0", tk.END).encode()
        password = self.encryption_key_var.get().encode()

        try:
            cipher = Blowfish.new(password, Blowfish.MODE_CBC)
            ct_bytes = cipher.encrypt(pad(text, Blowfish.block_size))
            iv = cipher.iv
            ct = base64.b64encode(iv + ct_bytes).decode("utf-8")
            self.output_text_widget.delete("1.0", tk.END)
            self.output_text_widget.insert(tk.END, ct)
            self.log("Text encrypted with Blowfish")
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))

    def decrypt_blowfish(self):
        encrypted_text = self.output_text_widget.get("1.0", tk.END).encode()
        password = self.encryption_key_var.get().encode()

        try:
            encrypted_data = base64.b64decode(encrypted_text)
            iv = encrypted_data[:8]
            ct = encrypted_data[8:]
            cipher = Blowfish.new(password, Blowfish.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), Blowfish.block_size).decode("utf-8")
            self.input_text_widget.delete("1.0", tk.END)
            self.input_text_widget.insert(tk.END, pt)
            self.log("Text decrypted with Blowfish")
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))

    def set_master_password(self):
        new_password = self.master_password_var.get()
        if new_password:
            self.master_password = new_password
            self.log("Master password updated")
        else:
            messagebox.showerror("Password Error", "Password cannot be empty")

    def show_user_guide(self):
        guide = "User Guide\n\n" \
                "1. Use the File menu to open and save text files.\n" \
                "2. Use the Edit menu for text operations like undo, redo, and clear text.\n" \
                "3. The Encrypt/Decrypt section allows you to encrypt and decrypt text using AES, RSA, and Blowfish.\n" \
                "4. Use the Logs section to view and export logs.\n" \
                "5. Use the Settings menu to customize themes and set the master password.\n" \
                "6. Dark Mode using the Settings menu."
        messagebox.showinfo("User Guide", guide)

    def show_about(self):
        about_text = "CipherLab\n" \
                     "Version 1.0\n" \
                     "Graphic Era Hill University\n" \
                     "Developed by Pranjal Sailwal"
        messagebox.showinfo("About", about_text)

    def log(self, message):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"{timestamp} - {message}\n"
        self.logs.append(log_message)
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.insert(tk.END, log_message)
        self.log_text.configure(state=tk.DISABLED)

    def detect_language(self):
        text = self.input_text_widget.get("1.0", tk.END).strip()
        if text:
            lang, confidence = langid.classify(text)
            self.log(f"Detected language: {lang} (Confidence: {confidence})")
        else:
            messagebox.showerror(
                "Language Detection Error", "Input text is empty")

    def speak_text(self):
        text = self.input_text_widget.get("1.0", tk.END).strip()
        if text:
            engine = pyttsx3.init()
            engine.say(text)
            engine.runAndWait()
            self.log("Text spoken")
        else:
            messagebox.showerror("Speech Synthesis Error",
                                 "Input text is empty")


if __name__ == "__main__":
    app = CipherLab()
    app.mainloop()
# Minor update to optimize function
