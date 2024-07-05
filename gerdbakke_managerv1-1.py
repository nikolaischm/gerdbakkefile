import os
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from cryptography.fernet import Fernet

# Generiere einen Schlüssel und speichere ihn in einer Datei (einmalig ausführen)
def generate_key():
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)

# Lese den Schlüssel aus der Datei
def load_key():
    return open("key.key", "rb").read()

# Verschlüsseln und Speichern von Daten im .gerdbakke-Format
def save_encrypted_gerdbakke_format(filename, title, author, date, content, key):
    fernet = Fernet(key)
    data = f"#HEADER\nTitle: {title}\nAuthor: {author}\nDate: {date}\n\n#CONTENT\n"
    for paragraph in content:
        data += paragraph + "\n\n"
    encrypted_data = fernet.encrypt(data.encode())

    with open(filename, 'wb') as file:
        file.write(encrypted_data)

# Entschlüsseln und Laden von Daten aus dem .gerdbakke-Format
def load_encrypted_gerdbakke_format(filename, key):
    fernet = Fernet(key)
    with open(filename, 'rb') as file:
        encrypted_data = file.read()
        decrypted_data = fernet.decrypt(encrypted_data).decode()

    lines = decrypted_data.split('\n')
    header = {}
    content = []
    reading_header = False
    reading_content = False

    for line in lines:
        if line.strip() == "#HEADER":
            reading_header = True
            continue
        elif line.strip() == "#CONTENT":
            reading_header = False
            reading_content = True
            continue

        if reading_header:
            if ": " in line:
                key, value = line.strip().split(": ", 1)
                header[key] = value
        elif reading_content:
            if line.strip():  # Absatz erkannt
                content.append(line.strip())

    return header, content

# Hauptfenster
class GerdbakkeApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Gerdbakke File Manager")
        self.geometry("500x400")
        self.key = None

        # Schlüssel laden oder generieren
        if not os.path.exists("key.key"):
            generate_key()
        self.key = load_key()

        # UI-Komponenten erstellen
        self.create_widgets()

    def create_widgets(self):
        self.create_button = tk.Button(self, text="Create a new .gerdbakke file", command=self.create_file)
        self.create_button.pack(pady=10)

        self.load_button = tk.Button(self, text="Load and display a .gerdbakke file", command=self.load_file)
        self.load_button.pack(pady=10)

        self.exit_button = tk.Button(self, text="Exit", command=self.quit)
        self.exit_button.pack(pady=10)

    def create_file(self):
        filename = filedialog.asksaveasfilename(defaultextension=".gerdbakke", filetypes=[("Gerdbakke files", "*.gerdbakke")])
        if filename:
            title = simpledialog.askstring("Input", "Enter the title:")
            author = simpledialog.askstring("Input", "Enter the author:")
            date = simpledialog.askstring("Input", "Enter the date (YYYY-MM-DD):")
            content = simpledialog.askstring("Input", "Enter the content (use '\\n' for new lines):")
            if title and author and date and content:
                content = content.split('\\n')
                save_encrypted_gerdbakke_format(filename, title, author, date, content, self.key)
                messagebox.showinfo("Success", f"File {filename} saved successfully!")

    def load_file(self):
        filename = filedialog.askopenfilename(filetypes=[("Gerdbakke files", "*.gerdbakke")])
        if filename:
            try:
                header, content = load_encrypted_gerdbakke_format(filename, self.key)
                content_text = "\n".join(content)
                messagebox.showinfo("File Content", f"Header: {header}\n\nContent:\n{content_text}")
            except FileNotFoundError:
                messagebox.showerror("Error", f"File {filename} not found.")
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred while loading the file: {e}")

if __name__ == "__main__":
    app = GerdbakkeApp()
    app.mainloop()
