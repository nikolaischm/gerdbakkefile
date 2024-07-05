from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken
import base64
import os
import sys
import getpass

# Generiere einen Schlüssel aus einem Passwort
def generate_key_from_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

# Verschlüsseln und Speichern von Daten im .gerdbakke-Format
def save_encrypted_gerdbakke_format(filename, title, author, date, content, password):
    salt = os.urandom(16)
    key = generate_key_from_password(password, salt)
    fernet = Fernet(key)
    data = f"#HEADER\nTitle: {title}\nAuthor: {author}\nDate: {date}\n\n#CONTENT\n"
    for paragraph in content:
        data += paragraph + "\n\n"
    encrypted_data = fernet.encrypt(data.encode())

    with open(filename, 'wb') as file:
        file.write(salt + encrypted_data)

# Entschlüsseln und Laden von Daten aus dem .gerdbakke-Format
def load_encrypted_gerdbakke_format(filepath, password):
    with open(filepath, 'rb') as file:
        salt = file.read(16)
        encrypted_data = file.read()

    key = generate_key_from_password(password, salt)
    fernet = Fernet(key)
    try:
        decrypted_data = fernet.decrypt(encrypted_data).decode()
    except InvalidToken:
        raise ValueError("Invalid password or corrupted file")

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

def main():
    if len(sys.argv) > 1:
        # Datei wurde als Argument übergeben (öffnen aus dem Datei-Explorer)
        filepath = sys.argv[1]
        password = getpass.getpass("Enter the password for this file: ")
        try:
            header, content = load_encrypted_gerdbakke_format(filepath, password)
            print("\nFile Header:")
            for k, value in header.items():
                print(f"{k}: {value}")
            print("\nFile Content:")
            for paragraph in content:
                print(paragraph)
        except FileNotFoundError:
            print(f"File {filepath} not found.")
        except ValueError as e:
            print(e)
        except Exception as e:
            print(f"An error occurred while loading the file: {e}")
    else:
        while True:
            print("\nGerdbakke File Manager")
            print("1. Create a new .gerdbakke file")
            print("2. Load and display a .gerdbakke file")
            print("3. Exit")
            choice = input("Enter your choice (1/2/3): ")

            if choice == '1':
                filename = input("Enter the filename (with .gerdbakke extension): ")
                title = input("Enter the title: ")
                author = input("Enter the author: ")
                date = input("Enter the date (YYYY-MM-DD): ")
                password = getpass.getpass("Enter a password for this file: ")
                print("Enter the content (end with an empty line):")
                content = []
                while True:
                    line = input()
                    if line == "":
                        break
                    content.append(line)

                save_encrypted_gerdbakke_format(filename, title, author, date, content, password)
                print(f"File {filename} saved successfully!")

            elif choice == '2':
                filepath = input("Enter the full filepath (with .gerdbakke extension): ")
                password = getpass.getpass("Enter the password for this file: ")
                try:
                    header, content = load_encrypted_gerdbakke_format(filepath, password)
                    print("\nFile Header:")
                    for k, value in header.items():
                        print(f"{k}: {value}")
                    print("\nFile Content:")
                    for paragraph in content:
                        print(paragraph)
                except FileNotFoundError:
                    print(f"File {filepath} not found.")
                except ValueError as e:
                    print(e)
                except Exception as e:
                    print(f"An error occurred while loading the file: {e}")

            elif choice == '3':
                print("Exiting the program.")
                break

            else:
                print("Invalid choice. Please enter 1, 2, or 3.")

if __name__ == "__main__":
    main()
