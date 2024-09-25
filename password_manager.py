import csv
import json
import os
import sys
import base64
import getpass
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt  # Correct import for Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def derive_key(password, salt):
    # Derive a 256-bit AES key from the password
    kdf_func = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
    )
    key = kdf_func.derive(password.encode())
    return key

def encrypt_field(key, plaintext):
    # Encrypt a single field
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(nonce + ciphertext).decode()

def decrypt_field(key, b64_ciphertext):
    # Decrypt a single field
    data = base64.b64decode(b64_ciphertext)
    nonce = data[:12]
    ciphertext = data[12:]
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode()

def ingest_csv(csv_file, json_file):
    # Ask for and confirm master password
    master_password = getpass.getpass("Set your master password: ")
    confirm_password = getpass.getpass("Confirm your master password: ")
    if master_password != confirm_password:
        print("Passwords do not match. Exiting.")
        sys.exit(1)

    # Generate a random salt and derive key
    salt = os.urandom(16)
    key = derive_key(master_password, salt)

    # Read CSV and encrypt data
    encrypted_entries = []
    with open(csv_file, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            encrypted_entry = {
                'name': encrypt_field(key, row['name']),
                'url': encrypt_field(key, row['url']),
                'username': encrypt_field(key, row['username']),
                'password': encrypt_field(key, row['password']),
                'note': encrypt_field(key, row['note'])
            }
            encrypted_entries.append(encrypted_entry)

    # Save encrypted data and salt to JSON
    data_to_save = {
        'salt': base64.b64encode(salt).decode(),
        'entries': encrypted_entries
    }
    with open(json_file, 'w') as jsonfile:
        json.dump(data_to_save, jsonfile)

    print("Data has been ingested and encrypted successfully.")

def load_data(json_file, master_password):
    # Load encrypted data and salt from JSON
    with open(json_file, 'r') as jsonfile:
        data = json.load(jsonfile)
    salt = base64.b64decode(data['salt'])
    key = derive_key(master_password, salt)
    return data, key

def decrypt_entries(data, key):
    decrypted_entries = []
    for idx, entry in enumerate(data['entries']):
        decrypted_entry = {
            'index': idx,
            'name': decrypt_field(key, entry['name']),
            'url': decrypt_field(key, entry['url']),
            'username': decrypt_field(key, entry['username']),
            'password': decrypt_field(key, entry['password']),
            'note': decrypt_field(key, entry['note'])
        }
        decrypted_entries.append(decrypted_entry)
    return decrypted_entries

def save_data(json_file, data):
    with open(json_file, 'w') as jsonfile:
        json.dump(data, jsonfile)

def change_master_password(json_file, master_password):
    data, old_key = load_data(json_file, master_password)
    new_password = getpass.getpass("Enter new master password: ")
    confirm_password = getpass.getpass("Confirm new master password: ")
    if new_password != confirm_password:
        print("Passwords do not match. Master password not changed.")
        return
    # Generate new salt and key
    new_salt = os.urandom(16)
    new_key = derive_key(new_password, new_salt)
    # Decrypt all entries using old key and re-encrypt with new key
    decrypted_entries = decrypt_entries(data, old_key)
    encrypted_entries = []
    for entry in decrypted_entries:
        encrypted_entry = {
            'name': encrypt_field(new_key, entry['name']),
            'url': encrypt_field(new_key, entry['url']),
            'username': encrypt_field(new_key, entry['username']),
            'password': encrypt_field(new_key, entry['password']),
            'note': encrypt_field(new_key, entry['note'])
        }
        encrypted_entries.append(encrypted_entry)
    data_to_save = {
        'salt': base64.b64encode(new_salt).decode(),
        'entries': encrypted_entries
    }
    save_data(json_file, data_to_save)
    print("Master password changed successfully.")

def view_entry(decrypted_entries):
    print("\nAvailable Accounts:")
    for entry in decrypted_entries:
        print(f"{entry['index']}: {entry['name']}")
    try:
        selected_index = int(input("\nEnter the index of the account to view: "))
        selected_entry = next((item for item in decrypted_entries if item["index"] == selected_index), None)
        if selected_entry:
            print("\nDecrypted Account Details:")
            print(f"Name: {selected_entry['name']}")
            print(f"URL: {selected_entry['url']}")
            print(f"Username: {selected_entry['username']}")
            print(f"Password: {selected_entry['password']}")
            print(f"Note: {selected_entry['note']}")
        else:
            print("Invalid index selected.")
    except ValueError:
        print("Invalid input.")

def add_entry(data, key):
    # Prompt user for new entry details
    print("\nEnter details for new password entry:")
    name = input("Name: ")
    url = input("URL: ")
    username = input("Username: ")
    password = getpass.getpass("Password: ")
    note = input("Note: ")

    # Encrypt the new entry
    encrypted_entry = {
        'name': encrypt_field(key, name),
        'url': encrypt_field(key, url),
        'username': encrypt_field(key, username),
        'password': encrypt_field(key, password),
        'note': encrypt_field(key, note)
    }

    # Append to the list of encrypted entries
    data['entries'].append(encrypted_entry)
    print("New password entry added successfully.")

def delete_entry(data, decrypted_entries):
    print("\nAvailable Accounts:")
    for entry in decrypted_entries:
        print(f"{entry['index']}: {entry['name']}")
    try:
        selected_index = int(input("\nEnter the index of the account to delete: "))
        selected_entry = next((item for item in decrypted_entries if item["index"] == selected_index), None)
        if selected_entry is None:
            print("Invalid index selected.")
            return
    except ValueError:
        print("Invalid input.")
        return
    confirm = input(f"Are you sure you want to delete '{selected_entry['name']}'? (y/N): ")
    if confirm.lower() != 'y':
        print("Deletion cancelled.")
        return
    # Remove the entry
    del data['entries'][selected_index]
    print("Password entry deleted successfully.")

def change_entry(data, key, decrypted_entries):
    print("\nAvailable Accounts:")
    for entry in decrypted_entries:
        print(f"{entry['index']}: {entry['name']}")
    try:
        selected_index = int(input("\nEnter the index of the account to change: "))
        selected_entry = next((item for item in decrypted_entries if item["index"] == selected_index), None)
        if selected_entry is None:
            print("Invalid index selected.")
            return
    except ValueError:
        print("Invalid input.")
        return

    # Prompt user for new details, with existing details as default
    print("\nEnter new details (leave blank to keep current value):")
    name = input(f"Name [{selected_entry['name']}]: ") or selected_entry['name']
    url = input(f"URL [{selected_entry['url']}]: ") or selected_entry['url']
    username = input(f"Username [{selected_entry['username']}]: ") or selected_entry['username']
    password_input = getpass.getpass("Password [hidden]: ")
    password = password_input if password_input else selected_entry['password']
    note = input(f"Note [{selected_entry['note']}]: ") or selected_entry['note']

    # Encrypt updated entry
    encrypted_entry = {
        'name': encrypt_field(key, name),
        'url': encrypt_field(key, url),
        'username': encrypt_field(key, username),
        'password': encrypt_field(key, password),
        'note': encrypt_field(key, note)
    }

    # Update the encrypted entries list
    data['entries'][selected_index] = encrypted_entry
    print("Password entry updated successfully.")

def main():
    json_file = 'encrypted_data.json'
    if not os.path.exists(json_file):
        print("No data found. You need to ingest data first.")
        if len(sys.argv) != 2:
            print("Usage: python password_manager.py <csv_file>")
            sys.exit(1)
        csv_file = sys.argv[1]
        ingest_csv(csv_file, json_file)
        sys.exit(0)

    # Prompt for master password
    master_password = getpass.getpass("Enter your master password: ")

    try:
        data, key = load_data(json_file, master_password)
        decrypted_entries = decrypt_entries(data, key)
    except Exception as e:
        print("Incorrect master password or corrupted data. Exiting.")
        sys.exit(1)

    while True:
        print("\nPassword Manager Menu:")
        print("1. Change Master Password")
        print("2. View an Entry")
        print("3. Add an Entry")
        print("4. Delete an Entry")
        print("5. Change an Entry")
        print("6. Quit")
        choice = input("Enter your choice (1-6): ")
        if choice == '1':
            change_master_password(json_file, master_password)
            # Reload data with new master password
            master_password = getpass.getpass("Enter your new master password to continue: ")
            try:
                data, key = load_data(json_file, master_password)
                decrypted_entries = decrypt_entries(data, key)
            except Exception as e:
                print("Error loading data with new master password. Exiting.")
                sys.exit(1)
        elif choice == '2':
            view_entry(decrypted_entries)
        elif choice == '3':
            add_entry(data, key)
            # Save data after adding
            save_data(json_file, data)
            # Refresh decrypted entries
            decrypted_entries = decrypt_entries(data, key)
        elif choice == '4':
            delete_entry(data, decrypted_entries)
            # Save data after deletion
            save_data(json_file, data)
            # Refresh decrypted entries
            decrypted_entries = decrypt_entries(data, key)
        elif choice == '5':
            change_entry(data, key, decrypted_entries)
            # Save data after change
            save_data(json_file, data)
            # Refresh decrypted entries
            decrypted_entries = decrypt_entries(data, key)
        elif choice == '6':
            print("Exiting Password Manager.")
            sys.exit(0)
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
