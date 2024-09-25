# Secure Password Manager CLI

A simple, menu-driven password manager for the command-line interface (CLI) built using Python. The manager uses AES encryption to securely store and retrieve your passwords, and allows users to manage password entries including adding, viewing, changing, deleting, and updating the master password.

## Features

- **AES Encryption**: Uses Scrypt key derivation and AES-GCM encryption to ensure your passwords are secure.
- **Master Password**: Protects all your passwords with a single master password.
- **Menu-Driven Interface**: Easy-to-use menu for adding, viewing, changing, and deleting password entries.
- **Secure Storage**: Passwords are securely stored in a JSON file and encrypted with AES-GCM.
- **Password Management**: Ability to:
  - View an entry
  - Add a new password entry
  - Change an existing entry
  - Delete an entry
  - Change the master password

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Commands](#commands)
- [Ingestion](#ingestion)
- [License](#license)

## Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/yourusername/secure-password-manager-cli.git
   ```

2. **Navigate to the project directory:**

   ```bash
   cd secure-password-manager-cli
   ```

3. **Install dependencies:**

   This project requires Python 3 and the `cryptography` library. Install the required dependencies with:

   ```bash
   pip install cryptography
   ```

## Usage

To use the password manager, you need to set up your passwords by ingesting a CSV file or using the manager directly after starting it.

1. **Start the password manager:**

   ```bash
   python password_manager.py
   ```

2. **Enter your master password:**

   If this is your first time running the program, it will prompt you to ingest passwords from a CSV file or create a master password.

3. **Interact with the menu:**

   After entering the master password, you'll be presented with the following options:

   ```
   Password Manager Menu:
   1. Change Master Password
   2. View an Entry
   3. Add an Entry
   4. Delete an Entry
   5. Change an Entry
   6. Quit
   ```

4. **Add/View/Delete/Change passwords as needed.**

## Commands

- **Add an Entry:**
  
  Use the "Add an Entry" option to securely add a new password to your storage.

- **View an Entry:**
  
  Select the "View an Entry" option to see a list of your accounts and view their details.

- **Change an Entry:**

  Update the details of an existing entry.

- **Delete an Entry:**
  
  Remove an existing password entry from storage.

- **Change Master Password:**

  Use this option to update your master password and re-encrypt all stored passwords with a new key.

## Ingestion

To ingest passwords from a CSV file for the first time, run:

```bash
python password_manager.py <csv_file>
```

The CSV file should contain the following headers: `name`, `url`, `username`, `password`, `note`.

Example CSV structure:

```csv
name,url,username,password,note
Gmail,https://mail.google.com,your_username,your_password,Personal Gmail account
Facebook,https://www.facebook.com,your_username,your_password,Facebook account
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
