import os
import json
import tkinter as tk
from tkinter import messagebox, ttk
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import secrets
import string
import pyperclip
import requests

# File to store data
DATA_FILE = "data.json"

# jsonbin.io configuration
JSONBIN_URL = "https://api.jsonbin.io/v3/b/"
BIN_ID = "67a15efeacd3cb34a8d7da18"  # Replace with your bin ID
API_KEY = "$2a$10$5ay/mqRhcigPqcvEOoJKp.cnr1rEyHRvjDZmZa7G/8uKPBP1nVX6O"  # Replace with your API key

# Generate a key for encryption
def generate_key(master_key):
    salt = b"salt_"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_key.encode()))
    return key

# Encrypt data
def encrypt_data(data, key):
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data.encode())
    return encrypted_data.decode()

# Decrypt data
def decrypt_data(encrypted_data, key):
    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data.encode())
    return decrypted_data.decode()

# Load data from file
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as file:
            data = json.load(file)
            data.setdefault("is_updated", False)
            return data
    return {"master_key_hash": None, "accounts": [], "is_updated": False}

# Save data to file
def save_data(data):
    with open(DATA_FILE, "w") as file:
        json.dump(data, file)

# Hash master key
def hash_master_key(master_key):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(master_key.encode())
    return base64.urlsafe_b64encode(digest.finalize()).decode()

# Generate a strong random password
def generate_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(characters) for _ in range(length))

# Fetch data from jsonbin.io
def fetch_data_from_cloud():
    headers = {
        "X-Master-Key": API_KEY,
        "Content-Type": "application/json"
    }
    response = requests.get(f"{JSONBIN_URL}{BIN_ID}", headers=headers)
    if response.status_code == 200:
        data = response.json().get("record", {})
        data.setdefault("master_key_hash", None)
        data.setdefault("accounts", [])
        data.setdefault("is_updated", False)
        return data
    else:
        print(f"Error fetching data: {response.status_code}")
        return {"master_key_hash": None, "accounts": [], "is_updated": False}

# Save data to jsonbin.io
def save_data_to_cloud(data):
    headers = {
        "X-Master-Key": API_KEY,
        "Content-Type": "application/json"
    }
    response = requests.put(f"{JSONBIN_URL}{BIN_ID}", json=data, headers=headers)
    if response.status_code == 200:
        print("Data saved to cloud successfully.")
    else:
        print(f"Error saving data: {response.status_code}")

# Sync data with cloud
def sync_with_cloud():
    cloud_data = fetch_data_from_cloud()
    if cloud_data.get("is_updated", False):
        with open(DATA_FILE, "w") as file:
            json.dump(cloud_data, file)
        print("Local data updated from cloud.")

# Password Manager Application
class PasswordManagerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Password Manager")
        self.geometry("800x600")  # Window size
        self.configure(bg="#ffffff")  # Background color for the app

        self.center_window()

        remembered_email = check_remembered_login()
        if remembered_email:
            self.current_user_email = remembered_email
            self.show_master_key_screen()
        else:
            self.show_login_screen()

    def center_window(self):
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        window_width = 800
        window_height = 600
        position_top = int(screen_height / 2 - window_height / 2)
        position_right = int(screen_width / 2 - window_width / 2)
        self.geometry(f'{window_width}x{window_height}+{position_right}+{position_top}')

    def show_login_screen(self):
        self.login_frame = tk.Frame(self, bg="#ffffff")
        self.login_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(self.login_frame, text="Email:", font=("Arial", 16, 'bold'), background="#ffffff").pack(pady=10)
        self.email_entry = ttk.Entry(self.login_frame, font=("Arial", 14), width=30, justify="center")
        self.email_entry.pack(pady=10)

        ttk.Label(self.login_frame, text="Password:", font=("Arial", 16, 'bold'), background="#ffffff").pack(pady=10)
        self.password_entry = ttk.Entry(self.login_frame, show="*", font=("Arial", 14), width=30, justify="center")
        self.password_entry.pack(pady=10)

        ttk.Button(self.login_frame, text="Login", command=self.submit_login, style="TButton").pack(pady=20)

    def submit_login(self):
        email = self.email_entry.get()
        password = self.password_entry.get()
        if login(email, password):
            remember_login(email)
            self.current_user_email = email
            self.login_frame.pack_forget()
            self.show_master_key_screen()

    def show_master_key_screen(self):
        self.master_key_frame = tk.Frame(self, bg="#ffffff")
        self.master_key_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(self.master_key_frame, text="Enter Master Key:", font=("Arial", 16, 'bold'), background="#ffffff").pack(pady=20)
        self.master_key_entry = ttk.Entry(self.master_key_frame, show="*", font=("Arial", 14), width=30, justify="center")
        self.master_key_entry.pack(pady=10)
        ttk.Button(self.master_key_frame, text="Submit", command=self.submit_master_key, style="TButton").pack(pady=20)

    def submit_master_key(self):
        master_key = self.master_key_entry.get()
        if not master_key:
            messagebox.showerror("Error", "Master Key cannot be empty.")
            return

        data = load_data()
        if not data["master_key_hash"]:
            data["master_key_hash"] = hash_master_key(master_key)
            save_data(data)
            self.switch_to_main_app(master_key)
        else:
            if hash_master_key(master_key) == data["master_key_hash"]:
                self.switch_to_main_app(master_key)
            else:
                messagebox.showerror("Error", "Invalid Master Key.")

    def switch_to_main_app(self, master_key):
        self.master_key_frame.pack_forget()
        self.main_app_frame = tk.Frame(self, bg="#ffffff")
        self.main_app_frame.pack(fill=tk.BOTH, expand=True)

        self.master_key = master_key
        self.key = generate_key(master_key)
        self.data = load_data()

        # Create a frame for account list
        self.list_frame = ttk.LabelFrame(self.main_app_frame, text="Accounts", padding=(10, 5))
        self.list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.listbox = tk.Listbox(self.list_frame, height=10, font=("Arial", 12), selectmode=tk.SINGLE, bg="#f5f5f5", bd=0)
        self.listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.listbox.bind("<<ListboxSelect>>", self.on_account_select)

        # Account details section
        self.details_frame = ttk.LabelFrame(self.main_app_frame, text="Account Details", padding=(10, 5))
        self.details_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.email_label = ttk.Label(self.details_frame, text="Email:", font=("Arial", 12), foreground="#000000")
        self.email_label.pack()
        self.email_value = ttk.Label(self.details_frame, text="", foreground="#000000", font=("Arial", 12))
        self.email_value.pack()

        self.username_label = ttk.Label(self.details_frame, text="Username:", font=("Arial", 12), foreground="#000000")
        self.username_label.pack()
        self.username_value = ttk.Label(self.details_frame, text="", foreground="#000000", font=("Arial", 12))
        self.username_value.pack()

        self.password_label = ttk.Label(self.details_frame, text="Password:", font=("Arial", 12), foreground="#000000")
        self.password_label.pack()
        self.password_value = ttk.Label(self.details_frame, text="", foreground="#000000", font=("Arial", 12))
        self.password_value.pack()

        self.copy_password_button = ttk.Button(self.details_frame, text="Copy Password", command=self.copy_password, style="TButton")
        self.copy_password_button.pack(pady=10)

        self.button_frame = ttk.Frame(self.main_app_frame)
        self.button_frame.pack(pady=10)

        self.add_button = ttk.Button(self.button_frame, text="Add Account", command=self.show_add_account_frame, style="TButton")
        self.add_button.grid(row=0, column=0, padx=5)

        self.edit_button = ttk.Button(self.button_frame, text="Edit Account", command=self.show_edit_account_frame, style="TButton")
        self.edit_button.grid(row=0, column=1, padx=5)

        self.delete_button = ttk.Button(self.button_frame, text="Delete Account", command=self.delete_account, style="TButton")
        self.delete_button.grid(row=0, column=2, padx=5)

        self.sync_button = ttk.Button(self.button_frame, text="Sync with Cloud", command=self.sync_with_cloud, style="TButton")
        self.sync_button.grid(row=0, column=3, padx=5)

        self.style = ttk.Style()
        self.style.configure("TButton",
                             font=("Arial", 12, "bold"),
                             padding=6,
                             relief="flat",
                             background="#4CAF50",
                             foreground="#000000")
        self.style.map("TButton",
                       foreground=[('pressed', '#000000'), ('active', '#000000')],
                       background=[('pressed', '#3e8e41'), ('active', '#45a049')])

        self.refresh_accounts()

    def show_add_account_frame(self):
        self.main_app_frame.pack_forget()

        self.add_account_frame = tk.Frame(self, bg="#ffffff")
        self.add_account_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(self.add_account_frame, text="Account Name:", font=("Arial", 12), foreground="#000000").pack(pady=5)
        self.account_name_entry = ttk.Entry(self.add_account_frame, font=("Arial", 12))
        self.account_name_entry.pack(pady=5)

        ttk.Label(self.add_account_frame, text="Email:", font=("Arial", 12), foreground="#000000").pack(pady=5)
        self.email_entry = ttk.Entry(self.add_account_frame, font=("Arial", 12))
        self.email_entry.pack(pady=5)

        ttk.Label(self.add_account_frame, text="Username:", font=("Arial", 12), foreground="#000000").pack(pady=5)
        self.username_entry = ttk.Entry(self.add_account_frame, font=("Arial", 12))
        self.username_entry.pack(pady=5)

        ttk.Label(self.add_account_frame, text="Password:", font=("Arial", 12), foreground="#000000").pack(pady=5)
        self.password_entry = ttk.Entry(self.add_account_frame, font=("Arial", 12))
        self.password_entry.pack(pady=5)

        ttk.Label(self.add_account_frame, text="Notes:", font=("Arial", 12), foreground="#000000").pack(pady=5)
        self.notes_entry = ttk.Entry(self.add_account_frame, font=("Arial", 12))
        self.notes_entry.pack(pady=5)

        # Password generator functionality
        def generate_and_fill_password():
            self.password_entry.delete(0, tk.END)
            self.password_entry.insert(0, generate_password())

        ttk.Button(self.add_account_frame, text="Generate Password", command=generate_and_fill_password).pack(pady=10)

        def save_account():
            account_name = self.account_name_entry.get()
            email = self.email_entry.get()
            username = self.username_entry.get()
            password = self.password_entry.get()
            notes = self.notes_entry.get()

            if not account_name or not password:
                messagebox.showerror("Error", "Account Name and Password are required.")
                return

            encrypted_password = encrypt_data(password, self.key)
            self.data["accounts"].append({
                "account_name": account_name,
                "email": email,
                "username": username,
                "password": encrypted_password,
                "notes": notes
            })
            self.data["is_updated"] = True
            save_data(self.data)
            save_data_to_cloud(self.data)
            self.refresh_accounts()
            self.add_account_frame.pack_forget()
            self.main_app_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Button(self.add_account_frame, text="Save", command=save_account).pack(pady=10)
        ttk.Button(self.add_account_frame, text="Back", command=self.go_back_to_main_app).pack(pady=10)

    def show_edit_account_frame(self):
        selected_index = self.listbox.curselection()
        if not selected_index:
            messagebox.showerror("Error", "No account selected.")
            return

        self.main_app_frame.pack_forget()

        self.edit_account_frame = tk.Frame(self, bg="#ffffff")
        self.edit_account_frame.pack(fill=tk.BOTH, expand=True)

        account = self.data["accounts"][selected_index[0]]

        ttk.Label(self.edit_account_frame, text="Account Name:", font=("Arial", 12), foreground="#000000").pack(pady=5)
        self.account_name_entry = ttk.Entry(self.edit_account_frame, font=("Arial", 12))
        self.account_name_entry.insert(0, account["account_name"])
        self.account_name_entry.pack(pady=5)

        ttk.Label(self.edit_account_frame, text="Email:", font=("Arial", 12), foreground="#000000").pack(pady=5)
        self.email_entry = ttk.Entry(self.edit_account_frame, font=("Arial", 12))
        self.email_entry.insert(0, account["email"])
        self.email_entry.pack(pady=5)

        ttk.Label(self.edit_account_frame, text="Username:", font=("Arial", 12), foreground="#000000").pack(pady=5)
        self.username_entry = ttk.Entry(self.edit_account_frame, font=("Arial", 12))
        self.username_entry.insert(0, account["username"])
        self.username_entry.pack(pady=5)

        ttk.Label(self.edit_account_frame, text="Password:", font=("Arial", 12), foreground="#000000").pack(pady=5)
        self.password_entry = ttk.Entry(self.edit_account_frame, font=("Arial", 12))
        self.password_entry.insert(0, decrypt_data(account["password"], self.key))
        self.password_entry.pack(pady=5)

        ttk.Label(self.edit_account_frame, text="Notes:", font=("Arial", 12), foreground="#000000").pack(pady=5)
        self.notes_entry = ttk.Entry(self.edit_account_frame, font=("Arial", 12))
        self.notes_entry.insert(0, account["notes"])
        self.notes_entry.pack(pady=5)

        def save_account():
            account["account_name"] = self.account_name_entry.get()
            account["email"] = self.email_entry.get()
            account["username"] = self.username_entry.get()
            account["password"] = encrypt_data(self.password_entry.get(), self.key)
            account["notes"] = self.notes_entry.get()
            self.data["is_updated"] = True
            save_data(self.data)
            save_data_to_cloud(self.data)
            self.refresh_accounts()
            self.edit_account_frame.pack_forget()
            self.main_app_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Button(self.edit_account_frame, text="Save", command=save_account).pack(pady=10)
        ttk.Button(self.edit_account_frame, text="Back", command=self.go_back_to_main_app).pack(pady=10)

    def go_back_to_main_app(self):
        # Check if the add_account_frame exists and remove it
        if hasattr(self, 'add_account_frame'):
            self.add_account_frame.pack_forget()
        
        # Check if the edit_account_frame exists and remove it
        if hasattr(self, 'edit_account_frame'):
            self.edit_account_frame.pack_forget()
        
        # Show the main app frame again
        self.main_app_frame.pack(fill=tk.BOTH, expand=True)


    def refresh_accounts(self):
        self.listbox.delete(0, tk.END)
        for account in self.data["accounts"]:
            self.listbox.insert(tk.END, account["account_name"])

    def on_account_select(self, event):
        selected_index = self.listbox.curselection()
        if selected_index:
            account = self.data["accounts"][selected_index[0]]
            self.email_value.config(text=account["email"])
            self.username_value.config(text=account["username"])
            decrypted_password = decrypt_data(account["password"], self.key)
            self.password_value.config(text=decrypted_password)

    def delete_account(self):
        selected_index = self.listbox.curselection()
        if not selected_index:
            messagebox.showerror("Error", "No account selected.")
            return

        self.data["accounts"].pop(selected_index[0])
        self.data["is_updated"] = True
        save_data(self.data)
        save_data_to_cloud(self.data)
        self.refresh_accounts()

    def copy_password(self):
        selected_index = self.listbox.curselection()
        if not selected_index:
            messagebox.showerror("Error", "No account selected.")
            return

        account = self.data["accounts"][selected_index[0]]
        password = decrypt_data(account["password"], self.key)
        pyperclip.copy(password)
        messagebox.showinfo("Success", "Password copied to clipboard.")

    def sync_with_cloud(self):
        sync_with_cloud()
        messagebox.showinfo("Success", "Data synchronized with cloud.")

def login(email, password):
    # Allow only the specific email and password
    if email == "salahezzat120@gmail.com" and password == "salahezzat":
        return True
    else:
        messagebox.showerror("Error", "Invalid email or password.")
        return False


def remember_login(email):
    with open("remembered_user.txt", "w") as file:
        file.write(email)

def check_remembered_login():
    if os.path.exists("remembered_user.txt"):
        with open("remembered_user.txt", "r") as file:
            email = file.read().strip()
            if email:
                return email
    return None


# Run the application
if __name__ == "__main__":
    app = PasswordManagerApp()
    app.mainloop()
