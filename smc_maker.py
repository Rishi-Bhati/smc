import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import base64
from nacl.signing import SigningKey
import os
import json
import zlib
import struct
import os # Needed to get filenames and generate random salts
from nacl.secret import SecretBox # The tool for fast encryption/decryption
from nacl.pwhash import scrypt # The KDF for turning passwords into keys


# A new magic number for our new file format
SMC_MAGIC = b"SMC5"


#main window setup...
root = tk.Tk()
root.title("SMC Maker")
root.geometry("500x550")

# --- Variables for the Create SMC Tab ---
img_path_var = tk.StringVar()
sign_key_path_var = tk.StringVar()
out_path_var = tk.StringVar()

# Variables for the new optional features
encrypt_bool_var = tk.BooleanVar()
encryption_pass_var = tk.StringVar()
phrase_bool_var = tk.BooleanVar()
phrase_pass_var = tk.StringVar()
secret_phrase_var = tk.StringVar()

# CORE functions

def create_smc(input_path:str, output_path:str, sign_key_path:str, encryption_password: str = None, secret_phrase: str = None, phrase_passkey: str = None):

    # Create secure smc container    
    try :
        # 1. read the file as raw binary data
        with open(input_path,'rb') as f:
            file_data = f.read()

        # 2. Handle full file encryption
        main_payload = file_data
        encryption_salt = None
        is_payload_encrypted = False

        if encryption_password:
            is_payload_encrypted = True
            encryption_salt = os.urandom(scrypt.SALTBYTES) # generate a random salt

            # use KDF to stretch the password

            key = scrypt.kdf(SecretBox.KEY_SIZE, encryption_password.encode('utf-8'), encryption_salt)

            # encrypt the the file data
            main_payload = SecretBox(key).encrypt(file_data)

        # 3. Handle phrase and passkey (if provided)

        encrypted_phrase_payload = b'' # An empty bytes string
        phrase_salt = None
        has_secret_phrase = False

        if secret_phrase and phrase_passkey:
            has_secret_phrase = True
            phrase_salt = os.urandom(scrypt.SALTBYTES) # generate a random salt

            # use KDF to stretch the passkey
            phrase_key = scrypt.kdf(SecretBox.KEY_SIZE, phrase_passkey.encode('utf-8'), phrase_salt)

            # encrypt the secret phrase
            encrypted_phrase_payload = SecretBox(phrase_key).encrypt(secret_phrase.encode('utf-8'))

        # 4. prepare the headers

        sk_bytes = read_b64_file(sign_key_path)
        sk = SigningKey(sk_bytes)
        pk = sk.verify_key

        main_payload_len = len(main_payload) # Length of the main payload for the header
        
        header = {
            "version": 5.1, # Let's update the version number
            "payload_len": main_payload_len, # <-- ADD THIS LINE
            "author_pk": base64.b64encode(pk.encode()).decode('utf-8'),
            "original_filename": os.path.basename(input_path),
            "is_payload_encrypted": is_payload_encrypted,
            "has_secret_phrase": has_secret_phrase,
            # base64 encode salts so they can be stored in JSON
            "encryption_salt": base64.b64encode(encryption_salt).decode('utf-8') if encryption_salt else None,
            "phrase_salt": base64.b64encode(phrase_salt).decode('utf-8') if phrase_salt else None,
        }

        header_json = json.dumps(header, sort_keys=True).encode('utf-8')

        # --- 5. Sign the complete package ---

        # The signature covers the header and all data chunks for total integrity
        signature = sk.sign(header_json + main_payload + encrypted_phrase_payload).signature

        # --- 6. Write the SMCv5 file ---       

        with open(output_path, 'wb') as f:
            f.write(SMC_MAGIC)
            f.write(struct.pack(">I", len(header_json)))
            f.write(header_json)
            f.write(signature)
            f.write(main_payload)
            f.write(encrypted_phrase_payload) # Will write nothing if it's empty
            
        messagebox.showinfo("Success", f"SMC file created successfully:\n{output_path}")

    except Exception as e:
        messagebox.showerror("Error", f"Failed to create SMC file: {type(e).__name__}: {e}")

def read_b64_file(path):
    """A helper function to read our Base64 encoded key files."""
    with open(path, 'r') as f:
        return base64.b64decode(f.read().strip())


def genkey(prefix:str):  #generate ed25519 key pair
    
    try:
        sk = SigningKey.generate()
        pk = sk.verify_key
        print(f"Secret Key: {sk} Public Key: {pk}")

        sk_filename = f"{prefix}_ed25519_sk.b64"

        with open(sk_filename, "w") as f:
            f.write(base64.b64encode(sk.encode()).decode('utf-8')) # write secret key to file in base64 format as utf-8 string

        pk_filename = f"{prefix}_ed25519_pk.b64"
        with open(pk_filename, "w") as f:
            f.write(base64.b64encode(pk.encode()).decode('utf-8')) # write public key to file in base64 format as utf-8 string

        messagebox.showinfo("Success", f"Keys saved:\n{sk_filename}\n{pk_filename}")
    except Exception as e:
        messagebox.showerror("Error", f"{type(e).__name__}: {e}")



# other functions...

def setup_create_tab(parent_frame):
    global encrypt_pass_label, encrypt_pass_entry
    global phrase_pass_label, phrase_pass_entry, secret_phrase_label, secret_phrase_entry

    
    # --- File Paths (same as before, but using new variables) ---
    # A function to create the file browser rows to avoid repeating code
    # In setup_create_tab, modify this function:
    def create_file_row(parent, label_text, var, cmd): # <-- Add cmd here
        frame = ttk.Frame(parent)
        frame.pack(fill='x', padx=5, pady=5)
        ttk.Label(frame, text=label_text, width=12).pack(side='left', padx=5)
        ttk.Entry(frame, textvariable=var).pack(side='left', expand=True, fill='x')
        # Use the new cmd variable to connect the button
        ttk.Button(frame, text="Browse...", command=cmd).pack(side='left', padx=5) # <-- Add command=cmd here

    # In setup_create_tab, modify these three lines:
    create_file_row(parent_frame, "Input File:", img_path_var, browse_input_file)
    create_file_row(parent_frame, "Signing Key:", sign_key_path_var, browse_signing_key)
    create_file_row(parent_frame, "Output File:", out_path_var, browse_output_file)

    # --- Full File Encryption Section ---

    encrypt_frame = ttk.LabelFrame(parent_frame, text="Full File Encryption (Optional)", padding=10)
    encrypt_frame.pack(fill='x', padx=5, pady=10)

    encrypt_check = ttk.Checkbutton(
        encrypt_frame, 
        text="Encrypt the main file data",
        variable=encrypt_bool_var
    )
    encrypt_check.pack(anchor='w')

    # We will create these widgets but leave them disabled initially
    encrypt_pass_label = ttk.Label(encrypt_frame, text="Password:")
    encrypt_pass_label.pack(anchor='w', pady=(5,0))
    encrypt_pass_entry = ttk.Entry(encrypt_frame, textvariable=encryption_pass_var, show="*")
    encrypt_pass_entry.pack(fill='x')

    # --- Secret Phrase Section ---
    phrase_frame = ttk.LabelFrame(parent_frame, text="Secret Phrase (Optional)", padding=10)
    phrase_frame.pack(fill='x', padx=5, pady=5)

    phrase_check = ttk.Checkbutton(
        phrase_frame,
        text="Add a hidden, password-protected phrase",
        variable=phrase_bool_var
    )
    phrase_check.pack(anchor='w')

    phrase_pass_label = ttk.Label(phrase_frame, text="Passkey:")
    phrase_pass_label.pack(anchor='w', pady=(5,0))
    phrase_pass_entry = ttk.Entry(phrase_frame, textvariable=phrase_pass_var, show="*")
    phrase_pass_entry.pack(fill='x')

    secret_phrase_label = ttk.Label(phrase_frame, text="Secret Phrase:")
    secret_phrase_label.pack(anchor='w', pady=(5,0))
    secret_phrase_entry = ttk.Entry(phrase_frame, textvariable=secret_phrase_var)
    secret_phrase_entry.pack(fill='x')
    
    # --- Final Create Button ---
    # We will connect this button in the final step
    create_button = ttk.Button(parent_frame, text="Create SMC File", command=create_smc_action)
    create_button.pack(pady=20)

def toggle_encryption_widgets():
    # Get the current state of the checkbox (True if checked)
    is_enabled = encrypt_bool_var.get()
    new_state = 'normal' if is_enabled else 'disabled'
    
    # These widget variables need to be found by the function,
    # so we'll update how they are created in the setup function.
    encrypt_pass_label.config(state=new_state)
    encrypt_pass_entry.config(state=new_state)

def toggle_phrase_widgets():
    is_enabled = phrase_bool_var.get()
    new_state = 'normal' if is_enabled else 'disabled'
    
    phrase_pass_label.config(state=new_state)
    phrase_pass_entry.config(state=new_state)
    secret_phrase_label.config(state=new_state)
    secret_phrase_entry.config(state=new_state)


# Action functions for buttons

def generate_keys_action():
    # get prefix from entry field
    prefix = key_prefix_entry.get().strip()
    if not prefix:
        messagebox.showerror("Error", "Please enter a valid prefix.")
        return
    
    genkey(prefix)
# --- Action Functions for Create SMC Tab ---

def browse_input_file():
    path = filedialog.askopenfilename()
    if path:
        img_path_var.set(path)

def browse_signing_key():
    path = filedialog.askopenfilename(filetypes=[("Base64 Key Files", "*_sk.b64")])
    if path:
        sign_key_path_var.set(path)

def browse_output_file():
    path = filedialog.asksaveasfilename(defaultextension=".smc", filetypes=[("SMC Files", "*.smc")])
    if path:
        out_path_var.set(path)

def create_smc_action():
    # 1. Get all the file paths
    input_f = img_path_var.get()
    key_f = sign_key_path_var.get()
    output_f = out_path_var.get()

    if not all([input_f, key_f, output_f]):
        messagebox.showwarning("Warning", "Please fill in all file paths.")
        return

    # 2. Get the optional passwords, setting them to None if disabled
    enc_pass = None
    if encrypt_bool_var.get():
        enc_pass = encryption_pass_var.get()
        if not enc_pass:
            messagebox.showwarning("Warning", "Encryption is checked, but the password field is empty.")
            return

    phrase = None
    phrase_pass = None
    if phrase_bool_var.get():
        phrase = secret_phrase_var.get()
        phrase_pass = phrase_pass_var.get()
        if not all([phrase, phrase_pass]):
            messagebox.showwarning("Warning", "Secret Phrase is checked, but the passkey or phrase field is empty.")
            return
            
    # 3. Call the engine!
    create_smc(input_f, output_f, key_f, enc_pass, phrase, phrase_pass)


#creating a notebook to manage tabs and place in root window...

notebook = tk.ttk.Notebook(root)
notebook.pack(pady=10, padx=10, fill="both", expand=True)

#creating frames for generate keys and make smc tabs

genkey_frame = ttk.Frame(notebook)
create_frame = ttk.Frame(notebook)

notebook.add(create_frame, text="Create SMC")
# --- NEW LINE ---
setup_create_tab(create_frame)


#add frames to notebook as tabs
notebook.add(genkey_frame, text="Generate Keys")
notebook.add(create_frame, text="Create SMC")

# Create a label and add it to the 'genkey_frame'
label = ttk.Label(genkey_frame, text="Enter prefix for key filenames:")
label.pack(pady=10)


# Create an entry box. Add it to the 'genkey_frame'
key_prefix_entry = ttk.Entry(genkey_frame, width=40)
key_prefix_entry.pack(pady=5)
key_prefix_entry.insert(0, "author") # Add some default text

# Create a button and link it to our action function
gen_button = ttk.Button(genkey_frame, text="Generate Keys", command=generate_keys_action)
gen_button.pack(pady=20)


root.mainloop()