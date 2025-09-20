import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import base64
import json
import struct
import os
from nacl.signing import VerifyKey
from nacl.secret import SecretBox
from nacl.pwhash import scrypt
from nacl.exceptions import CryptoError
from PIL import Image, ImageTk
import io
import zipfile

# The magic number must match the creator's
SMC_MAGIC = b"SMC5"

# --- YOUR TRUSTED LIST ---
# Add the public keys of authors you trust.
# To get your own key, use the SMC Maker to generate a keypair,
# then open the .b64 public key file and copy the text.
TRUSTED_AUTHORS = {
    "My Own Key": "PASTE_YOUR_PUBLIC_KEY_STRING_HERE",
    "Another Trusted Person": "PASTE_THEIR_PUBLIC_KEY_HERE"
}

# --- GLOBAL VARIABLES TO HOLD FILE DATA ---
current_header = None
decrypted_payload = None
phrase_payload_raw = None 

# --- CORE LOGIC ---
def view_smc(smc_path):
    """Opens and verifies an SMCv5 file. Returns a dictionary with the results."""
    try:
        with open(smc_path, 'rb') as f:
            # 1. Parse the file structure
            if f.read(len(SMC_MAGIC)) != SMC_MAGIC: raise ValueError("Not a valid SMCv5 file.")
            header_len = struct.unpack(">I", f.read(4))[0]
            header_json = f.read(header_len)
            header = json.loads(header_json)
            signature = f.read(64)
            all_payloads = f.read()

        # 2. Check if the author is in our trusted list
        author_pk_b64 = header.get("author_pk")
        if not author_pk_b64: raise ValueError("Header missing author key.")
            
        author_name = "Unknown (Untrusted)"
        is_trusted = False
        for name, trusted_pk in TRUSTED_AUTHORS.items():
            if trusted_pk == author_pk_b64:
                author_name = name
                is_trusted = True
                break
        
        # 3. Verify the digital signature (integrity check)
        # This is done regardless of whether the author is trusted.
        verify_key = VerifyKey(base64.b64decode(author_pk_b64))
        # If this line fails, it raises an exception, meaning the file was tampered with.
        verify_key.verify(header_json + all_payloads, signature)

                # NEW: Split the payloads using the length from the header
        payload_len = header.get("payload_len")
        if payload_len is None: raise ValueError("Header missing payload length.")
        
        main_payload = all_payloads[:payload_len]
        phrase_payload = all_payloads[payload_len:]

        return {
            "status": "VERIFIED", 
            "is_trusted": is_trusted,
            "author_name": author_name, 
            "header": header, 
            "main_payload": main_payload, # Return split payloads
            "phrase_payload": phrase_payload
        }
        
    except CryptoError:
        # This specific error means the signature did not match the data.
        return {"status": "ERROR: TAMPERING DETECTED! Signature is invalid."}
    except Exception as e:
        # Handle all other errors (bad file format, etc.)
        return {"status": f"ERROR: {type(e).__name__}: {e}"}

# --- GUI DISPLAY FUNCTIONS ---
def clear_display_frame():
    for widget in display_frame.winfo_children():
        widget.destroy()

def display_image(data):
    clear_display_frame()
    try:
        img = Image.open(io.BytesIO(data))
        img.thumbnail((450, 450))
        photo = ImageTk.PhotoImage(img)
        img_label = ttk.Label(display_frame, image=photo)
        img_label.image = photo
        img_label.pack()
    except Exception as e:
        display_unsupported(f"Could not display image: {e}")

def display_zip_contents(data):
    clear_display_frame()
    try:
        with zipfile.ZipFile(io.BytesIO(data), 'r') as zf:
            file_list = zf.namelist()
        text_widget = tk.Text(display_frame, height=10, width=50, relief="flat")
        text_widget.pack(padx=5, pady=5, fill="both", expand=True)
        text_widget.insert(tk.END, "Contents of ZIP file:\n\n")
        for name in file_list:
            text_widget.insert(tk.END, f"- {name}\n")
        text_widget.config(state='disabled')
    except Exception as e:
        display_unsupported(f"Could not read zip file: {e}")

def display_unsupported(message="This file type cannot be previewed."):
    clear_display_frame()
    ttk.Label(display_frame, text=message, font="-size 10").pack(pady=20)
    ttk.Label(display_frame, text="Please save the file to view it externally.").pack()

# --- ACTION FUNCTIONS ---
# --- MODIFIED reset_ui function ---
def reset_ui():
    global current_header, decrypted_payload
    current_header = None
    decrypted_payload = None

    status_var.set("Waiting for file...")
    author_var.set("N/A")
    filename_var.set("N/A")
    # Use the variable we created earlier
    warning_label.config(text="", background=default_bg_color) 
    save_button.config(state='disabled')
    phrase_pass_entry.config(state='disabled')
    unlock_phrase_button.config(state='disabled')
    clear_display_frame()

def open_smc_action():
    global current_header, decrypted_payload, phrase_payload_raw
    
    path = filedialog.askopenfilename(filetypes=[("SMC Files", "*.smc")])
    if not path: return

    result = view_smc(path)
    status = result.get("status")
    
    if status.startswith("ERROR"):
        status_var.set("FAILED!")
        warning_label.config(text=status, background="#FF7F7F") # Red
        return

    # If status is "VERIFIED", proceed regardless of trust
    if status == "VERIFIED":
        current_header = result["header"]
        status_var.set("SUCCESS: Signature is valid!")
        author_var.set(result["author_name"])
        filename = current_header["original_filename"]
        filename_var.set(filename)
    
        # NEW: Get the correctly split payloads
        main_payload_raw = result["main_payload"]
        phrase_payload_raw = result["phrase_payload"] # We store this for the unlock button
    
        # Set warning if author is untrusted
        if not result["is_trusted"]:
            warning_label.config(text="WARNING: Author is not in your trusted list.", background="#FFD700")
    
        # Decrypt if necessary, using main_payload_raw
        if current_header["is_payload_encrypted"]:
            password = simpledialog.askstring("Password Required", "Enter password to decrypt this file:", show="*")
            if not password:
                status_var.set("DECRYPTION CANCELED")
                return
            try:
                salt = base64.b64decode(current_header["encryption_salt"])
                key = scrypt.kdf(SecretBox.KEY_SIZE, password.encode('utf-8'), salt)
                # Use main_payload_raw here!
                decrypted_payload = SecretBox(key).decrypt(main_payload_raw)
            except CryptoError:
                messagebox.showerror("Error", "Decryption failed. The password may be incorrect.")
                status_var.set("DECRYPTION FAILED")
                return
        else:
            # If not encrypted, the raw payload is the decrypted data
            decrypted_payload = main_payload_raw

    if decrypted_payload is None: return

    # Route to the correct display function
    save_button.config(state='normal')
    if filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp')):
        display_image(decrypted_payload)
    elif filename.lower().endswith('.zip'):
        display_zip_contents(decrypted_payload)
    else:
        display_unsupported()
    
    if current_header["has_secret_phrase"]:
        phrase_pass_entry.config(state='normal')
        unlock_phrase_button.config(state='normal')

        if decrypted_payload is None: return

        # Route to the correct display function
        save_button.config(state='normal')
        if filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp')):
            display_image(decrypted_payload)
        elif filename.lower().endswith('.zip'):
            display_zip_contents(decrypted_payload)
        else:
            display_unsupported()
        
        if current_header["has_secret_phrase"]:
            phrase_pass_entry.config(state='normal')
            unlock_phrase_button.config(state='normal')

def save_file_action():
    if not decrypted_payload or not current_header: return
    save_path = filedialog.asksaveasfilename(initialfile=current_header["original_filename"])
    if save_path:
        with open(save_path, 'wb') as f:
            f.write(decrypted_payload)
        messagebox.showinfo("Success", f"File saved to:\n{save_path}")

# Replace your old unlock_phrase_action with this one
def unlock_phrase_action():
    # Make sure the function can see the globally stored header and phrase data
    global current_header, phrase_payload_raw 

    if not current_header or not current_header["has_secret_phrase"]: return
    
    passkey = phrase_pass_var.get()
    if not passkey:
        messagebox.showwarning("Input Required", "Please enter the passkey.")
        return
    
    try:
        # Get the salt from the header and the raw phrase payload
        salt = base64.b64decode(current_header["phrase_salt"])
        # Derive the key from the user's passkey and the salt
        key = scrypt.kdf(SecretBox.KEY_SIZE, passkey.encode('utf-8'), salt)
        # Decrypt the phrase payload!
        decrypted_phrase_bytes = SecretBox(key).decrypt(phrase_payload_raw)
        
        # Show the result in a new pop-up
        messagebox.showinfo("Secret Phrase Unlocked", decrypted_phrase_bytes.decode('utf-8'))

    except CryptoError:
        messagebox.showerror("Error", "Failed to unlock phrase. The passkey may be incorrect.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")


#helper functions 

# Add this function with your other helper/action functions

def _on_mousewheel(event):
    """Handles mouse wheel scrolling for cross-platform compatibility."""
    # The direction and value are different on Linux vs. Windows/macOS
    if event.num == 4 or event.delta > 0:
        # Scroll up
        canvas.yview_scroll(-1, "units")
    elif event.num == 5 or event.delta < 0:
        # Scroll down
        canvas.yview_scroll(1, "units")

# --- MAIN APPLICATION AND GUI SETUP (WITH SCROLLBAR & WIDTH FIX) ---
root = tk.Tk()
root.title("SMC Smart Viewer")
root.geometry("500x650")

# 1. Create a Canvas and a Scrollbar
canvas = tk.Canvas(root)
scrollbar = ttk.Scrollbar(root, orient="vertical", command=canvas.yview)
canvas.configure(yscrollcommand=scrollbar.set)

# 2. Create the frame that will hold all our content
scrollable_frame = ttk.Frame(canvas)

# 3. This binding updates the scroll region for VERTICAL scrolling
scrollable_frame.bind(
    "<Configure>",
    lambda e: canvas.configure(
        scrollregion=canvas.bbox("all")
    )
)

# 4. Place the scrollable frame inside the canvas and get its ID
# --- MODIFIED LINE ---
scrollable_window_id = canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")

# --- NEW BINDING ---
# 5. This new binding updates the frame's WIDTH when the canvas is resized
canvas.bind(
    "<Configure>",
    lambda e: canvas.itemconfig(scrollable_window_id, width=e.width)
)

# 6. Pack the canvas and scrollbar into the main window
scrollbar.pack(side="right", fill="y")
canvas.pack(side="left", fill="both", expand=True)

canvas.bind_all("<MouseWheel>", _on_mousewheel) # For Windows and macOS
canvas.bind_all("<Button-4>", _on_mousewheel)   # For Linux scroll up
canvas.bind_all("<Button-5>", _on_mousewheel)   # For Linux scroll down


# --- NOW, ALL WIDGETS USE 'scrollable_frame' AS THEIR PARENT ---
# (The rest of this section is the same as before)
open_button = ttk.Button(scrollable_frame, text="Open SMC File...", command=open_smc_action)
open_button.pack(fill='x', pady=5, padx=10)

warning_label = ttk.Label(scrollable_frame, text="", anchor="center", font="-weight bold")
warning_label.pack(fill='x', padx=10)

status_frame = ttk.LabelFrame(scrollable_frame, text="File Status", padding=10)
status_frame.pack(fill='x', pady=(5, 10), padx=10)
status_var = tk.StringVar(value="Waiting for file...")
author_var = tk.StringVar(value="N/A")
filename_var = tk.StringVar(value="N/A")
ttk.Label(status_frame, text="Status:").grid(row=0, column=0, sticky='w')
ttk.Label(status_frame, textvariable=status_var, font="-weight bold").grid(row=0, column=1, sticky='w')
ttk.Label(status_frame, text="Author:").grid(row=1, column=0, sticky='w')
ttk.Label(status_frame, textvariable=author_var).grid(row=1, column=1, sticky='w')
ttk.Label(status_frame, text="Original File:").grid(row=2, column=0, sticky='w')
ttk.Label(status_frame, textvariable=filename_var).grid(row=2, column=1, sticky='w')

display_frame = ttk.LabelFrame(scrollable_frame, text="File Content", padding=10)
display_frame.pack(fill='both', expand=True, padx=10)

phrase_frame = ttk.LabelFrame(scrollable_frame, text="Secret Phrase", padding=10)
phrase_frame.pack(fill='x', pady=10, padx=10)
phrase_pass_var = tk.StringVar()
ttk.Label(phrase_frame, text="Passkey:").pack(side='left')
phrase_pass_entry = ttk.Entry(phrase_frame, textvariable=phrase_pass_var, show="*", state='disabled')
phrase_pass_entry.pack(side='left', expand=True, fill='x', padx=5)
unlock_phrase_button = ttk.Button(phrase_frame, text="Unlock", state='disabled', command=unlock_phrase_action)
unlock_phrase_button.pack(side='left')

save_button = ttk.Button(scrollable_frame, text="Save File...", state='disabled', command=save_file_action)
save_button.pack(fill='x', pady=5, padx=10)

# --- GET DEFAULT BG COLOR (as before) ---
default_bg_color = ttk.Style().lookup('TLabel', 'background')

root.mainloop()