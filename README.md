# SMC: The Secure Media Container
> Because zipping a file with the password 'password123' and emailing it is a cry for help.

Ever needed to send a file to someone and be *absolutely certain* it arrived untouched and that it was *really* you who sent it? Ever wished you could wrap a file in layers of cryptographic armor so thick that even a government-level hacker would just sigh and move on to an easier target?

**SMC is your new best friend.**

Think of it as a digital armored box with an unforgeable wax seal, and optionally, a secret compartment with its own password. It’s designed to be simple for you, and a nightmare for anyone trying to snoop.

---
## ✅ Core Features
So, what's in the box? Magic, mostly. But also:

* **Ironclad Digital Signatures:** Using the power of Ed25519 public-key cryptography, every SMC file is signed. This proves who the author is and guarantees that the file hasn't been modified by even a single bit since it was created. No more "Are you sure this is the right version?" nonsense.

* **Paranoid-Grade Encryption (Optional):** For when you need to send something that *absolutely nobody else* can see. The entire file payload can be encrypted with a password. We use a salted KDF (scrypt) to turn your simple password into a monstrously strong encryption key. This isn't your grandma's password protection.

* **Hidden Messages (Also Optional):** Need to include a secret phrase or code word that's protected by a *different* password? You can. The main file can be perfectly visible, while a hidden message stays locked away, waiting for the right passkey. It's the digital equivalent of a secret note taped to the back.

* **The Spy Network™ Trust Model:** You don't just trust any key that shows up. The SMC Viewer maintains a hardcoded list of public keys you trust. If a file is signed by a key that isn't on your list, the viewer will immediately warn you that you're dealing with a stranger. A stranger with a cryptographically valid file, but a stranger nonetheless.

* **Universal File Support:** This isn't just for images. Wrap up PDFs, videos, zip archives, your secret novel, *anything*. If it's a file, SMC can protect it.

* **Dead-Simple GUI Tools:** No command-line wizardry required.
    * **SMC Maker:** A simple point-and-click interface to generate your keys and package your files with all the security options you want.
    * **SMC Smart Viewer:** A drag-and-drop-friendly viewer that automatically verifies, decrypts, and displays your files, all while giving you a clear status on their authenticity and trust level.

---
## 🛠️ The Tech Stack
This project was built with pure Python and a sprinkle of cryptographic genius, relying on:
* **Python 3:** The language of choice.
* **Tkinter:** For our lovely, no-frills graphical user interfaces.
* **PyNaCl:** The powerhouse library that handles all the serious cryptographic lifting (Ed25519 signatures, scrypt KDF, and XChaCha20-Poly1_305 encryption).

---
## 🚀 Installation & Setup

Getting started is easy. Don't be intimidated by the cryptography; it's already scared of you.

1.  **Clone the repo (or just save the files):**
    ```bash
    git clone https://github.com/Rishi-Bhati/smc.git
    cd smc-project
    ```

2.  **Set up a virtual environment (it's just good manners):**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

3.  **Install the dependencies:**
    ```bash
    pip install pynacl Pillow
    ```

---
## 📜 How to Use It: A Walkthrough

Your journey from paranoid data-hoarder to secure communications expert in 4 easy steps.

### Step 1: Generate Your Identity (Keys)
Before you can sign anything, you need a signature.
1.  Run the **SMC Maker** (`smc_maker.py`).
2.  Go to the "Generate Keys" tab.
3.  Enter a unique name or prefix for your key files (e.g., `agent_cobra`).
4.  Click "Generate Keys".
5.  Two files will appear: `agent_cobra_ed25519_sk.b64` (your **SECRET** key) and `agent_cobra_ed25519_pk.b64` (your **PUBLIC** key).

**Guard your secret key with your life.** (Don't lose it. Seriously.) Share your public key with anyone you want to receive secure files from you.

### Step 2: Establish the Trust Network
For the viewer to trust you, you must add your public key to its trusted list.
1.  Open your public key file (`agent_cobra_ed25519_pk.b64`) with a text editor.
2.  Copy the long string of text inside.
3.  Open the **SMC Viewer** script (`smc_viewer.py`) in your code editor.
4.  Find the `TRUSTED_AUTHORS` dictionary at the top.
5.  Add an entry for yourself and paste your key.
    ```python
    TRUSTED_AUTHORS = {
        "My Own Key": "qG3p...your...long...public...key...string...Z7o=",
        "Agent Cobra": "PASTE_THE_KEY_YOU_JUST_COPIED_HERE" 
    }
    ```
6.  Save the viewer script. Now it trusts you. Tell your friends to do the same with your public key.

### Step 3: Create a Secure Package (SMC)
1.  Run the **SMC Maker**.
2.  Go to the "Create SMC" tab.
3.  **Input File:** Browse and select the file you want to protect.
4.  **Signing Key:** Browse and select your **SECRET** key file.
5.  **Output File:** Choose where to save the new `.smc` file.
6.  **Choose your security:**
    * Want it to be unreadable without a password? Check "Encrypt the main file data" and enter a strong password.
    * Want to add a hidden note? Check "Add a hidden... phrase" and enter a passkey and the phrase.
    * Want both? Go for it.
    * Want neither? Just leave them unchecked for a standard, signed-only file.
7.  Click "Create SMC File". Boom. Done.

### Step 4: Open and Verify
1.  Run the **SMC Smart Viewer**.
2.  Click "Open SMC File..." and select the `.smc` file you just created.
3.  The viewer will instantly perform all checks:
    * **If everything is perfect:** Status will be "SUCCESS: Signature is valid!", the author will be your name, and the file content will be displayed.
    * **If the signature is valid but the author isn't in your trusted list:** You'll see a big yellow **WARNING** bar. The file is intact, but it's from a stranger. Proceed with caution.
    * **If the file has been tampered with:** You'll get a big red **ERROR** bar. The signature is invalid. **Do not trust this file.** Abort mission.

---
## 🕵️ A Note on the Security Model

This tool is built on a "zero-trust" foundation where verification is paramount. The signature check proves the file's integrity, while the trusted list check proves the author's authenticity. A file can be integral (un-tampered) but inauthentic (from an unknown person), and the viewer is smart enough to tell you the difference.

---
## ⚠️ Disclaimer
The SMC toolkit is built using the industry-standard PyNaCl library, which provides a high-level interface to the robust and heavily audited libsodium cryptographic library. All cryptographic operations—from the Ed25519 digital signatures to the scrypt KDF and XChaCha20-Poly1305 encryption—are handled by these trusted, professional-grade components.

This application is provided "AS IS" under the MIT License, without warranty of any kind. As with any security tool, you are encouraged to understand its functionality and evaluate its suitability for your specific use case. The security of your data depends on both the strength of the underlying cryptography and the secure management of your own secret keys. (Writing it on a sticky note stuck to your monitor is not considered 'secure management'.)

Have fun staying secure!