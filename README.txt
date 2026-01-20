ST2504 Applied Cryptography - Assignment 2: Secure Vault System

--------------------------------------------------------------------------
1. PREREQUISITES
--------------------------------------------------------------------------
This application requires Python 3.x and the 'cryptography' library.

To install the required library, open your terminal/command prompt and run:
   pip install cryptography

--------------------------------------------------------------------------
2. DIRECTORY STRUCTURE
--------------------------------------------------------------------------
The submitted zip file contains the following:

/ (Root)
  |-- README.txt
  |-- keys/                 <-- Auto-generated keys
  |-- utils/
      |-- crypto_utils.py   <-- Shared Library
      |-- keygen.py         <-- Run this first!
  |-- Server/
      |-- server.py
      |-- server_vault/     <-- Storage (Auto-generated)
  |-- Client/
      |-- client.py

--------------------------------------------------------------------------
3. HOW TO DEPLOY & RUN
--------------------------------------------------------------------------
Follow these steps in order to test the Secure Vault.

STEP 1: GENERATE KEYS (Deployment)
   - Before running the client or server, you must generate the RSA key pairs.
   - Run the following command:
     python utils/keygen.py
   - You should see a new folder named 'keys/' containing:
     client_private.pem, client_public.pem, server_private.pem, server_public.pem

STEP 2: START THE SERVER
   - Open a terminal window.
   - Run the server script:
     python Server/server.py
   - The server will display: "🔒 Secure Vault Server listening on 127.0.0.1:65432"
   - Keep this terminal open.

STEP 3: RUN THE CLIENT
   - Open a NEW terminal window (do not close the server).
   - Create a dummy file to test (e.g., create a text file named 'secret.txt').
   - Run the client script:
     python Client/client.py
   - Follow the prompt:
     "Enter filename to upload (e.g., secret.txt):" -> Enter your file name.

--------------------------------------------------------------------------
4. VERIFICATION (What to look for)
--------------------------------------------------------------------------
To verify the security features during the demo:

1. CONFIDENTIALITY (Encryption):
   - Observe the Client Terminal: It will show the size of the encrypted ciphertext.
   - Observe the Server Terminal: It will confirm "AES Key Decrypted."

2. INTEGRITY & NON-REPUDIATION (Digital Signature):
   - Observe the Server Terminal: It must print "✅ Signature Verified".
   - If the file was tampered with during transit, the server would reject it.

3. SUCCESSFUL STORAGE:
   - Check the 'server_vault/' folder. Your uploaded file should appear there.

--------------------------------------------------------------------------
5. TROUBLESHOOTING
--------------------------------------------------------------------------
- "ConnectionRefusedError": Ensure server.py is running before starting client.py.
- "FileNotFoundError (Keys)": Ensure you ran keygen.py first.
- "ModuleNotFoundError": Ensure you ran 'pip install cryptography'.

END OF README
# ACG CA2 2026
