# SecureFS

A small browser based secure file vault made with HTML, CSS, JavaScript, Web Crypto, and a local Python server.

## Run it

On Windows, run `py server.py` from this project folder (or `python server.py`), then open `http://127.0.0.1:8000` in a modern browser. Keep the server window open while using the app. If you open the page through a localhost static preview such as VS Code Live Server, storage requests still go to the SecureFS server on port 8000.

First-time demo login:

- User ID: `Tanishq111`
- Password: `Tanishq@111`

Create folders to organize uploads, then choose a folder before uploading with the button or drag and drop. The app displays a success message listing uploaded files. Click **View** on a PDF to decrypt and preview it in the browser, or use the download button to save the original file. Files and folder names are encrypted in the browser using AES-GCM with a key derived from the password using PBKDF2, then saved in a compact binary `.sfs` format under the project’s `uploaded_files/` directory. Each folder gets its own directory there, named with a private ID. The files contain ciphertext and the AES-GCM nonce, without a readable JSON wrapper. Delete removes its encrypted record. Existing browser vault records are copied to the project folder the first time you sign in with the server running.

## Demo security note

This is a college project demonstration, not a production secure filesystem. The starter login is necessarily visible in client-side JavaScript, so it is not suitable for protecting sensitive files. The server binds to localhost and has no user management, recovery flow, or cross-device sync. Use sample files only. Browser Web Crypto and Python 3 are required.
