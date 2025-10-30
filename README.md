# Secure_file_transfer


This project implements a **secure file transfer system** between multiple clients and a central file server. The main goal is to make sure files are shared inside an organization **safely**, **with access control**, and **with cryptographic protection**.

### Key Features
- **Client–Server Architecture:** all clients connect to a central file server over sockets.
- **Multi-Client Support:** the server can handle multiple clients at the same time.
- **Role-Based Access Control (RBAC):** each user has one of three roles:
  - **admin** – can create/delete users, change user roles, upload files, download all files, and delete files.
  - **maintainer** – can upload files, manage their own files on the server, and download all files.
  - **guest** – can only download files that exist on the server.
- **Secure Communication (Encryption in Transit):** after a client connects, the server generates a **session symmetric key** and sends it securely to the client. All messages and file transfers in that session are encrypted with this key.
- **Encrypted Storage (Encryption at Rest):** files that are uploaded to the server are stored **encrypted** using the server’s encryption key, so even if the storage is accessed directly, the content is not readable.
- **Digital Signatures & Integrity:** before uploading, the client **signs** the file with its own private key. When the file is downloaded, the receiver can verify the signature to make sure the file has not been changed.
- **Public Key Registry:** the server keeps the public key of every registered user so that signatures can be verified.

### How It Works

1. **User Registration**
   - Each user generates a key pair (private/public).
   - The user sends their **public key** to the server.
   - By default, new users are created with the **guest** role.

2. **Client Connection**
   - The client connects to the server via a socket.
   - The server creates a **new symmetric key** for that session.
   - From now on, all data between client and server is **encrypted**.

3. **Uploading a File**
   - The client signs the file with their **private key**.
   - The client encrypts the signed file with the **session key** and sends it.
   - The server checks the user’s **role**; if the user is allowed to upload, the server decrypts the incoming data and **stores the file encrypted** on disk.

4. **Downloading a File**
   - The client requests a file.
   - The server checks access, decrypts the stored file, and sends it over the encrypted channel.
   - The client decrypts it and verifies the **digital signature** to make sure the file is authentic.

### Roles and Permissions

| Role      | Upload | Download | Manage Users | Change Roles | Delete Files |
|-----------|--------|----------|--------------|--------------|--------------|
| admin     | ✔      | ✔        | ✔            | ✔            | ✔            |
| maintainer| ✔      | ✔        | ✖            | ✖            | only own     |
| guest     | ✖      | ✔        | ✖            | ✖            | ✖            |

### Technologies / Concepts Used
- Socket programming (client–server)
- Symmetric and asymmetric cryptography
- Digital signatures
- Role-Based Access Control (RBAC)
- Secure file storage

### Possible Extensions
- Secure session key exchange (e.g. Diffie–Hellman)
- Logging and audit trail for uploaded/downloaded files
- Web or GUI client
