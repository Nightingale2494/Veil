# Veil

<p align="center">
  <img src="https://img.shields.io/badge/rust-%23000000.svg?style=for-the-badge&logo=rust&logoColor=white" alt="Rust" />
  <img src="https://img.shields.io/badge/Flutter-%2302569B.svg?style=for-the-badge&logo=Flutter&logoColor=white" alt="Flutter" />
  <img src="https://img.shields.io/badge/postgres-%23316192.svg?style=for-the-badge&logo=postgresql&logoColor=white" alt="PostgreSQL" />
  <img src="https://img.shields.io/badge/websockets-%23010101.svg?style=for-the-badge&logo=socket.io&logoColor=white" alt="WebSockets" />
  <img src="https://img.shields.io/badge/GoogleCloud-%234285F4.svg?style=for-the-badge&logo=google-cloud&logoColor=white" alt="Google Cloud" />
  <img src="https://img.shields.io/badge/license-Proprietary-red.svg?style=for-the-badge" alt="License: Proprietary" />
</p>

Veil is a privacy-first, end-to-end encrypted (E2EE) messaging platform built from the ground up using Flutter, Rust, PostgreSQL, WebSockets, and modern cryptographic protocols. The system is designed to provide secure, real-time communication across multiple devices while keeping the server entirely agnostic to the contents of messages, media attachments, and WebRTC streams.

This project was created as a full-stack systems engineering project to explore and implement secure communication standards, distributed networking systems, cryptographically enforced data privacy, and reliable cloud-based backend architectures.

---

## Features

### Authentication & Identity
* **Secure Account Registration**: Client-side public identity key creation with zero-knowledge password verification.
* **Device Authentication**: Secure token-based session management using Argon2id hashing for device validation.
* **Multi-Device Support**: Identity keys are managed per-device, allowing users to safely connect and authorize new client instances.
* **Recovery Phrase Support**: BIP-39 mnemonic phrase generation for key backup and device identity recovery.

### Messaging
* **End-to-End Encryption**: Direct client-to-client message encryption using the double ratchet algorithm.
* **Real-time Messaging**: Low-latency message delivery using a binary WebSocket connection.
* **Offline Message Queue**: Transient database queueing that stores encrypted envelopes for offline devices until delivery.
* **Interactive Chat Controls**: Live typing indicators, emoji reactions, and read-receipt indicators.
* **Rich Media Sharing**: Dynamic inline rendering for shared images, documents, audio files, and attachments.

### Secure Attachments
* **Chunked Uploads**: Reliable file chunking supporting large file sharing (exact 4 MiB chunks).
* **Attachment Encryption**: Files are encrypted with locally generated key blocks before upload.
* **Integrity Verification**: Automatic client-and-server SHA-256 hash checks to prevent data tampering.
* **Offline Attachment Delivery**: Delayed binding of attachments to message identifiers to support queue retention.

### Groups
* **Secure Group Chats**: Pairwise Double Ratchet sessions established between all group participants.
* **Member Management**: Dynamic group admin controls to invite or remove participants.
* **Group Notifications**: Encrypted notifications triggered for membership changes.

### Calls
* **Voice & Video Calling**: Real-time media streaming built on WebRTC channels.
* **WebRTC Signaling**: Signaling coordination implemented over WebSocket connections.
* **ICE Exchange**: Secure ICE candidate routing for peer-to-peer connection establishment.

### Infrastructure
* **Rust Backend**: Memory-safe, high-performance HTTP & WebSocket server built with Axum.
* **PostgreSQL Database**: Relational schema optimizing pre-keys, devices, groups, and temporary queues.
* **Linux Deployment**: Runs as a persistent systemd service with automatic crash recovery.
* **Background Workers**: Auto-expiry workers that purge delivered messages and orphaned file attachments.

---

## Technology Stack

| Layer | Component | Description |
| :--- | :--- | :--- |
| **Frontend** | Flutter / Dart | Responsive UI, state management via Riverpod, WebRTC rendering |
| **Backend** | Rust / Axum / Tokio | Async event loop, WebSocket gateway, REST API, system service |
| **Database** | PostgreSQL | Relational storage for sessions, prekey bundles, and offline queues |
| **Security** | Cryptography | X3DH, Double Ratchet, Ed25519, X25519, ChaCha20-Poly1305, HKDF, CBOR |
| **Deployment** | Infrastructure | Google Cloud Compute Engine, Ubuntu Linux, systemd daemon management |

---

## Architecture

```
                       +----------------------------------+
                       |          Flutter Client          |
                       +-----------------+----------------+
                                         |
                +------------------------+------------------------+
                |                                                 |
                v (HTTPS REST)                                    v (WSS binary CBOR)
    +-----------------------+                         +-----------------------+
    |       REST API        |                         |   WebSocket Gateway   |
    | (Auth, Prekeys, Media)|                         | (Signal, Live Relay)  |
    +-----------+-----------+                         +-----------+-----------+
                |                                                 |
                +------------------------+------------------------+
                                         |
                                         v
                              +-----------------------+
                              |     Rust Backend      |
                              |    (Axum & Tokio)     |
                              +-----------+-----------+
                                         |
                                         v
                              +-----------------------+
                              |      PostgreSQL       |
                              |   (Transient Store)   |
                              +-----------------------+
```

### Protocol Flow
1. **Device Pre-key Generation**: Clients generate identity keys and prekey bundles on startup, registering them via the REST API to the database.
2. **WebSocket Connection**: The client initiates a secure WebSocket connection upgrading to a binary protocol (CBOR serialization) using session token authentication.
3. **P2P Channel establishment**: To message a contact, the client fetches the recipient's prekey bundle from the server, computes a shared secret, and launches a peer-to-peer session.
4. **Zero-Trust Relay**: All message content, calls, and attachments are encrypted client-side. The server functions exclusively as a transient transport layer and cannot access the plain text.

---

## End-to-End Cryptography

Veil protects communications using a modern Double Ratchet cryptographic architecture, ensuring that messages remain private even if the server infrastructure is completely compromised.

* **Identity Keys (IK)**: Long-term X25519 key pairs representing a user's stable cryptographic identity.
* **Signed PreKeys (SPK)**: Medium-term key pairs signed by the identity key to prevent man-in-the-middle attacks during offline handshakes.
* **One-Time PreKeys (OTK)**: Ephemeral key pairs consumed upon session initialization to maximize security.
* **X3DH (Extended Triple Diffie-Hellman)**: A protocol used to establish a shared session secret between two parties who do not actively share a connection, even if one party is offline. It performs four DH exchanges (IK-SPK, IK-IK, SPK-IK, and optionally SPK-OTK).
* **Double Ratchet**: Executes a combination of KDF chain ratchets (symmetric-key ratchet) and Diffie-Hellman ratchets (DH ratchet) for every message sent. This provides:
  * **Forward Secrecy**: Compromise of current keys does not reveal previously sent messages.
  * **Future Secrecy (Break-in Recovery)**: Compromise of current keys does not allow an eavesdropper to read future messages once the ratchet performs another DH step.
* **Session Keys**: Temporary keys generated dynamically per-message to encrypt payloads using ChaCha20-Poly1305.

---

## Rich Media & Attachments

Veil handles attachments securely by keeping the files encrypted end-to-end and managing storage efficiently through transient binding.

```
[Local File] ──► Encrypt (ChaCha20) ──► Compute SHA-256 ──► Upload Chunks (4 MiB) 
                                                                   │
[Delivered Message] ◄── Decrypt ◄── Download Chunks ◄── Bind Message ID (REST)
```

1. **Local Encryption**: The client generates a random 32-byte key locally, encrypts the file using ChaCha20-Poly1305, and computes the SHA-256 checksum of the ciphertext.
2. **Chunked Uploads**: The ciphertext is uploaded in exact 4 MiB chunks. The final chunk may be smaller.
3. **Integrity Checks**: The server validates that the reassembled file's SHA-256 matches the checksum supplied by the client during initialization.
4. **Transient Binding**: The attachment's `message_id` references `pending_messages(id)`. When the recipient comes online, they retrieve the queued message and download the media chunks. 
5. **Orphan Cleanup**: Once delivered, the message is deleted from the queue. The database constraint set to `ON DELETE SET NULL` zeroes out the attachment's `message_id`. An automatic background worker permanently deletes unreferenced file blobs from disk after a configured duration.

---

## Group Chats

Group conversations in Veil are built on pairwise session management:
* **Pairwise Session Delivery**: To send a group message, the client encrypts the message payload individually for every member device using their respective Double Ratchet sessions. The resulting encrypted envelopes are sent in a batch over WebSockets.
* **Group Management**: Group information (metadata, roles, and member device IDs) is synced via secure API endpoints.
* **Member Roles**: Administrators can invite or remove members, prompting client devices to update their local group routing lists.

---

## Voice & Video Calling

Veil uses WebRTC for high-quality, low-latency audio and video streams:
* **WebSocket Signaling**: Clients use the active WebSocket connection to exchange JSON-wrapped signaling packets.
* **Offer/Answer Exchange**: The caller sends a WebRTC session description (Offer), and the callee responds with an Answer.
* **ICE Candidate Exchange**: Interactive Connectivity Establishment (ICE) candidates are dynamically routed to negotiate direct peer-to-peer connections.
* **Fallback & Secure Streams**: Media encryption is handled natively by DTLS-SRTP, bypassing the server entirely once the peer connection is established.

---

## Deployment

The Veil backend is deployed on a Linux VM environment:
* **Platform**: Google Cloud Compute Engine (Ubuntu Linux).
* **Service Manager**: Managed by `systemd` to ensure persistent execution.
* **Environment Configuration**: Secrets and database connection strings are stored securely in `/etc/veil/veil.env` with `600` permissions.
* **Resilience**: Configured with automatic restarts to relaunch the service within 5 seconds in case of a crash or server reboot.

---

## Project Structure

```
Veil/
├── backend/                  # Rust Backend Source (Axum, Tokio, SQLx)
│   ├── src/
│   │   ├── domain/           # Core models & repositories definition
│   │   ├── infrastructure/   # Database access & push notifications
│   │   └── presentation/     # REST routes & WebSocket gateways
│   └── Cargo.toml
├── database/                 # Database Schema & Migrations
│   └── migrations/           # SQL migration files
├── frontend/                 # Flutter Mobile Frontend
│   ├── lib/
│   │   ├── application/      # Riverpod providers & state logic
│   │   ├── domain/           # Models & business rules
│   │   ├── infrastructure/   # API client & SQLite local DB
│   │   └── main.dart         # Main widgets & UI views
│   └── pubspec.yaml
├── deploy.sh                 # Idempotent Linux deployment script
├── veil.service              # Systemd unit file template
├── LICENSE                   # Custom proprietary license file
└── README.md                 # Project documentation
```

---

## Screenshots

<p align="center">
  <table>
    <tr>
      <td><b>Login / Setup</b></td>
      <td><b>Home / Chats</b></td>
    </tr>
    <tr>
      <td><img src="https://via.placeholder.com/200x400.png?text=Login+Screen" alt="Login Screenshot" width="200" /></td>
      <td><img src="https://via.placeholder.com/200x400.png?text=Chats+List" alt="Home Screenshot" width="200" /></td>
    </tr>
    <tr>
      <td><b>Secure Group Chat</b></td>
      <td><b>Voice / Video Call Overlay</b></td>
    </tr>
    <tr>
      <td><img src="https://via.placeholder.com/200x400.png?text=Group+Chat" alt="Groups Screenshot" width="200" /></td>
      <td><img src="https://via.placeholder.com/200x400.png?text=WebRTC+Call" alt="Voice/Video Call" width="200" /></td>
    </tr>
  </table>
</p>

---

## Future Roadmap

- [ ] **Native Push Notifications**: Integration with APNs/FCM for background message receipt.
- [ ] **Profile Customization**: Cryptographically signed profile cards and custom avatars.
- [ ] **Presence Indicators**: Ephemeral online/offline status updates using low-overhead WebSockets.
- [ ] **Desktop & Desktop Client**: Compilation support for macOS, Windows, and Linux.
- [ ] **Message Search**: Local search functionality indexing decrypted messages inside client-side SQLite.
- [ ] **Comprehensive Security Audit**: Verification of Double Ratchet implementation by independent cryptographic researchers.

---

## Why I Built Veil

Veil was built as a systems design challenge to master advanced engineering domains:
* **Systems Languages**: Deepening practical knowledge of memory safety and concurrency models in Rust.
* **Modern Cryptography**: Gaining hands-on experience implementing the Double Ratchet and X3DH standards.
* **Networking & Concurrency**: Designing real-time, low-overhead WebSocket gateways.
* **Infrastructure & Linux Administration**: Configuring secure, production-grade Linux daemons and PostgreSQL connection pooling.
* **Cross-platform UI**: Building fluid, state-driven interfaces with Flutter.

---

## Disclaimer

Veil is an educational, portfolio, and demonstration project. It has not undergone formal cryptographic audits or penetration testing. It should not be used to protect highly sensitive communications or deployed in environment scenarios where complete security is mission-critical.

---

## License

Copyright (c) 2026 Ishaan Chowdhury. All Rights Reserved.

This repository and its contents are made publicly visible for portfolio, demonstration, and evaluation purposes only. Unauthorized copying, redistribution, modification, publishing, sublicensing, or commercial utilization of this software is strictly prohibited without prior written consent from the copyright owner.
