## Experimental Backup Feature 

https://github.com/user-attachments/assets/bf3d0cc2-65dc-4a50-97ac-b09059554e54

### What it does

Adds **Tools → Encrypted Cloud Backup** and **Tools → Restore from Cloud Backup**. A backup can be created and later recovered with nothing but the wallet's BIP39 seed words, on any Sparrow instance.

### How it works

- The seed words are passed through HKDF-SHA256 to derive two independent secrets: an AES-256-GCM encryption key and a secp256k1 nostr identity.
- The backup blob is the gzipped, unencrypted Sparrow wallet file (preserving labels, accounts, birthdate, etc.) encrypted with the AES key, then uploaded to https://blossom.primal.net using BIP-340 signed Blossom (BUD-02) auth events.
- Restore re-derives both keys from the entered words, lists blobs owned by the derived pubkey, downloads the newest, decrypts it, and imports it through Sparrow's standard flow.

### Trade-offs

- **The seed words are the entire security boundary**: anyone holding them can locate *and* decrypt the backup. The wallet password is intentionally not part of the blob, so it cannot help or hinder recovery.
- **Compress-then-encrypt leaks the compressed wallet size** to the server. Since no attacker can inject content into the wallet file, this is benign metadata here, but it does reveal roughly how large (and over time, how fast-growing) the wallet is.
- The server sees your IP and the seed-derived pubkey (uploads bypass Sparrow's Tor proxy), and makes no retention guarantee — treat this as a convenience backup, not the only one.

Implementation: `com.sparrowwallet.sparrow.io.blossom.BlossomBackup`.
