# There is a man in the middle!!

This project implements a secure messaging channel protocol inspired by modern cryptographic ratchet designs, featuring Diffie–Hellman key exchange, a key derivation function (KDF), symmetric encryption (AES-CBC), message authentication (HMAC-SHA256), forward secrecy, integrity and replay protection, and a simple simulation of a man-in-the-middle (MITM) attacker. This channel provides confidentiality, integrity, and mutual authentication, protecting data against unauthorized access and tampering. It was developed as the final Projects for a cybersecurity course during my exchange studies at the University of British Columbia (UBC), Vancouver, Canada.
- Note: In a real-world deployment, the initial key exchange would be protected by certificates (e.g., X.509/TLS) or another form of authenticated channel to prevent a man-in-the-middle from tampering with these long-term public keys

## My Communication Protocol:

1. **Initial Handshake (Asymmetric Key Exchange)**
   Upon connecting, the client and server each possess a long-term ECC keypair (P-256 curve). The client initiates the handshake by sending its public key (Base64‑encoded DER) to the server. The server responds with its own public key in the same format.
   • This exchange establishes mutual authentication of the long-term keys.
   • Both sides then compute a shared secret via Elliptic‑Curve Diffie–Hellman (ECDH).

2. **Key Derivation Function (KDF)**
   The raw ECDH secret is passed into a KDF based on SHAKE128 XOF, which "squeezes" exactly 32 bytes of pseudorandom output.
   • **Purpose**: normalize the secret to a fixed length, ensure high entropy distribution, and prepare it for symmetric-key usage.

3. **Symmetric Key Splitting**
   From the 32‑byte KDF output, we derive two distinct symmetric keys by hashing with different labels:
   • **enc\_key** is used to encrypt message payloads under AES‑CBC with random IV.
   • **auth\_key** is used to generate and verify HMAC-SHA256 over the JSON body.

  <img width="869" height="250" alt="image" src="https://github.com/user-attachments/assets/d60f88b1-2f0e-4fa8-aa18-cef669e865b7" />

4. **Per-Message Ratchet**
   For each message cycle, both client and server generate fresh ephemeral ECC keypairs and include the new public key in the next message or acknowledgment.
   • After sending, each side updates its private key to the new ephemeral one, discarding the old.
   • They recompute a fresh shared secret and symmetric keys, achieving forward secrecy: past keys cannot decrypt future messages.

5. **Message Format and Transmission**
   Each message is encapsulated as a JSON object.
<img width="869" height="100" alt="image" src="https://github.com/user-attachments/assets/9df6821c-2f1c-4770-abb5-3571c034b125" />


 #### Sample Execution
   
```json{
  "body": {
    "nonce": 1,
    "warnings": [],
    "text": "5a8717dc4718ff1e40b244d8eec69047",
    "iv": "e14ee2ea6d57f701f82acb3c85e98fd9",
    "new_pub_key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEkqarK+XcgKKbSTVi+ajdjB8lFp3SlsvFGwTl8qFc7w1NuYLyuKDUnr9QncQl0Q2kZYfBa4nVQckfcFCOQ/3uog=="
  },
  "hmac": "b4bc93bf989554b30239529c08464420e20fb7ec2a05be9c7c6adb5086574a1d"
}
```

   - **nonce** prevents replay: each side rejects messages with an older counter. 
   - **warnings** accumulates codes for any detected integrity or availability issues.
   - **text** and **iv** represent the encrypted plaintext and IV.
   - **new\_pub\_key** seeds the next ratchet step.

7. **Message Processing**

   * **Sender**: pads and encrypts the UTF-8 plaintext under AES-CBC, encodes IV and ciphertext in hex, builds the JSON body, computes HMAC over the body, and serializes the full payload.
   * **Receiver**: parses JSON, validates structure, verifies HMAC (throws `InvalidHashError` on mismatch), checks nonce order (`InvalidNonceError` on replay), decrypts ciphertext (`ValueError` if padding/IV wrong), logs content and warnings, then updates ratchet state.

8. **Attack Simulation (MITM)**
   A separate `mitm_wrapper.py` acts as a proxy between client and server, allowing configurable behaviors per message index:

   * **Drop**: return empty payload to simulate availability attack.
   * **Modify**: tamper with JSON fields or ciphertext to test integrity checks.
   * **Replay**: resend old messages to test nonce-based replay protection.

## Running the Project

- **Install dependencies** - `pip install -r requirements.txt`
- **(Optional)Generate fresh keys** - Run `entrypoints/generate_keys.py`, copy the printed base64 values into `config/keys.py`.
- **Start the server** - run `entrypoints/server_wrapper.py`, Ensure the server listens on its configured PORT (default 65432).
- **(Optional) Start the MITM** - run `entrypoints/mitm_wrapper.py`, Listen on the client port (65431) and forward to the server port (65432).
- **Start the client** - run `entrypoints/client_wrapper.py` (default 65432, set to 65431 if you want to invite the "man in the middle".
- **Observe logs** - Server logs decrypted messages to `server_output.txt` and Console warnings appear on integrity or drop attacks.

Enjoy experimenting with secure messaging, ratchets, and MITM resilience! :)

## Feedback & Contact
If you find any issues, have questions, or suggestions for improvement, feel free to reach out:
- Email: yonzra12@gmail.com
- Linkdin: www.linkedin.com/in/yehonatanezra
---

