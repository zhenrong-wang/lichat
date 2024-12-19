# How To Make UDP Communications Secure?

This is a design to make UDP communication between a communication pair (we can call it `client` and `server`) secure.

# 1. Prerequisites

There are 2 key pairs at client side and server side: `curve25519` for key exchange and `ed25519` for signature.

At Client Side: `client_crypto.pub, client_crypto.sec` (**c_crypto_pk**, **c_crypto_sk**) and `client_sign.pub, client_sign.sec` (**c_sign_pk**, **c_sign_sk**).

At Server Side: `server_crypto.pub, server_crypto.sec` (**s_crypto_pk**, **s_crypto_sk**) and `server_sign.pub, server_sign.sec` (**s_sign_pk**, **s_sign_sk**).

The `*_crypto.pub` (**\*_crypto_pk**) and `*_crypto.sec` (**\*_crypto_sk**) are public key and secret key of a curve25519 key pair.

The `*_sign.pub` (**\*_sign_pk**) and `*_sign.sec` (**\*_sign_sk**) are public and secret key of a ed25519 key pair.

Please keep in mind that the `*.sec` (**\*_sk**) files are **secret keys** and would not be exposed to anyone or anywhere else.

To make the name short, we define the abbreviations:

- `c_spk`: Client Sign Public Key
- `c_ssk`: Client Sign Secret Key
- `c_cpk`: Client Crypto Public Key
- `c_csk`: Client Crypto Secret Key

- `s_spk`: Server Sign Public Key
- `s_ssk`: Server Sign Secret Key
- `s_cpk`: Server Crypto Public Key
- `s_csk`: Server Crypto Secret Key

- `aes_key`: AES256-GCM key
- `aes_nonce`: AES256-GCM Nonce bytes

# 2. Communication Process

Diagram as below, detailed description follows the diagram.

```
          Client                                  Server
*HANDSHAKE* | 00 c_spk             \                | Generate
            |    SIGNED(cid c_cpk)  |               | cinfo_hash
            |        OR             |-------------->| Generate
            | 01 c_spk              |               | sid
            |    SIGNED(cid c_cpk) /                | Calculate AES Key
            |                                       |
            |       / 00 s_spk SIGNED(s_cpk)        | 
            |      |     Encrypted: server_sid      | 
Calculate   |      |                cinfo_hash OK   | 
AES Key     |<-----|            OR                  | AES nonce
AES-Decrypt |      |  01 SIGNED(ok)                 | AES-Encrypt
            |      |     Encrypted: server_sid      | 
            |       \               cinfo_hash OK   | 
            |             _______________           |
AES nonce   | 02         | server_sid OK |          | AES-Decrypt
AES-Encrypt | cinfo_hash-+---Encrypted---+--------->| Activate session
            |                      _______________  | 
            |                     | server_sid    | |
            |                     | cinfo_hash    | |
            |                     | OK            | | AES nonce
AES-Decrypt |<-----------------02-+---Encrypted---+ | AES-Encrypt
            |                                       |
*MESSAGING* |             _____________________     |                        
AES nonce   | 0x10       | server_sid msg_body |    |
AES-Encrypt | cinfo_hash-+------Encrypted------+--->| AES-Decrypt
            |                      _______________  | 
            |                     | server_sid    | |
            |                     | cinfo_hash    | |
            |                     | msg_body      | | AES nonce
AES-Decrypt |<---------------0x10 +---Encrypted---+ | AES-Encrypt
            |                                       |
            | ...                                   |
``` 

## 2.1 Exchange Public Keys

There are 2 public keys to exchange at the very beginning: `s_spk` `c_spk` for signature and `s_cpk` `c_cpk` for AES shared key generation.

- Client generates a random `client_cid`, checks whether the `s_spk` and `s_cpk` already stored.
  - If stored, reads them and sends a `0x00` `c_spk` **SELF_SIGNED**[`client_cid c_cpk`] packet.
  - If not, sends a `0x01` `c_spk` **SELF_SIGNED**[`client_cid c_cpk`] packet.
- Server checks the received packet, gets the `c_spk` for signature verification.
  - If signature verified, server gets the `c_cpk` and:
    - calculates an `aes_key`.
    - hash the [`client_cid` `c_cpk`] to generate a `cinfo_hash`.
    - generate a random `server_sid`.
  - If the header is `0x00`, server sends a `0x00` `s_spk` **SELF_SIGNED**[`s_cpk`] **AES_ENCRYPTED**[`server_sid` `cinfo_hash` `OK`] packet.
  - If the header is `0x01`, server sends a `0x01` **SELF_SIGNED**[`OK`] **AES_ENCRYPTED**[`server_sid` `cinfo_hash` `OK`] packet.
- Client checks the received packet:
  - It verifies the signature first using stored or received `s_spk`.
  - If signature verified, client calculates `aes_key` using stored or received `s_cpk` and tries to decrypt the encrypted bytes.

## 2.2 Validate the AES Encryption
- If decryption OK, client would store server side public keys `s_spk` `s_cpk` locally for reuse.
- Client sends a `0x02` `cinfo_hash` **AES_ENCRYPTED**[`server_sid` `OK`] packet.
- Server decrypts the packet using the `aes_key` and verifies the received `server_sid` `OK` bytes. 
- If everything good, handshake done, server activates the session, and sends `0x02` **AES_ENCRYPTED**[`server_sid` `cinfo_hash` `OK`] packet.
- Server compares the received `server_sid` and stored `server_sid`.

## 2.4 Communication / Messaging

Now, with the validated handshake, server and client can send/recv messages securely. Suppose the client send the message `hello!`, and the server feedback with `yes!`. Here is the process:

- Any ordinary (non-handshaking) messages must start with a 1-byte header `0x10`, the server will parse the 1-byte header and determine the reponse. That byte will be discarded after parsing.
- Following the `0x10` is the **unencrypted** `cinfo_hash` `AES nonce`, and **AES encrypted** `server_sid` `hello!`. So the whole message would be:
  - (**unencrypted**)`0x10` (**unencrypted**) `cinfo_hash` `AES nonce` (**AES encrypted**)`server_sid` (**AES encrypted**)`hello!`
- Server receives the message. It will follow the steps:
  - Parses the header, it is `0x10`, so the message is not for handshaking, it is an ordinary message.
  - Gets the fixed-length `cinfo_hash` and `AES_nonce`, retrieve the `AES_key` and `server_sid`.
  - Try to decrypt the message body, aka the (**AES encrypted**)`server_sid` (**AES encrypted**)`hello!`
  - Get the `server_sid` first, and compare whether received `server_sid` == stored `server_sid`.
    - If `server_sid`s matche, the message is good to process. Server will assemble a message `server_sid` `cinfo_hash` `yes!`, encrypt it with `AES_key`, and add a header `0x10` `AES_nonce`, send back to the client address.
    - If `server_sid`s don't match, send `0xCF` `SIDERR` to client, and the client will restart the handshake. 
- Client receives the message `0x10 AES_nonce`, tries to decrypt the message with the local stored `AES_key` `AES_attr`, and gets the `yes!` message body.

## 2.5 Public Messaging With Signatures

Although the secure communication channel has been established, clients and servers still can do public/insecure messaging. However, all messages **MUST** be signed with the exchanged signature keys. 

Signed public message format is simple:

- The header is `0x11`, it is 1 byte.
- Following the header flag is the message body.

None of the information above is encrypted, but they **MUST** be signed for verification. 

## 2.5 Heartbeating and Goodbye

Client needs to send heartbeating packets to the server in a reasonable interval. And, when a client signed off, a goodbye packet should be sent to the server. The heartbeating and goodbye packets are signed but **NOT** encrypted.

The format of heartbeating packets from clients:

- `0x1F` **SELF_SIGNED**[`cinfo_hash`]

Server verifies the signature and the received `cinfo_hash`, if all good, it sends back:

- `0x1F` **SELF_SIGNED**[`received_cinfo_hash`]

The Goodbye packet is sent from clients to servers, the format is:

- `0x1F` **SELF_SIGNED**[`cinfo_hash` `!`]

Server verifies the signature and the last byte, if all good, it broadcasts to all active clients.

# 3. Session Management

With the design above, we can manage sessions effectively. 

## 3.1 Activate a Session

Any session must go through the handshake process. Once handshake done, the session would be tagged as `activated`, and OK for messaging.

## 3.2 Securing a Session

As described above, any ordinary messages on a session contain an **unencrypted** `cinfo_hash` and an **AES encrypted** `server_sid`, an ordinary message is considered as **valid** only when `cinfo_hash` and `server_sid` in the message and stored in the server match. That design makes the message secure and hard to construct.

## 3.3 Disable a Session

In this design, either server or client can disable a session:

- Server side can invalidate the `server_sid` to disable a session and request a new handshake.
- Client side can invalidate the `cinfo_hash` to disable a session and initiate a new handshake. 

Once disabled, all the attributes attached to/generated by this session would be invalidated immediately by default. Maybe in the future, we will add an expiration control of storing the exchanged public keys to avoid frequent exchanging public keys, including:

- Client may store the `s_spk` and `s_cpk` for a period, as long as the key doesn't get invalidated by the server, no need to request them.
- Server may cache `c_spk`s or `c_cpk`s just for attack identification and other purposes.

## 3.4 On an Activated Session

On an activated session, the client can do everything securely, including `signin`, `signup`, `reset password`, `posting messages`, etc.

# 4. Future Works

First of all, this design needs to be reviewed. If it is good, I'll implement it in C++.