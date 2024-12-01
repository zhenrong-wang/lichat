# How To Make UDP Communications Secure?

The current udp_chatroom is not encrypted, super bad for secure or privacy. Here is a design to make it secure, to be discussed.

# 1. Prerequisites

Client manages its **RSA key pair**. Server manages its **RSA key pair**. They are:

- **Client Public Key:** `client_public_key`
- **Client Private Key:** `client_private_key`
- **Server Public Key:** `server_public_key`
- **Server Private Key:** `server_private_key`

# 2. Communication Process

Diagram as below, detailed description follows the diagram.

```
          Client                                  Server
*HANDSHAKE* | 00 client_public_key \                |
            |        OR             |-------------->| 
            | 01 client_public_key /                |
            |                                       |
            |                / 00 server_public_key |
            |<--------------|         OR            |
            |                \ 01 OK                |
            |     ___________________               |
Server      |    | client_cid        |              | Server
Public Key  |    | client_public_key |              | Private Key
RSA-Encrypt | 02 +---RSA-Encrypted---+------------->| RSA-Decrypt
            |                      _______________  |
            |                     | client_cid    | |
            |                     | server_sid    | | 
Client      |                     | AES_key       | | Client
Private Key |                     | AES_attr      | | Public Key
RSA-Decrypt |<---------------- 02 +-RSA-Encrypted-+ | RSA Encrypt    
            |             _______________           |
            | 03         | server_sid OK |          |
AES-Encrypt | client_cid-+-AES-Encrypted-+--------->| AES-Decrypt
            |                      _______________  | 
            |                     | server_sid    | |
            |                     | client_cid OK | |
AES-Decrypt |<---------------- 03 +-AES-Encrypted-+ | AES-Encrypt
            |                                       |
*MESSAGING* |             _____________________     |                        
            | 0x10       | server_sid msg_body |    |
AES-Encrypt | client_cid-+----AES-Encrypted----+--->| AES-Decrypt
            |                      _______________  | 
            |                     | server_sid    | |
            |                     | client_cid    | |
            |                     | msg_body      | |
AES-Decrypt |<---------------0x10 +-AES-Encrypted-+ | AES-Encrypt
            |                                       |
            | ...                                   |
``` 

## 2.1 Exchange RSA Public Keys

- Client checks whether the `server_public_key` is stored locally. If stored, clients check the date and determins whether it is expired.
  - If absent or expired, client sends a message with a 1-byte header `0x00` followed by its `client_public_key`.
  - If exists, client sends a message with a 1-byte header `0x01`, followed by its `client_public_key`.
- Server gets `0x00` or `0x01` header, parses the following `client_public_key`.
  - If the following bytes are not a well-formatted **RSA Public Key**, sends `0xFF` `FAILED` to the client and the client restart handshake.
  - If format is good, server accepts and stores it temperorily.
- Server responds according to the header.
  - If header is `0x00`, server sends back a message with header `0x00`, followed by its `server_public_key`.
  - If header is `0x01`, server sends back a message with header `0x01` `OK`
- Client parses the header, if it is `0x00`, check the following bytes.
  - If the following bytes are not a well-formatted **RSA Public Key**, send `0xFF` `FAILED` `client_public_key` to the server. The server may do self-checks when receiving this type of messages.
- (Optional) Client generates the fingerprint (**SHA-256**) of the received/stored `server_public_key`, requires user to manually check the public fingerprint(s) and confirm.
  - If the confirmation timeout, client sends `0xFF` `TIMOUT` `client_public_key` to server, server deletes the `client_public_key`.
- Client stores the `server_public_key` locally. 

## 2.2 Validate the RSA Public Keys

- Client generates a random `client_cid`, assembles a message `client_cid` `client_public_key`, encrypts it with the `server_public_key`, adds a header `0x02` and sends it back to the server.
- Server receives `0x02` header, decrypts the remaining message with its `server_private_key`.
  - If decryption failed, server sends `0xEF` `RSAERR` to client. Client will remove any stored `server_public_key` and restart the handshake.
- Server gets the `client_public_key` and the `client_cid`, bind them together as a pair, then generates a random `server_sid` and a random **128-bit AES-128 encryption/decryption Key** `AES_key`, determines the **AES attibutes** `AES_attr`, it also binds the `client_cid`, `server_sid`, `AES_key`, and `AES_attr` together as a **prepared session**.
- Server assembles a message `client_cid` `server_sid` `AES_key` `AES_attr`, encrypts them with the `client_public_key`, adds a `0x02` header, and sends back.
- Client receives `0x02` header, decrypts the remaining message with its `client_private_key`, gets the `client_cid`, `server_sid`.
  - If decryption failed, client sends `0xEF` `RSAERR` to the server, restart handshake.
  - (not quite possible) If the received `client_cid` and the local generated `client_cid` don't match, re-generates a random `client_cid` and retry the validation. If fails too many times (set by the server), the server will send a `0xEF` `!RETRY` to the client and the client will restart the handshake.
- Client stores the `client_cid` `server_sid` `AES_key` `AES_attr` locally for future messaging.

## 2.3 Validate the AES Encryption

- Client assembles a message `server_sid` `OK` , encrypts it with the exchanged `AES_key` and `AES_attr`, adds a header `0x03` `client_cid`, and sends to server.
- Server receives the `0x03` header message and gets the `client_cid`, then retrives the stored `server_sid`, `AES_key`and `AES_attr` by the received `client_cid`. 
- Server tries to decrypt the remaining message.
  - If decryption failed, server will re-generate an `AES_key` `AES_attr`, refresh the **prepared session** and send back a `0x02` header message (encrypted by `client_public_key`) to client. Client will retry AES validation. If fails too many times (set by the server), restart the handshake.
- Server compares the received `server_sid` and stored `server_sid`.
  - If they match, handshake done, activate the session, server assembles an encrypted `server_sid` `client_cid` `OK` message with a header `0x03`, sends to the client.
  - Otherwise send `0xDF` `AESERR` to client and restart handshake. 

## 2.4 Communication / Messaging

Now, with the exchanged and validated `AES_key` and `AES_attr`, server and client can send/recv messages securely. Suppose the client send the message `hello!`, and the server feedback with `yes!`. Here is the process:

- Any ordinary (non-handshaking) messages must start with a 1-byte header `0x10`, the server will parse the 1-byte header and determine the reponse. That byte will be discarded after parsing.
- Following the `0x10` is the **unencrypted** `client_cid`, and **AES encrypted** `server_sid` `hello!`. So the whole message would be:
  - (**unencrypted**)`0x10` (**unencrypted**) `client_cid` (**AES encrypted**)`server_sid` (**AES encrypted**)`hello!`
- Server receives the message. It will follow the steps:
  - Parses the header, it is `0x10`, so the message is not for handshaking, it is an ordinary message.
  - Gets the fixed-length `client_cid`, retrieve the `AES_key` `AES_attr` and `server_sid` corresponding to the `client_cid`.
  - Try to decrypt the message body, aka the (**AES encrypted**)`server_sid` (**AES encrypted**)`hello!`
  - Get the `server_sid` first, and compare whether received `server_sid` == stored `server_sid`.
    - If `server_sid`s matche, the message is good to process. Server will assemble a message `server_sid` `client_cid` `yes!`, encrypt it with `AES_key`, and add a header `0x10`, send back to the client address.
    - If `server_sid`s don't match, send `0xCF` `SIDERR` to client, and the client will restart the handshake. 
- Client receives the message `0x10 ...`, tries to decrypt the message with the local stored `AES_key` `AES_attr`, and gets the `yes!` message body.

## 2.5 Force Confirmation

Ordinary messages from the server to client on a session don't require a confirmation. To enable a session checking, we define a special header `0x1F` for activated sessions. Server may send a backend **encrypted message** `?` with a header `0x1F` to client, and the client **must** send back a **encrypted** message `!`  with a header `0x1F` immediately to keep alive. Otherwise the server may disable the session actively. 

# 3. Session Management

With the design above, we can manage sessions effectively. 

## 3.1 Activate a Session

Any session must go through the handshake process. Once handshake done, the session would be tagged as `activated`, and OK for messaging.

## 3.2 Securing a Session

As described above, any ordinary messages on a session contain an **unencrypted** `client_cid` and an **AES encrypted** `server_sid`, an ordinary message is considered as **valid** only when `client_cid` and `server_sid` in the message and stored in the server match. That design makes the message secure and hard to construct.

## 3.3 Disable a Session

In this design, either server or client can disable a session:

- Server side can invalidate the `server_sid` to disable a session and request a new handshake.
- Client side can invalidate the `client_cid` to disable a session and initiate a new handshake. 

Once disabled, all the attributes attached to/generated by this session would be invalidated immediately by default. Maybe in the future, we will add an expiration control of storing the exchanged public keys to avoid frequent exchanging public keys, including:

- Client may store the `server_public_key` for a period, as long as the key doesn't get invalidated by the server, no need to request `server_public_key`.
- Server may cache `client_public_key`s just for attack identification and other purposes.

## 3.4 On an Activated Session

On an activated session, the client can do everything securely, including `signin`, `signup`, `reset password`, `posting messages`, etc.

# 4. Future Works

First of all, this design needs to be reviewed. If it is good, I'll implement it in C++.