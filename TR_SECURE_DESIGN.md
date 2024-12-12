# How To Make UDP Communications Secure?

The current udp_chatroom is not encrypted, super bad for secure or privacy. Here is a design to make it secure, to be discussed.

# 1. Prerequisites

Client manages its Curve25519 **key pair**. Server manages its Curve25519 **key pair**. They are:

- **Client Public Key:** `client_public_key`
- **Client Private Key:** `client_private_key`
- **Server Public Key:** `server_public_key`
- **Server Private Key:** `server_private_key`

# 2. Communication Process

Diagram as below, detailed description follows the diagram.

```
          Client                                  Server
*HANDSHAKE* | 00 client_cid        \                | Generate
            |    client_public_key  |               | cinfo_hash
            |        OR             |-------------->| Generate
            | 01 client_cid         |               | server_sid
            |    client_public_key /                | Calculate AES Key
            |                                       |
            |       / 00 server_public_key          | 
            |      |     Encrypted: server_sid      | 
Calculate   |      |                cinfo_hash OK   | AES nonce
AES Key     |<-----|            OR                  | AES-Encrypt
AES-Decrypt |      |  01 Encrypted: server_sid      | 
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

- Client generates a random `cliend_cid` (with fixed length 64 bits, aka 8 bytes), checks whether the `server_public_key` is stored locally. If stored, clients check the date and determins whether it is expired.
  - If absent or expired, client sends a message with a 1-byte header `0x00` followed by its `client_cid` `client_public_key`.
  - If exists, client sends a message with a 1-byte header `0x01`, followed by its `client_cid` `client_public_key`.
- Server gets `0x00` or `0x01` header and `client_cid`, parses the following `client_public_key`.
  - If the following bytes are not a well-formatted **Public Key**, sends `0xFF` `FAILED` to the client and the client restart handshake.
- Server generates a 64bit `cinfo_hash` of the combined [`client_cid` `client_public_key`], calculate the `AES_key` with `server_private_key`, and generates a `server_sid`. Then, server encrypts the `cinfo_hash` `server_sid` with the `AES_key`.
- Server responds according to the header.
  - If header is `0x00`, server sends back a message with header `0x00` `server_public_key` `AES_nonce`, followed by encrypted `server_sid` `cinfo_hash` `OK`.
  - If header is `0x01`, server sends back a message with header `0x01` `AES_nonce`, followed by encrypted `server_sid` `cinfo_hash` `OK`
- Client parses the header, use received or pre-stored `server_public_key` to calculate and store `AES_key`.
- (Optional) Client generates the fingerprint (**SHA-256**) of the received/stored `server_public_key`, requires user to manually check the public fingerprint(s) and confirm.
  - If the confirmation timeout, client sends `0xFF` `TIMOUT` `client_cid` `client_public_key` to server, restart the handshake.

## 2.2 Validate the AES Encryption
- Client tries to decrypt the following bytes with the received `AES_nonce` and calculated `AES_key`.
  - If decryption failed, client sends `0xEF` `KEYERR` `client_cid` `client_public_key` to server, restart the handshake.
  - If the last 2 bytes are not ASCII `OK`, or the decrypted lengths are invalid, sends a `0xDF` `MSGERR` `client_cid` `client_public_key`, restart the handshake.
- Client stores the `server_public_key` locally.
- Client assembles a message `server_sid` `OK` , encrypts it with the calculated `AES_key`, adds a header `0x02` `cinfo_hash` `AES_nonce`, and sends to server.
- Server receives the `0x02` header message and gets the `cinfo_hash` `AES_nonce`, then retrives the stored `server_sid`, `AES_key` by the received `cinfo_hash`. 
- Server tries to decrypt the remaining message.
  - If decryption failed, server sends `0xEF` `KEYERR` `client_cinfo` `server_public_key` and restart the handshake. Client can use the new `server_public_key` for next handshake.
- Server compares the received `server_sid` and stored `server_sid`.
  - If they match, handshake done, activate the session, server assembles an encrypted `server_sid` `cinfo_hash` `OK` message with a header `0x02`, sends to the client.
  - Otherwise send `0xDF` `MSGERR` `client_cinfo` `server_public_key` to client and restart handshake. Client can use the new `server_public_key` for next handshake.

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

## 2.5 Public Messaging

Although the secure communication channel has been established, clients and servers still can do public/insecure messaging. E.g. System broadcasting would not be encrypted for performance consideration. 

Insecure message format is easy:

- The header is `0x11`, it is 1 byte.
- Following the header flag is the message body.

None of the information above is encrypted. 

## 2.5 Force Confirmation

Ordinary messages from the server to client on a session don't require a confirmation. To enable a session checking, we define a special header `0x1F` for activated sessions. Server may send a backend **encrypted message** `?` with a header `0x1F` to client, and the client **must** send back a **encrypted** message `!`  with a header `0x1F` immediately to keep alive. Otherwise the server may disable the session actively. 

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

- Client may store the `server_public_key` for a period, as long as the key doesn't get invalidated by the server, no need to request `server_public_key`.
- Server may cache `client_public_key`s just for attack identification and other purposes.

## 3.4 On an Activated Session

On an activated session, the client can do everything securely, including `signin`, `signup`, `reset password`, `posting messages`, etc.

# 4. Future Works

First of all, this design needs to be reviewed. If it is good, I'll implement it in C++.