# How To Make UDP Communications Secure?

The current udp_chatroom is not encrypted, super bad for secure or privacy. Here is a design to make it secure, to be discussed.

# 1. Prerequisites

Client manages its RSA key pair. Server manages its **RSA key pair**. They are:

- **Client Public Key:** `client_public_key`
- **Client Private Key:** `client_private_key`
- **Server Public Key:** `server_public_key`
- **Server Private Key:** `server_private_key`

# 2. Communication Process

- Client sends a message with a 1-byte header `0x00` followed by its `client_public_key`.
- Server parses the first byte, if it is `0x00`, ingests the following `client_public_key`.
  - *If the following bytes are not a well-formatted **RSA Public Key**, echo back with error.
- If format is good, server accepts and store it temperorily.
- Server sends back a message with header `0x01`, fowllowed by its `server_public_key`.
- Client parses the first byte, if it is `0x01`, generates a random `client_cid`, assembles a message `0x02` `client_cid` `client_public_key`, encrypts the message **except the 1-byte header `0x02`** with the `server_public_key`, sends it back to the server.
- Server receives `0x02` header, decrypts the remaining message with its `server_private_key`, retrieve the `client_public_key` and the `client_cid`, bind them together as a pair. 
- Server generates a random `server_sid` and a random **128-bit AES-128 encryption/decryption Key** `AES_key`, determine the **encryption algorithm** `AES_algo`, it also binds the `client_cid`, `server_sid`, `AES_key`, and `AES_algo` together as a **prepared session**.
- Server assembles a message `0x03` `client_cid` `server_sid` `AES_key` `AES_algo`, encrypts them **except the 1-byte header `0x03`** with the `client_public_key`, and sends back.
- Client receives `0x03` header, decrypts the remaining message with its `client_private_key`, gets the `client_cid`, `server_sid` and store the `AES_key` `AES_algo`, store them locally.
- Client assembles a message `0x04` `client_cid` `server_sid` `OK` , encrypts the `server_sid` `OK` part, and send to server.
- Server receives the `0x04` header message, retrives `server_sid`, `AES_key`and `AES_algo` by the `client_cid`. 
- Server decrypts the remaining message, compare the received `server_sid` and stored `server_sid`, if they match, handshake done, activate the session; otherwise echo back with an error. 


Now, with the exchanged `AES_key` and `AES_algo`, server and client can send/recv messages securely. Suppose the client send the message `hello!`, and the server feedback with `yes!`. Here is the process:

- Any following messages should start with a 1-byte header `0x10`, the server will parse the 1-byte header and determine the reponse. That byte will be discarded after parsing.
- Following the `0x10` is the **unencrypted** `client_cid`, and **AES encrypted** `server_sid` `hello!`. So the whole message would be:
  - `0x10` **unencrypted** `client_cid` **AES encrypted**`server_sid` `hello!`
- Server receives the message. It will follow the steps:
  - Parses the header, it is `0x10`, so the message is not for handshaking.
  - Gets the fixed-length `client_cid`, retrieve the `AES_key` `AES_algo` and `server_sid` corresponding to the `client_cid`.
  - Try to decrypt the message body, aka the **AES encrypted** `server_sid` `hello!`
  - Get the `server_sid` first, and compare whether the `server_sid` in the message body == `server_sid` stored in the server.
    - If `server_sid` matches, the message is good to process. Server will assemble a message `yes!`, encrypt it with `AES_key`, and add a header `0x10`, send back to the client address.
    - If `server_sid` doesn't match, notify the client to do handshake again.

# 3. Future Works

First of all, this design needs to be reviewed. If it is good, I'll implement it in C++.