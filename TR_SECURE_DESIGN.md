# How To Make UDP Communications Secure?

The current udp_chatroom is not encrypted, super bad for secure or privacy. Here is a design to make it secure, to be discussed.

# 1. Prerequisites

Client manages its **RSA key pair**. Server manages its **RSA key pair**. They are:

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
- Client parses the first byte, if it is `0x01`, generates a random `client_cid`, assembles a message `client_cid` `client_public_key`, encrypts it with the `server_public_key`, adds a header `0x02` and sends it back to the server.
- Server receives `0x02` header, decrypts the remaining message with its `server_private_key`, gets the `client_public_key` and the `client_cid`, bind them together as a pair. 
- Server generates a random `server_sid` and a random **128-bit AES-128 encryption/decryption Key** `AES_key`, determine the **algorithm details such as padding** `AES_algo`, it also binds the `client_cid`, `server_sid`, `AES_key`, and `AES_algo` together as a **prepared session**.
- Server assembles a message `client_cid` `server_sid` `AES_key` `AES_algo`, encrypts them with the `client_public_key`, adds a `0x03` header, and sends back.
- Client receives `0x03` header, decrypts the remaining message with its `client_private_key`, gets the `client_cid`, `server_sid`.
  - If the received `client_cid` and the local generated `client_cid` don't match, restart the handshake.
  - If they match, client stores the `AES_key` `AES_algo`, store them locally.
- Client assembles a message `server_sid` `OK` , encrypts it with the exchanged `AES_key` and `AES_algo`, adds a header `0x04` `client_cid`, and send to server.
- Server receives the `0x04` header message and gets the `client_cid`, then retrives `server_sid`, `AES_key`and `AES_algo` by the received `client_cid`. 
- Server decrypts the remaining message, compare the received `server_sid` and stored `server_sid`, if they match, handshake done, activate the session; otherwise echo back and restart the handshake.


Now, with the exchanged `AES_key` and `AES_algo`, server and client can send/recv messages securely. Suppose the client send the message `hello!`, and the server feedback with `yes!`. Here is the process:

- Any ordinary (non-handshaking) messages must start with a 1-byte header `0x10`, the server will parse the 1-byte header and determine the reponse. That byte will be discarded after parsing.
- Following the `0x10` is the **unencrypted** `client_cid`, and **AES encrypted** `server_sid` `hello!`. So the whole message would be:
  - (**unencrypted**)`0x10` (**unencrypted**) `client_cid` (**AES encrypted**)`server_sid` (**AES encrypted**)`hello!`
- Server receives the message. It will follow the steps:
  - Parses the header, it is `0x10`, so the message is not for handshaking, it is an ordinary message.
  - Gets the fixed-length `client_cid`, retrieve the `AES_key` `AES_algo` and `server_sid` corresponding to the `client_cid`.
  - Try to decrypt the message body, aka the (**AES encrypted**)`server_sid` (**AES encrypted**)`hello!`
  - Get the `server_sid` first, and compare whether received `server_sid` == stored `server_sid`.
    - If `server_sid` matches, the message is good to process. Server will assemble a message `yes!`, encrypt it with `AES_key`, and add a header `0x10`, send back to the client address.
    - If `server_sid` doesn't match, notify the client to do handshake again.


# 3. Session Management

With the design above, we can manage sessions effectively. 

## 3.1 Activate a Session

Any session must go through the handshake process. Once handshake done, the session would be tagged as `activated`, and OK for messaging.

## 3.2 Securing a Session

As described above, any ordinary messages on a session contain an **unencrypted** `client_cid` and an **AES encrypted** `server_sid`, an ordinary message is considered as **valid** only when `client_cid` and `server_sid` match. That design makes the message secure and impossible to construct.

## 3.3 Disable a Session

In this design, either server or client can disable a session:

- Server side can invalidate the `server_sid` to disable a session and request a new handshake.
- Client side can invalidate the `client_cid` to disable a session and initiate a new handshake. 
- To enhance security, any new handshake **must** starts from exchanging **RSA Public Keys**.

## 3.4 On an Activated Session

On an activated session, the client can do everything securely, including `signin`, `signup`, `reset password`, `posting messages`, etc.

# 4. Future Works

First of all, this design needs to be reviewed. If it is good, I'll implement it in C++.