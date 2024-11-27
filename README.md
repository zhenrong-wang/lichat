# LiChat: A Light-Weight Web Chatroom Service in C++

## 1. Core Features

LiChat is a light-weight chat room service. It provides many features:

- **Super-light**: It is UDP and message based, very easy to deploy.
- **Privacy**: It doesn't store any message at the backend/server side.
- **Freedom**: It is free software, and it supports free speech; no censorship.
- **Functional** (currently minimal):
  - manages multiple clients
  - allows multiple users
  - processes text messages
  - supports public chats, tagging users, and private messages.
- **Secure**: message encryption (WIP)

That's it, as simple and light as possible.

Currently, there is only server code, the cross-platform client code is working in progress.

## 2. Technical Review

Please check the [file](./TR_UDP_CHATROOM.md) for all the technical details.

## 3. How-To

### 3.1 How To Build

The code works on **GNU/Linux** (maybe other Unix-like platforms), not on Microsoft Windows. 

But the client (WIP) would work on different platforms.

- Fork this repository or clone directly
- Change directory to your local cloned dir
- You will need a C++ compiler (e.g. Clang++ or g++), and pre-install the libsodium.
- Build command: `g++ udp_chatroom.cpp -lsodium -o lichat`
- Run the build: `./lichat`. The port number would be displayed in your `STDOUT`

### 3.2 How To Chat

- Once service started, it would start receiving and processing UDP messages.
- Because the client is absent and in planning, currently you can choose an UDP client such as `nc` on GNU/Linux to post messages, command:
  - `nc -u SERVICE_IP_ADDR SERVICE_PORT` e.g. `nc -u localhost 8081`
- A fresh new client would be required to choose `signup | signin` and set or provide credentials.
- Once authenticated, users would be able to post public or private messages (aka. Chat).

## 4. Problems and Future Works

Currently the session management is done by `client addr`, which obviously is not suitable for real world asymmetric networking. The `client addr` probably drifts when the client device is in private network behind NAT or other devices. 

Currently the messages are not encrypted. That's not good at all.

In summary, this project is in its very preliminery stage. It is functional, but there are still lots of things to do. 

If you are interested, please feel free to contribute.