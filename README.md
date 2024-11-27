# LiChat: A Light-Weight Web Chatroom Service in C++

## 1. Core Features

LiChat is a light-weight chat room service. It provides many features:

- Super light. It is UDP-based, message-based, easy to deploy.
- Pure service. It works with any UDP client from any platform.
- Privacy. It doesn't store any message at the backend/server side.
- Freedom. It is free software, and support free speech, no censorship by default.
- Functional:
  - manages multiple clients
  - allows multiple users
  - process text messages
  - support public chats, tagging users, and private messages.

That's it, as simple and light as possible.

## 2. Technical Review

Please check the [file](./TR_UDP_CHATROOM.md) for all the technical details.

## 3. How-To

### 3.1 How To Build

The code works on **GNU/Linux** (maybe other Unix-like platforms), not on Microsoft Windows. 

But to make it clear, as a pure service, it works with any UDP clients.

- Fork this repository or clone directry
- Change directory to your local cloned dir
- You will need a C++ compiler (e.g. Clang++ or g++), and pre-install the libsodium.
- Build command: `g++ udp_chatroom.cpp -lsodium -o lichat`
- Run the build: `./lichat`. The port number would be displayed in your `STDOUT`

### 3.2 How To Chat

- Once service started, it would start receiving and processing UDP messages.
- Any user can choose an UDP client such as `nc` on GNU/Linux to post messages, command:
  - `nc -u SERVICE_IP_ADDR SERVICE_PORT`. e.g. `nc -u localhost 8081`
- A fresh new client would be required to choose `signup | signin` and set or provide credentials
- Once authenticated, users would be able to post public or private messages (aka. Chat)

## 4. Future Works

This project is in its very preliminery stage. It is functional, but there are still lots of things to do. If you are interested, please feel free to contribute.