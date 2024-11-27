# LiChat: A Light-Weight Web Chatroom Service in C++

## 1. Core Features

LiChat is a light-weight chat room service. It provides many features:

- Super light. It is UDP-based, message-based, easy to deploy.
- Pure service. Any UDP client can work with LiChat.
- Functional. It manages multiple clients and users, and process text messages.
- Privacy. It doesn't store any message at the backend/server side.
- Channels. Users can post messages publicly, tag signed user, or send private messages.
- Freedom. It is free software, and support free speech, no censorship by default.

## 2. Technical Review

Please check the [file](./TR_UDP_CHATROOM.md) for all the technical details.

## 3. How-To

### 3.1 How To Build

The code works on GNU/Linux, not on Microsoft Windows. But since it is a pure service, the UDP client can come from anywhere, any platform. 

- Fork this repository or clone directry
- Change directory to your local cloned dir
- You will need a C++ compiler (e.g. Clang++ or g++), and pre-install the libsodium.
- Build command: `g++ udp_chatroom.cpp -lsodium -o lichat`
- Run the build: `./lichat`. The port number would be displayed in your `STDOUT`

### 3.2 How To Chat

- Once service started, it would start receiving and processing UDP messages.
- Any user can choose an UDP client such as `nc` on GNU/Linux to post messages, command:
  - `nc -u 101.100.189.89 8081`
- A fresh new client would be required to choose `signup | signin` and set or provide credentials
- Once authenticated, users would be able to post public or private messages (aka. Chat)

## 4. Future Works

This project is in its very preliminery stage. It is functional, but there are still lots of things to do. If you are interested, please feel free to contribute.