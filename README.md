# LiChat: A Light-Weight Web Chatroom Service in C++

## 1. Core Features

LiChat is a light-weight chat room service. It provides many features:

- **Super-light**: It is UDP and message based, very easy to deploy.
- **Privacy**: It doesn't store any message at the backend/server side.
- **Freedom**: It is free software, and it supports free speech; no censorship.
- **Functional**:
  - manages multiple clients
  - allows multiple users
  - processes UTF-8 text messages
  - supports public chats, tagging users, and private messages. (WIP)
- **Secure**: message encryption

That's it, as simple and light as possible.

## 2. Technical Review

This is free software, every design is transparent and ready for being reviewed or challanged. Please check the [file](./secure_udp_comm) for all the technical details.

## 3. How-To

### 3.1 How To Build

The code works on **GNU/Linux** (maybe other Unix-like platforms), not on Microsoft Windows. 

But the client (WIP) would work on different platforms.

- Fork this repository or clone directly
- Change directory to your local cloned dir
- You will need a C++ compiler (e.g. Clang++ or g++).
- Dependencies: `sodium` for security. The client code depends on `ncursesw` for TUI, `POSIX Thread` for threading, and `ICU` for UnicodeString processing. 
- Build command: 
  - `g++ server.cpp -lsodium -o server` 
  - `g++ client.cpp -lsodium -lncursesw -licuuc -lpthread -o client`
- Run the build: `./server`. The port number would be displayed in your `STDOUT`
- Run the build: `./client`. It would connect to localhost by default but you can also specify a domain name and a port.

### 3.2 How To Chat

- Once service started, it would start receiving and processing UDP messages.
- Use the `client` to securely signup, signin, and chat.
  - To send a message, you need to press `SHIFT` + `END` key.
  - To signout a client, you need to send a message `:q!` (the Vim style).

## 4. Problems and Future Works

Currently there are many problems:

- Long messages is not supported.
- Client message scrolling
- ...

Anyway, this project is in its very preliminery stage. It is functional, but there are still lots of things to do. 

If you are interested, please feel free to contribute.