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

### 3.1 Prerequisites
#### Compiler
This is a C++ project, so you'll definitely need some kind of C++ compiler. Our CI uses GCC (14), so that's a good compiler to use, because we know it works for our code! Other good compilers are available though. Clang, for example.

#### Third-party library dependencies
This project depends on a few other libraries:
* [**Sodium**](https://doc.libsodium.org/), for SSL (secure communication) features
* [**NCurses**](https://invisible-island.net/ncurses/announce.html), for the client terminal UI
* [**IUC**](https://icu.unicode.org/), for UNICODE support
* **POSIX threads**, for, well, threading.

If you plan to build via [CMake](https://cmake.org/download/), then you will also need to have CMake > 3.25 installed and usable. CMake will also invoke [VCPKG](https://github.com/microsoft/vcpkg) to manage the above dependencies, so you should also have that.

For some reason, the version of NCurses installed by VCPKG doesn't support wide characters :( This means that you should install NCurses in some other way. If you're willing to install it globally on your system, then you can use your system's package manager to do that---be sure to **install the "development libraries"**. These are packages that contain the include files, so that you can build code against them. They will have a name like "ncurses-devel", or "ncurses-dev", so something, depending on which package manager you're using.

If you're building on something like **Ubuntu**, then you can see EXACTLY what you need to do to get your system ready and build by looking at the Github workflow files in the `.github/workflows` directory of this repo :) 

If you don't plan to build with CMake and use VCPKG, then you're on your own! We assume you know what you're doing with dependencies and will install them in the right place for the compiler to find them when you invoke it.

### 3.2 Get the code
* Clone this repo with Git (we use SSH below, but use your favourite authentication method)
```shell
git clone git@github.com:zhenrong-wang/lichat.git
cd lichat
```

If you plan to contribute as well as just build, then you might want to first fork this repo into your own Github repos and then clone that fork instead.
### 3.3 Building

The code works on **GNU/Linux** (maybe other Unix-like platforms), not on Microsoft Windows. 

But the client (WIP) would work on different platforms.

#### Direct compiler invocation
If you want to just directly invoke the compiler (and have sorted out the dependencies mentioned above), then you can build (with GCC) using a command like:
```shell
g++ server.cpp -lsodium -o server
g++ client.cpp -lsodium -lncursesw -licuuc -lpthread -o client`
```
Or, you can just run the easy build shell script `./make_on_linux`, please note:

- It only runs on GNU/Linux distros.
- It would try to build both server and client, regardless of their dependencies.
- It only detects g++ and clang++, other compilers are not accepted yet.

#### CMake build
If you have CMake, VCPKG and Ncurses installed (see above), then you can resolve the dependencies and build the code with
```shell
cmake --preset=x64-linux-debug
cmake --build --preset=x64-linux-debug
```
this will download the third-party dependencies, build them and then build the Lichat client and server. The resulting client and server binaries will be in `$/out/build/x64-linux-debug/`.  If you would like to build in release, then you should use the `x64-linux-release` preset.

### 3.4 Running the Server and Client
Run the server with something like:
```shell
./server
```
The port number would be displayed in your `STDOUT`

Once the server is running, the run the client(s):
```shell
./client
```

It would connect to localhost by default, but you can also specify a domain name and a port.

### 3.5 How To Chat

- Once service started, it would start receiving and processing UDP messages.
- Use the `client` to securely signup, signin, and chat.
  - To send a message, you need to press `SHIFT` + `END` key.
  - To sign out of a client, you need to send a message `:q!` (the Vim style).

## 4. Problems and Future Works

Currently, there are many problems:

- Long messages is not supported.
- Client message scrolling
- ...

Anyway, this project is in its very preliminary stage. It is functional, but there are still lots of things to do. 

If you are interested, please feel free to contribute.