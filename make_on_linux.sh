#!/bin/sh

uname -s | grep Linux >> /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "[FATAL] You are not working on a GNU/Linux distro. Exit now."
    exit 1
fi

which g++ >> /dev/null 2>&1
if [ $? -eq 0 ]; then
    compiler='g++'
else
    which clang++ >> /dev/null 2>&1
    if [ $? -eq 0 ]; then
        compiler='clang++'
    else
        echo "[FATAL] Compiler (g++/clang++) not found. Please install."
        exit 3
    fi
fi
echo "[INFO] Using the compiler ${compiler} to build this project."

${compiler} server.cpp -lsodium -o server -Wall
${compiler} client.cpp -o client -lncursesw -lpthread -lsodium -licuuc -Wall

echo "[DONE] Build done. Check the server and client binary."
exit 0