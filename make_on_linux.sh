#!/bin/sh

g++ server.cpp -lsodium -o server
g++ client.cpp -o client -lncursesw -lpthread -lsodium -licuuc

echo "Build done. Check the server and client binary."