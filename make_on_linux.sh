#!/bin/sh

g++ server.cpp -lsodium -o server -Wall
g++ client.cpp -o client -lncursesw -lpthread -lsodium -licuuc -Wall

echo "Build done. Check the server and client binary."