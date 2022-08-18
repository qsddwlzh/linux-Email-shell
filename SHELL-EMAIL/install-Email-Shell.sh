#!/bin/sh
sudo apt-get install cmake
sudo apt-get install wget
sudo wget https://www.openssl.org/source/openssl-3.0.5.tar.gz
sudo apt-get install libssl-dev
sudo tar xvf openssl-3.0.5.tar.gz
cd openssl-3.0.5
./config
make
sudo make install
export LD_LIBRARY_PATH="/home/pi/SHELL-EMAIL/openssl-3.0.5"
cd ..
g++ -g -rdynamic -Wall NET-SSL-Client1.cpp -lssl -lcrypto -o Email-shell


