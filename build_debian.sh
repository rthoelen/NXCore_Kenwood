#!/bin/bash
apt update -y
apt install -y build-essential libboost-dev libboost-program-options-dev
make
