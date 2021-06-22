# Assignment 4: One-Time Pads Encryption
 	By: Terence Tang
 	tangte@oregonstate.edu
 	CS 344 Operating Systems
 	5/30/2021

## Included files:
    - keygen.c
    - enc_server.c
    - enc_client.c
    - dec_server.c
    - dec_client.c
    - compileall (compilation script)
    - p5testscript (test script)
    - plaintext1
    - plaintext2
    - plaintext3
    - plaintext4
    - plaintext5
    Note: Plaintext files and testscript provided for testing purposes.

## Description
    Server-Client based programs that provides encryption and decryption services using the One-Time Pads (OTP) encryption technique, written in C. Also provides a program to generate the key for use in OTP.  Features implementation of request handling and data communications via Socket Connections.
    
    Program features the following highlights:
	- Inter-Process Communication (IPC) via Socket Connections w/ Client/Server interaction model
	- Multi-Process server-side handling of encryption requests (upto 5 concurrent request processes)
	- OTP encryption / decryption

## Installation
    Instructions on how to compile One-Time Pads program:
	- Terminal Command for compiling - Compilation script provided to compile all 5 c program files at once
	./scripts/commpileall 

    Note: Permissions may need to be granted to scripts with the following cmd -> $chmod +x ./scripts/compileall

    - Terminal Command for running resulting server executables -
    ./enc_server RANDOM_PORT_NUMBER &
    ./dec_server RANDOM_PORT_NUMBER &

## Tests
    Provided testing script and example plain text available for demoing functionality.
    - To run testing script, please use the following terminal command:
    ./tests/testscript