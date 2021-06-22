/* 
*  Name : Terence Tang
*  Course : CS344 - Operating Systems
*  Date : May 30 2021
*  Assignment #5: One-Time Pads - Encryption Server
*  Description:  Server for handling encryption requests that provide plaintext and key data.  Requests
*                and data transfer is made via socket communications.  The server will accept upto 5 concurrent 
*                encryption requests at any given time.  
*
*                Encryption via plaintext and key is done via the One-Time Pads model where each letter from 
*                each file is added together and mod 27 is applied.
*
*                Server can handle max message sizes of 100000 bytes and will send transmissions of 1024 bytes/send.
*
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>


// Declare Global Resources 
static const int MAX_TRANSMISSION_SIZE = 1024;       // maximum size of data for transmission to server
static const int MAX_MSG_SIZE = 100000;              // maximum size of data to be sent
static const int CIPHER_TEXT_MOD = 27;               // mod value for ciphertext encryption

// Error function used for reporting issues
void error(const char *msg) {
    perror(msg);
    exit(1);
} 

// Set up the address struct for the server socket
void setupAddressStruct(struct sockaddr_in* address, int portNumber)
{ 
    memset((char*) address, '\0', sizeof(*address));                // Clear out the address struct
    address->sin_family = AF_INET;                                  // The address should be network capable
    address->sin_port = htons(portNumber);                          // Store the port number
    address->sin_addr.s_addr = INADDR_ANY;                          // Allow a client at any address to connect to this server
}

// Send data via provided socket
int sendData(int socketFD, char *msg)
{
    int charsWritten = send(socketFD, msg, strlen(msg), 0);                 // Sends msg data to a socket File Descriptor
    if (charsWritten < 0)                                                   // Error check sent data
    {                                          
        error("SERVER: ERROR reading from socket");
    }
    if (charsWritten < strlen(msg))
    {
        fprintf(stderr,"SERVER: WARNING: Not all data written to socket!\n"); 
    }
    return charsWritten;
}

// Read data via provided socket
int readData(int socketFD, char *buffer, int bufferLen)
{
    memset(buffer, '\0', bufferLen);                                        // Clear out buffers and charsRead for next recv
    int charsRead = 0;
    while (charsRead == 0)                                                  // Wait for next available recv data
    {
        charsRead = recv(socketFD, buffer, bufferLen - 1, 0);               // Read the client's message from the socket
    }
    if (charsRead < 0)                                                      // Error check received data
    {                                          
        error("SERVER: ERROR writing to socket");
    }
    if (charsRead < strlen(buffer))
    {
        fprintf(stderr,"SERVER: WARNING: Not all read from socket!\n"); 
    }
    return charsRead;
}

// Converts integers between 0-26 to chars from A-Z or SPACE
int itoc(int i)
{
    if (i < 26)                                 // if int is less than 26 (not space), then add 'A' to get ASCII value
    {
        i += 'A';
    }
    else                                        // if int is for space, then add ' ' to get ASCII value
    {
        i = ' ';
    }
    return i;
}

// Converts chars from A-Z or SPACE to integers between 0-26
int ctoi(char c)
{
    if (c != ' ')                               // if char is not a space, then subtract ascii 'A' value to get int
    {
        c -= 'A';
    }
    else                                        // if char is a space ' ', then return 26
    {
        c = 26;
    }
    return c;
}

// Encrypts given plaintext with a given key via the One-Time Pads encryption method
void encryptData(char *plaintext, char *key, char *ciphertext)
{
    // iterate through each char in file
    for (int i = 0; i < strlen(plaintext); i++) {
        // get plaintext and key chars at index in integer form
        char p = plaintext[i];
        p = ctoi(p);
        char k = key[i];
        k = ctoi(k);

        // add chars together and mod 27 (A-Z + space char) and update to char form
        char c = (p + k) % CIPHER_TEXT_MOD;
        c = itoc(c);

        // add result to ciphertext
        ciphertext[i] = c;
    }
}

int main(int argc, char *argv[])
{
    int connectionSocket, charsRead, charsWritten, dataLength, activeConnections, childStatus, childSocket;
    char buffer[MAX_TRANSMISSION_SIZE];
    char plaintext[MAX_MSG_SIZE];
    char key[MAX_MSG_SIZE];
    char ciphertext[MAX_MSG_SIZE];
    struct sockaddr_in serverAddress, clientAddress;
    socklen_t sizeOfClientInfo = sizeof(clientAddress);
    pid_t childPid;

    /*-- Check usage & args --*/
    if (argc < 2) 
    { 
        fprintf(stderr,"USAGE: %s port\n", argv[0]); 
        exit(1);
    }
    
    /*-- Create and Bind Socket & Start Listening For Connections --*/
    // Create the socket
    int listenSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (listenSocket < 0) 
        error("ERROR opening socket");

    // Set up the address struct for the server socket
    setupAddressStruct(&serverAddress, atoi(argv[1]));

    // Bind/Associate the socket to the port
    if (bind(listenSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
        error("ERROR on binding");

    // Start listening for connetions. Allow up to 5 connections to queue up
    listen(listenSocket, 5); 


    /*-- Queue and Accept Upto 5 Active Connections --*/
    // Set up perpetual loop for server service
    activeConnections = 0;
    while(1){
        // check num of active encryption requests, if already at 5, does not accept any new connections
        if (activeConnections <= 5)
        {
            // Accept the connection request which creates a connection socket
            connectionSocket = accept(listenSocket, (struct sockaddr *)&clientAddress, &sizeOfClientInfo); 
            if (connectionSocket < 0)
                error("ERROR on accept");

            childPid = fork();                    // Fork a new child process to handle encryption request
            switch(childPid)                      // switch statements for error / child / and parent process instructions
            {                     
            // for errors
            case -1:
                perror("fork()\n");
                
            // for child processes - handles encryption requests and sends back ciphertext
            case 0:
                /*-- Receive and Confirm Valid Request Type from Client --*/
                // Receive request type from client
                charsRead = readData(connectionSocket, buffer, sizeof(buffer));
                
                // confirm if request type is valid for this server
                if (strcmp(buffer, "enc_server") == 0)
                {
                    charsWritten = sendData(connectionSocket, "confirmed");
                }
                else
                {
                    charsWritten = sendData(connectionSocket, "denied");
                }

                /*-- Receive and Confirm Data Length from Client --*/
                // Receive data length from client
                charsRead = readData(connectionSocket, buffer, sizeof(buffer));
                dataLength = atoi(buffer);                                      // convert string to int for dataLen storage
                charsWritten = sendData(connectionSocket, "continue");          // confirm that data length reeceived

                /*-- Receive Plaintext Data from Client --*/
                memset(plaintext, '\0', sizeof(plaintext));
                charsRead = 0;
                // continues to read plaintext data from client until expected length
                while (charsRead < dataLength)
                {
                    charsRead += readData(connectionSocket, buffer, sizeof(buffer));
                    strcat(plaintext, buffer);
                }
                sendData(connectionSocket, "Plaintext Received");               // confirm that plaintext reeceived

                /*-- Receive Key Data from Client --*/
                memset(key, '\0', sizeof(key));
                charsRead = 0;
                // continues to read key data from client until expected length
                while (charsRead < dataLength)                                  
                {
                    charsRead += readData(connectionSocket, buffer, sizeof(buffer));
                    strcat(key, buffer);
                }
                sendData(connectionSocket, "Key Received");                     // confirm that key received
                readData(connectionSocket, buffer, sizeof(buffer));             // allows client-side to confirm ready for ciphertext

                /*-- Encrypt Data and Send Back to Client --*/
                // encrypt data
                encryptData(plaintext, key, ciphertext);

                // send data back to client
                charsWritten = 0;
                int totalWritten = 0;
                char *tempPtr = ciphertext;                                     // ptr used to track str position as we send data
                // continues to write ciphertext data to client until end of str reached
                while (totalWritten < dataLength)
                {
                    charsWritten = send(connectionSocket, tempPtr, MAX_TRANSMISSION_SIZE - 1, 0);
                    tempPtr += charsWritten;
                    totalWritten += charsWritten;
                }
                
                /*-- Close connection socket for this client and exit child process --*/
                close(connectionSocket); 
                exit(0);

            // for parent process - goes back to listening for encryption requests
            default:            
                activeConnections++;
            }
        }
        
        // check for terminated processes and update the # of active connections
        while((childPid = waitpid(-1, &childStatus, WNOHANG)) > 0)
        {
            activeConnections--;
        }
    }

    // Close the listening socket and exit program
    close(listenSocket); 
    return 0;
}