/* 
*  Name : Terence Tang
*  Course : CS344 - Operating Systems
*  Date : May 30 2021
*  Assignment #5: One-Time Pads - Decryption Client
*  Description:  Client which takes user provided cipher and key files and sends decryption requests to an 
*                localhost decryption service via a provided port number.  The data transfer is made via socket 
*                communications.  The client checks cipher and key inputs for valid length and input characters
*                before sending a request to the decryption service.  It then checks that it has connected to the 
*                right service and sends all relevant data.  It then waits to receive a plaintext response which
*                it prints to stdout (which can be redirected).
*
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>  // ssize_t
#include <sys/socket.h> // send(),recv()
#include <netdb.h>      // gethostbyname()


// Declare Global Resources 
static const char *HOSTNAME = "localhost";           // hostname used in creating socket connection requests
static const int MAX_MSG_SIZE = 100000;              // maximum size of data to be sent
static const int MAX_TRANSMISSION_SIZE = 1024;       // maximum size of data for transmission to server
static const char validChars[27] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ ";

// Error function used for reporting issues with errno
void error(const char *msg)
{ 
  perror(msg); 
  exit(0); 
} 

// Set up the address struct
void setupAddressStruct(struct sockaddr_in* address, int portNumber)
{
    // Clear out the address struct
    memset((char*) address, '\0', sizeof(*address)); 

    // The address should be network capable
    address->sin_family = AF_INET;
    // Store the port number
    address->sin_port = htons(portNumber);

    // Get the DNS entry for this host name
    struct hostent* hostInfo = gethostbyname(HOSTNAME); 
    if (hostInfo == NULL) { 
        fprintf(stderr, "CLIENT: ERROR, no such host found for %s\n", HOSTNAME); 
        exit(2); 
    }
    // Copy the first IP address from the DNS entry to sin_addr.s_addr
    memcpy((char*) &address->sin_addr.s_addr, 
            hostInfo->h_addr_list[0],
            hostInfo->h_length);
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

// Check if input file contains only valid chars via validChar mapping
void checkFileForValidChars(char *input, char *fileName)
{
    // replace new line chars with null terminating chars
    input[strcspn(input, "\n")] = '\0'; 

    // iterate through each char in file
    for (int j = 0; j < strlen(input); j++) {
        // compare char to each valid char from validChar mapping
        for (int i = 0; i < sizeof(validChars) + 1; i++)
        {   
            // if no match found throw invalid input error and exit
            if (i == 27)
            {
                fprintf(stderr, "Error: \'%s\' contains invalid characters.\n", fileName);
				exit(1);
            }
            // if match found, move onto next char in file
            if (input[j] == validChars[i])
            {
                break;
            }
        }
    }
}

int main(int argc, char *argv[])
{
    int socketFD, portNumber, charsWritten, charsRead, ciphertextLen, keyLen;
    struct sockaddr_in serverAddress;
    char buffer[MAX_TRANSMISSION_SIZE];
    char ciphertext[MAX_MSG_SIZE];
    char key[MAX_MSG_SIZE];
    char plaintext[MAX_MSG_SIZE];
    char filePath[256];


    /*-- Check usage & args --*/
    if (argc < 4) 
    { 
        fprintf(stderr,"USAGE: %s plaintext key port\n", argv[0]); 
        exit(0); 
    }

    /*-- Check Plaintext and Key inputs --*/
    // Clears all string storage for input
    memset(filePath, '\0', sizeof(filePath));   
    memset(ciphertext, '\0', sizeof(ciphertext));                           
    memset(key, '\0', sizeof(key));                           

    // Open specified plaintext file text for read only
    strcpy(filePath, "./");                                                 // generate filepath
    strcat(filePath, argv[1]); 
    FILE *plaintextFile = fopen(filePath, "r");
    if (plaintextFile == NULL)                                              // error handling for invalid files
    {
        fprintf(stderr,"Invalid File: specified plaintext file \'%s\' not found\n", argv[1]); 
        exit(1);
    }

    // Check if Plaintext file has valid chars and store file size
    fgets(ciphertext, sizeof(ciphertext) - 1, plaintextFile);               // stores file contents to str
    fseek(plaintextFile, 0, SEEK_SET);                                      // reset pointer for next use
    checkFileForValidChars(ciphertext, argv[1]);
    ciphertextLen = strlen(ciphertext);                                     // store ciphertext len

    // Open specified key file text for read only
    memset(filePath, '\0', sizeof(filePath));                               // clear filepath    
    strcpy(filePath, "./");                                                 // generate filepath
    strcat(filePath, argv[2]); 
    FILE *keyFile = fopen(filePath, "r");
    if (keyFile == NULL)                                                    // error handling for invalid files
    {
        fprintf(stderr,"Invalid File: specified key file %s not found\n", argv[2]);
        exit(1);
    }

    // Check if key file has valid chars and store file size
    fgets(key, sizeof(key) - 1, keyFile);                                   // stores file contents to str
    fseek(keyFile, 0, SEEK_SET);                                            // reset pointer for next use
    checkFileForValidChars(key, argv[2]);
    keyLen = strlen(key);                                                   // store key len

    // check if plaintext is greater than key size, throw error and exit if true
    if(keyLen < ciphertextLen){ 
        fprintf(stderr,"Error: key \'%s\' is too short\n", argv[2]);
        exit(1);
	}

    /*-- Create and Validate Encryption Socket Connection --*/
    // Create a socket
    socketFD = socket(AF_INET, SOCK_STREAM, 0); 
    if (socketFD < 0)
    {
        error("CLIENT: ERROR opening socket");
		fprintf(stderr, "Error: could not contact enc_server on port %d\n", atoi(argv[3]));
        exit(2);
    }

    // Set up the server address struct
    setupAddressStruct(&serverAddress, atoi(argv[3]));

    // Connect to server
    if (connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0)
    {
        error("CLIENT: ERROR connecting to server");
		fprintf(stderr, "Error: could not contact enc_server on port %d\n", atoi(argv[3]));
        exit(2);
    }

    /*-- Validate Socket Connection Is For Right Decryption Service --*/
    char* checkMsg = "dec_server";                                          // Send request type to server
    sendData(socketFD, checkMsg);                                                               
    charsRead = readData(socketFD, buffer, sizeof(buffer));                 // Receive server response - accepted or denied
    if(strcmp(buffer, "denied") == 0){                                      // Check if server affirms correct connection type
		fprintf(stderr, "Error: dec_client cannot use enc_server on port %d\n", atoi(argv[3]));
		exit(2);    // if invalid, else exits
	}

    /*-- Send Ciphertext Data to Decryption Server --*/
    // Send data length
    memset(buffer, '\0', sizeof(buffer));                                   // Clear out buffers and charsread for next send
	sprintf(buffer, "%d", ciphertextLen);
    sendData(socketFD, buffer);                                             // Send ciphertext length to server
    charsRead = readData(socketFD, buffer, sizeof(buffer));                 // Receive server response - continue msg

    // Send ciphertext data to dec_server
    charsWritten = 0;
    // continues to write cipher data to client until cipher length reached
    while (charsWritten < ciphertextLen)
    {
        memset(buffer, '\0', sizeof(buffer));                               // Clear out buffer for next line
        fgets(buffer, sizeof(buffer) - 1, plaintextFile);                   // Get buffer sized chunk from plaintext
        buffer[strcspn(buffer, "\n")] = '\0';                               // Remove the trailing \n that fgets adds
        charsWritten += sendData(socketFD, buffer);
    }
    charsRead = readData(socketFD, buffer, sizeof(buffer));                 // Receive server response - ciphertext received msg
    if (strcmp(buffer, "Ciphertext Received") != 0)                         // Confirm server received ciphertext
    {
        fprintf(stderr, "ERROR: Server did not receive plaintext data\n"); 
        exit(2); 
    }

    /*-- Send Key Data to Decryption Server --*/
    // Send key data to dec_server
    charsWritten = 0;
    // continues to write key data to client until ciphertext length reached
    while (charsWritten < ciphertextLen)
    {
        memset(buffer, '\0', sizeof(buffer));                               // Clear out buffer for next line
        fgets(buffer, sizeof(buffer) - 1, keyFile);                         // Get buffer sized chunk from plaintext
        buffer[strcspn(buffer, "\n")] = '\0';                               // Remove the trailing \n that fgets adds
        charsWritten += sendData(socketFD, buffer);
    }
    charsRead = readData(socketFD, buffer, sizeof(buffer));                 // Receive server response - key received msg
    if (strcmp(buffer, "Key Received") != 0)                                // Confirm server received key
    {
        fprintf(stderr, "ERROR: Server did not receive key data\n"); 
        exit(2); 
    }
    charsWritten += sendData(socketFD, "Waiting for ciphertext..");

    /*-- Receive Plaintext Data from Server --*/
    memset(plaintext, '\0', sizeof(plaintext));
    charsRead = 0;
    // continues to read plaintext data from server until expected data length
    while (charsRead < ciphertextLen)
    {
        charsRead += readData(socketFD, buffer, sizeof(buffer));
        strcat(plaintext, buffer);                                         // store plaintext to str
    }
    printf("%s\n", plaintext);                                             // prints plaintext with added newline char

	close(socketFD); // Close the socket
	return 0;
}