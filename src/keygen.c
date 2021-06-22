/* 
*  Name : Terence Tang
*  Course : CS344 - Operating Systems
*  Date : May 30 2021
*  Assignment #5: One-Time Pads - Keygen
*  Description:  Program for generating random keys of a specified length.
*
*/


// compiled using gcc option --std=c99

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
#include <unistd.h>

// Declare Global Resources 
int MAX_RANGE = 27;                             // max range of integers to represent A-Z and SPACE

// Converts integers between 0-26 to chars for A-Z or SPACE
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

int main (int argc, char *argv[])
{
    // Check usage & args
    if (argc < 2) { 
        fprintf(stderr, "USAGE: %s keylength\n", argv[0]); 
        exit(0); 
    }

    int i;
    int length = strtol(argv[1], NULL, 10);     // convert str to long int type for console keylength input
    char buffer[length+1];
    srand(time(0));                             // initialize seed for random

    /* Print random letters given a randomly generated 0-27 num */
    for(i = 0 ; i < length ; i++ ) 
    {
        int random = rand() % MAX_RANGE;
        random = itoc(random);
        buffer[i] = (char) random;
    }

    buffer[i] = '\n';                           // adds new line and null terminator to string
    buffer[i+1] = '\0';
    printf("%s", buffer);                       // prints key to stdout - should be redirected
    return(0);
}