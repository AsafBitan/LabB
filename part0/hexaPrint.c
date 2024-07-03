#include <stdio.h>
#include <stdlib.h>

void PrintHex(char buffer[], int length){
    for(int i = 0; i < length; i++){
        printf("%02X ", (unsigned char) buffer[i]);
    }
    printf("\n");
}

int main(int argc, char **argv){
    FILE * binaryFile = fopen(argv[1], "r");
    //int size = sizeof(binaryFile);
    fseek(binaryFile, 0, SEEK_END);
    int fileSize = ftell(binaryFile);
    fseek(binaryFile, 0, SEEK_SET);
    //printf("%c", sizeof(binaryFile));
    char buffer[fileSize];
    fread(buffer, fileSize, 1, binaryFile);
    PrintHex(buffer, fileSize);
    fclose(binaryFile);
    return 0;
}