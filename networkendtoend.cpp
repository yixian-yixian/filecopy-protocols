#include "networkendtoend.h"
#include <cassert>

#define SIZE "SIZE:"
#define SHA1 "SHA1:"
#define ACK "ACK"
#define RESEND "RESEND"
#define LAST "LAST"
#define NLAST "NOTLAST"
#define BUFSIZE 1024
const int UPPERBOUND = 1e6;
using namespace std;
using namespace C150NETWORK;  // for all the comp150 utilities



// true: file successfully sent in one iteration
// false: file fails to be sent and update iteration by 1 
bool 
sendtoTar(C150DgmSocket& sock, fileProp& file, unsigned& iterationNum)
{
    // send Size 
    sock.turnOnTimeouts(30000);
    string contentSize = file.contentSize.str(); 
    ssize_t contentSize = strlen(contentSize);
    sock.write((const char*)contentSize.c_str(), contentSize);

    // check Size sent successfully
    char sizeMsg[3]; 
    sock.read(sizeMsg, sizeof(sizeMsg));
    if (sock.timedout()){
        iteration++;
        return false;
    } 
    
    // send SHA1 
    sock.write((const char*)file.fileSHA1, 20);

    // check SHA1 sent successfully
    char SHA1Msg[3]; 
    sock.read(sizeMsg, sizeof(sizeMsg));
    if (sock.timedout()){
        iteration++;
        return false;
    }
    
    // send Content 
    sock.write((const char*)file.contentbuf, file.contentSize);

    // check Content sent successfully
    char ContentMsg[3]; 
    sock.read(sizeMsg, sizeof(sizeMsg));
    if (sock.timedout()){
        iteration++;
        return false;
    }
    return true;
}


// True  - end of directory 
// False - more files to read from directory 
// send ACK if (1) SIZE received (2) SHA1 received 
// (3) CONTENTBUF of expected SHA1 and SIZE received 
bool
readfromSrc(C150DgmSocket& sock, unsigned& iterationNum)
{
    sock.turnOnTimeouts(30000);
    // receive status
    char statusMsg[BUFSIZE];
    sock.read(statusMsg, sizeof(statusMsg));
    string status(statusMsg);
    
    // send ACK
    if (!sock.timedout()){ 
        sock.write(ACK, 3);
    }else{
        sock.write(RESEND, strlen(RESEND));
        return false;
    }

    // receive Size 
    char sizeMsg[BUFSIZE];
    sock.read(sizeMsg, sizeof(sizeMsg));

    // send ACK
    if (!sock.timedout()){ 
        sock.write(ACK, 3);
    }else{
        sock.write(RESEND, strlen(RESEND));
        return false;
    }
    
    // receive SHA1
    char SHA1Msg[20];
    sock.read(SHA1Msg, 20);

    // send ACK
    if (!sock.timedout()){ 
        sock.write(ACK, 3);
    } else{
        sock.write(RESEND, strlen(RESEND));
        return false;
    }

    // receive content 
    string size(sizeMsg);
    int contentlen = atoi(size);
    vector<unsigned char> allFileContent;
    ssize_t totalBytes = 0;
    unsigned char* temporaryBuf = (unsigned char*)malloc(BUFSIZE * sizeof(unsigned char));
    ssize_t chunk = sock.read(temporaryBuf, 1, BUFSIZE);
    while(1) { // read until the end
        for (ssize_t t = 0; t <= chunk; t += sizeof(unsigned char)) {
            allFileContent.push_back(*(temporaryBuf + t)); }
        bzero(temporaryBuf, BUFSIZE); // clean up the buf for next read 
        if (chunk <= BUFSIZE) break;
        chunk = sock.read(temporaryBuf, 1, BUFSIZE);;
        totalBytes += chunk;
    }

    // compare length 
    if (totalBytes != contentlen){
        sock.write(RESEND, strlen(RESEND));
        return false;
    }
    // calculate SHA1 
    char obuf[20];
    SHA1(temporaryBuf, totalBytes, obuf);
    if (strcmp(obuf, SHA1Msg) != 0){
        sock.write(RESEND, strlen(RESEND));
        return false;
    } 
    
    // send ACK 
    sock.write(ACK, 3);
    if (status == LAST){
        return true;
    }
    return false;
}

void 
FileSendE2ECheck(C150DgmSocket& sock, vector<fileProp>& allFilesProp)
{
    // if one file fails more than 3 times, give up
    long unsigned int index = 0;
    unsigned iteration = 0;
    while (index < allFilesProp.size())
    {
        if (iteration < 10){
            if (!sendtoServer(sock, allFilesProp.at(index), iteration)) continue;
        }
        index++;
        iteration = 0;
    }
}

void 
FileReceiveE2ECheck(C150DgmSocket& sock)
{
    while (1){
        if (readfromSrc(sock)) break;
    }
}



void 
formatRequestBuf(fileProp& singleFile, unsigned char **requestBuf)
{
    stringstream contentSizeSS;
    contentSizeSS << SIZE << singleFile.contentSize << "\n" << SHA1 << singleFile.fileSHA1 << "\n\n\n";
    string header = contentSizeSS.str(); 
    const char* h = header.c_str();
    ssize_t totalBufSize = strlen(h) + singleFile.contentSize;
    char *generateBuf = (char*)malloc(totalBufSize * sizeof(unsigned char));
    strcpy(generateBuf, h);
    strcpy(generateBuf + strlen(h), (const char*)singleFile.contentbuf);
    *requestBuf = (unsigned char*)generateBuf;
    cout << *requestBuf << endl;
}

