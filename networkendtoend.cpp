#include "networkendtoend.h"

#define ACK "ACK"
#define REJ "REJ"
#define LAST "LAST"
#define CONT "CONT"
#define BUFSIZE 512
const int UPPERBOUND = 1e6;
using namespace std;
using namespace C150NETWORK;  // for all the comp150 utilities



// true: file successfully sent in one iteration
// false: file fails to be sent and update iteration by 1 
bool 
sendtoTar(C150DgmSocket& sock, fileProp& file, unsigned& iteration, bool& lastfile)
{
    sock.turnOnTimeouts(30000);
    // TODO send file_name and its SHA1 

    // Send status
    if (lastfile){
        sock.write((const char*)LAST, strlen(LAST));
    }else{
        sock.write((const char*)CONT, strlen(CONT));
    }
    printf("successfully sent status\n");

    // check status sent successfully
    char statusMsg[4]; 
    sock.read(statusMsg, sizeof(statusMsg));

    if (sock.timedout()){
        printf("No ACK for statusMsg recevied.\n");
        iteration++;
        return false;
    }else{
        if (strcmp(statusMsg, ACK) != 0){
            printf("Response for status received is not ACK, it is %s.\n", statusMsg);
            iteration++;
            return false;
        }else{
            printf("Response for status received is %s.\n", statusMsg); 
        }
    }

    
    // send Size 
    string sizeField = to_string(file.contentSize); 
    ssize_t contentSize = strlen(sizeField.c_str());
    sock.write((const char*)sizeField.c_str(), contentSize);
    printf("successfully sent size: %s\n", (const char*)sizeField.c_str());

    // check Size sent successfully
    char sizeMsg[4]; 
    bzero(sizeMsg,4);
    sock.read(sizeMsg, sizeof(sizeMsg));
    
    if (sock.timedout()){
        printf("No ACK for sizeMsg recevied.\n");
        iteration++;
        return false;
    }else{
        if (strcmp(sizeMsg, ACK) != 0){
            printf("Response for size received is not ACK, it is %s.\n", sizeMsg);
            iteration++;
            return false;
        }else{
            printf("Response for size received is %s.\n", sizeMsg); 
        }
    }
    
    // send SHA1
    cout << "sending SHA1[";
    for (int j = 0; j < 20; j++)
    {
        printf ("%02x", (unsigned int) file.fileSHA1[j]);
    }
    cout <<"]\n";
    sock.write((const char*)file.fileSHA1, 21);
    printf("successfully sent sha1\n");

    // check SHA1 sent successfully
    char SHA1Msg[4]; 
    bzero(SHA1Msg, 4);
    sock.read(SHA1Msg, sizeof(SHA1Msg));
    if (sock.timedout()){
        iteration++;
        return false;
    } else {
        if (strcmp(SHA1Msg, ACK) != 0){
            printf("Response for sha1 received is not ACK, it is %s.\n", SHA1Msg);
            iteration++;
            return false;
        }else{
            printf("Response for sha1 received is %s.\n", SHA1Msg); 
        }
    }
    
    // send Content 
    ssize_t ByteSent = 0; 
    while (ByteSent < file.contentSize){
        if (ByteSent + BUFSIZE > file.contentSize){
            sock.write((const char*)(file.contentbuf + ByteSent), file.contentSize - ByteSent);
            printf("successfully sent %lu bytes, total goal is %lu bytes\n", ByteSent, file.contentSize);
        }else{
            sock.write((const char*)(file.contentbuf + ByteSent), BUFSIZE);
            printf("successfully sent %lu bytes, total goal is %lu bytes\n", ByteSent, file.contentSize);
        }
        ByteSent += BUFSIZE;
    }
    printf("successfully sent content of size\n");

    // check Content sent successfully
    char ContentMsg[4]; 
    bzero(ContentMsg, 4);
    sock.read(ContentMsg, sizeof(ContentMsg));
    if (sock.timedout()){
        iteration++;
        return false;
    } else{
        if (strcmp(ContentMsg, ACK) != 0){
            printf("Response for content received is not ACK, it is %s.\n", ContentMsg);
            iteration++;
            return false;
        }else{
            printf("Response for content received is %s.\n", ContentMsg); 
        }
    }

    // check size is equal
    char ContentSizeMsg[4]; 
    bzero(ContentSizeMsg, 4);
    sock.read(ContentSizeMsg, sizeof(ContentSizeMsg));
    if (sock.timedout()){
        iteration++;
        return false;
    } else{
        if (strcmp(ContentSizeMsg, ACK) != 0){
            printf("Response for content size received is not ACK, it is %s.\n", ContentSizeMsg);
            iteration++;
            return false;
        }else{
            printf("Response for content size received is %s.\n", ContentSizeMsg); 
        }
    }

    // check sha1 is equal
    char ContentSHA1Msg[4]; 
    bzero(ContentSHA1Msg, 4);
    sock.read(ContentSHA1Msg, sizeof(ContentSHA1Msg));
    if (sock.timedout()){
        iteration++;
        return false;
    } else{
        if (strcmp(ContentSHA1Msg, ACK) != 0){
            printf("Response for content sha1 received is not ACK, it is %s.\n", ContentSHA1Msg);
            iteration++;
            return false;
        }else{
            printf("Response for content sha1 received is %s.\n", ContentSHA1Msg); 
        }
    }

    return true;
}


// True  - end of directory 
// False - more files to read from directory 
// send ACK if (1) SIZE received (2) SHA1 received 
// (3) CONTENTBUF of expected SHA1 and SIZE received 
bool
readfromSrc(C150DgmSocket& sock)
{
    sock.turnOnTimeouts(30000);
    // receive status
    char statusMsg[4];
    bzero(statusMsg, 4);
    sock.read(statusMsg, sizeof(statusMsg));
    string status(statusMsg);
    printf("successfully read message %s\n", statusMsg);
    
    // send ACK
    if (!sock.timedout()){ 
        sock.write(ACK, 3);
        printf("finished sending ACK\n");
    }else{
        printf("broken write below\n");
        sock.write(REJ, strlen(REJ));
        printf("nope write is fine\n");
        return false;
    }
    
    // receive Size 
    char sizeMsg[BUFSIZE];
    bzero(sizeMsg, BUFSIZE);
    sock.read(sizeMsg, sizeof(sizeMsg));
    printf("current size %s\n", sizeMsg);

    // send ACK
    if (!sock.timedout()){ 
        printf("DID NOT TIME OUT\n");
        sock.write(ACK, 3);
        printf("sending ACK\n");
    }else{
        printf("broken write below\n");
        sock.write(REJ, strlen(REJ));
        printf("nope write is fine\n");
        return false;
    }
    
    // receive SHA1
    char SHA1Msg[20];
    bzero(SHA1Msg, 20);
    sock.read(SHA1Msg, 20);
    unsigned char SHA1dup[20];
    cout << "received SHA1:[";
    for (int j = 0; j < 20; j++)
    {
        SHA1dup[j] = (unsigned char)SHA1Msg[j];
        printf ("%02x", SHA1dup[j]);
    }
    cout << "]\n";

    // send ACK
    if (!sock.timedout()){ 
        sock.write(ACK, 3);
        printf("write ACK for SHA1\n");
    } else{
        sock.write(REJ, strlen(REJ));
        return false;
    }

    // receive content 
    string size(sizeMsg);
    int contentlen = atoi(size.c_str());
    vector<unsigned char> allFileContent;
    ssize_t totalBytes = 0;
    unsigned char* temporaryBuf = (unsigned char*)malloc(contentlen * sizeof(unsigned char));
    ssize_t chunk = 0;

    
    while(1) { // read until the end
        chunk = sock.read((char *)temporaryBuf, contentlen);
        printf("finished first read of size %lu\n", chunk);
        cout << "read content message[" << (char *)temporaryBuf << "]"<< endl;
        for (ssize_t t = 0; t <= chunk; t += sizeof(unsigned char)) {
            allFileContent.push_back(*(temporaryBuf + t)); }
        bzero(temporaryBuf, contentlen); // clean up the buf for next read 
        totalBytes += chunk;
        if (totalBytes == contentlen) break;
        if (sock.timedout()){
            sock.write(REJ, strlen(REJ));
            return false;
        }
    }

    if (!sock.timedout()){ 
        sock.write(ACK, 3);
        printf("write ACK after entire read \n");
    } else{
        sock.write(REJ, strlen(REJ));
        return false;
    }

    // compare length 
    printf("Content length %u and actual read %lu\n", contentlen, totalBytes);
    if (totalBytes != contentlen){
        printf("Content length %u and actual read %lu does not match \n", contentlen, totalBytes);
        sock.write(REJ, strlen(REJ));
        return false;
    } else {
        sock.write(ACK, 3);
    }
    
    // calculate SHA1 
    for (unsigned int i = 0; i < allFileContent.size();i++) {
        *(temporaryBuf + i) = allFileContent.at(i); 
    }
    // cout << "received["<< (char *)temporaryBuf << "]" << endl;
    unsigned char obuf[20];
    SHA1(temporaryBuf, totalBytes, obuf);
    cout <<"calculated SHA1[";
    for (int j = 0; j < 20; j++)
    {
        cout << obuf[j];
        if (SHA1dup[j] != obuf[j]) {
            sock.write(REJ, strlen(REJ));
            printf("SHA1 calculated and received do not match \n");
            return false;
        }
    }
    cout <<"]\n";
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
    bool lastfile = false;
    while (index < allFilesProp.size())
    {
        printf("currently sending to socket\n");
        if (index == allFilesProp.size() - 1){lastfile = true;}
        if (iteration > 1){break;}
        if (iteration < 10){
            if (!sendtoTar(sock, allFilesProp.at(index), iteration, lastfile)){continue;}
        }
        index++;
        iteration = 0;
    }
    printf("sending complete\n");
}

void 
FileReceiveE2ECheck(C150DgmSocket& sock)
{
    printf("inside file receive e2e check\n");
    while (1){
        printf("currently reading from socket\n");
        if (readfromSrc(sock)) break;
        printf("not last message\n");
    }
}



// void 
// formatRequestBuf(fileProp& singleFile, unsigned char **requestBuf)
// {
//     stringstream contentSizeSS;
//     contentSizeSS << SIZE << singleFile.contentSize << "\n" << SHA1 << singleFile.fileSHA1 << "\n\n\n";
//     string header = contentSizeSS.str(); 
//     const char* h = header.c_str();
//     ssize_t totalBufSize = strlen(h) + singleFile.contentSize;
//     char *generateBuf = (char*)malloc(totalBufSize * sizeof(unsigned char));
//     strcpy(generateBuf, h);
//     strcpy(generateBuf + strlen(h), (const char*)singleFile.contentbuf);
//     *requestBuf = (unsigned char*)generateBuf;
//     cout << *requestBuf << endl;
// }

