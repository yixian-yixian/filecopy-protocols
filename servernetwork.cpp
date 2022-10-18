#include "servernetwork.h"

#define ACK "ACK"
#define REJ "REJ"
#define LAST "LAST"
#define CONT "CONT"
#define BUFSIZE 512
#define WRITESIZE 512
#define PARTSIZE 5120
#define MAXTIME 30000
#define STATUS 4
#define SHA_MSG 20
#define CONTENT_SIZE 50
#define UPPERBOUND 1000000
using namespace std;
using namespace C150NETWORK;  // for all the comp150 utilities

void printSHA1(unsigned char *partialSHA1dup);
void parseHeaderField(unsigned char *receivedBuf);
bool compareSHA1(unsigned char* receivedSHA1, unsigned char* calculateSHA1);


typedef struct header_info{
    unsigned char filenameSHA1[20];
    unsigned char contentSHA1[20];
    char filename_str[256]; // no filename can have length higher than 255
    size_t contentSize;
    // 0 not complete 1 complete
    size_t status;
} *Socket_Header;



/* * * * * *  * * * * * * * * * *  NETWORK SERVER FUNCTIONS  * * * * * * * * * * * * * * * */
/* parseHeaderField
 * purpose: parse the header information received from client 
 * parameter: 
 *       unsigned char *receivedBuf: buffer with received content 
 *       fileProp& received_file: the target fileProp to populate passed in by reference 
 *       bool& lastfile: boolean to update whether last file is received 
 *                          passed in by reference 
 * return: True if filename is received correctly by comparing calculated filenameSHA1 
 *          with received filenameSHA1, False if there is mismatch
*/

bool 
parseHeaderField(unsigned char *receivedBuf, fileProp& received_file, bool& lastfile)
{
    cout << "parse header field " << endl;
    // casting received 304 bytes into header object 
    Socket_Header header = (Socket_Header)malloc(sizeof(struct header_info));
    memcpy((void *)header, receivedBuf, sizeof(struct header_info));
    // check if filename SHA1 and filename matches 
    unsigned char *calc_filenameSHA1 = (unsigned char*)malloc(20 * sizeof(unsigned char));
    SHA1((unsigned char *)header->filename_str, strlen(header->filename_str), calc_filenameSHA1);
    if (!compareSHA1(calc_filenameSHA1, header->filenameSHA1)){
        cout << "calculated filnameSHA1" << endl;
        printSHA1(calc_filenameSHA1);
        cout << "received filnameSHA1" << endl;
        printSHA1(header->filenameSHA1);
        return false;  // error raised with unmatched filename SHA1 
    } 
    cout << "after checking filename SHA1 \n";

    // populate fileProp with received information 
    memcpy((void *)received_file.fileSHA1, (void *)header->contentSHA1, 20);
    received_file.contentSize = header->contentSize;
    cout << header->contentSize << endl;
    int filename_len = strlen(header->filename_str);
    char filename_string_arr[256];
    strncpy(filename_string_arr, header->filename_str, filename_len + 1);
    received_file.filename = string(filename_string_arr);
    
    if (header->status == 0){ 
        cout << "not last file\n"; 
        lastfile = false;
    } else{ 
        cout << "last file\n"; 
        lastfile = true;
    }
    cout << "copied received filename " << received_file.filename << endl;
    cout << "copied received file name size "<< filename_len << endl;
    printSHA1(header->contentSHA1);
    cout << "This is the " << (lastfile? "LAST":"CONT");
    cout << " file.\n";
    return true;
}


void 
FileReceiveE2ECheck(C150DgmSocket& sock, vector<fileProp>& allArrivedFiles)
{
    *GRADING << "Begining to receive whole files from client." << endl; 
    while (1){
        if (readfromSrc(sock, allArrivedFiles)) break;
    }
    *GRADING << "Received and successfully read a total of " << allArrivedFiles.size() << " files from client." << endl;
}

/* readSizefromSocket 
 * purpose: read provided amount of bytes from socket 
 * parameter: 
 *      C150DgmSocket& sock: reference to socket object 
 *      size_t bytestoRead: number of bytes to read from socket
 *      char& bytes_storage: character array to store read bytes passed by reference
 * return: True if no timeout and signalize continuation of program, False if timeout 
 *          and this iteration terminates.
 * notes: none
*/
bool 
readSizefromSocket(C150DgmSocket& sock, size_t bytestoRead, char** bytes_storage)
{
    bzero((*bytes_storage), bytestoRead);
    sock.read((*bytes_storage), bytestoRead);
    /* evaluate conditions to send ACK or REJ */
    if (sock.timedout()){ 
        sock.write(REJ, strlen(REJ));
        return false;
    }
    return true;
    
}

/* compareSHA1 
 * purpose: compare the receivedSHA1 and calculatedSHA1 byte by byte 
 * parameter: 
 * return: True if every byte match, False if any byte does not match
 */
bool 
compareSHA1(unsigned char* receivedSHA1, unsigned char* calculateSHA1)
{
    for (int j = 0; j < 20; j++) {
        if (receivedSHA1[j] != calculateSHA1[j])
            return false;
    }
    return true;

}


// return True if all 10 packets successfully received with no drop, False if timedout 
bool 
readPackets(C150DgmSocket& sock, vector<unsigned char>& temporaryFileContent, bool& last_packets) {
    size_t chunk = 0;
    unsigned char *temporaryBuf =  (unsigned char*)malloc(sizeof(unsigned char) * BUFSIZE);
    int iterator = 0;
    while (iterator < 10){
        chunk = sock.read((char *)temporaryBuf, BUFSIZE);
        if (sock.timedout()) { 
            temporaryFileContent.clear();
            free(temporaryBuf);
            return false;
        }
        // move the content into vector
        for(unsigned int t = 0; t < chunk; t ++) {
            temporaryFileContent.push_back(*(temporaryBuf + t));
        }
        bzero(temporaryBuf, chunk);
        if (chunk < BUFSIZE) {
            last_packets = true;
            break;
        }
        iterator += 1;
    }
    return true;
}

/* readContentfromSocket 
 * purpose: read the incoming packets that represent content from server socket
 * parameter: 
 *     C150DgmSocket& sock: reference to socket object
 *     size_t contentSize: total bytes to read from the content
 *     unsigned char** read_result_addr: address of pointer to the finally read bytes
 * return: True if no timeout and signalize continuation of program, False if timeout 
 *          and this iteration terminates. 
 * notes: none
*/
bool
readContentfromSocket(C150DgmSocket& sock, int contentlen, unsigned char** read_result_addr)
{
    vector<unsigned char> allFileContent; /* dynamically expanded memory for all content bytes */
    vector<unsigned char> temporaryFileV;
    /* totalBytes */
    ssize_t totalBytes = 0, curBytes = 0;
    unsigned char* temporaryBuf;
    bool last_packets = false;
    // int readtimes = 0;
    /* read from socket in unit of 10 packets */
    while (totalBytes != contentlen) { /* read until all bytes from sockets are received */
        if (readPackets(sock, temporaryFileV, last_packets)) { // read 10 packets SHA1 
            curBytes = temporaryFileV.size();
            if (last_packets){
                sock.write(ACK, strlen(ACK));
                allFileContent.insert(allFileContent.end(), temporaryFileV.begin(), temporaryFileV.end());
                totalBytes += curBytes;
                temporaryFileV.clear();
                break;
            }
            char *partialSHA1_tmp = (char*)malloc(SHA_MSG * sizeof(char));
            if (!readSizefromSocket(sock, SHA_MSG, &partialSHA1_tmp)){ 
                sock.write(REJ, strlen(REJ)); // read partial SHA1
                temporaryFileV.clear();
                continue;}
            unsigned char provided_SHA1[20];
            for (int i = 0; i < 20; i++) {
                provided_SHA1[i] = (unsigned char)partialSHA1_tmp[i];
            }
            // copy vector content into buffer for SHA1 calculations 
            temporaryBuf = (unsigned char*)malloc((curBytes + 10) * sizeof(unsigned char));
            copy(temporaryFileV.begin(), temporaryFileV.end(), temporaryBuf);
            // calculate partial content SHA1 
            unsigned char *partialSHA1dup = (unsigned char*)malloc(SHA_MSG * sizeof(unsigned char)); 
            SHA1((const unsigned char*)temporaryBuf, curBytes, partialSHA1dup);
            if (!compareSHA1(provided_SHA1, partialSHA1dup)) { // mismatched chunk 
                *GRADING << "The received bytes SHA1 do not match, requesting resend." << endl;
                sock.write(REJ, strlen(REJ));
                temporaryFileV.clear();
                continue;
            } else { // everything successful 
                sock.write(ACK, strlen(ACK));
                allFileContent.insert(allFileContent.end(), temporaryFileV.begin(), temporaryFileV.end());
                totalBytes += curBytes;
                temporaryFileV.clear();
            }
        } else {
            // returned False read_packets have already cleaned the vector
            sock.write(REJ, strlen(REJ));
        }
    }

    /* compare total received bytes with received contentlen field */
    if (totalBytes != contentlen) {
        *GRADING << "read total bytes " << totalBytes <<" content length "<< contentlen << " " << endl;
        sock.write(REJ, strlen(REJ));
        return false;
    } 
    /* calculate SHA1 of the received content bytes */
    unsigned char* prod = (unsigned char*)malloc((allFileContent.size())*sizeof(unsigned char));
    bzero(prod, allFileContent.size()); /* zero out the field */
    copy(allFileContent.begin(), allFileContent.end(), prod);
    sock.write(ACK, strlen(ACK)); // entire file and SHA1 is correct 
    *read_result_addr = prod;
    return true;
}

/* readfromSrc 
 * purpose: read any incoming packets in order from the server socket 
 * parameter: 
 *     C150DgmSocket& sock: reference to socket object 
 * return: True if the socket have received the last packet in the 
 *          network stream, False if the socket is expecting more
 *          packets in the next read 
 * notes: none  
 */
bool
readfromSrc(C150DgmSocket& sock, vector<fileProp>& allArrivedFiles)
{
    /* 1ACK-receive fileheader from client */
    bool lastfile = false;
    unsigned char *fileHeader = (unsigned char*)malloc(sizeof(struct header_info));
    string garb = "garb";
    unsigned char garbage[20];
    SHA1((unsigned char*) garb.c_str(), strlen((const char*)garb.c_str()), garbage);
    struct fileProp fileInfo = fileProp("a", garbage, 0, nullptr);

    bzero(fileHeader, sizeof(struct header_info));
    sock.read((char*)fileHeader, sizeof(struct header_info));
    cout << "error after line 383 " << endl;
    /* evaluate conditions to send ACK or REJ */
    if (sock.timedout()) { 
        cerr << "timed out error in write" << endl;
        sock.write(REJ, strlen(REJ));
        return false;
    }
    /*1ACK-receive header information and correct filenameSHA1 */
    if (parseHeaderField(fileHeader, fileInfo, lastfile))
    {
        sock.write(ACK, strlen(ACK));
    }else{
        sock.write(REJ, strlen(REJ));
        return false;
    }

    /* 2ACK-receive content from client */
    /* many ACKs for receiving contents in packets and with correct SHA1 */
    int contentlen = fileInfo.contentSize;
    unsigned char* prod = nullptr;
    if (!readContentfromSocket(sock, contentlen, &prod)){
        /* unsuccessful read of the entire content */
        *GRADING << "File: <" << fileInfo.filename << "> failed at socket to socket check for failing to receive contents from client." << endl;
        free(prod);
        return false;
    }
    *GRADING << "File: <" << fileInfo.filename << "> succeed at socket to socket check with receiving the entire content." << endl;
    unsigned char *obuf = (unsigned char*)malloc(SHA_MSG * sizeof(unsigned char));
    SHA1((const unsigned char *)prod, contentlen, obuf);

    /*9ACK-check consistency in received and calculated SHA1 to client */
    if (!compareSHA1(obuf, fileInfo.fileSHA1)) {
        sock.write(REJ, strlen(REJ));
        *GRADING << "File: <" << fileInfo.filename << "> socket to socket failed at inconsistency in received and calculated content SHA1." << endl;
        return false;
    }
    sock.write(ACK, strlen(ACK)); /* log for purpose of recording failure caused by network nastiness */
    *GRADING << "File: <" << fileInfo.filename << ">  succeed at socket to socket check with consistency in size and SHA1 of the content." << endl;
    fileInfo.contentbuf = prod;
    allArrivedFiles.push_back(fileInfo);
    free(obuf);
    free(prod);
    *GRADING << "File: <" << fileInfo.filename << "> socket to socket end-to-end check succeeded." << endl;
    return lastfile;
}


/* Helper function for viewing SHA1 */
void 
printSHA1(unsigned char *partialSHA1dup)
{
    printf("received SHA1[");
    for (int i = 0; i < 20; i++)
    {
        printf ("%02x", (unsigned int) partialSHA1dup[i]);
    }
    printf("].\n");
}
