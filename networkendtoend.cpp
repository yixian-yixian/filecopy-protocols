#include "networkendtoend.h"

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


typedef struct header_info{
    unsigned char filenameSHA1[20];
    unsigned char contentSHA1[20];
    size_t contentSize;
    char filename_str[256];  // no filename can have length higher than 255

} *Socket_Header;

/* * * * * *  * * * * * * * * * *  NETWORK CLIENT FUNCTIONS  * * * * * * * * * * * * * * * */
void 
FileSendE2ECheck(C150DgmSocket& sock, vector<fileProp>& allFilesProp, vector<string>& filenames)
{
    // if one file fails more than 3 times, give up
    long unsigned int index = 0;
    unsigned iteration = 0;
    bool lastfile = false;
    while (index < allFilesProp.size())
    {
        if (index == allFilesProp.size() - 1){lastfile = true;}
        if (iteration < 10){
            *GRADING << "File: <" << filenames.at(index) << ">, beginning transmission, attempt <" << iteration << ">\n";
            if (!sendtoTar(sock, allFilesProp.at(index), iteration, lastfile, filenames.at(index))){continue;}
        }
        *GRADING << "File: <" << filenames.at(index) << "> transmission complete, waiting for end-to-end check, attempt <" << iteration << ">\n";
        index++;
        iteration = 0;
    }
}

/* formatRequestBuf 
 * purpose: Check if the server sends a confirmation message
 * parameter: 
 *            C150DgmSocket& sock: reference to socket object
 * return: none
 * notes: N/A
 */
void 
formatRequestBuf(fileProp& singleFile, unsigned char **requestBuf)
{ 
    // find the filename size
    size_t filname_size = (singleFile.filename).size();
    // calculate filenameSHA1
    unsigned char nameSHA1[20];
    SHA1((unsigned char*)singleFile.filename.c_str(), filname_size, nameSHA1);
    // assign information into each field
    Socket_Header header = (Socket_Header)malloc(sizeof(struct header_info));
    memcpy((void *)header->filenameSHA1, (void *)nameSHA1, 20);
    memcpy((void *)header->contentSHA1, (void *)singleFile.fileSHA1, 20);
    header->contentSize = singleFile.contentSize;
    // memcpy((void *)header->filename_str, (void *)singleFile.filename.c_str(), filname_size);
    strcpy(header->filename_str, (const char*)singleFile.filename.c_str());
    *requestBuf = (unsigned char *)malloc(sizeof(*header) * sizeof(unsigned char));
    memcpy(*requestBuf, header, sizeof(struct header_info));
    parseHeaderField(*requestBuf);
     
}

void 
parseHeaderField(unsigned char *receivedBuf)
{
    cout << "parse header field " << endl;
    Socket_Header header = (Socket_Header)malloc(sizeof(struct header_info));
    memcpy((void *)header, receivedBuf, sizeof(struct header_info));
    printSHA1(header->filenameSHA1);
    cout << header->filename_str << endl;
    
}



/* ServerRESCheck 
 * purpose: Check if the server sends a confirmation message
 * parameter: 
 *            C150DgmSocket& sock: reference to socket object
 * return: true if the message received is ACK, false otherwise
 * notes: N/A
 */
bool 
ServerRESCheck(C150DgmSocket& sock, unsigned& iteration)
{
    char serverRES[4]; 
    sock.read(serverRES, sizeof(serverRES));

    if (sock.timedout()){
        iteration++;
        return false;
    }else{
        if (strcmp(serverRES, ACK) != 0){
            iteration++;
            return false;
        }
    }
    return true;

}

/* sendtoTar 
 * purpose: Check if the server sends a confirmation message
 * parameter: 
 *            C150DgmSocket& sock: reference to socket object
 *            fileProp& file: reference to file struct
 *            unsigned& iteration: reference to the iteration number
 *            bool& lastfile: reference to whether the file sent is last
 * return: true if the server response is ACK, false otherwise
 * notes: true: file successfully sent in one iteration
 *        false: file fails to be sent and update iteration by 1
 */
bool 
sendtoTar(C150DgmSocket& sock, fileProp& file, unsigned& iteration, bool& lastfile, string filename)
{

    // Send filename 
    ssize_t filenameSize = strlen(filename.c_str());
    sock.write((const char*)filename.c_str(), filenameSize+1);
    // Check filename sent successfully
    if (!ServerRESCheck(sock, iteration)){
        *GRADING << "File: <" << filename << ">, failed at sending filename, attempt <" << iteration + 1 << ">\n";
        return false;
    }
    
    // Send filename's Sha1
    unsigned char obuf[20];
    SHA1((unsigned char*)filename.c_str(), filenameSize, obuf);
    sock.write((const char*)obuf, 21);

    // Check filename's SHA1 sent successfully
    if (!ServerRESCheck(sock, iteration)){
        *GRADING << "File: <" << filename << ">, failed at sending SHA1 for filename, attempt <" << iteration + 1 << ">\n";
        return false;
    }
    if (!ServerRESCheck(sock, iteration)){
        *GRADING << "File: <" << filename << ">, failed at matching SHA1 for filename, attempt <" << iteration + 1 << ">\n";
        return false;
    }

    // Send Size 
    string sizeField = to_string(file.contentSize); 
    ssize_t contentSize = strlen(sizeField.c_str());
    sock.write((const char*)sizeField.c_str(), contentSize);

    // Check Size sent successfully
    if (!ServerRESCheck(sock, iteration)){
        *GRADING << "File: <" << filename << ">, failed at sending size of file, attempt <" << iteration + 1 << ">\n";
        return false;
    }

    // send SHA1
    sock.write((const char*)file.fileSHA1, 21);

    // check SHA1 sent successfully
    if (!ServerRESCheck(sock, iteration)){
        *GRADING << "File: <" << filename << ">, failed at sending SHA1 for file's content, attempt <" << iteration + 1 << ">\n";
        return false;
    }
    
    // send Content 
    ssize_t ByteSent = 0;
    int sendtimes = 0;
    ssize_t CurByteSent = 0;
    while (ByteSent < file.contentSize){
        if (sendtimes == 10){
            unsigned char pobuf[20];
            SHA1((const unsigned char*)(file.contentbuf + ByteSent - CurByteSent), CurByteSent, pobuf);
            sock.write((const char*)pobuf, 21);
            if (!ServerRESCheck(sock, iteration)){return false;}
            if (!ServerRESCheck(sock, iteration)){return false;}
            CurByteSent = 0;
            sendtimes = 0;
        }
        if (ByteSent + WRITESIZE > file.contentSize){
            sock.write((const char*)(file.contentbuf + ByteSent), file.contentSize - ByteSent);
            CurByteSent += file.contentSize - ByteSent;
            ByteSent += file.contentSize - ByteSent;
        }else{
            sock.write((const char*)(file.contentbuf + ByteSent), WRITESIZE);
            CurByteSent += WRITESIZE;
            ByteSent += WRITESIZE;
        }
        sendtimes++;
    }

    // check Content sent successfully
    if (!ServerRESCheck(sock, iteration)){
        *GRADING << "File: <" << filename << ">, failed at sending file's content, attempt <" << iteration + 1 << ">\n";
        return false;
    }

    // check size is equal
    if (!ServerRESCheck(sock, iteration)){
        *GRADING << "File: <" << filename << ">, failed at matching file's size, attempt <" << iteration + 1 << ">\n";
        return false;
    }
    
    // check sha1 is equal
    if (!ServerRESCheck(sock, iteration)){
        *GRADING << "File: <" << filename << ">, failed at matching SHA1 for file's content, attempt <" << iteration + 1 << ">\n";
        return false;
    }
    
    *GRADING << "File: <" << filename << ">, transmission complete, waiting for end-to-end check, attempt <" << iteration + 1 << ">\n";
    return true;
}

/* * * * * *  * * * * * * * * * *  NETWORK SERVER FUNCTIONS  * * * * * * * * * * * * * * * */
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
    sock.write(ACK, strlen(ACK));
    return true;
    
}

/* compareSHA1 
 * purpose: compare the receivedSHA1 and calculatedSHA1 byte by byte 
 * parameter: 
 * return: True if every byte match, False if any byte does not match
 */
bool 
compareSHA1(unsigned char** receivedSHA1, unsigned char** calculateSHA1)
{
    for (int j = 0; j < 20; j++) {
        if ((*receivedSHA1)[j] != (*calculateSHA1)[j])
            return false;
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
    ssize_t totalBytes = 0;
    ssize_t chunk = 0;
    ssize_t curBytes = 0;
    unsigned char* temporaryBuf = (unsigned char*)malloc(contentlen * sizeof(unsigned char));
    int readtimes = 0;
    while(totalBytes != contentlen) { /* read until all bytes from sockets are received */
        if (readtimes == 10){
            unsigned char* temp = (unsigned char*)malloc(curBytes * sizeof(unsigned char));
            bzero(temp, curBytes); /* zero out the field */
            int index = 0;
            for (unsigned int i = totalBytes - curBytes; i < totalBytes; i++) {
                *(temp + index) = allFileContent.at(i); 
                index++;
            }
            unsigned char *pobuf = (unsigned char*) malloc(SHA_MSG * sizeof(unsigned char));
            SHA1((const unsigned char*)temp, curBytes, pobuf);
            char *partialSHA1 = (char*)malloc(SHA_MSG * sizeof(char));
            if (!readSizefromSocket(sock, SHA_MSG, &partialSHA1)){
                return false;
            } 
            unsigned char *partialSHA1dup = (unsigned char*)malloc(SHA_MSG * sizeof(unsigned char)); 
            bzero(partialSHA1dup, 20);
            for (int j = 0; j < 20; j++){ 
                partialSHA1dup[j] = (unsigned char)partialSHA1[j];
            }
            if (!compareSHA1(&pobuf, &partialSHA1dup)) {
                *GRADING << "The received <" << "> bytes SHA1 do not match, requesting resend." << endl;
                sock.write(REJ, strlen(REJ));
                return false;
            } else {
                sock.write(ACK, strlen(ACK));
            }
            readtimes = 0;
            curBytes = 0;
            free(temp);
            free(pobuf);
            free(partialSHA1);
            free(partialSHA1dup);
        }
        chunk = sock.read((char *)temporaryBuf, BUFSIZE);
        for (ssize_t t = 0; t < chunk; t += sizeof(unsigned char)) {
            /* put read bytes into dynamically expanding memories */
            allFileContent.push_back(*(temporaryBuf + t)); }
        bzero(temporaryBuf, chunk); /* clean up the buf for next read */  
        curBytes += chunk;
        totalBytes += chunk;
        readtimes++;
        if (sock.timedout()){
            printf("oops timed out.\n");
            sock.write(REJ, strlen(REJ));
            return false;
        }
    }
    /* evaluate conditions to send ACK */
    if (!sock.timedout()){ /* confirm entire read for content */
        sock.write(ACK, strlen(ACK));
    }else{
        sock.write(REJ, strlen(REJ));
        return false;
    }
    /* compare total received bytes with received contentlen field */
    if (totalBytes == contentlen){
        sock.write(ACK, strlen(ACK));
    } else {
        sock.write(REJ, strlen(REJ));
        return false;
    }

    /* calculate SHA1 of the received content bytes */
    unsigned char* prod = (unsigned char*)malloc((allFileContent.size())*sizeof(unsigned char));
    bzero(prod, allFileContent.size()); /* zero out the field */
    for (unsigned int i = 0; i < allFileContent.size(); i ++) {
        *(prod + i) = allFileContent.at(i); 
    }
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
    /* 2ACK-receive filename from client */
    char *filename = (char*)malloc(BUFSIZE * sizeof(char));
    if (!readSizefromSocket(sock, BUFSIZE, &filename)){
        return false;
    } 
    string filename_str(filename); /* convert read characteres back to string */
    *GRADING << "File: <" << filename_str << "> starting to receive file." << endl;
    unsigned char *shabuf = (unsigned char*) malloc(SHA_MSG * sizeof(unsigned char));
    SHA1((unsigned char*)filename_str.c_str(), strlen(filename_str.c_str()), shabuf);

    /* 3ACK-receive filename SHA1 from client */
    char *filenameSHA1 = (char*)malloc(SHA_MSG * sizeof(char));
    if (!readSizefromSocket(sock, SHA_MSG, &filenameSHA1)){
        *GRADING << "File: <" << filename_str << "> failed at socket to socket end-to-end check forreceiving filename." << endl;
        return false;
    } 
    
    /* 4ACK-check consistency in received and calculated filename SHA1 */
    unsigned char *FileSHA1dup = (unsigned char*)malloc(SHA_MSG * sizeof(unsigned char)); 
    for (int j = 0; j < 20; j++){ 
        FileSHA1dup[j] = (unsigned char)filenameSHA1[j];
    }
    if (!compareSHA1(&shabuf, &FileSHA1dup)) {
        *GRADING << "File: <" << filename_str << "> failed at socket to socket end-to-end check for inconsistency in received and calculated filename SHA1." << endl;
        sock.write(REJ, strlen(REJ));
        return false;
    } else {
        sock.write(ACK, strlen(ACK));
        *GRADING << "File: <" << filename_str << "> succeed at socket to socket end-to-end check for consistency in received and calculated filename SHA1." << endl;
    }
    
    /* 5ACK-receive content size from client */ 
    char *sizeMsg = (char*)malloc(CONTENT_SIZE * sizeof(char));
    if (!readSizefromSocket(sock, CONTENT_SIZE, &sizeMsg)){
        *GRADING << "File: <" << filename_str << "> failed at socket to socket end-to-end check for failing to receive contents from client." << endl;
        return false;
    }

    /* 6ACK-receive content SHA1 from client */
    char *SHA1Msg = (char*)malloc(SHA_MSG * sizeof(char));
    if (!readSizefromSocket(sock, SHA_MSG, &SHA1Msg)){ 
        *GRADING << "File: <" << filename_str << "> failed at socket to socket check for failing to receive contents SHA1 from client." << endl;
        return false;
    }
    unsigned char *SHA1dup = (unsigned char*)malloc(SHA_MSG * sizeof(char));
    bzero(SHA1dup, 20);
    for (int j = 0; j < 20; j++){ /* casting received SHA1 */
        SHA1dup[j] = (unsigned char)SHA1Msg[j];
    }
    free(SHA1Msg);
    /* 7ACK-receive content from client */
    /* 8ACK-receive correct size from client*/
    string size(sizeMsg); /* convert content sizeMsg to integer representation */
    int contentlen = atoi(size.c_str());
    unsigned char* prod = nullptr;
    if (!readContentfromSocket(sock, contentlen, &prod)){
        /* unsuccessful read of the entire content */
        *GRADING << "File: <" << filename_str << "> failed at socket to socket check for failing to receive contents from client." << endl;
        free(prod);
        return false;
    }
    *GRADING << "File: <" << filename_str << "> succeed at socket to socket check with receiving the entire content." << endl;
    unsigned char *obuf = (unsigned char*)malloc(SHA_MSG * sizeof(unsigned char));
    SHA1((const unsigned char *)prod, contentlen, obuf);

    /*9ACK-check consistency in received and calculated SHA1 to client */
    if (!compareSHA1(&obuf, &SHA1dup)) {
        sock.write(REJ, strlen(REJ));
        *GRADING << "File: <" << filename_str << "> socket to socket failed at inconsistency in received and calculated content SHA1." << endl;
        return false;
    }
    sock.write(ACK, strlen(ACK)); /* log for purpose of recording failure caused by network nastiness */
    *GRADING << "File: <" << filename_str << ">  succeed at socket to socket check with consistency in size and SHA1 of the content." << endl;
    fileProp file_unit = fileProp(filename_str, SHA1dup, contentlen, prod);
    allArrivedFiles.push_back(file_unit);
    free(obuf);
    free(prod);
    free(SHA1dup);
    free(sizeMsg);
    free(FileSHA1dup);
    free(filenameSHA1);
    free(shabuf);
    *GRADING << "File: <" << filename_str << "> socket to socket end-to-end check succeeded." << endl;
    return true;
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
