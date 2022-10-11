#include "networkendtoend.h"

#define ACK "ACK"
#define REJ "REJ"
#define LAST "LAST"
#define CONT "CONT"
#define BUFSIZE 512
#define READSIZE 1024
#define MAXTIME 30000
#define STATUS 4
#define SHA_MSG 20
#define CONTENT_SIZE 512
#define UPPERBOUND 1000000
using namespace std;
using namespace C150NETWORK;  // for all the comp150 utilities


// ------------------------------------------------------
//
//                   isFile
//
//  Make sure the supplied file is not a directory or
//  other non-regular file.
//     
// ------------------------------------------------------

bool
isFile(string fname) {
  const char *filename = fname.c_str();
  struct stat statbuf;  
  if (lstat(filename, &statbuf) != 0) {
    fprintf(stderr,"isFile: Error stating supplied source file %s\n", filename);
    return false;
  }

  if (!S_ISREG(statbuf.st_mode)) {
    fprintf(stderr,"isFile: %s exists but is not a regular file\n", filename);
    return false;
  }
  return true;
}


// ------------------------------------------------------
//
//                   copyFile
//
// Copy a single file from sourcdir to target dir
//
// ------------------------------------------------------

void
copyFile(string sourceDir, string fileName, string targetDir, int nastiness) {

  //  Misc variables, mostly for return codes
  void *fopenretval;
  size_t len;
  string errorString;
  char *buffer;
  struct stat statbuf;  
  size_t sourceSize;

  // Put together directory and filenames SRC/file TARGET/file
  string sourceName = makeFileName(sourceDir, fileName);
  string targetName = makeFileName(targetDir, fileName);

  // make sure the file we're copying is not a directory
  if (!isFile(sourceName)) {
    cerr << "Input file " << sourceName << " is a directory or other non-regular file. Skipping" << endl;
    return;
  }

  cout << "Copying " << sourceName << " to " << targetName << endl;

  try {

    // Read whole input file 
    if (lstat(sourceName.c_str(), &statbuf) != 0) {
      fprintf(stderr,"copyFile: Error stating supplied source file %s\n", sourceName.c_str());
     exit(20);
    }
  
    // Make an input buffer large enough for
    // the whole file
    sourceSize = statbuf.st_size;
    buffer = (char *)malloc(sourceSize);

    // Define the wrapped file descriptors
    //
    // All the operations on outputFile are the same
    // ones you get documented by doing "man 3 fread", etc.
    // except that the file descriptor arguments must
    // be left off.
    //
    // Note: the NASTYFILE type is meant to be similar
    //       to the Unix FILE type
    NASTYFILE inputFile(nastiness);      // See c150nastyfile.h for interface
    NASTYFILE outputFile(nastiness);     // NASTYFILE is supposed to
                                         // remind you of FILE
                                         //  It's defined as: 
                                         // typedef C150NastyFile NASTYFILE
  
    // do an fopen on the input file
    fopenretval = inputFile.fopen(sourceName.c_str(), "rb");  
                                         // wraps Unix fopen
                                         // Note rb gives "read, binary"
                                         // which avoids line end munging
  
    if (fopenretval == NULL) {
      cerr << "Error opening input file " << sourceName << 
	      " errno=" << strerror(errno) << endl;
      exit(12);
    }
  
    // Read the whole file
    len = inputFile.fread(buffer, 1, sourceSize);
    if (len != sourceSize) {
      cerr << "Error reading file " << sourceName << 
	      "  errno=" << strerror(errno) << endl;
      exit(16);
    }
  
    if (inputFile.fclose() != 0 ) {
      cerr << "Error closing input file " << targetName << 
	      " errno=" << strerror(errno) << endl;
      exit(16);
    }


    // do an fopen on the output file
    fopenretval = outputFile.fopen(targetName.c_str(), "wb");  
                                         // wraps Unix fopen
                                         // Note wb gives "write, binary"
                                         // which avoids line and munging
  
    // Write the whole file
    len = outputFile.fwrite(buffer, 1, sourceSize);
    if (len != sourceSize) {
      cerr << "Error writing file " << targetName << 
	      "  errno=" << strerror(errno) << endl;
      exit(16);
    }
  
    if (outputFile.fclose() == 0 ) {
       cout << "Finished writing file " << targetName <<endl;
    } else {
      cerr << "Error closing output file " << targetName << 
	      " errno=" << strerror(errno) << endl;
      exit(16);
    }

    // Free the input buffer to avoid memory leaks
    free(buffer);

    // Handle any errors thrown by the file framekwork
  }   catch (C150Exception& e) {
       cerr << "nastyfiletest:copyfile(): Caught C150Exception: " << 
	       e.formattedExplanation() << endl;
    
  }
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
    // Send status
    if (lastfile){
        sock.write(LAST, strlen(LAST));
    }else{
        sock.write(CONT, strlen(CONT));
    }
    
    // check status sent successfully
    if (!ServerRESCheck(sock, iteration)){return false;}

    // Send filename 
    ssize_t filenameSize = strlen(filename.c_str());
    sock.write((const char*)filename.c_str(), filenameSize+1);
    // Check filename sent successfully
    if (!ServerRESCheck(sock, iteration)){return false;}
    
    // Send filename's Sha1
    unsigned char obuf[20];
    SHA1((unsigned char*)filename.c_str(), filenameSize, obuf);
    sock.write((const char*)obuf, 21);

    // Check filename's SHA1 sent successfully
    if (!ServerRESCheck(sock, iteration)){return false;}
    if (!ServerRESCheck(sock, iteration)){return false;}

    // Send Size 
    string sizeField = to_string(file.contentSize); 
    ssize_t contentSize = strlen(sizeField.c_str());
    sock.write((const char*)sizeField.c_str(), contentSize);

    // Check Size sent successfully
    if (!ServerRESCheck(sock, iteration)){return false;}
    
    // send SHA1
    sock.write((const char*)file.fileSHA1, 21);

    // check SHA1 sent successfully
    if (!ServerRESCheck(sock, iteration)){return false;}
    
    // send Content 
    ssize_t ByteSent = 0; 
    while (ByteSent < file.contentSize){
        if (ByteSent + BUFSIZE > file.contentSize){
            sock.write((const char*)(file.contentbuf + ByteSent), file.contentSize - ByteSent);
        }else{
            sock.write((const char*)(file.contentbuf + ByteSent), BUFSIZE);
        }
        ByteSent += BUFSIZE;
    }

    // check Content sent successfully
    // check size is equal
    // check sha1 is equal
    for (int i = 0; i < 3; i++){
        if (!ServerRESCheck(sock, iteration)){return false;}
    }
    return true;
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
    ssize_t totalBytes = 0, chunk = 0;;
    unsigned char* temporaryBuf = (unsigned char*)malloc(contentlen * sizeof(unsigned char));
    while(1) { /* read until all bytes from sockets are received */
        chunk = sock.read((char *)temporaryBuf, READSIZE);
        for (ssize_t t = 0; t < chunk; t += sizeof(unsigned char)) {
            /* put read bytes into dynamically expanding memories */
            allFileContent.push_back(*(temporaryBuf + t)); }
        bzero(temporaryBuf, chunk); /* clean up the buf for next read */  
        totalBytes += chunk;
        if (totalBytes == contentlen){break;}
        if (sock.timedout()){
            sock.write(REJ, strlen(REJ));
            return false; }
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
    /* 1ACK-receive status message from client */ 
    char *statusMsg = (char *)malloc(STATUS * sizeof(char));
    if (!readSizefromSocket(sock, STATUS, &statusMsg)){
        return false;
    } 

    /* 2ACK-receive filename from client */
    char *filename = (char*)malloc(BUFSIZE * sizeof(char));
    if (!readSizefromSocket(sock, BUFSIZE, &filename)){
        return false;
    } 
    string filename_str(filename); /* convert read characteres back to string */
    unsigned char *shabuf = (unsigned char*) malloc(SHA_MSG * sizeof(unsigned char));
    SHA1((unsigned char*)filename_str.c_str(), strlen(filename_str.c_str()), shabuf);

    /* 3ACK-receive filename SHA1 from client */
    char *filenameSHA1 = (char*)malloc(SHA_MSG * sizeof(char));
    if (!readSizefromSocket(sock, SHA_MSG, &filenameSHA1)){
        return false;
    } 
    
    /* 4ACK-check consistency in received and calculated filename SHA1 */
    unsigned char *FileSHA1dup = (unsigned char*)malloc(SHA_MSG * sizeof(unsigned char)); 
    for (int j = 0; j < 20; j++){ 
        FileSHA1dup[j] = (unsigned char)filenameSHA1[j];
    }
    if (!compareSHA1(&shabuf, &FileSHA1dup)) {
        sock.write(REJ, strlen(REJ));
        return false;
    } else {
        sock.write(ACK, strlen(ACK));
    }
    
    /* 5ACK-receive content size from client */ 
    char *sizeMsg = (char*)malloc(CONTENT_SIZE * sizeof(char));
    if (!readSizefromSocket(sock, CONTENT_SIZE, &sizeMsg)){return false;}

    /* 6ACK-receive content SHA1 from client */
    char *SHA1Msg = (char*)malloc(SHA_MSG * sizeof(char));
    if (!readSizefromSocket(sock, SHA_MSG, &SHA1Msg)){ 
        return false;
    }
    unsigned char *SHA1dup = (unsigned char*)malloc(SHA_MSG * sizeof(char));
    bzero(SHA1dup, 20);
    for (int j = 0; j < 20; j++){ 
        SHA1dup[j] = (unsigned char)SHA1Msg[j];
    }
    /* 7ACK-receive content from client */
    /* 8ACK-receive correct size from client*/
    string size(sizeMsg); /* convert content sizeMsg to integer representation */
    int contentlen = atoi(size.c_str());
    unsigned char* prod = nullptr;
    if (!readContentfromSocket(sock, contentlen, &prod)){
        /* unsuccessful read of the entire content */
        free(prod);
        return false;
    };

    unsigned char *obuf = (unsigned char*)malloc(SHA_MSG * sizeof(unsigned char));
    SHA1((const unsigned char *)prod, contentlen, obuf);

    /*9ACK-check consistency in received and calculated SHA1 to client */
    if (!compareSHA1(&obuf, &SHA1dup)) {
        sock.write(REJ, strlen(REJ));
        return false;
    }
    sock.write(ACK, strlen(ACK));
    string status(statusMsg);
    fileProp file_unit = fileProp(filename_str, SHA1dup, contentlen, prod);
    allArrivedFiles.push_back(file_unit);
    return (status == LAST) ? true : false;
}

void 
FileSendE2ECheck(C150DgmSocket& sock, vector<fileProp>& allFilesProp, vector<string>& filenames)
{
    // if one file fails more than 3 times, give up
    long unsigned int index = 0;
    unsigned iteration = 0;
    bool lastfile = false;
    while (index < allFilesProp.size())
    {
        printf("currently sending to socket\n");
        if (index == allFilesProp.size() - 1){lastfile = true;}
        if (iteration < 10){
            if (!sendtoTar(sock, allFilesProp.at(index), iteration, lastfile, filenames.at(index))){continue;}
        }
        index++;
        iteration = 0;
    }
    printf("sending complete\n");
}

void 
FileReceiveE2ECheck(C150DgmSocket& sock, vector<fileProp>& allArrivedFiles)
{
    sock.turnOnTimeouts(MAXTIME);/* each file should be received within the same time period */
    printf("inside file receive e2e check\n");
    while (1){
        printf("currently reading from socket\n");
        if (readfromSrc(sock, allArrivedFiles)) break;
        printf("not last message\n");
    }
    printf("last message\n");
    printf("totally read %ld files", allArrivedFiles.size());
}
