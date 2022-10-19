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

typedef struct header_info{
    unsigned char filenameSHA1[20];
    unsigned char contentSHA1[20];
    char filename_str[256]; // no filename can have length higher than 255
    size_t contentSize;
    size_t status;
} *Socket_Header;


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
formatRequestBuf(fileProp& singleFile, unsigned char **requestBuf, bool lastfile)
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
    strcpy(header->filename_str, (const char*)singleFile.filename.c_str());
    if (lastfile){ header->status = 1;}
    else{ header->status = 0;}
    // copy information into sending buffer
    *requestBuf = (unsigned char *)malloc(sizeof(*header) * sizeof(unsigned char));
    cerr << "before memcpy information "<< endl;
    memcpy(*requestBuf, header, sizeof(struct header_info));
        cout << "filename ";
    printSHA1(header->filenameSHA1);
        cout << "file content ";
    printSHA1(header->contentSHA1);
    free(header);
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
    // // Wrap file info into a header
    // unsigned char* headInfo;
    // formatRequestBuf(file, &headInfo, lastfile);

    // // Send the header to server
    // sock.write((const char*)headInfo, sizeof(struct header_info));
    // free(headInfo);

    // // Check if the header is sent successfully and whether the filenameSha1 matches
    // if (!ServerRESCheck(sock, iteration)){
    //     *GRADING << "File: <" << filename << ">, failed at sending filename, attempt <" << iteration + 1 << ">\n";
    //     return false;
    // }
    
    // // send Content 
    // ssize_t ByteSent = 0;
    // int sendtimes = 0;
    // ssize_t CurByteSent = 0;
    // unsigned retryNum = 0;
    // while (ByteSent < file.contentSize){
    //     if (sendtimes == 10){
    //         unsigned char pobuf[20];
    //         SHA1((const unsigned char*)(file.contentbuf + ByteSent - CurByteSent), CurByteSent, pobuf);
    //         sock.write((const char*)pobuf, 20);
    //         if (!ServerRESCheck(sock, retryNum)) {
    //             // if (retryNum != 50){
    //             //     ByteSent -= CurByteSent;
    //             //     CurByteSent = 0;
    //             //     sendtimes = 0;
    //             //     continue;
    //             // }
    //             retryNum = 0;
    //             return false;
    //         }
    //         CurByteSent = 0;
    //         sendtimes = 0;
    //     }
    //     if (ByteSent + WRITESIZE > file.contentSize){
    //         sock.write((const char*)(file.contentbuf + ByteSent), file.contentSize - ByteSent);
    //         CurByteSent += file.contentSize - ByteSent;
    //         ByteSent += file.contentSize - ByteSent;
    //     }else{
    //         sock.write((const char*)(file.contentbuf + ByteSent), WRITESIZE);
    //         CurByteSent += WRITESIZE;
    //         ByteSent += WRITESIZE;
    //     }
    //     sendtimes++;
    // }
    
    // // check sha1 is equal
    // if (!ServerRESCheck(sock, iteration)){
    //     *GRADING << "File: <" << filename << ">, failed at matching SHA1 for file's content, attempt <" << iteration + 1 << ">\n";
    //     return false;
    // }
    
    // *GRADING << "File: <" << filename << ">, transmission complete, waiting for end-to-end check, attempt <" << iteration + 1 << ">\n";
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