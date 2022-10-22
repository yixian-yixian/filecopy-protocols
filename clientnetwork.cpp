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

bool ServerRESCheck(C150DgmSocket& sock, vector<Packet_ptr>* curFileCont);
bool sendtoTar(C150DgmSocket& sock, fileProp& file);
void printSHA1(unsigned char *partialSHA1dup);

void 
FileSendE2ECheck(C150DgmSocket& sock, vector<fileProp>& allFilesProp, vector<string>& filenames)
{
    // if one file fails more than 3 times, give up
    for (long unsigned int index = 0; index < allFilesProp.size(); index++)
    {
        *GRADING << "File: <" << filenames.at(index) << ">, beginning transmission, attempt <0>\n";
        sendtoTar(sock, allFilesProp.at(index));
        *GRADING << "File: <" << filenames.at(index) << "> transmission complete, waiting for end-to-end check, attempt <0>\n";
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
ServerRESCheck(C150DgmSocket& sock, vector<Packet_ptr>* curFileCont)
{
    unsigned char *response = (unsigned char*) malloc(sizeof(struct Packet)); 
    sock.read((char*)response, sizeof(struct Packet));

    if (sock.timedout()){
        return false;
    }else{
        Packet_ptr pktRes = (Packet_ptr) malloc(sizeof(struct Packet));
        memcpy((void *)pktRes, response, sizeof(struct Packet));
        free(response);
        if (pktRes->packet_status == LAST_PACK){
            sock.write((const char*) (curFileCont->at(curFileCont->size()-1)), sizeof(struct Packet));
            return false;
        }else if (pktRes->packet_status == MISS_FILE){
            size_t missingIndex = pktRes->seqNum;
            sock.write((const char*) (curFileCont->at(missingIndex)), sizeof(struct Packet));
            return false;
        }else if (pktRes->packet_status == FILENAME_P){
            sock.write((const char*) (curFileCont->at(0)), sizeof(struct Packet));
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
sendtoTar(C150DgmSocket& sock, fileProp& file)
{
    // Wrap file info into a header
    cout << "start sending file[" << file.filename << "]\n";
    vector<Packet_ptr>* curFileCont = file.fileContent;
    // Send the header to server
    for (long unsigned int index = 0; index < curFileCont->size(); index++){
        cout << "Sending packet num[" << index << "]\n";
        sock.write((const char*) (curFileCont->at(index)), sizeof(struct Packet));
    }
    cout << "finished sending all packets of file[" << file.filename << "] once\n";
    cout << "start checking and resending missing packets of file[" << file.filename << "]\n";
    clock_t start_t, end_t;
    start_t = clock();
    // Check if the header is sent successfully and whether the filenameSha1 matches
    while(!ServerRESCheck(sock, curFileCont)){        
        end_t = clock();
        if ((double(end_t - start_t) / CLOCKS_PER_SEC) > 30){ /* maximum 10 minutes span for retry */
            printf("have waiting over 30 seconds\n");
            break;
        }
    }
    cout << "finished checking and resending missing packets of file[" << file.filename << "]\n";
    // *GRADING << "File: <" << filename << ">, failed at sending filename, attempt <" << iteration + 1 << ">\n";
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