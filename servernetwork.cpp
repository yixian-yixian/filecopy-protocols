#include "servernetwork.h"

#define PACKET_SIZE 490
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
bool recv_one_file(C150DgmSocket& sock, size_t curr_file_index, vector<string> all_file_names, unordered_map<size_t, Packet_ptr>& one_file_contents);
bool readSizefromSocket(C150DgmSocket& sock, size_t bytestoRead, char** bytes_storage);
bool read_one_packet(C150DgmSocket& sock, size_t curr_file_index, bool& endpacketfound, size_t& maximum_packets, unordered_map<size_t, Packet_ptr>& one_file_contents, vector<string>& all_File_names);
void resend_confirmation(C150DgmSocket& sock, size_t curr_file_index);
Packet_ptr unpack_packet(unsigned char *receivedBuf);

/* * * * * *  * * * * * * * * * *  NETWORK SERVER FUNCTIONS  * * * * * * * * * * * * * * * */

bool
read_Start(C150DgmSocket& sock)
{
    bool startRcv = false;
    char *receivedBuf = (char *)malloc(sizeof(struct Packet));
    while(!startRcv){
        cerr << "START RECV loop\n";
        bzero(receivedBuf, sizeof(struct Packet));
        startRcv = readSizefromSocket(sock, BUFSIZE, &receivedBuf) ? false : true;
    }
    return startRcv;
}

void 
FileReceiveE2ECheck(C150DgmSocket& sock, int filenastiness, string tardir)
{
    *GRADING << "Begining to receive whole files from client." << endl; 
    unordered_set<uint32_t> all_files_arrived;
    vector<string> all_file_names;
    size_t curr_sequence_number = 0;
    char *recv_complete_confirmation =  (char *)malloc(BUFSIZE);
    read_Start(sock);
    while(1) {
        cerr << "RECV: starting to receive one packet\n";
        unordered_map<size_t, Packet_ptr> curr_file_contents;
        if (recv_one_file(sock, curr_sequence_number, all_file_names, curr_file_contents)) {
            printf("completely read a file \n");
            /* completely received the whole file */
        }
        curr_sequence_number++;
        Packet_ptr confirm = (Packet_ptr) malloc(sizeof(struct Packet));
        readSizefromSocket(sock, BUFSIZE, &recv_complete_confirmation); 
        memcpy((void *)confirm, (void *)recv_complete_confirmation, BUFSIZE);
        if (confirm->packet_status == COMPLETE) break;
    }  
    *GRADING << "Received and successfully read a total of " << all_file_names.size() << " files from client." << endl;
}

bool 
check_completeness(C150DgmSocket& sock, unordered_map<size_t, Packet_ptr>& all_file_contents, size_t& total_packets, vector<size_t>& missing_packets)
{
    *GRADING << "TOTAL packet " << total_packets << endl;
    *GRADING << "ALL file content size " << all_file_contents.size() << endl;
    bool found_file_name = false;
    unordered_set<size_t> seen_sequence;
    size_t pop = 0;
    /* populate a hashset to check for missing packets */
    while (pop < total_packets) {
        // cerr << "SEEN_SEQ added " << pop << endl;
        seen_sequence.insert(pop);
        pop += 1;
    }
    /* iterate through unorder_map to check for missing packet */
    for(auto& information : all_file_contents) {
        size_t found_seq = information.first;
        /* check if file name is found */
        // cerr << "SEQ is " << found_seq << " \n";
        if (information.second->packet_status == FILENAME_P){
            found_file_name = true; }
        seen_sequence.erase(seen_sequence.find(found_seq));
    }
    /* populate missing packets into array */
    if (seen_sequence.size() == 0 && !found_file_name) {
        Packet_ptr missing_filename = (Packet_ptr)calloc(sizeof(struct Packet), 1);
        missing_filename->packet_status = FILENAME_P;
        sock.write((const char*)missing_filename, sizeof(struct Packet));
        return true;
    } 
    missing_packets.insert(missing_packets.end(), seen_sequence.begin(), seen_sequence.end());
    return false;

    
}


// return true if timeout, false if not
bool 
read_one_packet(C150DgmSocket& sock, size_t curr_file_index, bool& endpacketfound, size_t& maximum_packets, unordered_map<size_t, Packet_ptr>& one_file_contents, vector<string>& all_File_names)
{
    bool is_timed_out = false;
    char filename[250];
    char *receivedBuf = (char *)malloc(sizeof(struct Packet));
    is_timed_out = readSizefromSocket(sock, BUFSIZE, &receivedBuf);
    if (is_timed_out) return true;
    
    Packet_ptr part_packet = unpack_packet((unsigned char*)receivedBuf);
    // mod status by 10, if 2, push it to allfilenames, if not 2, push it to onefilecontents
    if (part_packet->packet_status / 10 == curr_file_index) {
        /* check if packets belongs to current file */
        if (part_packet->packet_status % 10 == FILENAME_P){
            /* TODO make sure null character are placed at the content end */
            strcpy(filename, (const char*) part_packet->content);
            printf("RECV one file name \n");
            all_File_names.push_back(string(filename));
            cout << "The file we read is: "<< filename << endl;
        } else if (part_packet->packet_status % 10 == LAST_PACK){
            endpacketfound = true;
            maximum_packets = part_packet->seqNum + 1;
            cerr << "LAST packet recv\n";
            one_file_contents[part_packet->seqNum] = part_packet;
        } else{
            cerr << "REGULAR packet recv\n";
            auto it = one_file_contents.find(part_packet->seqNum);
            if (it == one_file_contents.end()){
                one_file_contents[part_packet->seqNum] = part_packet;
            }
        } 
    }
    
    return is_timed_out;
}


void 
write_missing_packets(C150DgmSocket& sock, vector<size_t>& missing_packets)
{
    cerr << "MISSING: write back to client!\n";
    Packet_ptr missing_notice = (Packet_ptr)malloc(sizeof(struct Packet));
    for (auto& packet: missing_packets) {
        cerr << "MISSING " << packet << endl;
        missing_notice->seqNum = packet + 1;
        missing_notice->packet_status = MISS_FILE;
        sock.write((const char*)missing_notice, sizeof(struct Packet));
        bzero(missing_notice, sizeof(struct Packet));
    } 
}




bool 
recv_one_file(C150DgmSocket& sock, size_t curr_file_index, vector<string> all_file_names, unordered_map<size_t, Packet_ptr>& one_file_contents)
{
    clock_t start_t, end_t;
    start_t = clock();
    // char filename[256];
    bool endpacketfound = false;
    bool is_timed_out = false, recv_complete = false;
    size_t maximum_packets;
    while (1) {
        is_timed_out = read_one_packet(sock, curr_file_index, endpacketfound, maximum_packets, one_file_contents, all_file_names); 
        end_t = clock();
        if ((double(end_t - start_t) / CLOCKS_PER_SEC) > 30){ /* maximum 10 minutes span for retry */
            printf("have waiting over 30 seconds\n");
            break; }
        if (is_timed_out){
            if (!endpacketfound) {
                // TODO send to client resent end packet 
                printf("MISS: end packet was not received \n");
                Packet_ptr missing_notice = (Packet_ptr) calloc(sizeof(struct Packet), 1);
                missing_notice->packet_status = LAST_PACK;
                sock.write((const char*)missing_notice, sizeof(struct Packet));
                free(missing_notice);
                cout << "successfully send request for last packet\n";
            } else {
                vector<size_t> missing_packets_seq;
                if (check_completeness(sock, one_file_contents, maximum_packets, missing_packets_seq)) {
                    recv_complete = true;
                    break;} 
                write_missing_packets(sock, missing_packets_seq);
            }
        }
    }
    resend_confirmation(sock, curr_file_index);
    return recv_complete;
}


void
resend_confirmation(C150DgmSocket& sock, size_t curr_file_index){
    Packet_ptr complete_notice = (Packet_ptr)calloc(sizeof(struct Packet), 1);
    complete_notice->packet_status = COMPLETE;
    bool good_to_go = false;
    char *receivedBuf = (char *)malloc(sizeof(struct Packet));
    while(!good_to_go) {
        sock.write((const char*)complete_notice, sizeof(struct Packet));
        cerr << "START RESEND loop\n";
        bzero(receivedBuf, sizeof(struct Packet));
        bool succ_read = readSizefromSocket(sock, BUFSIZE, &receivedBuf);
        if (!succ_read){
            complete_notice = unpack_packet((unsigned char*)receivedBuf);
            if (complete_notice->packet_status / 10 > curr_file_index){
                good_to_go = true;
            }
        }
    }
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
    if (sock.timedout()) { 
        return true;
    }
    return false;
}



// sequence number represent the order of packets in file
Packet_ptr 
unpack_packet(unsigned char *receivedBuf)
{
    Packet_ptr curr_packet = (Packet_ptr)malloc(sizeof(struct Packet));
    bzero(curr_packet, sizeof(struct Packet));
    /* cast one packet to better understand it */
    memcpy((void *)curr_packet, (void *)receivedBuf, BUFSIZE);
    cerr << "UNPACK seq [" << curr_packet->seqNum << "] \n";
    cerr << "UNPACK packetStatus [" << curr_packet->packet_status << "] \n";
    return curr_packet;
}





// /* Helper function for viewing SHA1 */
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
