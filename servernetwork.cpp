#include "servernetwork.h"
#include "localendtoend.h"


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
bool recv_one_file(C150DgmSocket& sock, size_t curr_file_index, vector<string>& all_file_names, unordered_map<size_t, Packet_ptr>& one_file_contents, uint32_t& total_file, size_t& last_pkt_bytes);
bool readSizefromSocket(C150DgmSocket& sock, size_t bytestoRead, char** bytes_storage);
bool read_one_packet(C150DgmSocket& sock, size_t curr_file_index, bool& endpacketfound, size_t& maximum_packets, unordered_map<size_t, Packet_ptr>& one_file_contents, vector<string>& all_File_names, size_t& last_pkt_bytes, bool& namepktfound);
void resend_confirmation(C150DgmSocket& sock, size_t curr_file_index, size_t total_file);
Packet_ptr unpack_packet(unsigned char *receivedBuf);
bool check_completeness(C150DgmSocket& sock, unordered_map<size_t, Packet_ptr>& all_file_contents, size_t& total_packets, vector<size_t>& missing_packets);

/* * * * * *  * * * * * * * * * *  NETWORK SERVER FUNCTIONS  * * * * * * * * * * * * * * * */

bool
read_Start(C150DgmSocket& sock)
{
    bool startRcv = false;
    char *receivedBuf = (char *)malloc(sizeof(struct Packet));
    while(!startRcv){
        bzero(receivedBuf, sizeof(struct Packet));
        startRcv = readSizefromSocket(sock, BUFSIZE, &receivedBuf) ? false : true;
    }
    return startRcv;
}

void 
FileReceiveE2ECheck(C150DgmSocket& sock, int filenastiness, string tardir)
{
    *GRADING << "Begining to receive whole files from client." << endl; 
    /* open or create target directory */
    struct stat dir_status = {0};
    if (stat(tardir.c_str(), &dir_status) == -1) {
        mkdir(tardir.c_str(), 0700);
    }
    unordered_set<uint32_t> all_files_arrived;
    vector<string> all_file_names;
    size_t curr_sequence_number = 0;
    size_t left_over_bytes = 0;
    read_Start(sock);
    uint32_t total_file = 0; 
    string target_file_name;
    vector<string> tmp_file_names;
    C150NETWORK::C150NastyFile C150NF = C150NETWORK::C150NastyFile(filenastiness);
    while(1) {
        unordered_map<size_t, Packet_ptr> curr_file_contents;
        if (recv_one_file(sock, curr_sequence_number, all_file_names, curr_file_contents, total_file, left_over_bytes)) {
            target_file_name = makeTmpFileName(tardir, all_file_names.at(curr_sequence_number));
            // cerr << "generated target: " << target_file_name << endl;
            WriteaFile(C150NF, curr_file_contents, target_file_name, left_over_bytes);
            tmp_file_names.push_back(target_file_name);
            curr_file_contents.clear();
            /* completely received the whole file */
        }
        curr_sequence_number++;
        if (curr_sequence_number == total_file) break;
    }
    RenameAllFiles(tardir);
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
read_one_packet(C150DgmSocket& sock, size_t curr_file_index, bool& endpacketfound, size_t& maximum_packets, unordered_map<size_t, Packet_ptr>& one_file_contents, vector<string>& all_File_names, size_t& last_pkt_bytes, bool& namepktfound)
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
            all_File_names.push_back(string(filename));
            last_pkt_bytes = part_packet->totalFileNum;
            namepktfound = true;
        } else if (part_packet->packet_status % 10 == LAST_PACK){
            endpacketfound = true;
            maximum_packets = part_packet->seqNum + 1;
            one_file_contents[part_packet->seqNum] = part_packet;
        } else{
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
    Packet_ptr missing_notice = (Packet_ptr)malloc(sizeof(struct Packet));
    for (auto& packet: missing_packets) {
        missing_notice->seqNum = packet + 1;
        missing_notice->packet_status = MISS_FILE;
        sock.write((const char*)missing_notice, sizeof(struct Packet));
        bzero(missing_notice, sizeof(struct Packet));
    } 
}




bool 
recv_one_file(C150DgmSocket& sock, size_t curr_file_index, vector<string>& all_file_names, unordered_map<size_t, Packet_ptr>& one_file_contents, uint32_t& total_file, size_t& last_pkt_bytes)
{
    clock_t start_t, end_t;
    start_t = clock();
    bool endpacketfound = false;
    bool is_timed_out = false, recv_complete = false, totalfilefound = false, namepktfound = false;
    size_t maximum_packets;
    while (1) {
        is_timed_out = read_one_packet(sock, curr_file_index, endpacketfound, maximum_packets, one_file_contents, all_file_names, last_pkt_bytes, namepktfound); 
        end_t = clock();
        if ((double(end_t - start_t) / CLOCKS_PER_SEC) > 30){ /* maximum 10 minutes span for retry */
            break; }
        if (is_timed_out){
            if (!totalfilefound && one_file_contents.size() > 1) {
                auto access_directory_size = one_file_contents.begin();
                if (access_directory_size->second->packet_status % 10 != FILENAME_P) {
                    total_file = access_directory_size->second->totalFileNum; 
                    totalfilefound = true; }
            }
            if (!endpacketfound) {
                // TODO send to client resent end packet 
                Packet_ptr missing_notice = (Packet_ptr) calloc(sizeof(struct Packet), 1);
                missing_notice->packet_status = LAST_PACK;
                sock.write((const char*)missing_notice, sizeof(struct Packet));
                free(missing_notice);
            } else if (!namepktfound){
                Packet_ptr missing_name = (Packet_ptr) calloc(sizeof(struct Packet), 1);
                missing_name->packet_status = FILENAME_P;
                sock.write((const char*)missing_name, sizeof(struct Packet));
                free(missing_name);
            } else {
                vector<size_t> missing_packets_seq;
                if (check_completeness(sock, one_file_contents, maximum_packets, missing_packets_seq)) {
                    recv_complete = true;
                    break;} 
                write_missing_packets(sock, missing_packets_seq);
            }
        }
    }
    resend_confirmation(sock, curr_file_index, total_file);
    return recv_complete;
}


void
resend_confirmation(C150DgmSocket& sock, size_t curr_file_index, size_t total_file){
    Packet_ptr complete_notice = (Packet_ptr)calloc(sizeof(struct Packet), 1);
    bool good_to_go = false;
    char *receivedBuf = (char *)malloc(sizeof(struct Packet));
    int timeoutNum = 0;
    while(!good_to_go) {
        bzero(complete_notice, sizeof(struct Packet));
        complete_notice->packet_status = pack_status(curr_file_index, COMPLETE);
        sock.write((const char*)complete_notice, sizeof(struct Packet));
        bzero(receivedBuf, sizeof(struct Packet));
        if (timeoutNum > 10){ 
            if (curr_file_index + 1 == total_file) { good_to_go = true; }
        }
        bool succ_read = readSizefromSocket(sock, BUFSIZE, &receivedBuf);
        if (!succ_read){
            complete_notice = unpack_packet((unsigned char*)receivedBuf);
            if (complete_notice->packet_status / 10 > curr_file_index){
                good_to_go = true;
            } 
        }else {timeoutNum++;}
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
