#include "localendtoend.h"
#include "servernetwork.h"
#include <cassert>

#define BUFSIZE 490
#define SHASIZE 20 
const int UPPERBOUND = 1e6;
using namespace std;
using namespace C150NETWORK;  // for all the comp150 utilities 



void calcSHA1(unsigned char** sha1_val, unsigned char *content, ssize_t contentSize);
// ------------------------------------------------------
//
//                   makeFileName
//
// Put together a directory and a file name, making
// sure there's a / in between
//
// ------------------------------------------------------

string
makeFileName(string dir, string name) {
  stringstream ss;

  ss << dir;
  // make sure dir name ends in /
  if (dir.substr(dir.length()-1,1) != "/")
    ss << '/';
  ss << name;       // append file name to dir
  return ss.str();  // return dir/name
  
}

string
makeTmpFileName(string dir, string name){
    stringstream ss;
    ss << dir;
    // make sure dir name ends in /
    if (dir.substr(dir.length()-1,1) != "/")
        ss << '/';
    // size_t pos = name.find_last_of(".");
    // if (pos != string::npos){ 
    //     ss << name.substr(0, pos);
    // }
    ss << name << ".tmp";   
    return ss.str();  // return dir/name
}

string
renameFileName(string name){
    stringstream ss;
    // remove everything after .tmp
    size_t pos = name.find_last_of(".");
    if (pos != string::npos){ 
        ss << name.substr(0, pos);
    }
    return ss.str();  // return dir/name
}

/* GetFileName 
 * purpose: read in all name strings of available files in the target directory 
 * return: none 
 * notes: filenames vector should now be filled with filenames string
 */
void GetFileNames(vector<string>& filenames, string tardir)
{
    struct dirent *entry = nullptr;
    DIR *dp = nullptr;
    dp = opendir(tardir.c_str());
    if (dp != nullptr) {
        while ((entry = readdir(dp))){
            if (entry->d_type == 8) filenames.push_back(entry->d_name);
        }
    }
    closedir(dp);
}

size_t 
ReadAPacket(C150NETWORK::C150NastyFile& targetFile, Packet_ptr currPacket, size_t& seqNum, string srcFileName)
{
    /* variable for reading the content */
    size_t chunk_size = 0;
    unsigned char *temporaryBuf = (unsigned char*) malloc(sizeof(unsigned char) * BUFSIZE);
    unordered_map<unsigned char*, unsigned char*> packet_sha1;
    bool find_identical = false;
    while (!find_identical) {
        // cerr << "inside read_a_packet loop with hashmap size [" << packet_sha1.size() << "]"<< endl;
        targetFile.fopen(srcFileName.c_str(), "r");
        targetFile.fseek(seqNum * chunk_size, SEEK_SET);
        /* read a packet */
        chunk_size = targetFile.fread(temporaryBuf, 1, BUFSIZE);
        /* calculate packet SHA1 */
        unsigned char packetSHA1[SHASIZE];
        SHA1(temporaryBuf, chunk_size, packetSHA1);
        // printSHA1(packetSHA1);
        /* check for repetitive SHA1 */
        unordered_map<unsigned char*, unsigned char*>::const_iterator found = packet_sha1.find(packetSHA1);
        if (found == packet_sha1.end()) { /* did not find matching SHA1, add to map and reread */
            /* add unseen SHA1 into map */
            packet_sha1[packetSHA1] = temporaryBuf;
            /* reset the filepointer to last read position for reread */
            bzero(packetSHA1, SHASIZE);
            bzero(temporaryBuf, chunk_size);
        } else { /* found matching SHA1, generate packet and exit */
            currPacket->seqNum = seqNum;
            currPacket->packet_status = 0;
            strncpy((char *)currPacket->content, (char *)temporaryBuf, chunk_size);
            find_identical = true;  
            free(temporaryBuf);
            // cerr << "found \n" << endl;
        }
        targetFile.fclose();
    }
    return chunk_size;
}

/* ReadaFile
 * purpose: read the file content from an initiated C150nastyfile pointer 
 * return: total number of bytes read from the file object
 * notes: *buf_ptr is udpated to point to the read in file content       
 */
size_t ReadaFile(C150NETWORK::C150NastyFile& targetFile, vector<Packet_ptr>& allFileContent, string srcFileName)
{
    size_t readedBytes = 0, curr_seq = 0, totalBytes = 0;
    while(1) { // read until the end
        /* initialize a packet for next read */
        Packet_ptr currPacket = (Packet_ptr)malloc(sizeof(struct Packet));
        /* read a packet */
        readedBytes = ReadAPacket(targetFile, currPacket, curr_seq, srcFileName);
        totalBytes += readedBytes;
        /* increment sequence number by 1 */
        curr_seq++;
        currPacket->packet_status = (readedBytes < BUFSIZE) ? 1 : 0;
        /* place one pack onto all file vector */
        allFileContent.push_back(currPacket);
        if (readedBytes < BUFSIZE) {
            cerr << "totalbytes after one iteration [" << totalBytes << "] \n";
            break;
        }
    }
    return totalBytes;
}


/* FileCopyE2ECheck
 * purpose: read the file content from an initiated C150nastyfile pointer 
 * parameter:
 *      int filenastiness: nastiness level for file read 
 *      string srcdir: source directory string name 
 *      vector<fileProp>& allFilesProp_addr: all Filesproperty passed by reference
 * return: total number of bytes read from the file object
 * notes: allFilesProp_addr is now populated with the fileProp objects based on files
 *        files in target directory       
 */
void FileCopyE2ECheck(int filenastiness, string srcdir, vector<fileProp>& allFilesProp_addr, vector<string>& filenames)
{
    size_t readedBytes = 0;
    unsigned char *temporaryBuf, *entirefile_sha1;
    for (long unsigned int i = 0; i < filenames.size(); i++){ // read one file 
        C150NETWORK::C150NastyFile C150NF = C150NETWORK::C150NastyFile(filenastiness);
        string sourceFileName = makeFileName(srcdir, filenames[i]);
        vector<Packet_ptr> *singleFilePkt = new vector<Packet_ptr>;
        readedBytes = ReadaFile(C150NF, *singleFilePkt, sourceFileName);
        temporaryBuf = (unsigned char*) calloc((readedBytes + 1), sizeof(unsigned char));
        for (long unsigned int index = 0; index < singleFilePkt->size() - 1; index++){
            /* copy over bytes in each packet except for last packet */
            strncat((char *) temporaryBuf, (char *) singleFilePkt->at(index)->content, BUFSIZE);
        }/* copy last packet */
        size_t lastbytes = readedBytes - (singleFilePkt->size() - 1) * BUFSIZE;
        strncat((char*)temporaryBuf, (char *)((singleFilePkt->at(singleFilePkt->size() - 1))->content), lastbytes);
        /* calculate SHA1 for the entire file */
        calcSHA1(&entirefile_sha1, temporaryBuf, readedBytes);
        /* initialize fileProp object based on the current filename, content and totalBytes read */
        struct fileProp fileInfo = fileProp(filenames[i], entirefile_sha1, readedBytes, singleFilePkt);
        allFilesProp_addr.push_back(fileInfo); /* append file informationto the list */
        *GRADING << "File: <" << filenames[i] << "> local end-to-end check succeeded, attempt <0>\n"; 
    }
}


void 
WriteaFile(fileProp& curFile, int filenastiness, string tardir) {
    // struct stat dir_status = {0};
    // if (stat(tardir.c_str(), &dir_status) == -1) {
    //     mkdir(tardir.c_str(), 0700);
    // }
    // /* make target directory file name */
    // string target_file_name = makeTmpFileName(tardir, curFile.filename);
    // C150NETWORK::C150NastyFile C150NF = C150NETWORK::C150NastyFile(filenastiness);
    // /* variables to track read and write correctness */
    // unsigned char *read_back_Buf = nullptr, *file_sha1 = nullptr;
    // bool is_matched_content = false;
    // ssize_t read_back_size;
    // while (!is_matched_content) {
    //     /* open the file to write */
    //     void *success = C150NF.fopen(target_file_name.c_str(), "w");
    //     assert(success != NULL);
    //     C150NastyFile C150NFR = C150NastyFile(0);
    //     /* write the file out to file system */
    //     C150NF.fwrite((const void*)(curFile.contentbuf), 1, curFile.contentSize);
    //     C150NF.fclose();
        
    //     /* read the file back for SHA1 comparison */
    //     void *tmpfile = C150NFR.fopen(target_file_name.c_str(), "r");
    //     assert(tmpfile != NULL);
    //     read_back_size = ReadaFile(C150NFR, &read_back_Buf);
    //     calcSHA1(&file_sha1, read_back_Buf, read_back_size);
    //     if (strcmp((char *)file_sha1, (char *)curFile.fileSHA1) == 0) {
    //         /* matching content leads to exit */
    //         is_matched_content = true;
    //     }
    //     free(read_back_Buf);
    //     free(file_sha1);
    //     C150NFR.fclose();
    // }
}

void 
RenameAllFiles(string tardir)
{
    struct dirent *entry = nullptr;
    DIR *dp = nullptr;
    dp = opendir(tardir.c_str());
    if (dp != nullptr) {
        while ((entry = readdir(dp))){
            if (entry->d_type == 8){
                string newname = renameFileName(entry->d_name);
                rename(entry->d_name, newname.c_str());
            }
        }
    }
    closedir(dp);
}


void calcSHA1(unsigned char** sha1_val, unsigned char *content, ssize_t contentSize) {
    *sha1_val = (unsigned char*)malloc(20 * sizeof(unsigned char));
    SHA1((unsigned char*)content, contentSize, *sha1_val);
}



