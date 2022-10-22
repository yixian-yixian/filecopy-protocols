// --------------------------------------------------------------
//
//                        endtoend.h
//
//        Author: Ivian Zhang, Jack Zhang       
//   
//        Provides debug output services for Tufts COMP 150-IDS
//        projects
//
//        All classes and interfaces are in the C150NETWORK namespace.
//        
//        Classes for general use:
//
//           DebugStream
//
//     
// --------------------------------------------------------------

#ifndef __LOCALENDTOEND_H_INCLUDED__  
#define __LOCALENDTOEND_H_INCLUDED__

#include "c150nastyfile.h"
#include "c150grading.h"
#include <openssl/sha.h>
#include <vector>
#include <unordered_map>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstring>                // for errno string formatting
#include <cerrno>
#include <cstring>               // for strerro
#include <iostream>               // for cout
#include <fstream>                // for input files

enum Packet_Status{ REG_PACK = 0, LAST_PACK = 1, FILENAME_P = 2, RECV_FILE = 3, MISS_FILE = 4, COMPLETE = 5, START = 6};

typedef struct Packet {
    unsigned char content[490];
    size_t seqNum;
    uint32_t packet_status; 
    /* decimal digit signals property of the packets in a file, 0 signals other content packets, 1 signals the last content packet, 2 signals filename packet */
    /* status - decimal digit signals the order of the file in directory */
} *Packet_ptr;

typedef struct fileProp{
    string filename;
    unsigned char fileSHA1[20];
    ssize_t contentSize;
    vector<Packet_ptr>* fileContent;
    fileProp(string fileName, unsigned char* SHA1, size_t Size, vector<Packet_ptr>* fileallContent) {
        filename = fileName;
        memcpy((void *)fileSHA1, SHA1, 20);
        contentSize = Size;
        fileContent = fileallContent; 
    }
} fileProp;

void GetFileNames(vector<string>& filenames, string tardir);
void FileCopyE2ECheck(int filenastiness, string srcdir, vector<fileProp>& allFilesProp_addr, vector<string>& filenames);
string makeFileName(string dir, string name);
void WriteaFile(fileProp& curFile, int filenastiness, string tardir);
size_t ReadaFile(C150NETWORK::C150NastyFile& targetFile, vector<Packet_ptr>& allFileContent, unsigned int fileindex);
size_t ReadAPacket(C150NETWORK::C150NastyFile& targetFile, Packet_ptr currPacket, size_t& seqNum, string srcFileName);
#endif






