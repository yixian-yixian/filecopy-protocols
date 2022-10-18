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


typedef struct fileProp{
    string filename;
    unsigned char fileSHA1[20];
    ssize_t contentSize;
    unsigned char* contentbuf;
    fileProp(string fileName, unsigned char* SHA1, size_t Size, unsigned char *contentAddr) {
        filename = fileName;
        memcpy((void *)fileSHA1, SHA1, 20);
        contentSize = Size;
        contentbuf = contentAddr; 
    }
} fileProp;

ssize_t ReadaFile(C150NETWORK::C150NastyFile *targetFile, unsigned char **buf_ptr);
void GetFileNames(vector<string>& filenames, string tardir);
void FileCopyE2ECheck(int filenastiness, string srcdir, vector<fileProp>& allFilesProp_addr, vector<string>& filenames);
string makeFileName(string dir, string name);
void WriteaFile(fileProp& curFile, int filenastiness, string tardir);

#endif






