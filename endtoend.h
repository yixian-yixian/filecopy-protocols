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
//2
//           DebugStream
//
//        Copyright: 2012 Noah Mendelsohn
//     
// --------------------------------------------------------------

#ifndef __ENDTOEND_H_INCLUDED__  
#define __ENDTOEND_H_INCLUDED__

#include "c150nastyfile.h"
#include <openssl/sha.h>
#include <vector>
#include <unordered_map>
#include <dirent.h>

typedef struct fileProp{
    string filename;
    unsigned char fileSHA1[20];
    size_t contentSize;
    unsigned char* contentbuf;
    fileProp(string fileName, unsigned char* SHA1, size_t Size, unsigned char *contentAddr) {
        filename = fileName;
        memcpy((void *)fileSHA1, SHA1, 20);
        contentSize = Size;
        contentbuf = contentAddr; 
    }
} fileProp;

size_t ReadaFile(C150NETWORK::C150NastyFile *targetFile, unsigned char **buf_ptr);
void GetFileNames(vector<string>& filenames, string tardir);
void FileCopyE2ECheck(string tardir, vector<fileProp>& allFilesProp_addr);


#endif






