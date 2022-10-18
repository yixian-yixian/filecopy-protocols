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

#ifndef __NETWORKENDTOEND_H_INCLUDED__  
#define __NETWORKENDTOEND_H_INCLUDED__

#include "c150nastydgmsocket.h"
#include "c150debug.h"
#include "c150grading.h"
#include <vector>
#include <unordered_map>
#include <openssl/sha.h>
#include <cassert>
#include <dirent.h>
#include <string>
#include "localendtoend.h"
using namespace std;
using namespace C150NETWORK;  // for all the comp150 utilities

bool ServerRESCheck(C150DgmSocket& sock);
bool sendtoTar(C150DgmSocket& sock, fileProp& file, unsigned& iteration, bool& lastfile, string filename);
bool readfromSrc(C150DgmSocket& sock, vector<fileProp>& allArrivedFiles);
void FileSendE2ECheck(C150DgmSocket& sock, vector<fileProp>& allFilesProp, vector<string>& filenames);
void FileReceiveE2ECheck(C150DgmSocket& sock, vector<fileProp>& allArrivedFiles);
bool readSizefromSocket(C150DgmSocket& sock, size_t bytestoRead, char** bytes_storage);
void formatRequestBuf(fileProp& singleFile, unsigned char **requestBuf, bool lastfile);
bool parseHeaderField(unsigned char *receivedBuf, fileProp& received_file, bool& lastfile);

#endif