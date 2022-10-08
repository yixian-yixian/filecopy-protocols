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
#include <openssl/sha.h>
#include <vector>
#include <unordered_map>
#include <dirent.h>
#include <string>
#include "localendtoend.h"
using namespace std;
using namespace C150NETWORK;  // for all the comp150 utilities


void FileSendE2ECheck(C150DgmSocket& sock, vector<fileProp>& allFilesProp);
void formatRequestBuf(fileProp& singleFile, unsigned char **requestBuf);
bool sendtoTar(C150DgmSocket& sock, fileProp& file, unsigned& iterationNum);
bool readfromSrc(C150DgmSocket& sock, fileProp& file, unsigned& iterationNum);

#endif