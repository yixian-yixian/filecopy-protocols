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
#include <tuple>
#include <queue>
#include <unordered_map>
#include <openssl/sha.h>
#include <cassert>
#include <dirent.h>
#include <string>
#include <unordered_set>
#include "localendtoend.h"

using namespace std;
using namespace C150NETWORK;  // for all the comp150 utilities

void FileSendE2ECheck(C150DgmSocket& sock, vector<fileProp>& allFilesProp, vector<string>& filenames);
void FileReceiveE2ECheck(C150DgmSocket& sock, int filenastiness, string tardir);

#endif