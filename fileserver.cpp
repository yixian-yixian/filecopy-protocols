// --------------------------------------------------------------
//
//                        pingserver.cpp
//
//        Author: Ivian Zhang and Jack Zhang
//   
//
//        This is a simple server, designed to illustrate use of:
//
//            * The C150DgmSocket class, which provides 
//              a convenient wrapper for sending and receiving
//              UDP packets in a client/server model
//
//            * The C150NastyDgmSocket class, which is a variant
//              of the socket class described above. The nasty version
//              takes an integer on its constructor, selecting a degree
//              of nastiness. Any nastiness > 0 tells the system
//              to occasionally drop, delay, reorder, duplicate or
//              damage incoming packets. Higher nastiness levels tend
//              to be more aggressive about causing trouble
//
//            * The c150debug interface, which provides a framework for
//              generating a timestamped log of debugging messages.
//              Note that the socket classes described above will
//              write to these same logs, providing information
//              about things like when UDP packets are sent and received.
//              See comments section below for more information on 
//              these logging classes and what they can do.
//
//
//        COMMAND LINE
//
//              fileserver <networknastiness> <filenastiness> <targetdir>
//
//
//        OPERATION
//
//              pingserver will loop receiving UDP packets from
//              any client. The data in each packet should be a null-
//              terminated string. If it is then the server
//              responds with a text message of its own.
//
//              Note that the C150DgmSocket class will select a UDP
//              port automatically based on the users login, so this
//              will (typically) work only on the test machines at Tufts
//              and for COMP 150-IDS who are registered. See documention
//              for getUserPort.
//
//
//       Copyright: Ivian Zhang and Jack Zhang
//     
// --------------------------------------------------------------

#include "c150nastydgmsocket.h"
#include "c150debug.h"
#include "c150nastyfile.h"
#include "localendtoend.h"
#include "networkendtoend.h"
#include "c150grading.h"
#include <fstream>
#include <cstdlib> 
#include <cstdint>

#define MAX_REQUEST_BUF 512 

using namespace C150NETWORK;  // for all the comp150 utilities 

int
main(int argc, char *argv[])
{
    int filenastiness, networknastiness;               // how aggressively do we drop packets, etc?

    // Check command line argument 
    if (argc != 4)  {
        fprintf(stderr,"Correct syntxt is: %s <networknastiness> <filenastiness> <targetdir>\n", argv[0]);
        exit(1);
    }
    if (strspn(argv[1], "0123456789") != strlen(argv[1])) {
        fprintf(stderr,"Network Nastiness %s is not numeric\n", argv[1]);     
        fprintf(stderr,"Correct syntxt is: %s <networknastiness> <filenastiness> <targetdir>\n", argv[0]);     
        exit(4);
    } else if (strspn(argv[2], "0123456789") != strlen(argv[2])) {
        fprintf(stderr,"File Nastiness %s is not numeric\n", argv[2]);     
        fprintf(stderr,"Correct syntxt is: %s <networknastiness> <filenastiness> <targetdir>\n", argv[0]);     
        exit(4);
    }
    networknastiness = atoi(argv[1]);
    filenastiness = atoi(argv[2]);   // convert command line string to integer
    string tarDir = argv[3];
    printf("current filenastiness %d\n", filenastiness);

    // TODO update server debug message 
    // setUpDebugLogging("fileserverdebug.txt",argc, argv);
    // c150debug->setIndent("    ");

    // Set up socket for listening mode 
    try {
        // Create the socket 
        c150debug->printf(C150APPLICATION,"Creating C150NastyDgmSocket(nastiness=%d)",
                          networknastiness);
        C150DgmSocket *sock = new C150NastyDgmSocket(networknastiness);
        c150debug->printf(C150APPLICATION,"Ready to accept messages");
        char *srcdir = (char *)malloc(MAX_REQUEST_BUF * sizeof(char));
        readSizefromSocket(*sock, MAX_REQUEST_BUF, &srcdir);
        string srcDir(srcdir);
        free(srcdir);
        // unordered_map<char *filename, fileProp info> 
        vector<fileProp> allArrivedFiles;
     
        FileReceiveE2ECheck(*sock, allArrivedFiles);

        long unsigned int index = 0;
        bool currentfilefail = false;
        while (index < allArrivedFiles.size()){
            currentfilefail = false;
            vector<string> filenames;
            copyFile(srcDir, allArrivedFiles.at(index).filename, tarDir, filenastiness);
            filenames.push_back(allArrivedFiles.at(index).filename);
            vector<fileProp> allReadinFiles;
            FileCopyE2ECheck(filenastiness, tarDir, allReadinFiles, filenames);
            for (int j = 0; j < 20; j++) {
                if (allReadinFiles.at(0).fileSHA1[j] != allArrivedFiles.at(index).fileSHA1[j]){
                    // cout << "local file [" << allReadinFiles.at(pos).filename << "] [";
                    // printf("%02x", (unsigned int)allReadinFiles.at(pos).fileSHA1[j]);
                    // cout << "] doesn't match original file [" << allArrivedFiles.at(pos).filename << "] [";
                    // printf("%02x", (unsigned int)allArrivedFiles.at(pos).fileSHA1[j]);
                    // cout << "].\n"
                    cout << "local file [" << allReadinFiles.at(0).filename << "] doesn't match.\n";
                    currentfilefail = true;
                    break;
                }
            }
            if (currentfilefail) {
                cout << "successfuly match [" << index+1 << "] files! moving onwards\n";
                index++;
            }
        }

        // for (fileProp item : allArrivedFiles){
        //     copyFile(srcDir, item.filename, tarDir, filenastiness);
        //     filenames.push_back(item.filename);
        // }
        // vector<fileProp> allReadinFiles;
        // FileCopyE2ECheck(filenastiness, tarDir, allReadinFiles, filenames);
    
        // for (long unsigned int index = 0; index < allReadinFiles.size(); index++){
        //     for (int j = 0; j < 20; j++) {
        //         if (allReadinFiles.at(index).fileSHA1[j] != allArrivedFiles.at(index).fileSHA1[j]){
        //             cout << "local file [" << allReadinFiles.at(index).filename << "] [";
        //             printf("%02x", (unsigned int)allReadinFiles.at(index).fileSHA1[j]);
        //             cout << "] doesn't match original file [" << allArrivedFiles.at(index).filename << "] [";
        //             printf("%02x", (unsigned int)allArrivedFiles.at(index).fileSHA1[j]);
        //             cout << "].\n";
        //         }
        //     }
        // }
        printf("MISSION COMPLETE!\n");
    } 
    catch (C150NetworkException& e){
        // Write to debug log
        c150debug->printf(C150ALWAYSLOG,"Caught C150NetworkException: %s\n",
                          e.formattedExplanation().c_str());
        // In case we're logging to a file, write to the console too
        cerr << argv[0] << ": caught C150NetworkException: " << e.formattedExplanation() << endl;
    }


}



