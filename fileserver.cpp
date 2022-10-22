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
#include "c150nastyfile.h"
#include "localendtoend.h"
#include "servernetwork.h"
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
    GRADEME(argc, argv);

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


    // Set up socket for listening mode 
    try {
        // Create the socket 
        C150DgmSocket *sock = new C150NastyDgmSocket(networknastiness);
        sock -> turnOnTimeouts(5000);
        vector<fileProp> allArrivedFiles;
        FileReceiveE2ECheck(*sock, filenastiness, tarDir);

        // bool currentfilefail = false;
        // unordered_map<string, fileProp*> TargetFiles;
        // vector<string> filenames;
        // vector<fileProp> allReadinFiles;
        // GetFileNames(filenames, tarDir);
        // FileCopyE2ECheck(filenastiness, tarDir, allReadinFiles, filenames);
        // for (long unsigned int i = 0; i < filenames.size(); i++)
        // {
        //     string filename = filenames.at(i);
        //     TargetFiles[filename] = &(allReadinFiles.at(i));
        // }

        // long unsigned int index = 0;
        // while (index < allArrivedFiles.size()){
        //     currentfilefail = false;
        //     string curfilename = allArrivedFiles.at(index).filename;
        //     *GRADING << "File: <" << curfilename << "> received, beginning end-to-end check." << endl;
        //     unordered_map<string, fileProp*>::const_iterator got = TargetFiles.find(curfilename);
        //     if (got == TargetFiles.end()) {
        //         *GRADING << "File: <" << curfilename << "> was not found in the target directory." << endl;
        //         *GRADING << "File: <" << curfilename << "> end-to-end check failed." << endl;
        //     }else{
        //         for (int j = 0; j < 20; j++) {
        //             if (TargetFiles[curfilename]->fileSHA1[j] != allArrivedFiles.at(index).fileSHA1[j]){
        //                 *GRADING << "File: <" << curfilename << "> end-to-end check failed." << endl;
        //                 currentfilefail = true;
        //                 break;
        //             }
        //         }
        //     }
        //     if (!currentfilefail) {
        //         *GRADING << "File: <" << curfilename << "> end-to-end check succeeded." << endl;
        //     }
        //     index++;
        // }
        // printf("MISSION COMPLETE!\n");
        // *GRADING << "Complete a total of <"  << allArrivedFiles.size() << "> files end-to-end check." << endl;
    } 
    catch (C150NetworkException& e){
        // In case we're logging to a file, write to the console too
        cerr << argv[0] << ": caught C150NetworkException: " << e.formattedExplanation() << endl;
    }

    return 0;
}



