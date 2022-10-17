// --------------------------------------------------------------
//
//                        fileclient.cpp
//
//        Author: Ivian Zhang and Jack Zhang
//
//        COMMAND LINE
//
//              fileclient <server> <networknastiness> <filenastiness> <srcdir>
//
//        OPERATION
//
//              fileclient will send a single UDP packet
//              to the named server, and will wait (forever)
//              for a single UDP packet response. The contents
//              of the packet sent will be the msgtxt, including
//              a terminating null. The response message
//              is checked to ensure that it's null terminated.
//              For safety, this application will use a routine
//              to clean up any garbage characters the server
//              sent us, (so a malicious server can't crash us), and
//              then print the result.
//
//              Note that the C150DgmSocket class will select a UDP
//              port automatically based on the user's login, so this
//              will (typically) work only on the test machines at Tufts
//              and for COMP 150-IDS who are registered. See documention
//              for the comp150ids getUserPort routine if you are
//              curious, but you shouldn't have to worry about it.
//              The framework automatically runs on a separate port
//              for each user, as long as you are registerd in the
//              the student port mapping table (ask Noah or the TAs if
//              the program dies because you don't have a port).
//
//       Copyright: Ivian Zhang and Jack Zhang
//
// --------------------------------------------------------------


#include "c150nastydgmsocket.h"
#include "c150nastyfile.h"
#include "c150grading.h"
#include "localendtoend.h"
#include "servernetwork.h"

using namespace std;          // for C++ std library
using namespace C150NETWORK;  // for all the comp150 utilities

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
//
//                    Command line arguments
//
// The following are used as subscripts to argv, the command line arguments
// If we want to change the command line syntax, doing this
// symbolically makes it a bit easier.
//
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

const int serverArg = 1;                // server name is 1st arg
const int netnastyArg = 2;      // network nasty level is 2nd arg
const int filenastyArg = 3;        // file nasty level is 3nd arg
const int srcdirArg = 4;           // source directory is 4nd arg

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
//
//                           main program
//
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

int main(int argc, char *argv[]) {
    // 
    // Grading command 
    // 
    GRADEME(argc, argv);
    *GRADING << "Start writing to client log.\n";
    //
    // Variable declarations
    //
    int filenastiness;
    int networknastiness;

    //
    // Make sure command line looks right
    //
    if (argc != 5) {
        fprintf(stderr,"Correct syntxt is: %s <server> <networknastiness> <filenastiness> <srcdir>\n", argv[0]);
        exit(1);
    }
    if (strspn(argv[netnastyArg], "0123456789") != strlen(argv[netnastyArg])) {
        fprintf(stderr,"Network nastiness %s is not numeric\n", argv[2]);     
        fprintf(stderr,"Correct syntxt is: %s <server> <networknastiness> <filenastiness> <srcdir>\n", argv[0]);     
        exit(4);
    }
    if (strspn(argv[filenastyArg], "0123456789") != strlen(argv[filenastyArg])) {
        fprintf(stderr,"File Nastiness %s is not numeric\n", argv[3]);     
        fprintf(stderr,"Correct syntxt is: %s <server> <networknastiness> <filenastiness> <srcdir>\n", argv[0]);     
        exit(4);
    }
    filenastiness = atoi(argv[filenastyArg]);
    networknastiness = atoi(argv[netnastyArg]);
    string srcdir = argv[srcdirArg];

    // end to end check from local to socket
    vector<string> filenames;
    GetFileNames(filenames, srcdir);
    vector<fileProp> allFilesProp;
    *GRADING << "Starting FileCopyE2ECheck\n";
    FileCopyE2ECheck(filenastiness, srcdir, allFilesProp, filenames);
    // for (long unsigned int index = 0; index < allFilesProp.size(); index++){
    //     unsigned char* address;
    //     formatRequestBuf(allFilesProp.at(index), &address);
    // }
    *GRADING << "Finished FileCopyE2ECheck\n";

    // end to end check from socket to socket
    try {
        // Create the socket
        C150DgmSocket *sock = new C150NastyDgmSocket(networknastiness);

        // Tell the DGMSocket which server to talk to
        sock -> setServerName(argv[serverArg]);
        sock -> turnOnTimeouts(5000);

        // network e2e check
        FileSendE2ECheck(*sock, allFilesProp, filenames);
    }
    //
    //  Handle networking errors -- for now, just print message and give up!
    //
    catch (C150NetworkException& e) {
        // In case we're logging to a file, write to the console too
        cerr << argv[0] << ": caught C150NetworkException: " << e.formattedExplanation() << endl;
    }
    return 0;
}