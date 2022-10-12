// --------------------------------------------------------------
//
//                        fileclient.cpp
//
//        Author: Ivian Zhang and Jack Zhang
//
//
//        This is a simple client, designed to illustrate use of:
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
//            * The C150NastyFile class, which provides a convenient
//              wrapper for causing operations to occasionally misbehave.
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
//              fileclient <server> <networknastiness> <filenastiness> <srcdir>
//
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
//        LIMITATIONS
//
//              This version does not timeout or retry when packets are lost.
//
//
//       Copyright: Ivian Zhang and Jack Zhang
//
// --------------------------------------------------------------


#include "c150nastydgmsocket.h"
#include "c150nastyfile.h"
#include "c150grading.h"
#include "localendtoend.h"
#include "networkendtoend.h"

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
    //
    // Variable declarations
    //
    int filenastiness;               // how aggressively do we drop packets, etc?
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
    FileCopyE2ECheck(filenastiness, srcdir, allFilesProp, filenames);
    printf("finished with FileCopyE2E\n");

    // end to end check from socket to socket
    printf("starting FileSendE2ECheck\n");    
    //      Send / receive / print
    
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
    printf("finished with FileSendE2ECheck\n");


    return 0;
}