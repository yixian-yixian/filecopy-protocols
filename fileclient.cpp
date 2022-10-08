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
#include "c150debug.h"
#include "c150grading.h"
#include "localendtoend.h"
#include "networkendtoend.h"

using namespace std;          // for C++ std library
using namespace C150NETWORK;  // for all the comp150 utilities

// forward declarations
void checkAndPrintMessage(ssize_t readlen, char *buf, ssize_t bufferlen);
void setUpDebugLogging(const char *logname, int argc, char *argv[]);

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
    *GRADING << "The sum of 100 + 20 + 3 is: " << 100+20+3 << endl;
    //
    // Variable declarations
    //
    // ssize_t readlen;             // amount of data read from socket
    int filenastiness;               // how aggressively do we drop packets, etc?
    // int networknastiness;

    //
    //  Set up debug message logging
    //
    setUpDebugLogging("fileclientdebug.txt",argc, argv);

    //
    // Make sure command line looks right
    //
    if (argc != 5) {
        fprintf(stderr,"Correct syntxt is: %s <server> <networknastiness> <filenastiness> <srcdir>\n", argv[0]);
        exit(1);
    }
    if (strspn(argv[2], "0123456789") != strlen(argv[netnastyArg])) {
        fprintf(stderr,"Network nastiness %s is not numeric\n", argv[2]);     
        fprintf(stderr,"Correct syntxt is: %s <server> <networknastiness> <filenastiness> <srcdir>\n", argv[0]);     
        exit(4);
    }
    if (strspn(argv[3], "0123456789") != strlen(argv[filenastyArg])) {
        fprintf(stderr,"File Nastiness %s is not numeric\n", argv[3]);     
        fprintf(stderr,"Correct syntxt is: %s <server> <networknastiness> <filenastiness> <srcdir>\n", argv[0]);     
        exit(4);
    }
    filenastiness = atoi(argv[filenastyArg]);
    // networknastiness = atoi(argv[netnastyArg]);
    string tardir = argv[4];
    vector<fileProp> allFilesProp;
    FileCopyE2ECheck(filenastiness, tardir, allFilesProp);
    printf("finished with FileCopyE2E\n");
    // C150DgmSocket *sock = new C150NastyDgmSocket(networknastiness);
    printf("starting FileSendE2ECheck\n");
    // FileSendE2ECheck(*sock, allFilesProp);
    for (long unsigned int i = 0; i < allFilesProp.size(); i++){
        unsigned char* protocolbuf;
        formatRequestBuf(allFilesProp.at(i), &protocolbuf);
    }
    printf("finished with FileSendE2ECheck\n");
    //
    //
    //        Send / receive / print
    //
    // try {

    //     // Create the socket
    //     c150debug->printf(C150APPLICATION,"Creating C150NastyDgmSocket(nastiness=%d)", networknastiness);
    //     C150DgmSocket *sock = new C150NastyDgmSocket(networknastiness);

    //     // Tell the DGMSocket which server to talk to
    //     sock -> setServerName(argv[serverArg]);
    //     // FileSendE2ECheck(sock, allFilesProp);
        
    //     // Send the message to the server
    //     c150debug->printf(C150APPLICATION,"%s: Reading from source directory: \"%s\"",
    //                       argv[0], argv[srcdirArg]);
    //     sock -> write(argv[srcdirArg], strlen(argv[srcdirArg])+1); // +1 includes the null
    //     // Read the response from the server
    //     c150debug->printf(C150APPLICATION,"%s: Returned from write, doing read()",
    //                       argv[0]);
    //     readlen = sock -> read(incomingMessage, sizeof(incomingMessage));

    //     // Check and print the incoming message
    //     checkAndPrintMessage(readlen, incomingMessage, sizeof(incomingMessage));

    // }

    // //
    // //  Handle networking errors -- for now, just print message and give up!
    // //
    // catch (C150NetworkException& e) {
    //     // Write to debug log
    //     c150debug->printf(C150ALWAYSLOG,"Caught C150NetworkException: %s\n",
    //                       e.formattedExplanation().c_str());
    //     // In case we're logging to a file, write to the console too
    //     cerr << argv[0] << ": caught C150NetworkException: " << e.formattedExplanation()
    //                     << endl;
    // }

    return 0;
}


// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
//
//                     checkAndPrintMessage
//
//        Make sure length is OK, clean up response buffer
//        and print it to standard output.
//
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -



void
checkAndPrintMessage(ssize_t readlen, char *msg, ssize_t bufferlen) {
    //
    // Except in case of timeouts, we're not expecting
    // a zero length read
    //
    if (readlen == 0) {
        throw C150NetworkException("Unexpected zero length read in client");
    }

    // DEFENSIVE PROGRAMMING: we aren't even trying to read this much
    // We're just being extra careful to check this
    if (readlen > (int)(bufferlen)) {
        throw C150NetworkException("Unexpected over length read in client");
    }

    //
    // Make sure server followed the rules and
    // sent a null-terminated string (well, we could
    // check that it's all legal characters, but
    // at least we look for the null)
    //
    if(msg[readlen-1] != '\0') {
        throw C150NetworkException("Client received message that was not null terminated");
    };

    //
    // Use a routine provided in c150utility.cpp to change any control
    // or non-printing characters to "." (this is just defensive programming:
    // if the server maliciously or inadvertently sent us junk characters, then we
    // won't send them to our terminal -- some
    // control characters can do nasty things!)
    //
    // Note: cleanString wants a C++ string, not a char*, so we make a temporary one
    // here. Not super-fast, but this is just a demo program.
    string s(msg);
    cleanString(s);

    // Echo the response on the console

    c150debug->printf(C150APPLICATION,"PRINTING RESPONSE: Response received is \"%s\"\n", s.c_str());
    printf("Response received is \"%s\"\n", s.c_str());

}


// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
//
//                     setUpDebugLogging
//
//        For COMP 150-IDS, a set of standards utilities
//        are provided for logging timestamped debug messages.
//        You can use them to write your own messages, but
//        more importantly, the communication libraries provided
//        to you will write into the same logs.
//
//        As shown below, you can use the enableLogging
//        method to choose which classes of messages will show up:
//        You may want to turn on a lot for some debugging, then
//        turn off some when it gets too noisy and your core code is
//        working. You can also make up and use your own flags
//        to create different classes of debug output within your
//        application code
//
//        NEEDSWORK: should be factored into shared code w/pingserver
//        NEEDSWORK: document arguments
//
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void setUpDebugLogging(const char *logname, int argc, char *argv[]) {

    //
    //           Choose where debug output should go
    //
    // The default is that debug output goes to cerr.
    //
    // Uncomment the following three lines to direct
    // debug output to a file. Comment them
    // to default to the console.
    //
    // Note: the new DebugStream and ofstream MUST live after we return
    // from setUpDebugLogging, so we have to allocate
    // them dynamically.
    //
    //
    // Explanation:
    //
    //     The first line is ordinary C++ to open a file
    //     as an output stream.
    //
    //     The second line wraps that will all the services
    //     of a comp 150-IDS debug stream, and names that filestreamp.
    //
    //     The third line replaces the global variable c150debug
    //     and sets it to point to the new debugstream. Since c150debug
    //     is what all the c150 debug routines use to find the debug stream,
    //     you've now effectively overridden the default.
    //
    ofstream *outstreamp = new ofstream(logname);
    DebugStream *filestreamp = new DebugStream(outstreamp);
    DebugStream::setDefaultLogger(filestreamp);

    //
    //  Put the program name and a timestamp on each line of the debug log.
    //
    c150debug->setPrefix(argv[0]);
    c150debug->enableTimestamp();

    //
    // Ask to receive all classes of debug message
    //
    // See c150debug.h for other classes you can enable. To get more than
    // one class, you can or (|) the flags together and pass the combined
    // mask to c150debug -> enableLogging
    //
    // By the way, the default is to disable all output except for
    // messages written with the C150ALWAYSLOG flag. Those are typically
    // used only for things like fatal errors. So, the default is
    // for the system to run quietly without producing debug output.
    //
    c150debug->enableLogging(C150APPLICATION | C150NETWORKTRAFFIC |
                             C150NETWORKDELIVERY);
}






