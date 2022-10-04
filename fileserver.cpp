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
//              pingserver <nastiness_number>
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
#include <fstream>
#include <cstdlib> 
#include <cstdint>

#define MAX_REQUEST_BUF 512 


using namespace C150NETWORK;  // for all the comp150 utilities 

int
main(int argc, char *argv[])
{

    // Variable Declaration  
    ssize_t readlen;             // amount of data read from socket
    char incomingMessage[MAX_REQUEST_BUF];   // received message data
    int nastiness;               // how aggressively do we drop packets, etc?

    // Check command line argument 
    if (argc != 2)  {
        fprintf(stderr,"Correct syntxt is: %s <nastiness_number>\n", argv[0]);
        exit(1);
    }
    if (strspn(argv[1], "0123456789") != strlen(argv[1])) {
        fprintf(stderr,"Nastiness %s is not numeric\n", argv[1]);     
        fprintf(stderr,"Correct syntxt is: %s <nastiness_number>\n", argv[0]);     
        exit(4);
    }
    nastiness = atoi(argv[1]);   // convert command line string to integer

    // TODO update server debug message 
    // setUpDebugLogging("fileserverdebug.txt",argc, argv);
    // c150debug->setIndent("    ");

    // Set up socket for listening mode 
    try {
        // Create the socket 
        c150debug->printf(C150APPLICATION,"Creating C150NastyDgmSocket(nastiness=%d)",
                          nastiness);
        C150DgmSocket *sock = new C150NastyDgmSocket(nastiness);
        c150debug->printf(C150APPLICATION,"Ready to accept messages");

        // infinite loop processing message 
        while (1) {
            readlen = sock -> read(incomingMessage, sizeof(incomingMessage)-1);
            if (readlen == 0) {
                c150debug->printf(C150APPLICATION,"Read zero length message, trying again");
                continue;
            }
            //
            // Clean up the message in case it contained junk
            //
            incomingMessage[readlen] = '\0';  // make sure null terminated
            string incoming(incomingMessage); // Convert to C++ string ...it's slightly
                                              // easier to work with, and cleanString
                                              // expects it
            cleanString(incoming);            // c150ids-supplied utility: changes
                                              // non-printing characters to .
            c150debug->printf(C150APPLICATION,"Successfully read %d bytes. Message=\"%s\"",
                              readlen, incoming.c_str());

            // create the return message 
            bool found = false;
            string response = "You requested: " + incoming;
            string fileLocate = "The directory is" + (char *)(found ? " ": " not") + " found locally \n".



            // write the return message
            //
            c150debug->printf(C150APPLICATION,"Responding with message=\"%s\"",
                              response.c_str());
            sock -> write(response.c_str(), response.length()+1);

        }

    } 
    catch (C150NetworkException& e){
        // Write to debug log
        c150debug->printf(C150ALWAYSLOG,"Caught C150NetworkException: %s\n",
                          e.formattedExplanation().c_str());
        // In case we're logging to a file, write to the console too
        cerr << argv[0] << ": caught C150NetworkException: " << e.formattedExplanation() << endl;
    }


}

uint64_t calculateStringsha1(string message)
{
    return 0;

}


