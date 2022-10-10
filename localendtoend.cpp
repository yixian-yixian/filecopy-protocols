#include "localendtoend.h"
#include <cassert>

#define BUFSIZE 1024
const int UPPERBOUND = 1e6;
using namespace std;

/* GetFileName 
 * purpose: read in all name strings of available files in the target directory 
 * return: none 
 * notes: filenames vector should now be filled with filenames string
 */
void GetFileNames(vector<string>& filenames, string tardir)
{
    struct dirent *entry = nullptr;
    DIR *dp = nullptr;

    dp = opendir(tardir.c_str());
    if (dp != nullptr) {
        while ((entry = readdir(dp))){
            if (entry->d_type == 8){
                filenames.push_back(tardir + "/" + entry->d_name);
            }
        }
    }
    closedir(dp);
}

/* ReadaFile
 * purpose: read the file content from an initiated C150nastyfile pointer 
 * return: total number of bytes read from the file object
 * notes: *buf_ptr is udpated to point to the read in file content       
 */
ssize_t ReadaFile(C150NETWORK::C150NastyFile *targetFile, unsigned char **buf_ptr)
{
    assert(targetFile != nullptr);
    ssize_t totalBytes = 0;
    vector<unsigned char> allFileContent;
    unsigned char* temporaryBuf = (unsigned char*)malloc(BUFSIZE * sizeof(unsigned char));
    ssize_t chunk = 0;
    while(!(*targetFile).feof()) { // read until the end
        chunk = (*targetFile).fread(temporaryBuf, 1, BUFSIZE);
        for (ssize_t t = 0; t < chunk; t += sizeof(unsigned char)){
            allFileContent.push_back(*(temporaryBuf + t));
        }
        bzero(temporaryBuf, BUFSIZE); // clean up the buf for next read 
        totalBytes += chunk;
    }
    unsigned char* prod = (unsigned char*)malloc((allFileContent.size())*sizeof(unsigned char));
    for (unsigned int i = 0; i < allFileContent.size();i++) {
        *(prod + i) = allFileContent.at(i); 
    }
    *buf_ptr = prod;
    return totalBytes;
}


/* FileCopyE2ECheck
 * purpose: read the file content from an initiated C150nastyfile pointer 
 * parameter:
 *      int filenastiness: nastiness level for file read 
 *      string tardir: target directory string name 
 *      vector<fileProp>& allFilesProp_addr
 * return: total number of bytes read from the file object
 * notes: *buf_ptr is updated to point to the read in file content       
 */
void FileCopyE2ECheck(int filenastiness, string tardir, vector<fileProp>& allFilesProp_addr)
{
    printf("currently in FileCopyE2ECheck\n\n");
    unsigned char* temporaryBuf = nullptr;
    unordered_map<unsigned char*, unsigned char*> umSha1content; 
    int iteration = 0;
    ssize_t readedBytes = 0;
    vector<string> filenames;
    GetFileNames(filenames, tardir);
    
    for (long unsigned int i = 0; i < filenames.size(); i++){ // read one file 
        while (iteration < UPPERBOUND) /* limit each file to retry on read under upperbound iterations */
        {
            C150NETWORK::C150NastyFile C150NF = C150NETWORK::C150NastyFile(filenastiness);
            printf("current filename %s \n", filenames[i].c_str());
            void *success = C150NF.fopen(filenames[i].c_str(), "r");
            assert(success != NULL);
            printf("while loop iteration %d \n", iteration);
            readedBytes = ReadaFile(&C150NF, &temporaryBuf);
            unsigned char obuf[20]; /* calculate SHA1 for overall file */
            SHA1(temporaryBuf, readedBytes, obuf);
            printf("sha1 computed\n");/* decide if this read is correct */
            unordered_map<unsigned char*, unsigned char*>::const_iterator got = umSha1content.find(obuf);
            printf("after searching in hashmap \n");
            if (got == umSha1content.end()) { /* SHA1 not previously present */
                umSha1content[obuf] = temporaryBuf; /* add SHA1 for this read into table */
                printf("DID NOT find matching sha1\n");
            } else{ /* same SHA1 for correct file identified from table */
                struct fileProp fileInfo = fileProp(filenames[i], obuf, readedBytes, temporaryBuf);
                allFilesProp_addr.push_back(fileInfo);
                break;
            }
            iteration++;
            C150NF.fclose();
        }
        iteration = 0;
    }

}

