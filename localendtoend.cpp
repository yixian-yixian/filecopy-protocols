#include "localendtoend.h"
#include <cassert>

#define BUFSIZE 1024
const int UPPERBOUND = 1e6;
using namespace std;

// ------------------------------------------------------
//
//                   makeFileName
//
// Put together a directory and a file name, making
// sure there's a / in between
//
// ------------------------------------------------------

string
makeFileName(string dir, string name) {
  stringstream ss;

  ss << dir;
  // make sure dir name ends in /
  if (dir.substr(dir.length()-1,1) != "/")
    ss << '/';
  ss << name;       // append file name to dir
  return ss.str();  // return dir/name
  
}

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
            if (entry->d_type == 8) filenames.push_back(entry->d_name);
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
 *      string srcdir: source directory string name 
 *      vector<fileProp>& allFilesProp_addr: all Filesproperty passed by reference
 * return: total number of bytes read from the file object
 * notes: allFilesProp_addr is now populated with the fileProp objects based on files
 *        files in target directory       
 */
void FileCopyE2ECheck(int filenastiness, string srcdir, vector<fileProp>& allFilesProp_addr, vector<string>& filenames)
{
    printf("currently in FileCopyE2ECheck\n\n");
    unsigned char* temporaryBuf = nullptr;
    unordered_map<unsigned char*, unsigned char*> umSha1content; 
    int iteration = 0;
    ssize_t readedBytes = 0;
    
    for (long unsigned int i = 0; i < filenames.size(); i++){ // read one file 
        while (iteration < UPPERBOUND) /* limit each file to retry on read under upperbound iterations */
        {
            C150NETWORK::C150NastyFile C150NF = C150NETWORK::C150NastyFile(filenastiness);
            string sourceFileName = makeFileName(srcdir, filenames[i]);
            void *success = C150NF.fopen(sourceFileName.c_str(), "r");
            assert(success != NULL);
            readedBytes = ReadaFile(&C150NF, &temporaryBuf);
            unsigned char obuf[20]; /* calculate SHA1 for overall file */
            SHA1(temporaryBuf, readedBytes, obuf);
            unordered_map<unsigned char*, unsigned char*>::const_iterator got = umSha1content.find(obuf);
            if (got == umSha1content.end()) { /* SHA1 not previously present */
                umSha1content[obuf] = temporaryBuf; /* add SHA1 for this read into table */
            } else{ /* same SHA1 for correct file identified from table */
                /* initialize fileProp object based on the current filename, 
                content and totalBytes read */
                struct fileProp fileInfo = fileProp(filenames[i], obuf, readedBytes, temporaryBuf);
                allFilesProp_addr.push_back(fileInfo); /* append file informationto the list */
                break;
            }
            iteration++; /* unsuccessful find increment the iteration number for file read by 1*/
            C150NF.fclose(); /* close current socket */
        }
        iteration = 0;
    }
    printf("finished FileCopyE2ECheck\n");
}

