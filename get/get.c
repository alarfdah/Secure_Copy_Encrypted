#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <util/message.h>
#include <clientProtocol.h>

int socket; // the socket to communicate with the server
int eid; // the eid for the socket
FILE *destFile; // the destination file

/** 
 * ===  FUNCTION  ======================================================================
 *         Name:  verifyPath
 *  Description:  verify a path
 *
 *	@param path a path to a file
 * =====================================================================================
 */
static char *verifyPath(char *path) {
  int length = strlen(path);

  if (length < 1) 
    return NULL;

  char *str = (char *)malloc(length+1);
  
  if (str == NULL) {
    fprintf(stderr,"malloc() error\n");
    exit(-1);
  }

  strncpy(str,path,length+1);

  return str;
}

/**
 * ===  FUNCTION  ======================================================================
 *         Name:  getFile
 *  Description:  Get a file from the server
 *	@param source a path to the source file
 *      @param dest a path to the destination file
 * =====================================================================================
 */
static void getFile(char *source, char *dest) {

  setUpClientSocket(&socket,&eid);
  startClientProtocol(socket,source,dest);
  shutdownSocket(socket,eid);
}

int main(int argc, char **argv) {

  char *source;
  char *dest;

  if (argc == 3 ) {
    source = verifyPath(argv[1]);
    if (source == NULL) {
      fprintf(stderr,"Invalid path specification %s\n",argv[1]);
      exit(-1);
    }

    dest = verifyPath(argv[2]);
    if (dest == NULL) {
      fprintf(stderr,"Invalid path specification %s\n",argv[2]);
      exit(-1);
    }

    getFile(source,dest);
  }

}
