#include <stdio.h>
#include <stdlib.h>

#include <exit.h>
#include <message.h>

extern int socket; // a socket for communication
extern int eid; // eid for a socket`
extern FILE *destFile; // a destination file

/** 
 * ===  FUNCTION  ======================================================================
 *         Name:  exitProgram
 *  Description:  print an error message and exit a program 
 *
 *	@param msg an error message
 * =====================================================================================
 */
void exitProgram(char *msg) {

   fprintf(stderr,"%s\n",msg);
   shutdownSocket(socket,eid);
   if (destFile != NULL)
     fclose(destFile);
   exit(-1);
}
