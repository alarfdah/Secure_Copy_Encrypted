#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <pwd.h>

#include <systemFuncs.h>

#include <pwd.h>

/** 
 * ===  FUNCTION  ======================================================================
 *         Name:  getUserName
 *  Description:  get the name of a user from the password entry
 *
 *	@return the name of the user for this program
 * =====================================================================================
 */
char *getUserName() {

  struct passwd *info = getpwuid(getuid());

  if (info == NULL) {
    fprintf(stderr,"Error finding passwd entry\n");
    exit(-1);
  }

  return info->pw_name;
}
