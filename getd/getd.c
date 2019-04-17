#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <util/message.h>
#include <util/exit.h>

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>

int socket; // a socket to communicate with the  client
int eid;
char dn[DN_LENGTH+1]; // the distinguished name of the client
char sessionId[SID_LENGTH+1]; // the current session id
FILE *destFile; // the destination file name (for linking purposes only)

/**
 * ===  FUNCTION  ======================================================================
 *         Name:  sendFileContents
 *  Description:  send the contents of the file to the client
 *
 *	@param socket a socket to communicate with the client
 *      @param contents the contents (partial) of a file
 *	@param contentLength the length of the contents to send
 * =====================================================================================
 */
static bool sendFileContents(int socket,char *contents, int contentLength) {
    char buffer[MAX_CONTENT_LENGTH];
    int numBytes;

    memcpy(buffer,contents,contentLength);
    DEBUGL(printf("Sending %d bytes\n",contentLength));
    sendMessageType4(socket,sessionId,buffer,contentLength);
    char *msg = getValidMessage(socket,&numBytes, ENUM_BLOWFISH);
    if (getMessageType(msg) != TYPE6) {
      sendMessageType2(socket,"Expected Type 6 message");
      return false;
    }
    else if (strncmp(sessionId,((MessageType6*)msg)->sessionId,SID_LENGTH+1)) {
        DEBUGL(printf("Session Id = %s\n",sessionId));
        sendMessageType2(socket,"Received Type 6 message with invalid session Id");
        return false;
    }
    return true;
}

/**
 * ===  FUNCTION  ======================================================================
 *         Name:  fillBuffer
 *  Description:  read the file by character and fill the buffer
 *
 * 	@param buffer the buffer to hold the (partial) file contents
 *	@param fd the file descriptor for the source file
 * =====================================================================================
 */
static int fillBuffer(char *buffer,FILE *fd) {
  int num_chars = 0;
  int c;

  while (num_chars < MAX_CONTENT_LENGTH) {
    c = fgetc(fd);
    if (c != EOF)
      buffer[num_chars++] = (unsigned char)c;
    else
      break;
    }

  return num_chars;
}

/**
 * ===  FUNCTION  ======================================================================
 *         Name:  readAndSendFile
 *  Description:  read a file and send the contents to the client
 *
 * 	@param socket a socket for communicating with a client
 *	@param sourcePath a path to the source file
 * =====================================================================================
 */
static bool readAndSendFile(int socket,char *sourcePath) {
  FILE *fd = fopen(sourcePath,"r");
  if (fd == NULL) {
    sendMessageType2(socket,"File Error");
    return false;
  }

  int c;
  unsigned char *buffer = (unsigned char *)malloc(MAX_CONTENT_LENGTH+1);

  if (buffer == NULL) {
    sendMessageType2(socket,"Fatal error in getd");
    return false;
  }

  int num_chars;
  bool success = true;
  while ((num_chars = fillBuffer(buffer,fd)) == MAX_CONTENT_LENGTH &&
         (success = sendFileContents(socket,buffer,MAX_CONTENT_LENGTH)));

  if (success)
    success = sendFileContents(socket,buffer,num_chars);

  return success;

}

/**
 * ===  FUNCTION  ======================================================================
 *         Name:  readRSAPublicKey
 *  Description:  reads the public rsa key using the file path passed by message TYPE0
 *
 * 	@param socket a socket for communicating with a client
 *	@param sourcePath a path to the source file
 * =====================================================================================
 */
static bool readRSAPublicKey(int socket, char *rsa_path, RSA **key) {
  FILE *fp = fopen(rsa_path,"r");
  printf("PATH: %s\n", rsa_path);
  if (fp == NULL) {
    sendMessageType2(socket,"File Error");
    return false;
  }

  (*key) = PEM_read_RSA_PUBKEY(fp, key, NULL, NULL);
  if ((*key) == NULL) {
    sendMessageType2(socket,"Public Key Error");
    return false;
  }

  return true;
}

int main(const int argc, const char **argv) {
  RSA *rsa_public_key = RSA_new();
  setUpServerSocket(&socket,&eid);
  while(true) {
    int msgLength;

    char *msg = getValidMessage(socket,&msgLength, ENUM_NONE);

    if (getMessageType(msg) != TYPE0) {
      sendMessageType2(socket,"Expected TYPE 0 Message");
      shutdownSocket(socket,eid);
      continue;
    }

    DEBUGL(printf("DN = %s\n",((MessageType0*)msg)->distinguishedName));

    strcpy(sessionId,"0123456789abcedfghijklmnopqrstuv0123456789abcedfghijklmnopqrstuv0123456789abcedfghijklmnopqrstuv0123456789abcedfghijklmnopqrstuv");
    DEBUGL(printf("sessionId = %s\n",sessionId));


    if (!readRSAPublicKey(socket,((MessageType0 *)msg)->publicKey, &rsa_public_key)) {
      sendMessageType2(socket,"ERROR: UNABLE TO PROCESS RSA PUBLIC KEY");
      continue;
    }

    sendMessageType1(socket,sessionId,rsa_public_key);

    msg = getValidMessage(socket,&msgLength, ENUM_BLOWFISH);

    int mType = getMessageType(msg);

    if (mType != TYPE3) {
      sendMessageType2(socket,"Expected Type 3 message");
      shutdownSocket(socket,eid);
      continue;
    }

    MessageType3 *t3Msg = (MessageType3*)msg;
    DEBUGL(printf("Request session id = %s\n",t3Msg->sessionId));
    DEBUGL(printf("Request file path = %s\n",t3Msg->pathName));

    if (!strncmp(sessionId,t3Msg->sessionId,SID_LENGTH+1))
      readAndSendFile(socket, t3Msg->pathName);
    else {
      sendMessageType2(socket,"Invalid sessionId");
      shutdownSocket(socket,eid);
      continue;
    }

    sendMessageType5(socket,sessionId);
    msg = getValidMessage(socket,&msgLength, ENUM_BLOWFISH);
    if (getMessageType(msg) != TYPE6) {
      sendMessageType2(socket,"Expected Type 6 message");
    }
    else if (strcmp(sessionId,((MessageType6*)msg)->sessionId) != 0) {
      sendMessageType2(socket,"Invalid session Id");
    }
  }
  shutdownSocket(socket,eid);
}
