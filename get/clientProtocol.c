#include <stdio.h>
#include <string.h>

#include <util/message.h>
#include <util/systemFuncs.h>
#include <util/exit.h>
#include <clientProtocol.h>

extern FILE *destFile; /* The destination file */

static char sessionId[SID_LENGTH+1]; /* The session id */

/** 
 * ===  FUNCTION  ======================================================================
 *         Name:  invalidMessage
 *  Description:  Send a type 2 message and exit the program
 *
 *	@param socket a socket for communicating with the server
 *	@param mType the type of message that was invalid
 * =====================================================================================
 */
static void invalidMessage(int socket, int mType) {
    char errorMsg[32];

    snprintf(errorMsg,32,"Invalid message type: %c",mType);
    sendMessageType2(socket,errorMsg);
    exitProgram(errorMsg);
}

/** 
 * ===  FUNCTION  ======================================================================
 *         Name:  setSessionId
 *  Description:  set the session id 
 *
 *	@param msg the type 1 message containing the session id
 * =====================================================================================
 */
static void setSessionId(MessageType1 *msg) {
  strncpy(sessionId,msg->sessionId,msg->sidLength);
  sessionId[msg->sidLength] = '\0';

}

/** 
 * ===  FUNCTION  ======================================================================
 *         Name:  emitType2MessageAndExit
 *  Description:  emit a type 2 message received from the server to the console and exit
 *	
 *	@param msg a type 2 message
 * =====================================================================================
 */
static void emitType2MessageAndExit(MessageType2 *msg) {
  char buffer[MAX_ERROR_MESSAGE+1];
  char errorMsg[MAX_ERROR_MESSAGE+8];

  strncpy(buffer,msg->errorMessage,msg->msgLength);
  buffer[msg->msgLength] = '\0';
  snprintf(errorMsg,MAX_ERROR_MESSAGE+8, "Error: %s\n",buffer);
  exitProgram(errorMsg);
}

/** 
 * ===  FUNCTION  ======================================================================
 *         Name:  processType1Message
 *  Description:  process a type 1 message from the server
 *
 *	@param socket a socket for communicating with the server
 *	@param msg a type 1 message received from the server
 * =====================================================================================
 */
static void processType1Message(int socket, char *msg) {
  unsigned char mType = getMessageType(msg);

  if (mType == TYPE1)
    setSessionId((MessageType1 *)msg);
  else if (mType == TYPE2) {
    emitType2MessageAndExit((MessageType2 *)msg);
  }
  else
    invalidMessage(socket,mType);

}

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  processFileContents
 *  Description:  process the (partial) contents of a file received from the server
 *
 *	@param socket a socket for communicating with the server
 *	@param msg a message received from the server
 *      @param numBytes the number of bytes in the message
 * =====================================================================================
 */
static bool processFileContents(int socket,char *msg, int numBytes) {
  unsigned char mType = getMessageType(msg);

  // if the message is type 5, the full file has been received 
  if (mType == TYPE5)
    return true;

  // if the message is type 4, process the contents and write to a file if no errors
  else if (mType == TYPE4) {
     MessageType4 *t4Msg = (MessageType4 *)msg;
     // validate the session id
     if (!strncmp(sessionId,t4Msg->sessionId,t4Msg->sidLength)) {
       // write the contents to the file
       int nItems = fwrite(t4Msg->contentBuffer,sizeof(char),t4Msg->contentLength,destFile);
       if (nItems < t4Msg->contentLength) {
         // a write error occurred, notify the server and exit.
         char errorMsg[32];
         snprintf(errorMsg,32,"File I/O error on write\n");
         sendMessageType2(socket,errorMsg);
	 exitProgram(errorMsg);
       } else {
         DEBUGL(printf("Wrote %d bytes\n",nItems));
       }
     }
     else {

	// invalid session id

       char buffer[MAX_ERROR_MESSAGE+1];
       char errorMsg[MAX_ERROR_MESSAGE+33];
       memcpy(buffer,t4Msg->sessionId,t4Msg->sidLength);
       buffer[t4Msg->sidLength] = '\0';
       snprintf(errorMsg,MAX_ERROR_MESSAGE+33,"Invalid session id in Type 4 msg: %s\n",sessionId);
       sendMessageType2(socket,errorMsg);
       exitProgram(errorMsg);
     }
  }
 
  // process an error message from the server 

  else if (mType == TYPE2) {
    emitType2MessageAndExit((MessageType2 *)msg);
  }

  // an invalid message type was received
  else
    invalidMessage(socket,mType);

  return false;

}

/** 
 * ===  FUNCTION  ======================================================================
 *         Name:  receiveFile
 *  Description:  loop to receive the contents of a file from the server
 *
 *	@param socket a socket to communicate with the server
 *      @param destPath the full path to the destination file
 * =====================================================================================
 */
static void receiveFile(int socket, char *destPath) {
  bool end = false;
  int numBytes;

  destFile = fopen(destPath,"w+");

  if (destFile == NULL) {

    // error opening the destination file

    char errorMsg[32];
    snprintf(errorMsg,32,"Invalid destination file %s\n",destPath);
    sendMessageType2(socket,errorMsg);
    exitProgram(errorMsg);
  }

  // loop until the full file has been received
  while (!end) {
    char *msg = getValidMessage(socket,&numBytes);
    if (msg == NULL) {
      sendMessageType2(socket,"Message receive timed out");
      exitProgram("Message receive timed out");
    }
    end = processFileContents(socket,msg,numBytes);
    sendMessageType6(socket,sessionId);
  }

  if (fclose(destFile) != 0) {
    perror("Error: ");
    exitProgram("");
  }
}

/** 
 * ===  FUNCTION  ======================================================================
 *         Name:  startClientProtocol
 *  Description:  do the client end of the protocol to receive a file from a server
 *
 *	@param socket a socket to communicate with the server
 *      @param sourcePath a full path to the source file
 *	@param destpath a full path to the destination file
 * =====================================================================================
 */
void startClientProtocol(int socket, char *sourcePath, char *destPath) {
  int numBytes;
  char *msg;

  sendMessageType0(socket,getUserName());

  msg = getValidMessage(socket,&numBytes);
  if (msg == NULL) {
    sendMessageType2(socket,"Message receive timed out");
    exitProgram("Message receive timed out");
  }

  processType1Message(socket,msg);

  sendMessageType3(socket, sessionId, sourcePath);

  receiveFile(socket,destPath);
}
