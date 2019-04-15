#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <message.h>
#include <nanomsg/nn.h>
#include <nanomsg/pair.h>
#include <exit.h>
#include <util/string_util.h>

/** 
 * ===  FUNCTION  ======================================================================
 *         Name:  getMessageType
 *  Description:  Get the type of the message from the buffer
 *
 *	@param msg a message buffer
 *      @return the type of the message in the buffer
 * =====================================================================================
 */
unsigned char getMessageType (char *msg) {
   return ((Header *)msg)->messageType;
}

/** 
 * ===  FUNCTION  ======================================================================
 *         Name:  getMessageLength
 *  Description:  Get the length of a message from the header
 *
 *	@param msg a message buffer
 *	@return the length of the message from the header
 * =====================================================================================
 */
static unsigned int getMessageLength (char *msg) {
   return ((Header *)msg)->messageLength;
}

/** 
 * ===  FUNCTION  ======================================================================
 *         Name:  verifyType0Message
 *  Description:  verify the format of a type 0 message
 *	
 *	@param msg a message buffer
 *	@param msgLength the length of the message
 * =====================================================================================
 */
static void verifyType0Message(char *msg, int msgLength) {
   MessageType0 *message = (MessageType0 *)msg;

   if (msgLength != sizeof(MessageType0) || message->header.messageLength != sizeof(MessageType0))
     messageError(INVALID_TYPE0_MSG,msg);
}

/** 
 * ===  FUNCTION  ======================================================================
 *         Name:  verifyType1Message
 *  Description:  verify the format of a type 1 message
 *	
 *	@param msg a message buffer
 *	@param msgLength the length of the message
 * =====================================================================================
 */
static void verifyType1Message(char *msg, int msgLength) {
   MessageType1 *message = (MessageType1 *)msg;

   if (msgLength != sizeof(MessageType1) || message->header.messageLength != sizeof(MessageType1))
     messageError(INVALID_TYPE1_MSG,msg);
   else if (message->sidLength != SID_LENGTH)
     messageError(INVALID_TYPE1_MSG,msg);
   else if (strnlen(message->sessionId,SID_LENGTH+1) != SID_LENGTH)
     messageError(INVALID_TYPE1_MSG,msg);
}

/** 
 * ===  FUNCTION  ======================================================================
 *         Name:  verifyType2Message
 *  Description:  verify the format of a type 2 message
 *	
 *	@param msg a message buffer
 *	@param msgLength the length of the message
 * =====================================================================================
 */
static void verifyType2Message(char *msg, int msgLength) {
   MessageType2 *message = (MessageType2*)msg;

   if (msgLength != sizeof(MessageType2) || message->header.messageLength != sizeof(MessageType2))
     messageError(INVALID_TYPE2_MSG,msg);
   else if (message->msgLength == 0 || message->msgLength > MAX_ERROR_MESSAGE)
     messageError(INVALID_TYPE2_MSG,msg);
   else if (message->msgLength != strnlen(message->errorMessage,MAX_ERROR_MESSAGE+1))
     messageError(INVALID_TYPE2_MSG,msg);
}

/** 
 * ===  FUNCTION  ======================================================================
 *         Name:  verifyType3Message
 *  Description:  verify the format of a type 3 message
 *	
 *	@param msg a message buffer
 *	@param msgLength the length of the message
 * =====================================================================================
 */
static void verifyType3Message(char *msg, int msgLength) {
   MessageType3 *message = (MessageType3*)msg;

   if (msgLength != sizeof(MessageType3) || message->header.messageLength != sizeof(MessageType3))
     messageError(INVALID_TYPE3_MSG,msg);
   else if (message->sidLength != SID_LENGTH)
     messageError(INVALID_TYPE3_MSG,msg);
   else if (strnlen(message->sessionId,SID_LENGTH+1) != SID_LENGTH)
     messageError(INVALID_TYPE3_MSG,msg);
   else if (message->pathLength == 0 || message->pathLength > PATH_MAX)
     messageError(INVALID_TYPE3_MSG,msg);
   else if (message->pathLength != strnlen(message->pathName,PATH_MAX+1))
     messageError(INVALID_TYPE3_MSG,msg);
}

/** 
 * ===  FUNCTION  ======================================================================
 *         Name:  verifyType4Message
 *  Description:  verify the format of a type 4 message
 *	
 *	@param msg a message buffer
 *	@param msgLength the length of the message
 * =====================================================================================
 */
static void verifyType4Message(char *msg, int msgLength) {
   MessageType4 *message = (MessageType4*)msg;

   if (msgLength != sizeof(MessageType4) || message->header.messageLength != sizeof(MessageType4))
     messageError(INVALID_TYPE4_MSG,msg);
   else if (message->sidLength != SID_LENGTH)
     messageError(INVALID_TYPE4_MSG,msg);
   else if (strnlen(message->sessionId,SID_LENGTH+1) != SID_LENGTH)
     messageError(INVALID_TYPE4_MSG,msg);
   else if (message->contentLength == 0 || message->contentLength > MAX_CONTENT_LENGTH)
     messageError(INVALID_TYPE4_MSG,msg);
}

/** 
 * ===  FUNCTION  ======================================================================
 *         Name:  verifyType5Message
 *  Description:  verify the format of a type 5 message
 *	
 *	@param msg a message buffer
 *	@param msgLength the length of the message
 * =====================================================================================
 */
static void verifyType5Message(char *msg, int msgLength) {
   MessageType5 *message = (MessageType5*)msg;

   if (msgLength != sizeof(MessageType5) || message->header.messageLength != sizeof(MessageType5))
     messageError(INVALID_TYPE5_MSG,msg);
   else if (message->sidLength != SID_LENGTH)
     messageError(INVALID_TYPE5_MSG,msg);
   else if (strnlen(message->sessionId,SID_LENGTH+1) != SID_LENGTH)
     messageError(INVALID_TYPE5_MSG,msg);
}

/** 
 * ===  FUNCTION  ======================================================================
 *         Name:  verifyType6Message
 *  Description:  verify the format of a type 6 message
 *	
 *	@param msg a message buffer
 *	@param msgLength the length of the message
 * =====================================================================================
 */
static void verifyType6Message(char *msg, int msgLength) {
   MessageType6 *message = (MessageType6*)msg;

   if (msgLength != sizeof(MessageType6) || message->header.messageLength != sizeof(MessageType6))
     messageError(INVALID_MESSAGE_TYPE,msg);
   else if (message->sidLength != SID_LENGTH)
     messageError(INVALID_TYPE6_MSG,msg);
   else if (strnlen(message->sessionId,SID_LENGTH+1) != SID_LENGTH)
     messageError(INVALID_TYPE5_MSG,msg);
}

/** 
 * ===  FUNCTION  ======================================================================
 *         Name:  verifyType7Message
 *  Description:  verify the format of a type 7 message
 *	
 *	@param msg a message buffer
 *	@param msgLength the length of the message
 * =====================================================================================
 */
static void verifyType7Message(char *msg, int msgLength) {

   messageError(INVALID_MESSAGE_TYPE,msg);
}

/** 
 * ===  FUNCTION  ======================================================================
 *         Name:  verifyMessage
 *  Description:  verify the format of a message
 *	
 *	@param msg a message buffer
 *	@param msgLength the length of the message
 * =====================================================================================
 */
static void verifyMessage(char *msg, int msgLength) {

   switch(getMessageType(msg)) {

     case TYPE0:
       verifyType0Message(msg,msgLength);
       break;

     case TYPE1:
       verifyType1Message(msg,msgLength);
       break;

     case TYPE2:
       verifyType2Message(msg,msgLength);
       break;

     case TYPE3:
       verifyType3Message(msg,msgLength);
       break;

     case TYPE4:
       verifyType4Message(msg,msgLength);
       break;

     case TYPE5:
       verifyType5Message(msg,msgLength);
       break;

     case TYPE6:
       verifyType6Message(msg,msgLength);
       break;

     case TYPE7:
       verifyType7Message(msg,msgLength);
       break;

     default:
       messageError(INVALID_MESSAGE_TYPE,msg);
   }

}

/** 
 * ===  FUNCTION  ======================================================================
 *         Name:  getValidMessage
 *  Description:  receive a message and validiate it 
 *
 *	@param socket a socket for communcation
 *      @param msgLength a pointer to a integer for returning the message length
 *      @return a message if it is validated, if not the program exits
 * =====================================================================================
 */
char *getValidMessage(int socket,int *msgLength) {
  char *buff = NULL;

  DEBUGL(printf("Receiving message on socket %d\n",socket));
  int numBytes = nn_recv(socket,&buff,NN_MSG,0);

  if (numBytes < 0) {
    *msgLength = 0;
    return NULL;
  }

  if (numBytes < sizeof(Header))
     messageError(INVALID_MESSAGE_RECVD,buff);
  else if (numBytes != getMessageLength(buff))
     messageError(INVALID_MESSAGE_LENGTH,buff);

  char *msg = (char *)malloc(numBytes);
  memcpy(msg,buff,numBytes);

  if (nn_freemsg(buff))
    exitProgram("failure to free message buffer\n");

  verifyMessage(msg,numBytes);

  DEBUGL(printf("Received Type %u Message\n",((Header*)msg)->messageType));

  *msgLength = numBytes;

  return msg;
}

/** 
 * ===  FUNCTION  ======================================================================
 *         Name:  sendMessage
 *  Description:  send a message on the socket
 *	
 *	@param socket a socket for sending the message
 *	@param buff a message buffer
 *	@param size the size of the message in the buffer
 * =====================================================================================
 */
static void sendMessage(int socket, char *buff,unsigned int size) {
  void *msgBuffer = nn_allocmsg(size,0);

  memcpy(msgBuffer,buff,size);
  int numBytes = nn_send(socket, msgBuffer, size , 0);

  if (numBytes != size)
    exitProgram(nssave(2,"Send Error: ",nn_strerror(nn_errno())));
}

/** 
 * ===  FUNCTION  ======================================================================
 *         Name:  sendMessageType0
 *  Description:  send a type 0 message on the socket
 *
 *	@param socket a socket for sending a message
 *	@param distinguishedName the distinguished name of the client
 * =====================================================================================
 */
void sendMessageType0(int socket, char *distinguishedName) {

   MessageType0 *message = (MessageType0 *)malloc(sizeof(MessageType0));

   DEBUGL(printf("Server Sending Type 0 Message on socket %d\n",socket));

   if (message == NULL) {
     perror("Error: ");
     exit(-1);
   }

   unsigned int dn_length = strnlen(distinguishedName,DN_LENGTH+2);

   if (dn_length == 0 || dn_length > DN_LENGTH)
     messageError(INVALID_TYPE0_MSG,distinguishedName);

   message->dnLength = dn_length;
   strcpy(message->distinguishedName,distinguishedName);

   message->header.messageType = TYPE0;
   message->header.messageLength = sizeof(MessageType0);

   sendMessage(socket,(char *)message, sizeof(MessageType0));
}

/** 
 * ===  FUNCTION  ======================================================================
 *         Name:  sendMessageType1
 *  Description:  send a type 1 message on the socket
 *
 *	@param socket a socket on which to send the messge
 *	@param sessionId the unique session id
 * =====================================================================================
 */
void sendMessageType1(int socket, char *sessionId) {

   MessageType1 *message = (MessageType1 *)malloc(sizeof(MessageType1));

   DEBUGL(printf("Sending Type 1 Message\n"));

   if (message == NULL) {
     perror("Error: ");
     exit(-1);
   }

   unsigned int sidLength = strnlen(sessionId,SID_LENGTH+2);

   if (sidLength != SID_LENGTH)
     messageError(INVALID_TYPE1_MSG,sessionId);

   message->sidLength = sidLength;
   strcpy(message->sessionId,sessionId);

   message->header.messageType = TYPE1;
   message->header.messageLength = sizeof(MessageType1);

   sendMessage(socket,(char *)message, sizeof(MessageType1));
}

/** 
 * ===  FUNCTION  ======================================================================
 *         Name:  sendMessageType2
 *  Description:  send a type 2 message
 *
 *	@param socket the socket on which to send the message
 *	@param errorMessage the error message to send
 * =====================================================================================
 */
void sendMessageType2(int socket, char *errorMessage) {

   DEBUGL(printf("Sending Type 2 Message: %s\n",errorMessage));
   MessageType2 *message = (MessageType2 *)malloc(sizeof(MessageType2));

   if (message == NULL) {
     perror("Error: ");
     exit(-1);
   }

   int errorMsgLength = strnlen(errorMessage,MAX_ERROR_MESSAGE+2);

   if (errorMsgLength < 1 || errorMsgLength > MAX_ERROR_MESSAGE)
     messageError(INVALID_TYPE2_MSG,errorMessage);

   message->msgLength = errorMsgLength;
   strcpy(message->errorMessage,errorMessage);

   message->header.messageType = TYPE2;
   message->header.messageLength = sizeof(MessageType2);

   sendMessage(socket,(char *)message, sizeof(MessageType2));
}

/** 
 * ===  FUNCTION  ======================================================================
 *         Name:  sendMessageType3
 *  Description:  send a type 3 message
 *
 *	@param socket the socket on which to send the message
 *	@param sessionId the unique session id
 *	@param pathName the path to the source file
 * =====================================================================================
 */
void sendMessageType3(int socket, char *sessionId, char *pathName) {

   MessageType3 *message = (MessageType3 *)malloc(sizeof(MessageType3));

   DEBUGL(printf("Sending Type 3 Message\n"));

   if (message == NULL) {
     perror("Error: ");
     exit(-1);
   }

   unsigned int sidLength = strnlen(sessionId,SID_LENGTH+2);

   if (sidLength != SID_LENGTH)
     messageError(INVALID_TYPE3_MSG,sessionId);

   message->sidLength = sidLength;
   strcpy(message->sessionId,sessionId);

   unsigned int pathLength = strnlen(pathName,PATH_MAX+2);

   if (pathLength == 0 || pathLength > PATH_MAX)
     messageError(INVALID_TYPE3_MSG,pathName);

   message->pathLength = pathLength;
   strcpy(message->pathName,pathName);

   message->header.messageType = TYPE3;
   message->header.messageLength = sizeof(MessageType3);

   sendMessage(socket,(char *)message, sizeof(MessageType3));
}

/** 
 * ===  FUNCTION  ======================================================================
 *         Name:  sendMessageType4
 *  Description:  send a type 4 message
 *
 * 	@param socket the socket on which to send the message
 *	@param contentBuffer the contents of the file to send
 *	@param contentLength the length of the buffer
 * =====================================================================================
 */
void sendMessageType4(int socket, char *sessionId, char *contentBuffer, int contentLength) {

   MessageType4 *message = (MessageType4 *)malloc(sizeof(MessageType4));

   DEBUGL(printf("Sending Type 4 Message\n"));

   if (message == NULL) {
     perror("Error: ");
     exit(-1);
   }

   unsigned int sidLength = strnlen(sessionId,SID_LENGTH+2);

   if (sidLength != SID_LENGTH)
     messageError(INVALID_TYPE4_MSG,sessionId);

   message->sidLength = sidLength;
   strcpy(message->sessionId,sessionId);

   if (contentLength == 0 || contentLength > MAX_CONTENT_LENGTH)
     messageError(INVALID_TYPE4_MSG,contentBuffer);

   message->contentLength = contentLength;
   memcpy(message->contentBuffer,contentBuffer,contentLength);

   message->header.messageType = TYPE4;
   message->header.messageLength = sizeof(MessageType4);

   sendMessage(socket,(char *)message, sizeof(MessageType4));
}

/** 
 * ===  FUNCTION  ======================================================================
 *         Name:  sendMessageType5
 *  Description:  send a type 5  message
 *
 *	@param socket the socket on which to send the message
 *	@param sessionId the unique sessionId
 * =====================================================================================
 */
void sendMessageType5(int socket, char *sessionId) {

   MessageType5 *message = (MessageType5 *)malloc(sizeof(MessageType5));

   DEBUGL(printf("Sending Type 5 Message\n"));

   if (message == NULL) {
     perror("Error: ");
     exit(-5);
   }

   unsigned int sidLength = strnlen(sessionId,SID_LENGTH+2);

   if (sidLength != SID_LENGTH)
     messageError(INVALID_TYPE5_MSG,sessionId);

   message->sidLength = sidLength;
   strcpy(message->sessionId,sessionId);

   message->header.messageType = TYPE5;
   message->header.messageLength = sizeof(MessageType5);

   sendMessage(socket,(char *)message, sizeof(MessageType5));
}

/** 
 * ===  FUNCTION  ======================================================================
 *         Name:  sendMessageType5
 *  Description:  send a type 6 message
 *
 *	@param socket the socket on which to send the message
 *	@param sessionId the unique session id
 * =====================================================================================
 */
void sendMessageType6(int socket, char *sessionId) {

   MessageType6 *message = (MessageType6 *)malloc(sizeof(MessageType6));

   DEBUGL(printf("Sending Type 6 Message\n"));

   if (message == NULL) {
     perror("Error: ");
     exit(-1);
   }

   unsigned int sidLength = strnlen(sessionId,SID_LENGTH+2);

   if (sidLength != SID_LENGTH)
     messageError(INVALID_TYPE5_MSG,sessionId);

   message->sidLength = sidLength;
   strcpy(message->sessionId,sessionId);

   message->header.messageType = TYPE6;
   message->header.messageLength = sizeof(MessageType6);

   sendMessage(socket,(char *)message, sizeof(MessageType6));
}

static int timeout_val = 1000;

/** 
 * ===  FUNCTION  ======================================================================
 *         Name:  setUpClientSocket
 *  Description:  set up the socket for the client
 *
 *	@param socket a pointer to a socket
 *	@param eid a pointer to the eid for a socket
 * =====================================================================================
 */
void setUpClientSocket(int *socket, int *eid) {
  *socket = nn_socket(AF_SP,NN_PAIR);

  if (nn_setsockopt(*socket,NN_SOL_SOCKET,NN_RCVTIMEO,&timeout_val,sizeof(timeout_val)) == -1)
    *socket = -1;

  if (*socket == -1) {
    perror("Error: ");
    exit(-1);
  }

  *eid = nn_connect(*socket, IPC_ADDR);

  if (*eid < 0) {
    perror("Error: ");
    exit(-1);
  }

  DEBUGL(printf("Client Socket = %d, eid = %d\n",*socket,*eid));
}

/** 
 * ===  FUNCTION  ======================================================================
 *         Name:  setUpServerSocket
 *  Description:  set up a socket for the server
 *
 *	@param socket a pointer to a socket
 *	@param eid a pointer to an eid for the socket
 * =====================================================================================
 */
void setUpServerSocket(int *socket,int *eid) {

  *socket = nn_socket(AF_SP,NN_PAIR);

  if (*socket == -1) {
    perror("Error: ");
    exit(-1);
  }

  *eid = nn_bind(*socket, IPC_ADDR);

  if (*eid < 0) {
    perror("Error: ");
    exit(-1);
  }
  DEBUGL(printf("Server Socket = %d, eid = %d\n",*socket,*eid));
}

/** 
 * ===  FUNCTION  ======================================================================
 *         Name:  shutdownSocket
 *  Description:  shutdown a socket
 *
 *	@param socket a socket
 *	@param eid the eid for a socket
 * =====================================================================================
 */
void shutdownSocket(int socket, int eid) {

  if (nn_shutdown(socket,eid) < 0) {
    perror("Error: ");
    exit(-1);
  }
}

/** 
 * ===  FUNCTION  ======================================================================
 *         Name:  messageError
 *  Description:  construct and print an error message for a protocol error and exit
 *
 *	@param errorNumber the number of the error
 *	@param buff a message buffer
 * =====================================================================================
 */
void messageError(int errorNumber, char *buff) {

  int buffLength = strnlen(buff,8192) + 33 < 8192 ? strnlen(buff,8192) + 33 : 8192;
  char *errorMessage = (char *)malloc(buffLength);

  switch(errorNumber) {

    case INVALID_MESSAGE_RECVD:
      if (buff == NULL)
        snprintf(errorMessage,buffLength,"Null message\n");
      else
        snprintf(errorMessage,buffLength,"Message too small: %s\n",buff);
      break;

    case INVALID_MESSAGE_TYPE:
      snprintf(errorMessage,buffLength,"Invalid message type %c\n",getMessageType(buff));
      break;

    case INVALID_MESSAGE_LENGTH:
      snprintf(errorMessage,buffLength,"Invalid message length %u\n",getMessageLength(buff));
      break;

    case INVALID_TYPE0_MSG:
      snprintf(errorMessage,buffLength,"Invalid type 0 message %s\n",buff);
      break;

    case INVALID_TYPE1_MSG:
      snprintf(errorMessage,buffLength,"Invalid type 1 message %s\n",buff);
      break;

    case INVALID_TYPE2_MSG:
      snprintf(errorMessage,buffLength,"Invalid type 2 message %s\n",buff);
      break;

    case INVALID_TYPE3_MSG:
      snprintf(errorMessage,buffLength,"Invalid type 3 message %s\n",buff);
      break;

    case INVALID_TYPE4_MSG:
      snprintf(errorMessage,buffLength,"Invalid type 4 message %s\n",buff);
      break;

    case INVALID_TYPE5_MSG:
      snprintf(errorMessage,buffLength,"Invalid type 5 message %s\n",buff);
      break;

    case INVALID_TYPE6_MSG:
      snprintf(errorMessage,buffLength,"Invalid type 6 message %s\n",buff);
      break;

    case INVALID_TYPE7_MSG:
      snprintf(errorMessage,buffLength,"Invalid type 7 message %s\n",buff);
      break;

    default:
      snprintf(errorMessage,buffLength, "Invalid error number %u\n",errorNumber);
  }

  exitProgram(errorMessage);
}
