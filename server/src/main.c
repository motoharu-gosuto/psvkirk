#include <stdio.h>
#include <malloc.h>

#include <psp2/net/net.h>
#include <psp2/net/netctl.h>
#include <psp2/sysmodule.h>
#include <psp2/kernel/processmgr.h>

#include <psvkirk.h>

#include "debugScreen.h"

//net initialization part is taken from xerpi:
//https://gist.github.com/xerpi/e426284df19c217a8128

//also some usefull info here:
//https://github.com/xerpi/libftpvita/blob/master/libftpvita/ftpvita.c
//https://github.com/psxdev/debugnet/blob/master/libdebugnet/source/debugnet.c
 
//some refresher info about sockets here
//http://stackoverflow.com/questions/16486361/creating-a-basic-c-c-tcp-socket-writer
//http://matrixsust.blogspot.ru/2011/10/basic-tcp-server-client.html
//http://www.linuxhowtos.org/C_C++/socket.htm

#define NET_INIT_SIZE 1*1024*1024
 
int _kirk_sock = 0;
void *net_memory = NULL;

int kirk_port = 1330;
 
char* kirk_sock_name = "kirkproxy";
 
int _cli_sock = 0;

int init_net()
{
  if (sceNetShowNetstat() == SCE_NET_ERROR_ENOTINIT) 
  {
      net_memory = malloc(NET_INIT_SIZE);

      SceNetInitParam initparam;
      initparam.memory = net_memory;
      initparam.size = NET_INIT_SIZE;
      initparam.flags = 0;

      sceNetInit(&initparam);
      sceKernelDelayThread(100 * 1000);
      
      psvDebugScreenPrintf("psvkirk: net initialized\n");
  }
  
  if (sceNetCtlInit() < 0)
  {
    psvDebugScreenPrintf("psvkirk: faild to initialize netctl\n");
    return -1;
  }
  
  psvDebugScreenPrintf("psvkirk: netctl initialized\n");
     
  SceNetSockaddrIn server;
    
  server.sin_len = sizeof(server);
  server.sin_family = SCE_NET_AF_INET;
  server.sin_addr.s_addr = SCE_NET_INADDR_ANY;
  server.sin_port = sceNetHtons(kirk_port);
  
  memset(server.sin_zero, 0, sizeof(server.sin_zero));

  _kirk_sock = sceNetSocket(kirk_sock_name, SCE_NET_AF_INET, SCE_NET_SOCK_STREAM, 0);
  if(_kirk_sock < 0)
  {
    psvDebugScreenPrintf("psvkirk: failed to create socket\n");
    return -1;
  }
  
  psvDebugScreenPrintf("psvkirk: server socket created\n");
    
  int bind_res = sceNetBind(_kirk_sock, (SceNetSockaddr*)&server, sizeof(server));
  if(bind_res < 0)
  {
    psvDebugScreenPrintf("psvkirk: failed to bind socket %x\n", bind_res);
    return -1;
  }
  
  SceNetCtlInfo info;
  if (sceNetCtlInetGetInfo(SCE_NETCTL_INFO_GET_IP_ADDRESS, &info) < 0)
  {
    psvDebugScreenPrintf("psvkirk: failed to get network info\n");
    return -1;
  }
  
  psvDebugScreenPrintf("psvkirk: server socket binded %s:%d\n", info.ip_address, kirk_port);
   
  if(sceNetListen(_kirk_sock, 128) < 0)
  {
    psvDebugScreenPrintf("psvkirk: failed to listen socket\n");
    return -1;
  }
  
  psvDebugScreenPrintf("psvkirk: listening for connection\n");
  
  return 0;
}

void deinit_net()
{
  if(_cli_sock)
  {
    if(sceNetSocketClose(_cli_sock) < 0)
      psvDebugScreenPrintf("psvkirk: failed to close client socket\n");
    _cli_sock = 0;
  }
 
  if (_kirk_sock) 
  {
    if(sceNetSocketClose(_kirk_sock) < 0)
      psvDebugScreenPrintf("psvkirk: failed to close server socket\n");
    _kirk_sock = 0;
  }
  
  sceNetCtlTerm();
  
  sceNetTerm();
  
  if (net_memory) 
  {
    free(net_memory);
    net_memory = NULL;
  }
}

#define PSVKIRK_COMMAND_PING 0
#define PSVKIRK_COMMAND_TERM 1
#define PSVKIRK_COMMAND_GEN10 2
#define PSVKIRK_COMMAND_GEN20 3
#define PSVKIRK_COMMAND_KIRK 4
 
#pragma pack(push, 1)

typedef struct command_0_request
{
  int command;
} command_0_request;
 
typedef struct command_0_response
{
    int command;
    int vita_err;
    int proxy_err;
    char data[10];
} command_0_response;

typedef struct command_1_request
{
  int command;
} command_1_request;

typedef struct command_1_response
{
    int command;
    int vita_err;
    int proxy_err;
    char data[10];
} command_1_response;
 
typedef struct command_2_request
{
  int command;
} command_2_request;

typedef struct command_2_response
{
    int command;
    int vita_err;
    int proxy_err;
    char data[0x10];
} command_2_response;

typedef struct command_3_request
{
  int command;
} command_3_request;

typedef struct command_3_response
{
    int command;
    int vita_err;
    int proxy_err;
    char data[0x20];
} command_3_response;
 
typedef struct command_4_request
{
    int command;
    int kirk_command;
    int size;
    int kirk_param;
    char data[0x800]; //max is 116
} command_4_request;
 
typedef struct command_4_response
{
    int command;
    int vita_err;
    int proxy_err;
    int size;
    char data[0x800]; //max is 0x34
} command_4_response;
 
#pragma pack(pop)

int handle_command_0()
{
  command_0_response resp;
  memset(&resp, 0, sizeof(command_0_response));
  resp.command = PSVKIRK_COMMAND_PING;
  memcpy(resp.data, "kirkproxy", 9);
  
  psvDebugScreenPrintf("psvkirk: execute command 0\n");

  return sceNetSend(_cli_sock, &resp, sizeof(command_0_response), 0);
}

int handle_command_1()
{
  command_1_response resp;
  memset(&resp, 0, sizeof(command_1_response));
  resp.command = PSVKIRK_COMMAND_TERM;
  memcpy(resp.data, "kirkproxy", 9);
  
  psvDebugScreenPrintf("psvkirk: execute command 1\n");

  return sceNetSend(_cli_sock, &resp, sizeof(command_1_response), 0);
}
 
int handle_command_2()
{
  command_2_response resp;
  memset(&resp, 0, sizeof(command_2_response));
  resp.command = PSVKIRK_COMMAND_GEN10;
  
  psvDebugScreenPrintf("psvkirk: execute command 2\n");

  resp.proxy_err = psvkirkGenerate10(resp.data);
    
  if(resp.proxy_err != 0)
  {
    psvDebugScreenPrintf("psvkirk: failed to execute command 2\n");
  }

  return sceNetSend(_cli_sock, &resp, sizeof(command_2_response), 0);
}
 
int handle_command_3()
{
  command_3_response resp;
  memset(&resp, 0, sizeof(command_3_response));
  resp.command = PSVKIRK_COMMAND_GEN20;
  
  psvDebugScreenPrintf("psvkirk: execute command 3\n");

  resp.proxy_err = psvkirkGenerate20(resp.data);
    
  if(resp.proxy_err != 0)
  {
    psvDebugScreenPrintf("psvkirk: failed to execute command 3\n");
  }
    
  return sceNetSend(_cli_sock, &resp, sizeof(command_3_response), 0);
}
 
int handle_command_4(command_4_request* req)
{  
  command_4_response resp;
  memset(&resp, 0, sizeof(command_4_response));
  resp.command = PSVKIRK_COMMAND_KIRK;
  
  psvDebugScreenPrintf("psvkirk: execute command 4\n");
  
  psvDebugScreenPrintf("calling with args %x %x %x\n", req->kirk_command, req->size, req->kirk_param);
    
  kirk1000B_params params;
  params.command = req->kirk_command;
  params.size = req->size;
  params.packet6_de = req->kirk_param;
  params.respSize = &resp.size;
  
  resp.proxy_err = psvkirkCallService1000B(resp.data, req->data, &params);
    
  if(resp.proxy_err != 0)
  {
    psvDebugScreenPrintf("psvkirk: failed to execute command 4 with error: %x\n", resp.proxy_err);
  }
    
  int bytesToSend = sizeof(command_4_response);
  int bytesWereSend = 0;
  while(bytesWereSend != bytesToSend)
  {
     int sendLen = sceNetSend(_cli_sock, ((char*)&resp) + bytesWereSend, bytesToSend - bytesWereSend, 0);
     if(sendLen <= 0)
     {
        psvDebugScreenPrintf("psvkirk: failed to send data\n");
        return - 1;
     }
     
     bytesWereSend = bytesWereSend + sendLen;
  }
  
  return 0;
}

void receive_commands()
{
  while(1)
  {
    int command = -1;
    int recvLen = sceNetRecv(_cli_sock, &command, sizeof(int), 0);
    if(recvLen <= 0)
    {
      psvDebugScreenPrintf("psvkirk: failed to receive data\n");
      return;
    }
	  
    switch(command)
    {
    case PSVKIRK_COMMAND_PING:
       if(handle_command_0() < 0)
       {
	 psvDebugScreenPrintf("psvkirk: failed to handle command 0\n");
	 return;
       }
      break;
    case PSVKIRK_COMMAND_TERM:
      if(handle_command_1() < 0)
      {
	psvDebugScreenPrintf("psvkirk: failed to handle command 1\n");
	return;
      }
      return;
    case PSVKIRK_COMMAND_GEN10:
      if(handle_command_2() < 0)
      {
	psvDebugScreenPrintf("psvkirk: failed to handle command 2\n");
	return;
      }
      break;
    case PSVKIRK_COMMAND_GEN20:
      if(handle_command_3() < 0)
      {
	psvDebugScreenPrintf("psvkirk: failed to handle command 3\n");
	return;
      }
      break;
    case PSVKIRK_COMMAND_KIRK:
      {
         command_4_request recvBuffer;
         recvBuffer.command = command;

         int bytesToReceive = (sizeof(command_4_request) - sizeof(int));
         int bytesWereReceived = 0;
         while(bytesWereReceived != bytesToReceive)
         {
            int recvLen4 = sceNetRecv(_cli_sock, (((char*)&recvBuffer) + sizeof(int) + bytesWereReceived), bytesToReceive - bytesWereReceived, 0);
            if(recvLen4 <= 0)
            {
              psvDebugScreenPrintf("psvkirk: failed to receive data\n");
              return;
            }
            bytesWereReceived = bytesWereReceived + recvLen4;
         }

        if(handle_command_4(&recvBuffer) < 0)
        {
          psvDebugScreenPrintf("psvkirk: failed to handle command 4\n");
          return;
        }
      }
      break;
    default:
      psvDebugScreenPrintf("psvkirk: unknown command\n");
      return;
    }
  }
}

void accept_single_connection()
{
  while(1)
  {
    SceNetSockaddrIn client;
    memset(&client, 0, sizeof(client));
    client.sin_len = sizeof(client);

    unsigned int sin_size = sizeof(client);
    _cli_sock = sceNetAccept(_kirk_sock, (SceNetSockaddr*)&client, &sin_size);
    if(_cli_sock < 0)
    {
	psvDebugScreenPrintf("psvkirk: failed to accept socket'\n");
	return;
    }
	
    char ipstr[16];
    psvDebugScreenPrintf("psvkirk: Accepted connection from %s:%d\n", sceNetInetNtop(SCE_NET_AF_INET, &client.sin_addr, ipstr, 16), sceNetNtohs(client.sin_port));

    receive_commands();
    
    if(_cli_sock)
    {
      if(sceNetSocketClose(_cli_sock) < 0)
	psvDebugScreenPrintf("psvkirk: failed to close client socket\n");
      _cli_sock = 0;
    }
    
    psvDebugScreenPrintf("psvkirk: closed client socket\n");
  }
}


int main(int argc, char *argv[]) 
{
  psvDebugScreenInit();

  psvDebugScreenPrintf("psvkirk: server started\n");

  if (sceSysmoduleIsLoaded(SCE_SYSMODULE_NET) != SCE_SYSMODULE_LOADED)
  {
    if(sceSysmoduleLoadModule(SCE_SYSMODULE_NET) < 0)
    {
      psvDebugScreenPrintf("psvkirk: failed to load net module\n");
      return 1;
    }
  }
  
  if(init_net() >= 0)
  {
    accept_single_connection();
  }
  
  deinit_net();


  psvDebugScreenPrintf("psvkirk: server stopped\n");

  sceKernelDelayThread(10*1000*1000);

  sceKernelExitProcess(0);
  return 0;
}
