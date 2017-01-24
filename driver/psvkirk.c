#include "psvkirk.h"
 
//taihen plugin by yifanlu was used as a reference:
//https://github.com/yifanlu/taiHEN/blob/master/taihen.c
 
#include <psp2kern/types.h>
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/io/fcntl.h>

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define FILE_WRITE(f, msg) if(f >= 0) ksceIoWrite(f, msg, sizeof(msg))
#define FILE_WRITE_LEN(f, msg) if(f >= 0) ksceIoWrite(f, msg, strlen(msg))

SceUID global_log_fd;

void open_global_log()
{
  global_log_fd = ksceIoOpen("ux0:dump/psvkirk_dump.bin", SCE_O_CREAT | SCE_O_APPEND | SCE_O_WRONLY, 0777);  
}

void close_global_log()
{
  if(global_log_fd >= 0)
    ksceIoClose(global_log_fd);
}

//=================================================

#pragma pack(push, 1)

typedef struct elf_info_pair
{
  uint32_t size; // 0x0C
  char* elf_data; 
  uint32_t elf_size;
} elf_info_pair;

typedef struct sm_comm_pair
{
  int unk_0;
  int unk_4;
} sm_comm_pair;

typedef struct sm_comm_ctx_130
{
  uint32_t unk_0;
  uint32_t unk_4; //2
  char data0[0x90]; //hardcoded data
  char data1[0x90];
  uint32_t unk_128; //2
  uint32_t unk_12C;   
} sm_comm_ctx_130;

typedef struct sm_comm_context
{
  int unk_0; //0x01
  int gc_command;
  char gc_buffer[0x800];
  int gc_param;
  int length;
  int unk_810; //0x00
} sm_comm_context;

#pragma pack(pop)
 
//some reversed function definitions

int ksceSblSsMgrGenerate40(char* dest);


int ksceSysrootGetElfInfo(int index, elf_info_pair* state);


int ksceSblSmCommStartSm1(int num0, char* elf_data, int elf_size, int num1, sm_comm_ctx_130* ctx_130, int* id);

int ksceSblSmCommStartSm2(int num0, char* elf_path, int num1, sm_comm_ctx_130* ctx_130, int* id);

int ksceSblSmCommCallFunc(int id, int command_id, int* f00d_resp, sm_comm_context* buffer, int size);

int ksceSblSmCommStopSm(int id, sm_comm_pair* res);

//=================================================

//this part war created by reversing SceSblGcAuthMgr driver
 
//generates 0x10 bytes of data - partial reimplementation of sub_CA8E5C
int psvkirkGenerate10(char* destBuffer)
{
  char result[0x10];

  for(int i = 0; i < 0x10; i++)
  {
    char buffer[0x40];
    int res_0 = ksceSblSsMgrGenerate40(buffer);

    if(res_0 != 0)
      return 0x808A0700;
	  
    result[i] = buffer[0];
  }
    
  int res_1 = ksceKernelMemcpyKernelToUser((uintptr_t)destBuffer, result, 0x10);
  return res_1;
}
 
//generates 0x20 bytes of data - partial reimplementation of sub_CA2B4C
int psvkirkGenerate20(char* destBuffer)
{
  char buffer[0x40];
    
  int res_0 = ksceSblSsMgrGenerate40(buffer);
    
  if(res_0 != 0)
    return res_0;
    
  int res_1 = ksceKernelMemcpyKernelToUser((uintptr_t)destBuffer, buffer, 0x20);
  return res_1;
}

char dword_CADC10[0x90] = 
{
  0x01,0x00,0x00,0x00,
  0x00,0x00,0x08,0x28,
  0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,
  0x80,0x00,0x00,0x00,
  0xC0,0x00,0xF0,0x00,
  0x00,0x00,0x00,0x00,
  0xFF,0xFF,0xFF,0xFF,
  0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,
  0x80,0x09,0x80,0x03,
  0x00,0x00,0xC3,0x00,
  0x00,0x00,0x80,0x09,
  0x80,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,
  0xFF,0xFF,0xFF,0xFF,
  0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,
};
 
int exit_3(int* id, sm_comm_pair* result)
{
  if(id != 0 && result != 0)
  {
    result->unk_0 = -1;
    result->unk_4 = -1;
    return ksceSblSmCommStopSm(*id, result);
  }
  else
  {
    return 0x800F1816;
  }
}
 
int exit_2(int* id)
{
  sm_comm_pair result;

  if(id == 0)
    return 0x800F1816;

  if((*id) == -1)
    return 0x800F1816;

  int r0 = exit_3(id, &result);
  
  (*id) = -1;
  
  return r0;
}
 
int exit_1(int ret, int* id)
{
  if((*id) == -1)
    return ret;
      
  exit_2(id);
  return ret;
}
 
int copy_response(char* destination, char* source_user, int length, int* length_user, int ret, int* id)
{
  if(destination == 0 || length_user == 0)
    return exit_1(ret, id);

  if(length > 0)
  {
    int res_0 = ksceKernelMemcpyKernelToUser((uintptr_t)destination, source_user, length);
    if(res_0 < 0)
      return exit_1(res_0, id);

    int res_1 = ksceKernelMemcpyKernelToUser((uintptr_t)length_user, &length, sizeof(int));
    if(res_1 < 0)
      return exit_1(res_1, id);
  }

  return exit_1(ret, id);
}
 
int handle_response(int length, int command, int* id, char* source, char* destination, int* length_user)
{
    if(length > 0x800)
        return exit_1(0x10, id);
         
    switch(command)
    {
    case 0x1B:
    {
        if(length == 0x53)
            return copy_response(destination, source, length, length_user, 0, id);
        else
            return exit_1(0x10, id);
    }
    case 0x1C:
    {
        if(length == 0x33)
            return copy_response(destination, source, length, length_user, 0, id);
        else
            return exit_1(0x10, id);
    }
    case 0x1D:
    {
        if(length == 0xA3)
            return copy_response(destination, source, length, length_user, 0, id);
        else
            return exit_1(0x10, id);
    }
    case 0x1E:
    {
        if(length == 0x33)
            return copy_response(destination, source, length, length_user, 0, id);
        else
            return exit_1(0x10, id);
    }
    case 0x1F:
    {
        if(length == 0x20)
            return copy_response(destination, source, length, length_user, 0, id);
        else
            return exit_1(0x10, id);
    }
    case 0x20:
    {
        if(length == 0x34)
            return copy_response(destination, source, length, length_user, 0, id);
        else
            return exit_1(0x10, id);
    }
    default:
        return copy_response(destination, source, length, length_user, 0, id); 
    }
}

//this should not be on stack!
//looks like too much data corrupts the stack
sm_comm_context ctxg;

int psvkirkCallService1000B_internal(char* source_kernel, int cmd, int length, int packet6_de, char* destination, int* respSize)
{
  elf_info_pair elfData;
  elfData.size = sizeof(elf_info_pair);
  elfData.elf_data = 0x00;
  elfData.elf_size = 0x00;

  int res0 = ksceSysrootGetElfInfo(0, &elfData);
  if(res0 < 0)
    return 0x800F1816;
  
  sm_comm_ctx_130 ctx_130; // two structures of size ox98 ?
  memset(&ctx_130, 0x00, sizeof(sm_comm_ctx_130));
  memcpy(ctx_130.data0, dword_CADC10, 0x90);
  
  ctx_130.unk_4 = 0x02;
  ctx_130.unk_128 = 0x02;
   
  int id = -1; //id
     
  int res1 = ksceSblSmCommStartSm1(0x00, elfData.elf_data, elfData.elf_size, 0x00, &ctx_130, &id);
  
  if(res1 != 0)
    return exit_1(res1, &id);
   
  ctxg.unk_0 = 0x01;
  ctxg.gc_command = cmd;
  ctxg.gc_param = packet6_de;
  ctxg.length = length;
  ctxg.unk_810 = 0x00;
   
  memset(ctxg.gc_buffer, 0x00 , 0x800);
  memcpy(ctxg.gc_buffer, source_kernel, length);   
  
  
  int f00d_resp = 0x00; //lv0 response
    
  int res2 = ksceSblSmCommCallFunc(id, 0x1000B, &f00d_resp, &ctxg, 0x814);
  
  if(res2 != 0)
    return exit_1(res2, &id);
  
  if(f00d_resp != 0)
    return exit_1(f00d_resp, &id);
  
  return handle_response(ctxg.length, ctxg.gc_command, &id, ctxg.gc_buffer, destination, respSize);
}

char src_kernel[0x800];

//calls kirk service - partial reimplementation of sub_CAC924
int psvkirkCallService1000B(char* destination, char* source_user, kirk1000B_params* params)
{ 
  kirk1000B_params plocal;
  ksceKernelMemcpyUserToKernel(&plocal, (uintptr_t)params, sizeof(kirk1000B_params));
  
  if(plocal.size > 0x800)
    return 0x800F1816;
  
  if(source_user != 0)
  {
    int res_cpy = ksceKernelMemcpyUserToKernel(src_kernel, (uintptr_t)source_user, plocal.size);
    if(res_cpy < 0)
      return res_cpy;
  }
  
  return psvkirkCallService1000B_internal(src_kernel, plocal.command, plocal.size, plocal.packet6_de, destination, plocal.respSize);
}
 
int module_start(SceSize argc, const void *args) 
{  
   return SCE_KERNEL_START_SUCCESS;
}
 
//Alias to inhibit compiler warning
void _start() __attribute__ ((weak, alias ("module_start")));
 
int module_stop(SceSize argc, const void *args) 
{
    return SCE_KERNEL_STOP_SUCCESS;
}

