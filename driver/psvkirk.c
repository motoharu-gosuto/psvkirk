#include "psvkirk.h"
 
 
//taihen plugin by yifanlu was used as a reference:
//https://github.com/yifanlu/taiHEN/blob/master/taihen.c
 
#include <psp2kern/types.h>
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/sysmem.h>

#include <string.h>
 
//some reversed function definitions

int ksceSblSsMgrGenerate40(char* dest);

int sceSblSmCommStartSm(int, int, int, int, void* ctx, int* id);

int sceSblSmCommCallFunc(int id, int mode, int*, int* buffer, int size);

int sceSblSmCommStopSm(int id);

int ksceSysrootContextInit(int, void* state);


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

typedef struct input_f10ab792
{
   uint32_t size; //input
   uint32_t unk_4_var970; //output
   uint32_t unk_8_var96C; //output
} input_f10ab792;
 
typedef struct context_039c73b1
{
   char var968[0x130];
   int var838;
   int command;
   char data[0x800];
   int packet6_de;
   int size;
   int var28;
} context_039c73b1;
 
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
 
typedef struct pair_CAC8C0
{
    int unk_0;
    int unk_4;
} pair_CAC8C0;
 
int exit_3(int* var97C, pair_CAC8C0* result)
{
   if(var97C != 0 && result != 0)
   {
      result->unk_0 = -1;
      result->unk_4 = -1;
      return sceSblSmCommStopSm(*var97C);
   }
   else
   {
      return 0x800F1816;
   }
}
 
int exit_2(int* var97C)
{
   pair_CAC8C0 result;
 
   if(var97C == 0)
      return 0x800F1816;
 
   if((*var97C) == -1)
      return 0x800F1816;
 
   int r0 = exit_3(var97C, &result);
    
   (*var97C) = -1;
   
   return r0;
}
 
int exit_1(int ret, int* var97C)
{
    if((*var97C) == -1)
      return ret;
       
    exit_2(var97C);
    return ret;
}
 
int copy_response(char* destination, char* source, int size, int* respSizeDest, int ret, int* var97C)
{
   if(destination == 0)
      return exit_1(ret, var97C);
 
   int res_0 = ksceKernelMemcpyKernelToUser((uintptr_t)destination, source, size);
   
   if(res_0 < 0)
     return exit_1(res_0, var97C);
   
   int res_1 = ksceKernelMemcpyKernelToUser((uintptr_t)respSizeDest, &size, sizeof(int));
 
   return exit_1(res_0, var97C);
}
 
int handle_response(int respSize, int command, int* var97C, char* source, char* destination, int* respSizeDest)
{
    if(respSize > 0x800)
        return exit_1(0x10, var97C);
         
    switch(command)
    {
    case 0x1B:
    {
        if(respSize == 0x53)
            return copy_response(destination, source, respSize, respSizeDest, 0, var97C);
        else
            return exit_1(0x10, var97C);
    }
    case 0x1C:
    {
        if(respSize == 0x33)
            return copy_response(destination, source, respSize, respSizeDest, 0, var97C);
        else
            return exit_1(0x10, var97C);
    }
    case 0x1D:
    {
        if(respSize == 0xA3)
            return copy_response(destination, source, respSize, respSizeDest, 0, var97C);
        else
            return exit_1(0x10, var97C);
    }
    case 0x1E:
    {
        if(respSize == 0x33)
            return copy_response(destination, source, respSize, respSizeDest, 0, var97C);
        else
            return exit_1(0x10, var97C);
    }
    case 0x1F:
    {
        if(respSize == 0x20)
            return copy_response(destination, source, respSize, respSizeDest, 0, var97C);
        else
            return exit_1(0x10, var97C);
    }
    case 0x20:
    {
        if(respSize == 0x34)
            return copy_response(destination, source, respSize, respSizeDest, 0, var97C);
        else
            return exit_1(0x10, var97C);
    }
    default:
        return copy_response(destination, source, respSize, respSizeDest, 0, var97C); 
    }
}
 
//calls kirk service - partial reimplementation of sub_CAC924
int psvkirkCallService1000B(char* destination, char* source_user, int command, int size, int packet6_de, int* respSize)
{    
    int var97C = -1;
    int var978 = 0x00;
     
    input_f10ab792 state;
    state.size = sizeof(input_f10ab792);
    state.unk_4_var970 = 0x00;
    state.unk_8_var96C = 0x00;
     
    context_039c73b1 ctx;
    ctx.var838 = 0x01;
    ctx.command = command;
    ctx.packet6_de = packet6_de;
    ctx.size = size;
    ctx.var28 = 0x00;
     
    if(size > 0x800)
        return 0x800F1816;
     
    if(source_user != 0)
    {
        int res_cpy = ksceKernelMemcpyUserToKernel(ctx.data, (uintptr_t)source_user, size);
        if(res_cpy < 0)
            return res_cpy;
    }
 
    int res0 = ksceSysrootContextInit(0, &state);
    if(res0 < 0)
        return 0x800F1816;
      
    memset(ctx.var968, 0x00, 0x130);
 
    memcpy(ctx.var968 + 8, dword_CADC10, 0x90);
 
    ctx.var968[0x04] = 0x02;
    ctx.var968[0x128] = 0x02;
     
    int res1 = sceSblSmCommStartSm(0x00, state.unk_4_var970, state.unk_8_var96C, 0x00, &ctx, &var97C);
    if(res1 != 0)
       return exit_1(res1, &var97C);
         
    int res2 = sceSblSmCommCallFunc(var97C, 0x1000B, &var978, &ctx.var838, 0x814);
    if(res2 != 0)
       return exit_1(res2, &var97C);
         
    if(var978 != 0)
       return exit_1(var978, &var97C);
         
    return handle_response(ctx.size, ctx.command, &var97C, ctx.data, destination, respSize);
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

