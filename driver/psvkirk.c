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
  global_log_fd = ksceIoOpen("ux0:dump/psvkirk_log.txt", SCE_O_CREAT | SCE_O_APPEND | SCE_O_WRONLY, 0777);  
}

void close_global_log()
{
  if(global_log_fd >= 0)
    ksceIoClose(global_log_fd);
}

//---------------------------------------

#pragma pack(push, 1)

typedef struct input_f10ab792
{
   uint32_t size; //input
   char* unk_4_var970; //output //elf pointer
   uint32_t unk_8_var96C; //output //elf size
} input_f10ab792;
 
typedef struct context_039c73b1
{
   int var838; //0x01
   int command;
   char data[0x800];
   int packet6_de;
   int size;
   int var28; //0x00
} context_039c73b1;

typedef struct pair_CAC8C0
{
    int unk_0;
    int unk_4;
} pair_CAC8C0;

#pragma pack(pop)
 
//some reversed function definitions

int ksceSblSsMgrGenerate40(char* dest);

int ksceSblSmCommStartSm(int, char* elf_ptr, int elf_size, int, char* ctx, int* id);

int ksceSblSmCommCallFunc(int id, int mode, int* resp, context_039c73b1* buffer, int size);

int ksceSblSmCommStopSm(int id, pair_CAC8C0* res);

int ksceSysrootGetElf(int index, input_f10ab792* state);


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
 
int exit_3(int* var97C, pair_CAC8C0* result)
{
   if(var97C != 0 && result != 0)
   {
      result->unk_0 = -1;
      result->unk_4 = -1;
      return ksceSblSmCommStopSm(*var97C, result);
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
   if(destination == 0 || respSizeDest == 0)
      return exit_1(ret, var97C);
 
   if(size > 0)
   {
    int res_0 = ksceKernelMemcpyKernelToUser((uintptr_t)destination, source, size);
    if(res_0 < 0)
      return exit_1(res_0, var97C);
    
    int res_1 = ksceKernelMemcpyKernelToUser((uintptr_t)respSizeDest, &size, sizeof(int));
    if(res_1 < 0)
     return exit_1(res_1, var97C);
   }
   
   return exit_1(ret, var97C);
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

char src_data_const[0x800];

//this should not be on stack!
//looks like too much data corrupts the stack
context_039c73b1 ctxg;

int emulate_kirk(char* srcbf, int cmd, int srcbfsize, int packet6_de, char* destination, int* respSize)
{
   input_f10ab792 state;
   state.size = sizeof(input_f10ab792);
   state.unk_4_var970 = 0x00;
   state.unk_8_var96C = 0x00;

   int res0 = ksceSysrootGetElf(0, &state);
   if(res0 < 0)
      return 0x800F1816;
   
   char var968[0x130]; // two structures of size ox98 ?
   memset(var968, 0x00, 0x130);
   memcpy(var968 + 8, dword_CADC10, 0x90);
 
   var968[0x04] = 0x02;
   var968[0x128] = 0x02;
    
   int var97C = -1; //id
     
   int res1 = ksceSblSmCommStartSm(0x00, state.unk_4_var970, state.unk_8_var96C, 0x00, var968, &var97C);
   
   if(res1 != 0)
      return exit_1(res1, &var97C);
   
   ctxg.var838 = 0x01;
   ctxg.command = cmd;
   ctxg.packet6_de = packet6_de;
   ctxg.size = srcbfsize;
   ctxg.var28 = 0x00;
   
   memset(ctxg.data, 0x00 , 0x800);
   memcpy(ctxg.data, srcbf, srcbfsize);   
   
   int var978 = 0x00; //lv0 response
    
   int res2 = ksceSblSmCommCallFunc(var97C, 0x1000B, &var978, &ctxg, 0x814);
   
   if(res2 != 0)
      return exit_1(res2, &var97C);
   
   if(var978 != 0)
      return exit_1(var978, &var97C);
   
   return handle_response(ctxg.size, ctxg.command, &var97C, ctxg.data, destination, respSize);
}

//calls kirk service - partial reimplementation of sub_CAC924
int psvkirkCallService1000B(char* destination, char* source_user, kirk1000B_params* params)
{ 
  kirk1000B_params plocal;
  ksceKernelMemcpyUserToKernel(&plocal, (uintptr_t)params, sizeof(kirk1000B_params));
  
  if(plocal.size > 0x800)
    return 0x800F1816;
  
  if(source_user != 0)
  {
    int res_cpy = ksceKernelMemcpyUserToKernel(src_data_const, (uintptr_t)source_user, plocal.size);
    if(res_cpy < 0)
      return res_cpy;
  }
  
  return emulate_kirk(src_data_const, plocal.command, plocal.size, plocal.packet6_de, destination, plocal.respSize);
  
  /*
    if(size > 0x800)
        return 0x800F1816;
      
    ctxg.var838 = 0x01;
    ctxg.command = command;
    ctxg.packet6_de = packet6_de;
    ctxg.size = size;
    ctxg.var28 = 0x00;
    
    if(source_user != 0)
    {
        int res_cpy = ksceKernelMemcpyUserToKernel(ctxg.data, (uintptr_t)source_user, size);
        if(res_cpy < 0)
            return res_cpy;
    }
    
    input_f10ab792 state;
    state.size = sizeof(input_f10ab792);
    state.unk_4_var970 = 0x00; //pointer to elf
    state.unk_8_var96C = 0x00; //size of elf
 
    int res0 = ksceSysrootGetElf(0, &state);
    if(res0 < 0)
        return 0x800F1816;
    
    char var968[0x130]; // two structures of size ox98 ?
    memset(var968, 0x00, 0x130);
    memcpy(var968 + 8, dword_CADC10, 0x90);
 
    var968[0x04] = 0x02;
    var968[0x128] = 0x02;
    
    int var97C = -1; //id
     
    int res1 = ksceSblSmCommStartSm(0x00, state.unk_4_var970, state.unk_8_var96C, 0x00, var968, &var97C);
    if(res1 != 0)
       return exit_1(res1, &var97C);
    
    int var978 = 0x00; //lv0 response
         
    int res2 = ksceSblSmCommCallFunc(var97C, 0x1000B, &var978, &ctxg, 0x814);
    if(res2 != 0)
       return exit_1(res2, &var97C);
      
    if(var978 != 0)
       return exit_1(var978, &var97C);
         
    return handle_response(ctxg.size, ctxg.command, &var97C, ctxg.data, destination, respSize);
    */
}

typedef struct sd_ctx_global
{
  int unk_0;
} sd_ctx_global;

typedef struct sd_ctx_part
{
  int unk_0;
} sd_ctx_part;

sd_ctx_global* ksceSdifGetSdGlobalContextElement(int sd_ctx_idx);

sd_ctx_part* ksceSdifGetSdGlobalContextElement0Part(int sd_ctx_idx);
sd_ctx_part* ksceSdifGetSdGlobalContextElement1Part(int sd_ctx_idx);
sd_ctx_part* ksceSdifGetSdGlobalContextElement2Part(int sd_ctx_idx);

int ksceSdifGetGetCardInsertState1(int sd_ctx_idx);
int ksceSdifGetGetCardInsertState2(int sd_ctx_idx);

int ksceSdifInitializeSdDevice(int sd_ctx_index, sd_ctx_part** result);

#define SD_MODE_SINGLE_OP 1
//any othe number should be multiple op

//single mode means reading / writing single sector with CMD17 / CMD24
//multiple mode means reading / writing multiple sectors with CMD18 / CMD25

int ksceSdifReadSectorAsync(sd_ctx_part* ctx, int sector, char* buffer, int mode);
int ksceSdifReadSector(sd_ctx_part* ctx, int sector, char* buffer, int mode);
int ksceSdifWriteSectorAsync(sd_ctx_part* ctx, int sector, char* buffer, int mode);
int ksceSdifWriteSector(sd_ctx_part* ctx, int sector, char* buffer, int mode);

int dump_sd_elements()
{
  sd_ctx_global* e0 = ksceSdifGetSdGlobalContextElement(0);
  sd_ctx_global* e1 = ksceSdifGetSdGlobalContextElement(1);
  sd_ctx_global* e2 = ksceSdifGetSdGlobalContextElement(2);
  sd_ctx_global* e3 = ksceSdifGetSdGlobalContextElement(3);
  
  sd_ctx_part* p1 = ksceSdifGetSdGlobalContextElement0Part(0);
  sd_ctx_part* p2 = ksceSdifGetSdGlobalContextElement1Part(1);
  sd_ctx_part* p3 = ksceSdifGetSdGlobalContextElement2Part(2);
  
  int is0_0 = ksceSdifGetGetCardInsertState1(0); //inserted
  int is0_1 = ksceSdifGetGetCardInsertState1(1); //not inserted
  int is0_2 = ksceSdifGetGetCardInsertState1(2); //inserted
  
  //int is1_0 = ksceSdifGetGetCardInsertState2(0);
  //int is1_1 = ksceSdifGetGetCardInsertState2(1);
  //int is1_2 = ksceSdifGetGetCardInsertState2(2);
  
  sd_ctx_part* einit0 = 0;
  int res0 = ksceSdifInitializeSdDevice(0, &einit0);
  //int is0_01 = ksceSdifGetGetCardInsertState1(0);
  
  int idx0 = *((int*)(((char*)e0) + 0x2400 + 0x10)); //get index of device
  int idx1 = *((int*)(((char*)e1) + 0x2400 + 0x10)); //get index of device
  int idx2 = *((int*)(((char*)e2) + 0x2400 + 0x10)); //get index of device
    
  sd_ctx_part* ctxpart0 = *((sd_ctx_part**)(((char*)e0) + 0x2400 + 0x14)); //check that context part pointer is same as if I get it directly without function
  sd_ctx_part* ctxpart1 = *((sd_ctx_part**)(((char*)e1) + 0x2400 + 0x14)); //check that context part pointer is same as if I get it directly without function
  sd_ctx_part* ctxpart2 = *((sd_ctx_part**)(((char*)e2) + 0x2400 + 0x14)); //check that context part pointer is same as if I get it directly without function
  
  //char buff[0x200];
  //memset(buff, 0, 0x200);
  
  //int res1 = ksceSdifReadSectorAsync(einit0, 0, buff, SD_MODE_SINGLE_OP);
  
  open_global_log();
  {
    char buffer[100];
    snprintf(buffer, 100, "%x %x %x %x\n", e0, e1, e2, e3);
    FILE_WRITE_LEN(global_log_fd, buffer);

    snprintf(buffer, 100, "%x %x %x\n", p1, p2, p3);
    FILE_WRITE_LEN(global_log_fd, buffer);
    
    //snprintf(buffer, 100, "%x %x %x\n", is0_0, is0_1, is0_2); // 1 0 1
    //FILE_WRITE_LEN(global_log_fd, buffer);
    
    //snprintf(buffer, 100, "%x %x %x\n", is1_0, is1_1, is1_2); // 1 0 1 
    //FILE_WRITE_LEN(global_log_fd, buffer);
    
    snprintf(buffer, 100, "%x %x %x\n", idx0, idx1, idx2);
    FILE_WRITE_LEN(global_log_fd, buffer);
    
    snprintf(buffer, 100, "%x %x %x\n", ctxpart0, ctxpart1, ctxpart2);
    FILE_WRITE_LEN(global_log_fd, buffer);
    
    //snprintf(buffer, 100, "%x %x %x\n", einit0, res0, is0_01);
    //FILE_WRITE_LEN(global_log_fd, buffer);
    
    snprintf(buffer, 100, "res0: %x \n", res0);
    FILE_WRITE_LEN(global_log_fd, buffer);
    
    snprintf(buffer, 100, "einit0: %x \n", einit0);
    FILE_WRITE_LEN(global_log_fd, buffer);
    
    //snprintf(buffer, 100, "res1: %x \n", res1);
    //FILE_WRITE_LEN(global_log_fd, buffer);
    
    //ksceIoWrite(global_log_fd, buff, 0x200);
    
  }
  close_global_log();
  
  return 0;
}

#pragma pack(push, 1)

//these types is taken from my project psvcd
//https://github.com/motoharu-gosuto/psvcd
typedef struct FsSonyRoot
{
   uint8_t  SCEIid[32];
   uint32_t Unk0;
   uint32_t Unk1;
   uint64_t Unk2;
   uint64_t Unk3;
   uint64_t Unk4;
   uint64_t Unk5;
   uint64_t Unk6;
   uint32_t FsOffset;
   uint32_t VolumeLength;
   uint8_t BytesPerSectorShift; //not sure about this one TODO: not confirmed
   uint8_t unk70;
   uint8_t unk71;
   uint8_t unk72;
   uint32_t Unk8;
   uint32_t Unk9;
   uint32_t Unk10;
   uint32_t Unk11;
   uint32_t Unk12;
   uint8_t  BootCode[398];
   uint8_t  Signature[2];
} FsSonyRoot;

typedef struct VBR
{
   uint8_t    JumpBoot[3];
   uint8_t    FileSystemName[8];
   uint8_t    MustBeZero[53];
   uint64_t   PartitionOffset;
   uint64_t   VolumeLength;
   uint32_t    FatOffset; //sector address
   uint32_t    FatLength; // length in sectors
   uint32_t    ClusterHeapOffset; //sector address
   uint32_t    ClusterCount; //number of clusters
   uint32_t    RootDirFirstClust; //cluster address
   uint32_t    VolumeSerialNumber;
   uint8_t  FileSystemRevision2;
   uint8_t  FileSystemRevision1;
   uint8_t  VolumeFlags[2];
   uint8_t  BytesPerSectorShift;
   uint8_t  SectorsPerClusterShift;
   uint8_t  NumberOfFats;
   uint8_t  DriveSelect;
   uint8_t  PercentInUse;
   uint8_t  Reserved[7];
   uint8_t  BootCode[390];
   uint8_t  Signature[2];
} VBR;

#pragma pack(pop)

FsSonyRoot root_fs_sector;

VBR vbr_sector;

int dump_sectors()
{
  sd_ctx_global* e0 = ksceSdifGetSdGlobalContextElement(0); //element from global context - size 0x24C0
  
  sd_ctx_part* p0 = ksceSdifGetSdGlobalContextElement0Part(0); //real sd context - at offset 0x2414 - size currently unknown
  
  sd_ctx_part* einit0 = 0;
  int res0 = ksceSdifInitializeSdDevice(0, &einit0); //initialize sd device
  if(res0 < 0)
    return res0;
  
  memset((void*)&root_fs_sector, 0, 0x200);
  int res1 = ksceSdifReadSectorAsync(einit0, 0, (void*)&root_fs_sector, SD_MODE_SINGLE_OP);
  
  open_global_log(); 
  ksceIoWrite(global_log_fd, (void*)&root_fs_sector, 0x200);
  close_global_log();
  
  if(strncmp("Sony Computer Entertainment Inc.", (char*)root_fs_sector.SCEIid, 0x20) != 0)
    return -1;

  memset((void*)&vbr_sector, 0, 0x200);
  int res2 = ksceSdifReadSectorAsync(einit0, root_fs_sector.FsOffset, (void*)&vbr_sector, SD_MODE_SINGLE_OP);
  if(res0 < 0)
    return res0;
  
  open_global_log(); 
  ksceIoWrite(global_log_fd, (void*)&vbr_sector, 0x200);
  close_global_log();
  
  return 0; 
}

char temp_sector[0x200];

int dump_sectors2(int dev_index)
{
  sd_ctx_global* e0 = ksceSdifGetSdGlobalContextElement(dev_index); //element from global context - size 0x24C0
  
  sd_ctx_part* p0 = ksceSdifGetSdGlobalContextElement0Part(dev_index); //real sd context - at offset 0x2414 - size currently unknown
  
  sd_ctx_part* einit0 = 0;
  int res0 = ksceSdifInitializeSdDevice(dev_index, &einit0); //initialize sd device
  if(res0 < 0)
    return res0;
  
  int secIndex = 0;  
  while(secIndex < 0x500)
  {
    //memset(temp_sector, 0, 0x200);
    int res1 = ksceSdifReadSectorAsync(einit0, secIndex, temp_sector, SD_MODE_SINGLE_OP);
    if(res1 < 0)
      return -1;
    
    open_global_log(); 
    ksceIoWrite(global_log_fd, temp_sector, 0x200);
    close_global_log();
    
    secIndex++;
  }
  
  return 0;
}
 
int module_start(SceSize argc, const void *args) 
{
   //open_global_log();
   //FILE_WRITE(global_log_fd, "Hello from psvkirk 2!\n");
   //close_global_log();
  
   //dump_sd_elements();
   
   //dump_sectors();
   
   dump_sectors2(0); //ONLY USE INDEX 0 !
   
   return SCE_KERNEL_START_SUCCESS;
}
 
//Alias to inhibit compiler warning
void _start() __attribute__ ((weak, alias ("module_start")));
 
int module_stop(SceSize argc, const void *args) 
{
    return SCE_KERNEL_STOP_SUCCESS;
}

