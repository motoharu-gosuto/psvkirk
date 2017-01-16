#pragma once 

int psvkirkGenerate10(char* destBuffer);

int psvkirkGenerate20(char* destBuffer);

#pragma pack(push, 1)

typedef struct kirk1000B_params
{
  int command;
  int size;
  int packet6_de;
  int* respSize;
} kirk1000B_params;

#pragma pack(pop)

int psvkirkCallService1000B(char* destination, char* source_user, kirk1000B_params* params);