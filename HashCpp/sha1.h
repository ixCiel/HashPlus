#pragma once
//#include<string.h>
//#include<stdio.h>
bool SHA1Plus(const char *lpData_Input, unsigned int lpData_Length, char *lpSHACode_Output, long long  sha1times =1 );
inline void ProcessMessageBlock(const unsigned char *NBlock, unsigned int* H);

