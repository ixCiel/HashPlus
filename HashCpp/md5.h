#pragma once
#include <windows.h>

typedef struct {
    DWORD state[4];         //encypted message
    DWORD count[2];         //bits of plaintext
    unsigned char buffer[64];
}MD5_CTX;

void MD5Init(MD5_CTX*);
void MD5Update(MD5_CTX*, unsigned char*, unsigned int);//�����ܵ��������м��Ǹ�����
void MD5Final(MD5_CTX*);
