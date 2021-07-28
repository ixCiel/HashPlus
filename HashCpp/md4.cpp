#include "md4.h"
#include <Windows.h>
#include <memory>
#include <math.h>
#include "hexChar.h"
#define F(x,y,z) ((z) ^ ((x) & ((y) ^ (z))))
#define G(x,y,z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define H(x,y,z) ((x) ^ (y) ^ (z))
#define ROTATE_LEFT(x,n) (n?_lrotl(x,n):x)

#define FF(a,b,c,d,x,s) a=ROTATE_LEFT(a+F(b,c,d)+x,s);
#define GG(a,b,c,d,x,s) a=ROTATE_LEFT(a+G(b,c,d)+x+0x5a827999,s);
#define HH(a,b,c,d,x,s) a=ROTATE_LEFT(a+H(b,c,d)+x+0x6ed9eba1,s);

unsigned char md4PADDING[] = { 0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };

enum {
    MD4_BLOCK_SIZE = 64,
    MD4_DIGEST_SIZE = 16,
    MD4_PAD_SIZE = 56
};

typedef struct Md4 {
    unsigned int  buffLen;   /* in bytes          */
    unsigned int  loLen;     /* length in bytes   */
    unsigned int  hiLen;     /* length in bytes   */
    unsigned int  digest[MD4_DIGEST_SIZE / sizeof(unsigned int)];
    unsigned int  buffer[MD4_BLOCK_SIZE / sizeof(unsigned int)];
} Md4;
static void AddLength(Md4* md4, unsigned int len)
{
    unsigned int tmp = md4->loLen;
    if ((md4->loLen += len) < tmp)
        md4->hiLen++;                       /* carry low to high */
}

static void Transform(Md4* md4)
{

    /* Copy context->state[] to working vars  */
    unsigned int A = md4->digest[0];
    unsigned int B = md4->digest[1];
    unsigned int C = md4->digest[2];
    unsigned int D = md4->digest[3];

    FF(A, B, C, D, md4->buffer[0], 3);
    FF(D, A, B, C, md4->buffer[1], 7);
    FF(C, D, A, B, md4->buffer[2], 11);
    FF(B, C, D, A, md4->buffer[3], 19);
    FF(A, B, C, D, md4->buffer[4], 3);
    FF(D, A, B, C, md4->buffer[5], 7);
    FF(C, D, A, B, md4->buffer[6], 11);
    FF(B, C, D, A, md4->buffer[7], 19);
    FF(A, B, C, D, md4->buffer[8], 3);
    FF(D, A, B, C, md4->buffer[9], 7);
    FF(C, D, A, B, md4->buffer[10], 11);
    FF(B, C, D, A, md4->buffer[11], 19);
    FF(A, B, C, D, md4->buffer[12], 3);
    FF(D, A, B, C, md4->buffer[13], 7);
    FF(C, D, A, B, md4->buffer[14], 11);
    FF(B, C, D, A, md4->buffer[15], 19);


    GG(A, B, C, D, md4->buffer[0 ], 3);
    GG(D, A, B, C, md4->buffer[4 ], 5);
    GG(C, D, A, B, md4->buffer[8 ], 9);
    GG(B, C, D, A, md4->buffer[12], 13);
    GG(A, B, C, D, md4->buffer[1 ], 3);
    GG(D, A, B, C, md4->buffer[5 ], 5);
    GG(C, D, A, B, md4->buffer[9 ], 9);
    GG(B, C, D, A, md4->buffer[13], 13);
    GG(A, B, C, D, md4->buffer[2 ], 3);
    GG(D, A, B, C, md4->buffer[6 ], 5);
    GG(C, D, A, B, md4->buffer[10], 9);
    GG(B, C, D, A, md4->buffer[14], 13);
    GG(A, B, C, D, md4->buffer[3 ], 3);
    GG(D, A, B, C, md4->buffer[7 ], 5);
    GG(C, D, A, B, md4->buffer[11], 9);
    GG(B, C, D, A, md4->buffer[15], 13);


    HH(A, B, C, D, md4->buffer[0 ], 3);
    HH(D, A, B, C, md4->buffer[8 ], 9);
    HH(C, D, A, B, md4->buffer[4 ], 11);
    HH(B, C, D, A, md4->buffer[12], 15);
    HH(A, B, C, D, md4->buffer[2 ], 3);
    HH(D, A, B, C, md4->buffer[10], 9);
    HH(C, D, A, B, md4->buffer[6 ], 11);
    HH(B, C, D, A, md4->buffer[14], 15);
    HH(A, B, C, D, md4->buffer[1 ], 3);
    HH(D, A, B, C, md4->buffer[9 ], 9);
    HH(C, D, A, B, md4->buffer[5 ], 11);
    HH(B, C, D, A, md4->buffer[13], 15);
    HH(A, B, C, D, md4->buffer[3 ], 3);
    HH(D, A, B, C, md4->buffer[11], 9);
    HH(C, D, A, B, md4->buffer[7 ], 11);
    HH(B, C, D, A, md4->buffer[15], 15);

    /* Add the working vars back into digest state[]  */
    md4->digest[0] += A;
    md4->digest[1] += B;
    md4->digest[2] += C;
    md4->digest[3] += D;
}


void md4Update(Md4* md4, const unsigned char* data, unsigned int len)
{
    /* do block size increments */
    unsigned char* local = (unsigned char*)md4->buffer;

    while (len) {
        unsigned int add = min(len, MD4_BLOCK_SIZE - md4->buffLen);
        memcpy(&local[md4->buffLen], data, add);

        md4->buffLen += add;
        data += add;
        len -= add;

        if (md4->buffLen == MD4_BLOCK_SIZE) {
            Transform(md4);
            AddLength(md4, MD4_BLOCK_SIZE);
            md4->buffLen = 0;
        }
    }
}

void md4Final(Md4* md4, unsigned char* hash)
{
    unsigned char* local = (unsigned char*)md4->buffer;

    AddLength(md4, md4->buffLen);               /* before adding pads */

    local[md4->buffLen++] = 0x80;  /* add 1 */

                                   /* pad with zeros */
    if (md4->buffLen > MD4_PAD_SIZE) {
        memset(&local[md4->buffLen], 0, MD4_BLOCK_SIZE - md4->buffLen);
        md4->buffLen += MD4_BLOCK_SIZE - md4->buffLen;

        Transform(md4);
        md4->buffLen = 0;
    }
    memset(&local[md4->buffLen], 0, MD4_PAD_SIZE - md4->buffLen);

    /* put lengths in bits */
    md4->hiLen = (md4->loLen >> (8 * sizeof(md4->loLen) - 3)) +
        (md4->hiLen << 3);
    md4->loLen = md4->loLen << 3;


    /* ! length ordering dependent on digest endian type ! */
    memcpy(&local[MD4_PAD_SIZE], &md4->loLen, sizeof(unsigned int));
    memcpy(&local[MD4_PAD_SIZE + sizeof(unsigned int)], &md4->hiLen, sizeof(unsigned int));

    Transform(md4);

    //memcpy(hash, md4->digest, MD4_DIGEST_SIZE);
    unsigned char* cstate = (unsigned char*)md4->digest;
    for (int i = 0; i < 16; i++) {
        hash[i * 2] = fastHexCharHigh[cstate[i]];
        hash[i * 2 + 1] = fastHexCharLow[cstate[i]];
    }
}

void initMd4(Md4* md4)
{
    md4->digest[0] = 0x67452301L;
    md4->digest[1] = 0xefcdab89L;
    md4->digest[2] = 0x98badcfeL;
    md4->digest[3] = 0x10325476L;
    md4->buffLen = 0;
    md4->loLen = 0;
    md4->hiLen = 0;
}

void md4Plus(unsigned char* str, unsigned int str_length, unsigned char* md4str, long long md4times)
{
    Md4 md4;
    initMd4(&md4);
    md4Update(&md4, str, str_length);
    md4Final(&md4, md4str);
    for(long long z = 1;z<md4times;z++)
    {
        initMd4(&md4);
        md4Update(&md4, md4str, 32);
        md4Final(&md4, md4str);
    }

}

