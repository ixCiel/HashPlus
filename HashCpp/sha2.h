/*
 * FILE:	sha2.h
 * AUTHOR:	Aaron D. Gifford - http://www.aarongifford.com/
 *
 * Copyright (c) 2000-2001, Aaron D. Gifford
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTOR(S) ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTOR(S) BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: sha2.h,v 1.1 2001/11/08 00:02:01 adg Exp adg $
 */

#ifndef __SHA2_H__
#define __SHA2_H__

/*
 * Import u_intXX_t size_t type definitions from system headers.  You
 * may need to change this, or define these things yourself in this
 * file.
 */


/*** SHA-256/384/512 Various Length Definitions ***********************/
#define SHA2_SHA256_BLOCK_LENGTH		64
#define SHA2_SHA256_DIGEST_LENGTH		32
#define SHA2_SHA256_DIGEST_STRING_LENGTH	(SHA2_SHA256_DIGEST_LENGTH * 2 + 1)
#define SHA2_SHA384_BLOCK_LENGTH		128
#define SHA2_SHA384_DIGEST_LENGTH		48
#define SHA2_SHA384_DIGEST_STRING_LENGTH	(SHA2_SHA384_DIGEST_LENGTH * 2 + 1)
#define SHA2_SHA512_BLOCK_LENGTH		128
#define SHA2_SHA512_DIGEST_LENGTH		64
#define SHA2_SHA512_DIGEST_STRING_LENGTH	(SHA2_SHA512_DIGEST_LENGTH * 2 + 1)


/*** SHA-256/384/512 Context Structures *******************************/
/* NOTE: If your architecture does not define either u_intXX_t types or
 * uintXX_t (from inttypes.h), you may need to define things by hand
 * for your system:
 */
//#if 1
//typedef unsigned char u_int8_t;		/* 1-byte  (8-bits)  */
//typedef unsigned int u_int32_t;		/* 4-bytes (32-bits) */
//typedef unsigned long long u_int64_t;	/* 8-bytes (64-bits) */
//#endif
typedef struct _SHA2_SHA256_CTX
{
    unsigned int state[8];
    unsigned long long	bitcount;
    unsigned char	buffer[SHA2_SHA256_BLOCK_LENGTH];
} SHA2_SHA256_CTX;
typedef struct _SHA2_SHA512_CTX
{
    unsigned long long	state[8];
    unsigned long long	bitcount[2];
    unsigned char	buffer[SHA2_SHA512_BLOCK_LENGTH];
} SHA2_SHA512_CTX;

typedef SHA2_SHA512_CTX SHA2_SHA384_CTX;
void SHA2_SHA256_Init(SHA2_SHA256_CTX *);
void SHA2_SHA256_Update(SHA2_SHA256_CTX*, const unsigned char*, size_t);
void SHA2_SHA256_Final(unsigned char[SHA2_SHA256_DIGEST_LENGTH], SHA2_SHA256_CTX*);
void SHA2_SHA256_Final(SHA2_SHA256_CTX* ctx,char * digest);
char* SHA2_SHA256_End(SHA2_SHA256_CTX*, char[SHA2_SHA256_DIGEST_STRING_LENGTH]);
char* SHA2_SHA256_Data(const unsigned char*, size_t, char[SHA2_SHA256_DIGEST_STRING_LENGTH]);

void SHA2_SHA384_Init(SHA2_SHA384_CTX*);
void SHA2_SHA384_Update(SHA2_SHA384_CTX*, const unsigned char*, size_t);
void SHA2_SHA384_Final(unsigned char[SHA2_SHA384_DIGEST_LENGTH], SHA2_SHA384_CTX*);
void SHA2_SHA384_Final(SHA2_SHA384_CTX* ctx, char* digest);
char* SHA2_SHA384_End(SHA2_SHA384_CTX*, char[SHA2_SHA384_DIGEST_STRING_LENGTH]);
char* SHA2_SHA384_Data(const unsigned char*, size_t, char[SHA2_SHA384_DIGEST_STRING_LENGTH]);

void SHA2_SHA512_Init(SHA2_SHA512_CTX*);
void SHA2_SHA512_Update(SHA2_SHA512_CTX*, const unsigned char*, size_t);
void SHA2_SHA512_Final(unsigned char[SHA2_SHA512_DIGEST_LENGTH], SHA2_SHA512_CTX*);
void SHA2_SHA512_Final(SHA2_SHA512_CTX* ctx, char* digest);
char* SHA2_SHA512_End(SHA2_SHA512_CTX*, char[SHA2_SHA512_DIGEST_STRING_LENGTH]);
char* SHA2_SHA512_Data(const unsigned char*, size_t, char[SHA2_SHA512_DIGEST_STRING_LENGTH]);
#endif /* __SHA2_H__ */

