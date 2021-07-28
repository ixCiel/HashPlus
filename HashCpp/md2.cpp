/**
    * @file md2.c
    * @brief MD2 (Message-Digest Algorithm)
    *
    * @section License
    *
    * SPDX-License-Identifier: GPL-2.0-or-later
    *
    * Copyright (C) 2010-2019 Oryx Embedded SARL. All rights reserved.
    *
    * This file is part of CycloneCrypto Open.
    *
    * This program is free software; you can redistribute it and/or
    * modify it under the terms of the GNU General Public License
    * as published by the Free Software Foundation; either version 2
    * of the License, or (at your option) any later version.
    *
    * This program is distributed in the hope that it will be useful,
    * but WITHOUT ANY WARRANTY; without even the implied warranty of
    * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    * GNU General Public License for more details.
    *
    * You should have received a copy of the GNU General Public License
    * along with this program; if not, write to the Free Software Foundation,
    * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
    *
    * @section Description
    *
    * The MD2 algorithm takes as input a message of arbitrary length and produces
    * as output a 128-bit message digest of the input. Refer to RFC 1319
    *
    * @author Oryx Embedded SARL (www.oryx-embedded.com)
    * @version 1.9.6
    **/
    
   //Switch to the appropriate trace level
   //Dependencies
#include "md2.h"
#include <memory>
#include <math.h>
#include <Windows.h>
#include "hexChar.h"

#define CC(a,b) \
c[a] ^= s[m[a] ^c[b]];
#define CCF(a,b) \
c[a] = s[m[a] ^c[b]];
#define CC16(a,b) \
c[a] ^= s[c[b]^0x10];
#define XX(a,b) \
x[a] ^= s[x[b]];
#define XXF(a,b) \
x[a] = s[x[b]];
#define XXM(a,b,c) \
x[a] = s[x[b]] ^ m[c];
#define XXM16(a,b) \
x[a] = s[x[b]] ^ 0x10;
#define XX1TO47 \
XX(1,0) \
XX(2,1) \
XX(3,2) \
XX(4,3) \
XX(5,4) \
XX(6,5) \
XX(7,6) \
XX(8,7) \
XX(9,8) \
XX(10,9) \
XX(11,10) \
XX(12,11) \
XX(13,12) \
XX(14,13) \
XX(15,14) \
XX(16,15) \
XX(17,16) \
XX(18,17) \
XX(19,18) \
XX(20,19) \
XX(21,20) \
XX(22,21) \
XX(23,22) \
XX(24,23) \
XX(25,24) \
XX(26,25) \
XX(27,26) \
XX(28,27) \
XX(29,28) \
XX(30,29) \
XX(31,30) \
XX(32,31) \
XX(33,32) \
XX(34,33) \
XX(35,34) \
XX(36,35) \
XX(37,36) \
XX(38,37) \
XX(39,38) \
XX(40,39) \
XX(41,40) \
XX(42,41) \
XX(43,42) \
XX(44,43) \
XX(45,44) \
XX(46,45) \
XX(47,46)
#define XM(a,b) \
x[a] = m[b] ^ x[b];
#define XM16(a,b) \
x[a] = x[b] ^ 0x10;
#define XXR(a) \
x[0] ^= s[x[47] + a]; \
XX1TO47;

//Check crypto library configuration
 
//MD2 constants
static const uint8_t s[512] =
{
   0x29, 0x2E, 0x43, 0xC9, 0xA2, 0xD8, 0x7C, 0x01, 0x3D, 0x36, 0x54, 0xA1, 0xEC, 0xF0, 0x06, 0x13,
   0x62, 0xA7, 0x05, 0xF3, 0xC0, 0xC7, 0x73, 0x8C, 0x98, 0x93, 0x2B, 0xD9, 0xBC, 0x4C, 0x82, 0xCA,
   0x1E, 0x9B, 0x57, 0x3C, 0xFD, 0xD4, 0xE0, 0x16, 0x67, 0x42, 0x6F, 0x18, 0x8A, 0x17, 0xE5, 0x12,
   0xBE, 0x4E, 0xC4, 0xD6, 0xDA, 0x9E, 0xDE, 0x49, 0xA0, 0xFB, 0xF5, 0x8E, 0xBB, 0x2F, 0xEE, 0x7A,
   0xA9, 0x68, 0x79, 0x91, 0x15, 0xB2, 0x07, 0x3F, 0x94, 0xC2, 0x10, 0x89, 0x0B, 0x22, 0x5F, 0x21,
   0x80, 0x7F, 0x5D, 0x9A, 0x5A, 0x90, 0x32, 0x27, 0x35, 0x3E, 0xCC, 0xE7, 0xBF, 0xF7, 0x97, 0x03,
   0xFF, 0x19, 0x30, 0xB3, 0x48, 0xA5, 0xB5, 0xD1, 0xD7, 0x5E, 0x92, 0x2A, 0xAC, 0x56, 0xAA, 0xC6,
   0x4F, 0xB8, 0x38, 0xD2, 0x96, 0xA4, 0x7D, 0xB6, 0x76, 0xFC, 0x6B, 0xE2, 0x9C, 0x74, 0x04, 0xF1,
   0x45, 0x9D, 0x70, 0x59, 0x64, 0x71, 0x87, 0x20, 0x86, 0x5B, 0xCF, 0x65, 0xE6, 0x2D, 0xA8, 0x02,
   0x1B, 0x60, 0x25, 0xAD, 0xAE, 0xB0, 0xB9, 0xF6, 0x1C, 0x46, 0x61, 0x69, 0x34, 0x40, 0x7E, 0x0F,
   0x55, 0x47, 0xA3, 0x23, 0xDD, 0x51, 0xAF, 0x3A, 0xC3, 0x5C, 0xF9, 0xCE, 0xBA, 0xC5, 0xEA, 0x26,
   0x2C, 0x53, 0x0D, 0x6E, 0x85, 0x28, 0x84, 0x09, 0xD3, 0xDF, 0xCD, 0xF4, 0x41, 0x81, 0x4D, 0x52,
   0x6A, 0xDC, 0x37, 0xC8, 0x6C, 0xC1, 0xAB, 0xFA, 0x24, 0xE1, 0x7B, 0x08, 0x0C, 0xBD, 0xB1, 0x4A,
   0x78, 0x88, 0x95, 0x8B, 0xE3, 0x63, 0xE8, 0x6D, 0xE9, 0xCB, 0xD5, 0xFE, 0x3B, 0x00, 0x1D, 0x39,
   0xF2, 0xEF, 0xB7, 0x0E, 0x66, 0x58, 0xD0, 0xE4, 0xA6, 0x77, 0x72, 0xF8, 0xEB, 0x75, 0x4B, 0x0A,
   0x31, 0x44, 0x50, 0xB4, 0x8F, 0xED, 0x1F, 0x1A, 0xDB, 0x99, 0x8D, 0x33, 0x9F, 0x11, 0x83, 0x14,
   0x29, 0x2E, 0x43, 0xC9, 0xA2, 0xD8, 0x7C, 0x01, 0x3D, 0x36, 0x54, 0xA1, 0xEC, 0xF0, 0x06, 0x13,
   0x62, 0xA7, 0x05, 0xF3, 0xC0, 0xC7, 0x73, 0x8C, 0x98, 0x93, 0x2B, 0xD9, 0xBC, 0x4C, 0x82, 0xCA,
   0x1E, 0x9B, 0x57, 0x3C, 0xFD, 0xD4, 0xE0, 0x16, 0x67, 0x42, 0x6F, 0x18, 0x8A, 0x17, 0xE5, 0x12,
   0xBE, 0x4E, 0xC4, 0xD6, 0xDA, 0x9E, 0xDE, 0x49, 0xA0, 0xFB, 0xF5, 0x8E, 0xBB, 0x2F, 0xEE, 0x7A,
   0xA9, 0x68, 0x79, 0x91, 0x15, 0xB2, 0x07, 0x3F, 0x94, 0xC2, 0x10, 0x89, 0x0B, 0x22, 0x5F, 0x21,
   0x80, 0x7F, 0x5D, 0x9A, 0x5A, 0x90, 0x32, 0x27, 0x35, 0x3E, 0xCC, 0xE7, 0xBF, 0xF7, 0x97, 0x03,
   0xFF, 0x19, 0x30, 0xB3, 0x48, 0xA5, 0xB5, 0xD1, 0xD7, 0x5E, 0x92, 0x2A, 0xAC, 0x56, 0xAA, 0xC6,
   0x4F, 0xB8, 0x38, 0xD2, 0x96, 0xA4, 0x7D, 0xB6, 0x76, 0xFC, 0x6B, 0xE2, 0x9C, 0x74, 0x04, 0xF1,
   0x45, 0x9D, 0x70, 0x59, 0x64, 0x71, 0x87, 0x20, 0x86, 0x5B, 0xCF, 0x65, 0xE6, 0x2D, 0xA8, 0x02,
   0x1B, 0x60, 0x25, 0xAD, 0xAE, 0xB0, 0xB9, 0xF6, 0x1C, 0x46, 0x61, 0x69, 0x34, 0x40, 0x7E, 0x0F,
   0x55, 0x47, 0xA3, 0x23, 0xDD, 0x51, 0xAF, 0x3A, 0xC3, 0x5C, 0xF9, 0xCE, 0xBA, 0xC5, 0xEA, 0x26,
   0x2C, 0x53, 0x0D, 0x6E, 0x85, 0x28, 0x84, 0x09, 0xD3, 0xDF, 0xCD, 0xF4, 0x41, 0x81, 0x4D, 0x52,
   0x6A, 0xDC, 0x37, 0xC8, 0x6C, 0xC1, 0xAB, 0xFA, 0x24, 0xE1, 0x7B, 0x08, 0x0C, 0xBD, 0xB1, 0x4A,
   0x78, 0x88, 0x95, 0x8B, 0xE3, 0x63, 0xE8, 0x6D, 0xE9, 0xCB, 0xD5, 0xFE, 0x3B, 0x00, 0x1D, 0x39,
   0xF2, 0xEF, 0xB7, 0x0E, 0x66, 0x58, 0xD0, 0xE4, 0xA6, 0x77, 0x72, 0xF8, 0xEB, 0x75, 0x4B, 0x0A,
   0x31, 0x44, 0x50, 0xB4, 0x8F, 0xED, 0x1F, 0x1A, 0xDB, 0x99, 0x8D, 0x33, 0x9F, 0x11, 0x83, 0x14,
};

/**
 * @brief Digest a message using MD2
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/
 
//error_t md2Compute(const void *data, size_t length, uint8_t *digest)
//{
//   //Allocate a memory buffer to hold the MD2 context
//   Md2Context *context = cryptoAllocMem(sizeof(Md2Context));
//   //Failed to allocate memory?
//   if(context == NULL)
//      return ERROR_OUT_OF_MEMORY;
// 
//   //Initialize the MD2 context
//   md2Init(context);
//   //Digest the message
//   md2Update(context, data, length);
//   //Finalize the MD2 message digest
//   md2Final(context, digest);
// 
//   //Free previously allocated memory
//   cryptoFreeMem(context);
//   //Successful processing
//   return NO_ERROR;
//}
 
 
/**
 * @brief Initialize MD2 message digest context
 * @param[in] context Pointer to the MD2 context to initialize
 **/
 
void md2Init(Md2Context *context)
{
   //Initialize the 48-byte buffer X
   memset(context->x, 0, 48);
   //Clear checksum
   memset(context->c, 0, 16);
   //Number of bytes in the buffer
   context->size = 0;
}
 
 
/**
 * @brief Update the MD2 context with a portion of the message being hashed
 * @param[in] context Pointer to the MD2 context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/
 
void md2Update(Md2Context *context, const void *data, size_t length)
{
   unsigned char n;
 
   //Process the incoming data
   while(length > 0)
   {
      //The buffer can hold at most 16 bytes
      n = min(length, 16 - context->size);
 
      //Copy the data to the buffer
      memcpy(context->m + context->size, data, n);
 
      //Update the MD2 context
      context->size += n;
      //Advance the data pointer
      data = (uint8_t *) data + n;
      //Remaining bytes to process
      length -= n;
 
      //Process message in 16-word blocks
      if(context->size == 16)
      {
         //Transform the 16-word block
         md2ProcessBlock(context->m, context->x, context->c);
         //Empty the buffer
         context->size = 0;
      }
   }
}


/**
 * @brief Finish the MD2 message digest
 * @param[in] context Pointer to the MD2 context
 * @param[out] digest Calculated digest (optional parameter)
 **/

void md2Final(Md2Context *context, char* hash)
{
   unsigned int n;
 
   //Pad the message so that its length is congruent to 0 modulo 16
   n = 16 - context->size;
 
   //Append padding bytes
   memset(context->m + context->size, n, n);
   //Transform the 16-word block
   md2ProcessBlock(context->m, context->x, context->c);
 
   //Append the checksum
   //memcpy(context->m, context->c, 16);
   //Transform the 16-word block
   md2ProcessBlockL(context->c, context->x);
 
   //Copy the resulting digest
   //if(digest != NULL)
   //   memcpy(digest, context->digest, MD2_DIGEST_SIZE);

   unsigned char* cstate = (unsigned char*)context->digest;
   for (int i = 0; i < 16; i++) {
       //hash[i * 2] = fastHexCharHigh[cstate[i]];
       //hash[i * 2 + 1] = fastHexCharLow[cstate[i]];
       *hash++ = fastHexCharHigh[*cstate];
       *hash++ = fastHexCharLow[*cstate++];
   }
}

/**
 * @brief Process message in 16-word blocks
 * @param[in] m 16-byte data block to process
 * @param[in,out] x 48-byte buffer
 * @param[in,out] c 16-byte checksum
 **/

void md2ProcessBlockF(const uint8_t* m, uint8_t* x, uint8_t* c)
{
    uint8_t j;
    c[0] = s[m[0]];
    CCF(1, 0);
    CCF(2, 1);
    CCF(3, 2);
    CCF(4, 3);
    CCF(5, 4);
    CCF(6, 5);
    CCF(7, 6);
    CCF(8, 7);
    CCF(9, 8);
    CCF(10, 9);
    CCF(11, 10);
    CCF(12, 11);
    CCF(13, 12);
    CCF(14, 13);
    CCF(15, 14);
    x[0] = s[0];
    XXF(1, 0);
    XXF(2, 1);
    XXF(3, 2);
    XXF(4, 3);
    XXF(5, 4);
    XXF(6, 5);
    XXF(7, 6);
    XXF(8, 7);
    XXF(9, 8);
    XXF(10, 9);
    XXF(11, 10);
    XXF(12, 11);
    XXF(13, 12);
    XXF(14, 13);
    XXF(15, 14);
    XXM(16, 15, 0);
    XXM(17, 16, 1);
    XXM(18, 17, 2);
    XXM(19, 18, 3);
    XXM(20, 19, 4);
    XXM(21, 20, 5);
    XXM(22, 21, 6);
    XXM(23, 22, 7);
    XXM(24, 23, 8);
    XXM(25, 24, 9);
    XXM(26, 25, 10);
    XXM(27, 26, 11);
    XXM(28, 27, 12);
    XXM(29, 28, 13);
    XXM(30, 29, 14);
    XXM(31, 30, 15);
    XXM(32, 31, 0);
    XXM(33, 32, 1);
    XXM(34, 33, 2);
    XXM(35, 34, 3);
    XXM(36, 35, 4);
    XXM(37, 36, 5);
    XXM(38, 37, 6);
    XXM(39, 38, 7);
    XXM(40, 39, 8);
    XXM(41, 40, 9);
    XXM(42, 41, 10);
    XXM(43, 42, 11);
    XXM(44, 43, 12);
    XXM(45, 44, 13);
    XXM(46, 45, 14);
    XXM(47, 46, 15);

    /*XXR(0);
    XXR(1);
    XXR(2);
    XXR(3);
    XXR(4);
    XXR(5);
    XXR(6);
    XXR(7);
    XXR(8);
    XXR(9);
    XXR(10);
    XXR(11);
    XXR(12);
    XXR(13);
    XXR(14);
    XXR(15);
    XXR(16);*/

    for (j = 0; j < 17; j++)
    {
        x[0] ^= s[x[47] + j];
        XX1TO47;
    }
}
void md2ProcessBlock(const uint8_t* m, uint8_t* x, uint8_t* c)
{
    uint8_t j;
    
    CC(0, 15);
    CC(1, 0);
    CC(2, 1);
    CC(3, 2);
    CC(4, 3);
    CC(5, 4);
    CC(6, 5);
    CC(7, 6);
    CC(8, 7);
    CC(9, 8);
    CC(10, 9);
    CC(11, 10);
    CC(12, 11);
    CC(13, 12);
    CC(14, 13);
    CC(15, 14);
    

    XM(32, 0);
    XM(33, 1);
    XM(34, 2);
    XM(35, 3);
    XM(36, 4);
    XM(37, 5);
    XM(38, 6);
    XM(39, 7);
    XM(40, 8);
    XM(41, 9);
    XM(42, 10);
    XM(43, 11);
    XM(44, 12);
    XM(45, 13);
    XM(46, 14);
    XM(47, 15);


    x[0] ^= s[0];
    XX(1, 0);
    XX(2, 1);
    XX(3, 2);
    XX(4, 3);
    XX(5, 4);
    XX(6, 5);
    XX(7, 6);
    XX(8, 7);
    XX(9, 8);
    XX(10, 9);
    XX(11, 10);
    XX(12, 11);
    XX(13, 12);
    XX(14, 13);
    XX(15, 14);
    XXM(16, 15,0);
    XXM(17, 16, 1 );
    XXM(18, 17, 2 );
    XXM(19, 18, 3 );
    XXM(20, 19, 4 );
    XXM(21, 20, 5 );
    XXM(22, 21, 6 );
    XXM(23, 22, 7 );
    XXM(24, 23, 8 );
    XXM(25, 24, 9 );
    XXM(26, 25, 10);
    XXM(27, 26, 11);
    XXM(28, 27, 12);
    XXM(29, 28, 13);
    XXM(30, 29, 14);
    XXM(31, 30, 15);
    XX(32, 31);
    XX(33, 32);
    XX(34, 33);
    XX(35, 34);
    XX(36, 35);
    XX(37, 36);
    XX(38, 37);
    XX(39, 38);
    XX(40, 39);
    XX(41, 40);
    XX(42, 41);
    XX(43, 42);
    XX(44, 43);
    XX(45, 44);
    XX(46, 45);
    XX(47, 46);

    //XXR(0);
    //XXR(1);
    //XXR(2);
    //XXR(3);
    //XXR(4);
    //XXR(5);
    //XXR(6);
    //XXR(7);
    //XXR(8);
    //XXR(9);
    //XXR(10);
    //XXR(11);
    //XXR(12);
    //XXR(13);
    //XXR(14);
    //XXR(15);
    //XXR(16);
    for (j = 0; j < 17; j++)
{
    x[0] ^= s[x[47] + j];
    XX1TO47;
}
}

void md2ProcessBlock16(uint8_t* x, uint8_t* c)
{
    uint8_t j;
    CC16(0, 15);
    CC16(1, 0);
    CC16(2, 1);
    CC16(3, 2);
    CC16(4, 3);
    CC16(5, 4);
    CC16(6, 5);
    CC16(7, 6);
    CC16(8, 7);
    CC16(9, 8);
    CC16(10, 9);
    CC16(11, 10);
    CC16(12, 11);
    CC16(13, 12);
    CC16(14, 13);
    CC16(15, 14);
    

    XM16(32, 0);
    XM16(33, 1);
    XM16(34, 2);
    XM16(35, 3);
    XM16(36, 4);
    XM16(37, 5);
    XM16(38, 6);
    XM16(39, 7);
    XM16(40, 8);
    XM16(41, 9);
    XM16(42, 10);
    XM16(43, 11);
    XM16(44, 12);
    XM16(45, 13);
    XM16(46, 14);
    XM16(47, 15);

    x[0] ^= s[0];
    XX(1, 0);
    XX(2, 1);
    XX(3, 2);
    XX(4, 3);
    XX(5, 4);
    XX(6, 5);
    XX(7, 6);
    XX(8, 7);
    XX(9, 8);
    XX(10, 9);
    XX(11, 10);
    XX(12, 11);
    XX(13, 12);
    XX(14, 13);
    XX(15, 14);
    XXM16(16, 15);
    XXM16(17, 16);
    XXM16(18, 17);
    XXM16(19, 18);
    XXM16(20, 19);
    XXM16(21, 20);
    XXM16(22, 21);
    XXM16(23, 22);
    XXM16(24, 23);
    XXM16(25, 24);
    XXM16(26, 25);
    XXM16(27, 26);
    XXM16(28, 27);
    XXM16(29, 28);
    XXM16(30, 29);
    XXM16(31, 30);
    XX(32, 31);
    XX(33, 32);
    XX(34, 33);
    XX(35, 34);
    XX(36, 35);
    XX(37, 36);
    XX(38, 37);
    XX(39, 38);
    XX(40, 39);
    XX(41, 40);
    XX(42, 41);
    XX(43, 42);
    XX(44, 43);
    XX(45, 44);
    XX(46, 45);
    XX(47, 46);

    //XXR(0);
    //XXR(1);
    //XXR(2);
    //XXR(3);
    //XXR(4);
    //XXR(5);
    //XXR(6);
    //XXR(7);
    //XXR(8);
    //XXR(9);
    //XXR(10);
    //XXR(11);
    //XXR(12);
    //XXR(13);
    //XXR(14);
    //XXR(15);
    //XXR(16);
    for (j = 0; j < 17; j++)
    {
        x[0] ^= s[x[47] + j];
        XX1TO47;
    }
}

void md2ProcessBlockL(const uint8_t* m, uint8_t* x)
{
    uint8_t j;
    XM(32, 0);
    XM(33, 1);
    XM(34, 2);
    XM(35, 3);
    XM(36, 4);
    XM(37, 5);
    XM(38, 6);
    XM(39, 7);
    XM(40, 8);
    XM(41, 9);
    XM(42, 10);
    XM(43, 11);
    XM(44, 12);
    XM(45, 13);
    XM(46, 14);
    XM(47, 15);

    x[0] ^= s[0];
    XX(1, 0);
    XX(2, 1);
    XX(3, 2);
    XX(4, 3);
    XX(5, 4);
    XX(6, 5);
    XX(7, 6);
    XX(8, 7);
    XX(9, 8);
    XX(10, 9);
    XX(11, 10);
    XX(12, 11);
    XX(13, 12);
    XX(14, 13);
    XX(15, 14);
    XXM(16, 15, 0);
    XXM(17, 16, 1);
    XXM(18, 17, 2);
    XXM(19, 18, 3);
    XXM(20, 19, 4);
    XXM(21, 20, 5);
    XXM(22, 21, 6);
    XXM(23, 22, 7);
    XXM(24, 23, 8);
    XXM(25, 24, 9);
    XXM(26, 25, 10);
    XXM(27, 26, 11);
    XXM(28, 27, 12);
    XXM(29, 28, 13);
    XXM(30, 29, 14);
    XXM(31, 30, 15);
    XX(32, 31);
    XX(33, 32);
    XX(34, 33);
    XX(35, 34);
    XX(36, 35);
    XX(37, 36);
    XX(38, 37);
    XX(39, 38);
    XX(40, 39);
    XX(41, 40);
    XX(42, 41);
    XX(43, 42);
    XX(44, 43);
    XX(45, 44);
    XX(46, 45);
    XX(47, 46);

    //XXR(0);
    //XXR(1);
    //XXR(2);
    //XXR(3);
    //XXR(4);
    //XXR(5);
    //XXR(6);
    //XXR(7);
    //XXR(8);
    //XXR(9);
    //XXR(10);
    //XXR(11);
    //XXR(12);
    //XXR(13);
    //XXR(14);
    //XXR(15);
    //XXR(16);
    for (j = 0; j < 16; j++)
    {
        x[0] ^= s[x[47] + j];
        XX1TO47;
    }
    x[0] ^= s[x[47] + 16];
    XX(1, 0);
    XX(2, 1);
    XX(3, 2);
    XX(4, 3);
    XX(5, 4);
    XX(6, 5);
    XX(7, 6);
    XX(8, 7);
    XX(9, 8);
    XX(10, 9);
    XX(11, 10);
    XX(12, 11);
    XX(13, 12);
    XX(14, 13);
    XX(15, 14);
}

void Md2Plus(unsigned char* lpData_Input, unsigned int lpData_Length, char* lpCode_Output, long long hashTimes)
{
    unsigned char x[48], c[16],* first16 = (unsigned char *)&lpCode_Output[0],* last16 = (unsigned char*)&lpCode_Output[16],*start,*end;
    char* hash;
    Md2Context ctx,*p;
    end = &x[16];
    p = &ctx;
    md2Init(p);
    md2Update(p, lpData_Input, lpData_Length);
    md2Final(p, lpCode_Output);
    for (long long z = 1; z < hashTimes; z++)
    {
        md2ProcessBlockF(first16, x, c);
        md2ProcessBlock(last16, x, c);
        md2ProcessBlock16(x, c);
        md2ProcessBlockL(c, x);
        for (hash = lpCode_Output, start = x; start != end; start++) {
            *hash++ = fastHexCharHigh[*start];
            *hash++ = fastHexCharLow[*start];
        }
    }
}

