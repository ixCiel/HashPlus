#pragma once
/**
 * @file md2.h
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
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 1.9.6
 **/
 
#ifndef _MD2_H
#define _MD2_H
 
//MD2 block size
#define MD2_BLOCK_SIZE 16
//MD2 digest size
#define MD2_DIGEST_SIZE 16
//Minimum length of the padding string
#define MD2_MIN_PAD_SIZE 1
 
/**
 * @brief MD2 algorithm context
 **/
 
typedef struct
{
   union
   {
       unsigned char x[48];
       unsigned char digest[16];
   };
   unsigned char m[16];
   unsigned char c[16];
   unsigned char size;
} Md2Context;

//MD2 related functions
//error_t md2Compute(const void *data, size_t length, uint8_t *digest);
void md2Init(Md2Context *context);
void md2Update(Md2Context *context, const void *data, size_t length);
void md2Final(Md2Context *context, char* hash);
void md2ProcessBlock(const unsigned char*m, unsigned char*x, unsigned char*c);
void md2ProcessBlockL(const unsigned char* m, unsigned char* x);
void Md2Plus(unsigned char* lpData_Input, unsigned int lpData_Length, char* lpCode_Output, long long hashTimes);
#endif