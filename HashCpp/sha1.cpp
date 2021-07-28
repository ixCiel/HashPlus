#include "sha1.h"
#include<string.h>
#include<stdio.h>
#include "hexChar.h"

const unsigned char SHA1PADDING[] = { 0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
				 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
				 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
				 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };

#define CircularShift(word,x,y) (((word) << x/* & 0xFFFFFFFF*/) | ((word/* & 0xFFFFFFFF*/) >> y))

#define INITWA(t) \
w=(unsigned char*)&W[t]; \
d=&digit[t*4]; \
w[3] = d[0]; \
w[2] = d[1]; \
w[1] = d[2]; \
w[0] = d[3];

#define INITB(t,tmp) \
tmp = W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]; \
W[t] = CircularShift(tmp,1,31);

#define K0 0x5A827999
#define K1 0x6ED9EBA1
#define K2 0x8F1BBCDC
#define K3 0xCA62C1D6

#define FF(A,B,C,D,E,x) \
E = CircularShift(A,5,27) + ((B & C) | ((~B) & D)) + E + x + K0 /*& 0xFFFFFFFF*/; \
B = CircularShift(B,30,2);

#define GG(A,B,C,D,E,x) \
E = CircularShift(A,5,27) + (B ^ C ^ D) + E + x + K1 /*& 0xFFFFFFFF*/; \
B = CircularShift(B,30,2);

#define HH(A,B,C,D,E,x) \
E = CircularShift(A,5,27) + ((B & C) | (B & D) | (C & D)) + E + x + K2 /*& 0xFFFFFFFF*/; \
B = CircularShift(B,30,2);

#define II(A,B,C,D,E,x) \
E = CircularShift(A,5,27) + (B ^ C ^ D) + E + x + K3 /*& 0xFFFFFFFF*/; \
B = CircularShift(B,30,2);

bool SHA1Plus(const char *lpData_Input, unsigned int lpData_Length, char *lpSHACode_Output, long long sha1times)
{
	if (lpData_Input == NULL || lpSHACode_Output == NULL)
		return false;
	unsigned int Length_Low = 0;
	unsigned int Length_High = 0;
	unsigned char* ll = (unsigned char*)&Length_Low,*lh = (unsigned char *)&Length_High;
	unsigned char digit[65];
	unsigned int H[5];
	unsigned char Message_Block[64];
	memset(&digit[41], 0, 22);
	digit[40] = 0x80;
	digit[62] = 1;
	digit[63] = 64;
	digit[64] = 0;
	H[0] = 0x67452301;
	H[1] = 0xEFCDAB89;
	H[2] = 0x98BADCFE;
	H[3] = 0x10325476;
	H[4] = 0xC3D2E1F0;

	unsigned int nDealDataLen = 0;
	for(unsigned int pos=0 ; pos<= lpData_Length; pos+=64)
	{
		if (lpData_Length - pos >= 64)
		{
			ProcessMessageBlock((unsigned char *)lpData_Input + pos,H);
		}
		else
		{
			nDealDataLen = lpData_Length - pos;
			memset(Message_Block, 0, sizeof(Message_Block));
			memcpy(Message_Block, lpData_Input + pos, nDealDataLen);
			memcpy(&Message_Block[nDealDataLen],SHA1PADDING, 64 - nDealDataLen);

			Length_Low = lpData_Length << 3;
			Length_High = lpData_Length >> 29;
			if (nDealDataLen > 55)
			{
				ProcessMessageBlock(Message_Block,H);
				memset(Message_Block, 0, 56);
			}

			Message_Block[56] = lh[3];//(Length_High >> 24) & 0xFF;
			Message_Block[57] = lh[2];//(Length_High >> 16) & 0xFF;
			Message_Block[58] = lh[1];//(Length_High >> 8) & 0xFF;
			Message_Block[59] = lh[0];//(Length_High) & 0xFF;
			Message_Block[60] = ll[3];//(Length_Low >> 24) & 0xFF;
			Message_Block[61] = ll[2];//(Length_Low >> 16) & 0xFF;
			Message_Block[62] = ll[1];//(Length_Low >> 8) & 0xFF;
			Message_Block[63] = ll[0];//(Length_Low) & 0xFF;
			ProcessMessageBlock(Message_Block, H);
		}
	}

	unsigned char* input;
	unsigned char* output;
	for (int i = 0; i < 5; i++)
	{
		input = (unsigned char*)&H[i];
		output = &digit[i * 8];
		output[0] = fastHexCharHigh[input[3]];
		output[1] = fastHexCharLow[input[3] ];
		output[2] = fastHexCharHigh[input[2]];
		output[3] = fastHexCharLow[input[2] ];
		output[4] = fastHexCharHigh[input[1]];
		output[5] = fastHexCharLow[input[1] ];
		output[6] = fastHexCharHigh[input[0]];
		output[7] = fastHexCharLow[input[0] ];
	}

	unsigned int temp;						// Temporary word value
	unsigned int W[80];						// Word sequence
	unsigned char* w;
	unsigned char* d;
	unsigned int A, B, C, D, E;				// Word buffers
	for (long long z = 1; z < sha1times; z++)
	{
		H[0] = 0x67452301;
		H[1] = 0xEFCDAB89;
		H[2] = 0x98BADCFE;
		H[3] = 0x10325476;
		H[4] = 0xC3D2E1F0;

		INITWA(0);
		INITWA(1);
		INITWA(2);
		INITWA(3);
		INITWA(4);
		INITWA(5);
		INITWA(6);
		INITWA(7);
		INITWA(8);
		INITWA(9);

		W[10] = 2147483648;
		W[11] = W[12] = W[13] = W[14] = 0;
		W[15] = 320;

		INITB(16,temp);
		INITB(17,temp);
		INITB(18,temp);
		INITB(19,temp);
		INITB(20,temp);
		INITB(21,temp);
		INITB(22,temp);
		INITB(23,temp);
		INITB(24,temp);
		INITB(25,temp);
		INITB(26,temp);
		INITB(27,temp);
		INITB(28,temp);
		INITB(29,temp);
		INITB(30,temp);
		INITB(31,temp);
		INITB(32,temp);
		INITB(33,temp);
		INITB(34,temp);
		INITB(35,temp);
		INITB(36,temp);
		INITB(37,temp);
		INITB(38,temp);
		INITB(39,temp);
		INITB(40,temp);
		INITB(41,temp);
		INITB(42,temp);
		INITB(43,temp);
		INITB(44,temp);
		INITB(45,temp);
		INITB(46,temp);
		INITB(47,temp);
		INITB(48,temp);
		INITB(49,temp);
		INITB(50,temp);
		INITB(51,temp);
		INITB(52,temp);
		INITB(53,temp);
		INITB(54,temp);
		INITB(55,temp);
		INITB(56,temp);
		INITB(57,temp);
		INITB(58,temp);
		INITB(59,temp);
		INITB(60,temp);
		INITB(61,temp);
		INITB(62,temp);
		INITB(63,temp);
		INITB(64,temp);
		INITB(65,temp);
		INITB(66,temp);
		INITB(67,temp);
		INITB(68,temp);
		INITB(69,temp);
		INITB(70,temp);
		INITB(71,temp);
		INITB(72,temp);
		INITB(73,temp);
		INITB(74,temp);
		INITB(75,temp);
		INITB(76,temp);
		INITB(77,temp);
		INITB(78,temp);
		INITB(79,temp);

		A = H[0];
		B = H[1];
		C = H[2];
		D = H[3];
		E = H[4];

		FF(A, B, C, D, E, W[0]);
		FF(E, A, B, C, D, W[1]);
		FF(D, E, A, B, C, W[2]);
		FF(C, D, E, A, B, W[3]);
		FF(B, C, D, E, A, W[4]);
		FF(A, B, C, D, E, W[5]);
		FF(E, A, B, C, D, W[6]);
		FF(D, E, A, B, C, W[7]);
		FF(C, D, E, A, B, W[8]);
		FF(B, C, D, E, A, W[9]);
		FF(A, B, C, D, E, W[10]);
		FF(E, A, B, C, D, W[11]);
		FF(D, E, A, B, C, W[12]);
		FF(C, D, E, A, B, W[13]);
		FF(B, C, D, E, A, W[14]);
		FF(A, B, C, D, E, W[15]);
		FF(E, A, B, C, D, W[16]);
		FF(D, E, A, B, C, W[17]);
		FF(C, D, E, A, B, W[18]);
		FF(B, C, D, E, A, W[19]);

		GG(A, B, C, D, E, W[20]);
		GG(E, A, B, C, D, W[21]);
		GG(D, E, A, B, C, W[22]);
		GG(C, D, E, A, B, W[23]);
		GG(B, C, D, E, A, W[24]);
		GG(A, B, C, D, E, W[25]);
		GG(E, A, B, C, D, W[26]);
		GG(D, E, A, B, C, W[27]);
		GG(C, D, E, A, B, W[28]);
		GG(B, C, D, E, A, W[29]);
		GG(A, B, C, D, E, W[30]);
		GG(E, A, B, C, D, W[31]);
		GG(D, E, A, B, C, W[32]);
		GG(C, D, E, A, B, W[33]);
		GG(B, C, D, E, A, W[34]);
		GG(A, B, C, D, E, W[35]);
		GG(E, A, B, C, D, W[36]);
		GG(D, E, A, B, C, W[37]);
		GG(C, D, E, A, B, W[38]);
		GG(B, C, D, E, A, W[39]);

		HH(A, B, C, D, E, W[40]);
		HH(E, A, B, C, D, W[41]);
		HH(D, E, A, B, C, W[42]);
		HH(C, D, E, A, B, W[43]);
		HH(B, C, D, E, A, W[44]);
		HH(A, B, C, D, E, W[45]);
		HH(E, A, B, C, D, W[46]);
		HH(D, E, A, B, C, W[47]);
		HH(C, D, E, A, B, W[48]);
		HH(B, C, D, E, A, W[49]);
		HH(A, B, C, D, E, W[50]);
		HH(E, A, B, C, D, W[51]);
		HH(D, E, A, B, C, W[52]);
		HH(C, D, E, A, B, W[53]);
		HH(B, C, D, E, A, W[54]);
		HH(A, B, C, D, E, W[55]);
		HH(E, A, B, C, D, W[56]);
		HH(D, E, A, B, C, W[57]);
		HH(C, D, E, A, B, W[58]);
		HH(B, C, D, E, A, W[59]);

		II(A, B, C, D, E, W[60]);
		II(E, A, B, C, D, W[61]);
		II(D, E, A, B, C, W[62]);
		II(C, D, E, A, B, W[63]);
		II(B, C, D, E, A, W[64]);
		II(A, B, C, D, E, W[65]);
		II(E, A, B, C, D, W[66]);
		II(D, E, A, B, C, W[67]);
		II(C, D, E, A, B, W[68]);
		II(B, C, D, E, A, W[69]);
		II(A, B, C, D, E, W[70]);
		II(E, A, B, C, D, W[71]);
		II(D, E, A, B, C, W[72]);
		II(C, D, E, A, B, W[73]);
		II(B, C, D, E, A, W[74]);
		II(A, B, C, D, E, W[75]);
		II(E, A, B, C, D, W[76]);
		II(D, E, A, B, C, W[77]);
		II(C, D, E, A, B, W[78]);
		II(B, C, D, E, A, W[79]);

		H[0] += /*(H[0] +*/ A/*) /*& 0xFFFFFFFF*/;
		H[1] += /*(H[1] +*/ B/*) /*& 0xFFFFFFFF*/;
		H[2] += /*(H[2] +*/ C/*) /*& 0xFFFFFFFF*/;
		H[3] += /*(H[3] +*/ D/*) /*& 0xFFFFFFFF*/;
		H[4] += /*(H[4] +*/ E/*) /*& 0xFFFFFFFF*/;

		for (int i = 0; i < 5; i++)
		{
			input = (unsigned char*)&H[i];
			output = &digit[i * 8];
			output[0] = fastHexCharHigh[input[3]];
			output[1] = fastHexCharLow[input[3] ];
			output[2] = fastHexCharHigh[input[2]];
			output[3] = fastHexCharLow[input[2] ];
			output[4] = fastHexCharHigh[input[1]];
			output[5] = fastHexCharLow[input[1] ];
			output[6] = fastHexCharHigh[input[0]];
			output[7] = fastHexCharLow[input[0] ];
		}
	}

	memcpy(lpSHACode_Output, digit, 40);

	return true;
}

inline void ProcessMessageBlock(const unsigned char* digit,unsigned int * H)
{
	unsigned 	temp;						// Temporary word value
	unsigned	W[80];						// Word sequence
	unsigned	A, B, C, D, E;				// Word buffers
	unsigned char* w;
	const unsigned char* d;
	/*
	 *	Initialize the first 16 words in the array W
	 */
	INITWA(0);
	INITWA(1);
	INITWA(2);
	INITWA(3);
	INITWA(4);
	INITWA(5);
	INITWA(6);
	INITWA(7);
	INITWA(8);
	INITWA(9);
	INITWA(10);
	INITWA(11);
	INITWA(12);
	INITWA(13);
	INITWA(14);
	INITWA(15);
	//W[10] = 2147483648;
	//W[11] = W[12] = W[13] = W[14] = 0;
	//W[15] = 320;

	INITB(16,temp);
	INITB(17,temp);
	INITB(18,temp);
	INITB(19,temp);
	INITB(20,temp);
	INITB(21,temp);
	INITB(22,temp);
	INITB(23,temp);
	INITB(24,temp);
	INITB(25,temp);
	INITB(26,temp);
	INITB(27,temp);
	INITB(28,temp);
	INITB(29,temp);
	INITB(30,temp);
	INITB(31,temp);
	INITB(32,temp);
	INITB(33,temp);
	INITB(34,temp);
	INITB(35,temp);
	INITB(36,temp);
	INITB(37,temp);
	INITB(38,temp);
	INITB(39,temp);
	INITB(40,temp);
	INITB(41,temp);
	INITB(42,temp);
	INITB(43,temp);
	INITB(44,temp);
	INITB(45,temp);
	INITB(46,temp);
	INITB(47,temp);
	INITB(48,temp);
	INITB(49,temp);
	INITB(50,temp);
	INITB(51,temp);
	INITB(52,temp);
	INITB(53,temp);
	INITB(54,temp);
	INITB(55,temp);
	INITB(56,temp);
	INITB(57,temp);
	INITB(58,temp);
	INITB(59,temp);
	INITB(60,temp);
	INITB(61,temp);
	INITB(62,temp);
	INITB(63,temp);
	INITB(64,temp);
	INITB(65,temp);
	INITB(66,temp);
	INITB(67,temp);
	INITB(68,temp);
	INITB(69,temp);
	INITB(70,temp);
	INITB(71,temp);
	INITB(72,temp);
	INITB(73,temp);
	INITB(74,temp);
	INITB(75,temp);
	INITB(76,temp);
	INITB(77,temp);
	INITB(78,temp);
	INITB(79,temp);

	A = H[0];
	B = H[1];
	C = H[2];
	D = H[3];
	E = H[4];

	FF(A, B, C, D, E, W[0]);
	FF(E, A, B, C, D, W[1]);
	FF(D, E, A, B, C, W[2]);
	FF(C, D, E, A, B, W[3]);
	FF(B, C, D, E, A, W[4]);
	FF(A, B, C, D, E, W[5]);
	FF(E, A, B, C, D, W[6]);
	FF(D, E, A, B, C, W[7]);
	FF(C, D, E, A, B, W[8]);
	FF(B, C, D, E, A, W[9]);
	FF(A, B, C, D, E, W[10]);
	FF(E, A, B, C, D, W[11]);
	FF(D, E, A, B, C, W[12]);
	FF(C, D, E, A, B, W[13]);
	FF(B, C, D, E, A, W[14]);
	FF(A, B, C, D, E, W[15]);
	FF(E, A, B, C, D, W[16]);
	FF(D, E, A, B, C, W[17]);
	FF(C, D, E, A, B, W[18]);
	FF(B, C, D, E, A, W[19]);

	GG(A, B, C, D, E, W[20]);
	GG(E, A, B, C, D, W[21]);
	GG(D, E, A, B, C, W[22]);
	GG(C, D, E, A, B, W[23]);
	GG(B, C, D, E, A, W[24]);
	GG(A, B, C, D, E, W[25]);
	GG(E, A, B, C, D, W[26]);
	GG(D, E, A, B, C, W[27]);
	GG(C, D, E, A, B, W[28]);
	GG(B, C, D, E, A, W[29]);
	GG(A, B, C, D, E, W[30]);
	GG(E, A, B, C, D, W[31]);
	GG(D, E, A, B, C, W[32]);
	GG(C, D, E, A, B, W[33]);
	GG(B, C, D, E, A, W[34]);
	GG(A, B, C, D, E, W[35]);
	GG(E, A, B, C, D, W[36]);
	GG(D, E, A, B, C, W[37]);
	GG(C, D, E, A, B, W[38]);
	GG(B, C, D, E, A, W[39]);

	HH(A, B, C, D, E, W[40]);
	HH(E, A, B, C, D, W[41]);
	HH(D, E, A, B, C, W[42]);
	HH(C, D, E, A, B, W[43]);
	HH(B, C, D, E, A, W[44]);
	HH(A, B, C, D, E, W[45]);
	HH(E, A, B, C, D, W[46]);
	HH(D, E, A, B, C, W[47]);
	HH(C, D, E, A, B, W[48]);
	HH(B, C, D, E, A, W[49]);
	HH(A, B, C, D, E, W[50]);
	HH(E, A, B, C, D, W[51]);
	HH(D, E, A, B, C, W[52]);
	HH(C, D, E, A, B, W[53]);
	HH(B, C, D, E, A, W[54]);
	HH(A, B, C, D, E, W[55]);
	HH(E, A, B, C, D, W[56]);
	HH(D, E, A, B, C, W[57]);
	HH(C, D, E, A, B, W[58]);
	HH(B, C, D, E, A, W[59]);

	II(A, B, C, D, E, W[60]);
	II(E, A, B, C, D, W[61]);
	II(D, E, A, B, C, W[62]);
	II(C, D, E, A, B, W[63]);
	II(B, C, D, E, A, W[64]);
	II(A, B, C, D, E, W[65]);
	II(E, A, B, C, D, W[66]);
	II(D, E, A, B, C, W[67]);
	II(C, D, E, A, B, W[68]);
	II(B, C, D, E, A, W[69]);
	II(A, B, C, D, E, W[70]);
	II(E, A, B, C, D, W[71]);
	II(D, E, A, B, C, W[72]);
	II(C, D, E, A, B, W[73]);
	II(B, C, D, E, A, W[74]);
	II(A, B, C, D, E, W[75]);
	II(E, A, B, C, D, W[76]);
	II(D, E, A, B, C, W[77]);
	II(C, D, E, A, B, W[78]);
	II(B, C, D, E, A, W[79]);

	H[0] += /*(H[0] +*/ A/*) /*& 0xFFFFFFFF*/;
	H[1] += /*(H[1] +*/ B/*) /*& 0xFFFFFFFF*/;
	H[2] += /*(H[2] +*/ C/*) /*& 0xFFFFFFFF*/;
	H[3] += /*(H[3] +*/ D/*) /*& 0xFFFFFFFF*/;
	H[4] += /*(H[4] +*/ E/*) /*& 0xFFFFFFFF*/;
}

