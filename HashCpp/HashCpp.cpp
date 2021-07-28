// MD5Cpp.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include "md5plus.h"
#include "sha1.h"
#include "md2.h"
#include "md4.h"
#include "whirlpool.h"
#include "sha2.h"
#include<string>
#include<vector>
#include <windows.h>
#include <iostream>
#include <list>

std::wstring Acsi2WideByte(std::string& strascii)
{
    int widesize = MultiByteToWideChar(CP_ACP, 0, (char*)strascii.c_str(), -1, NULL, 0);
    if (widesize == ERROR_NO_UNICODE_TRANSLATION)
    {
        throw std::exception("Invalid UTF-8 sequence.");
    }
    if (widesize == 0)
    {
        throw std::exception("Error in conversion.");
    }
    std::vector<wchar_t> resultstring(widesize);
    int convresult = MultiByteToWideChar(CP_ACP, 0, (char*)strascii.c_str(), -1, &resultstring[0], widesize);


    if (convresult != widesize)
    {
        throw std::exception("La falla!");
    }

    return std::wstring(&resultstring[0]);
}

std::string Unicode2Utf8(const std::wstring& widestring)
{
    int utf8size = ::WideCharToMultiByte(CP_UTF8, 0, widestring.c_str(), -1, NULL, 0, NULL, NULL);
    if (utf8size == 0)
    {
        throw std::exception("Error in conversion.");
    }

    std::vector<char> resultstring(utf8size);

    int convresult = ::WideCharToMultiByte(CP_UTF8, 0, widestring.c_str(), -1, &resultstring[0], utf8size, NULL, NULL);

    if (convresult != utf8size)
    {
        throw std::exception("La falla!");
    }

    return std::string(&resultstring[0]);
}

std::string ASCII2UTF_8(std::string& strAsciiCode)
{
    std::string strRet("");
    //先把 ascii 转为 unicode  
    std::wstring wstr = Acsi2WideByte(strAsciiCode);
    //最后把 unicode 转为 utf8  
    strRet = Unicode2Utf8(wstr);
    return strRet;
}
enum HashType
{
    MD5=0,MD4=1,SHA1=2,SHA256=3,SHA384=4,SHA512=5,WHIRLPOOL=6,MD2=7
};
enum FileMode {
    LINES=0,TOTAL
};
enum Mode {
    HASH=0,TEST
};

const char *hashName[] = { "MD5","MD4","SHA1","SHA256","SHA384","SHA512","WHIRLPOOL","MD2" };

void printHelp()
{
    printf("HashCpp: version 1.0\r\nAuthor: ixCiel\r\nUsage:\r\n\thashcpp [options] [string to hash]\r\nOptions:\r\n\t-help\t\tPrint this help\r\n\t-h\t\tPrint this help\r\n\t-?\t\tPrint this help\r\n\t-v\t\tPrint this help\r\n");
    printf("\t-md2\t\tUse md2 hash algorithmn\r\n\t-md5\t\tUse md5 hash algorithmn\r\n\t-md4\t\tUse md4 hash algorithmn\r\n\t-sha1\t\tUse sha1 hash algorithmn\r\n\t-sha256\t\tUse sha256 hash algorithmn\r\n\t-sha384\t\tUse sha384 hash algorithmn\r\n\t-sha512\t\tUse sha512 hash algorithmn\r\n\t-whirlpool\t\tUse whirlpool hash algorithmn\r\n");
    printf("\t-t <times>\t\tHash times\r\n");
    //printf("\t-p <path>\t\tHash filepath\r\n");
    //printf("\t-lines\t\t One hash every line\r\n");
    //printf("\t-test\t\t");

}
//void Md2Plus(unsigned char* lpData_Input, unsigned int lpData_Length, char* lpCode_Output, long long hashTimes)
//{
//    Md2Context ctx;
//    md2Init(&ctx);
//    md2Update(&ctx, lpData_Input, lpData_Length);
//    md2Final(&ctx, lpCode_Output);
//    for (long long z = 1; z < hashTimes; z++)
//    {
//        md2Init(&ctx);
//        md2Update(&ctx, lpCode_Output, 32);
//        md2Final(&ctx, lpCode_Output);
//    }
//}
void SHA256Plus(unsigned char* lpData_Input, unsigned int lpData_Length, char* lpCode_Output, long long hashTimes)
{
    SHA2_SHA256_CTX ctx;
    SHA2_SHA256_Init(&ctx);
    SHA2_SHA256_Update(&ctx, lpData_Input, lpData_Length);
    SHA2_SHA256_Final(&ctx, lpCode_Output);
    for (long long z = 1; z < hashTimes; z++)
    {
        SHA2_SHA256_Init(&ctx);
        SHA2_SHA256_Update(&ctx, (unsigned char*)lpCode_Output, 64);
        SHA2_SHA256_Final(&ctx, lpCode_Output);
    }
}

void SHA384Plus(unsigned char* lpData_Input, unsigned int lpData_Length, char* lpCode_Output, long long hashTimes)
{
    SHA2_SHA384_CTX ctx;
    SHA2_SHA384_Init(&ctx);
    SHA2_SHA384_Update(&ctx, lpData_Input, lpData_Length);
    SHA2_SHA384_Final(&ctx, lpCode_Output);
    for (long long z = 1; z < hashTimes; z++)
    {
        SHA2_SHA384_Init(&ctx);
        SHA2_SHA384_Update(&ctx, (unsigned char*)lpCode_Output, 96);
        SHA2_SHA384_Final(&ctx, lpCode_Output);
    }
}


void SHA512Plus(unsigned char* lpData_Input, unsigned int lpData_Length, char* lpCode_Output, long long hashTimes)
{
    SHA2_SHA512_CTX ctx;
    SHA2_SHA512_Init(&ctx);
    SHA2_SHA512_Update(&ctx, lpData_Input, lpData_Length);
    SHA2_SHA512_Final(&ctx, lpCode_Output);
    for (long long z = 1; z < hashTimes; z++)
    {
        SHA2_SHA512_Init(&ctx);
        SHA2_SHA512_Update(&ctx, (unsigned char*)lpCode_Output, 128);
        SHA2_SHA512_Final(&ctx, lpCode_Output);
    }
}

int main(int argc, char* argv[])
{
    std::list<unsigned char*>contents;
    std::list<size_t>contentLengths;
    std::list<char*> files;
    std::list<HashType> types;
    unsigned char* str = nullptr;
    size_t strLength = 0;
    long long hashTimes = 1;
    char* path = nullptr;
    size_t pathLength = 0;
    char* key = nullptr;
    size_t keyLength = 0;
    char* value = nullptr;
    bool withoutContent = false;
    size_t valueLength = 0;
    FileMode fm = TOTAL;
    Mode mode = HASH;
    contents.clear();
    contentLengths.clear();
    files.clear();
    types.clear();
    for (int i = 1; i < argc; i++)
    {
        key = argv[i];
        keyLength = strlen(key);
        if (keyLength > 0)
        {
            if (key[0] == '-')
            {
                if (strcmp(key, "-md2") == 0)
                {
                    types.push_back(MD2);
                }
                else if (strcmp(key, "-md4") == 0)
                {
                    types.push_back(MD4);
                }
                else if (strcmp(key, "-md5") == 0)
                {
                    types.push_back(MD5);
                }
                else if (strcmp(key, "-sha1") == 0)
                {
                    types.push_back(SHA1);
                }
                else if (strcmp(key, "-sha256") == 0)
                {
                    types.push_back(SHA256);
                }
                else if (strcmp(key, "-sha384") == 0)
                {
                    types.push_back(SHA384);
                }
                else if (strcmp(key, "-sha512") == 0)
                {
                    types.push_back(SHA512);
                }
                else if (strcmp(key, "-whirlpool") == 0)
                {
                    types.push_back(WHIRLPOOL);
                }
                else if (strcmp(key, "-lines") == 0)
                {
                    fm = LINES;
                }
                else if (strcmp(key, "-test") == 0)
                {
                    mode = TEST;
                }
                else if (strcmp(key, "-p") == 0)
                {
                    i++;
                    if (i >= argc)
                    {
                        printHelp();
                        return 1;
                    }
                    value = argv[i];
                    pathLength = strlen(value);
                    if (pathLength == 0)
                    {
                        printHelp();
                        return 1;
                    }
                    path = (char*)malloc(pathLength + 1);
                    memcpy(path, value, pathLength);
                    path[pathLength] = 0;
                    files.push_back(path);
                }
                else if (strcmp(key, "-t") == 0)
                {
                    i++;
                    if (i >= argc)
                    {
                        printHelp();
                        return 1;
                    }
                    value = argv[i];
                    try
                    {
                        hashTimes = atoll(value);
                        
                    }
                    catch (...)
                    {
                        hashTimes = 0;
                    }
                    if (hashTimes == 0)
                    {
                        printHelp();
                        return 1;
                    }
                }
                else if (strcmp(key, "-?") == 0 || strcmp(key, "-h") == 0 || strcmp(key, "-help") == 0 || strcmp(key, "-H") == 0 || strcmp(key, "-v") == 0)
                {
                    printHelp();
                    return 1;
                }
                else if (strcmp(key, "-trad") == 0)
                {
                    withoutContent = true;
                }
            }
            else
            {
                //std::string tmp(key);
                //std::string content = ASCII2UTF_8(tmp);
                strLength = strlen(key);
                str = (unsigned char*)malloc(strLength + 1);
                memcpy(str, key, strLength);
                str[strLength] = 0;
                contents.push_back(str);
                contentLengths.push_back(strLength);
            }
        }
    }
    if (!files.empty())
    {

    }
    if (contents.empty())
    {
        printHelp();
        return 1;
    }
    LARGE_INTEGER t1, t2, tc;
    QueryPerformanceFrequency(&tc);
    printf("Frequency: %llu\r\n", tc.QuadPart);
    QueryPerformanceCounter(&t1);
    printf("Begin Time: %llu\r\n", t1.QuadPart);
    char HashCodeBuffer[1025];
    memset(HashCodeBuffer, 0, 1025);
    std::list<unsigned char*>::iterator it;
    std::list<HashType>::iterator type;
    withoutContent = contents.size() == 1 || withoutContent;
    if (types.empty())
        types.push_back(MD5);
    bool withHashType = types.size() != 1;
    unsigned char* utf8 = nullptr;
    std::vector<char> utf8Buffer;
    for (it = contents.begin(); it != contents.end(); it++)
    {
        str = *it;
        if (!withoutContent)
            printf("%s:\r\n", str);
        std::string tmp((char *)str);
        std::string content = ASCII2UTF_8(tmp);
        strLength = content.length();
        if (strLength >= utf8Buffer.size())
        {
            utf8Buffer.resize(strLength + 1);
        }
        utf8 = (unsigned char *)&utf8Buffer[0];
        memcpy(utf8, content.c_str(), strLength);
        utf8[strLength] = 0;
        for (type = types.begin(); type != types.end(); type++) {
            switch (*type)
            {
            case MD2:
                Md2Plus(utf8, strLength, HashCodeBuffer, hashTimes);
                break;
            case MD4:
                md4Plus(utf8, strLength, (unsigned char*)HashCodeBuffer, hashTimes);
                break;
            case MD5:
                md5Plus(utf8, strLength, (unsigned char*)HashCodeBuffer, hashTimes);
                break;
            case SHA1:
                SHA1Plus((char*)utf8, strLength, HashCodeBuffer, hashTimes);
                break;
            case WHIRLPOOL:
                WHIRLPOOLPlus(utf8, strLength, (unsigned char*)HashCodeBuffer, hashTimes);
                break;
            case SHA256:
                SHA256Plus(utf8, strLength, HashCodeBuffer, hashTimes);
                break;
            case SHA384:
                SHA384Plus(utf8, strLength, HashCodeBuffer, hashTimes);
                break;
            case SHA512:
                SHA512Plus(utf8, strLength, HashCodeBuffer, hashTimes);
                break;
            }
            if (!withoutContent)
                printf("\t");
            if (withHashType)
                printf("%s:\r\n\t", hashName[*type]);
            printf(HashCodeBuffer);
            printf("\r\n");
        }
    }

    QueryPerformanceCounter(&t2);
    printf("End Time: %llu\r\n", t2.QuadPart);
    printf("Lasting Time: %llu\r\n", (t2.QuadPart - t1.QuadPart));
    int time = (t2.QuadPart - t1.QuadPart) * 1000000 / tc.QuadPart;
    printf("Run Time: %ds%03d.%03dms\r\n", time/1000000,time % 1000000 / 1000,time % 1000);
    return 0;
}
