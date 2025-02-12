#pragma once

#include <Windows.h>
#include <cstdio>
#include <iostream>

extern BYTE shellCode[];

// 将文件读取到缓冲区 失败返回0 否则返回实际读取的大小
DWORD ReadPEFile(LPCSTR lpszFile, LPVOID *pFileBuffer);

// 将文件从FileBuffer复制到ImageBuffer 读取失败返回0 否则返回复制的大小
DWORD CopyFileBufferToImageBuffer(LPVOID pFileBuffer, LPVOID *pImageBuffer);

// 将内存数据复制到新的文件缓冲区中 读取失败返回0 否则返回复制的大小
DWORD CopyImageBufferToNewBuffer(LPVOID pImageBuffer, LPVOID *pNewBuffer);

//通过内存地址找到文件偏移	返回转换后的FOA的值  如果失败返回0							
DWORD RvaToFileOffset(LPVOID pFileBuffer, DWORD dwRva);

// 将 RVA ->  FOA
DWORD RvaToFoa(LPVOID pFileBuffer, DWORD dwRva);

// 将 FOA -> RVA
DWORD FoaToRva(LPVOID pFileBuffer, DWORD Rva);

// 加壳 往代码段添加自己的代码
void TestAddCodeInCodeSec();

//添加节表：模式一:直接在旧节表后面添加
void TestAddImageNewSec2();

//添加节表：模式二:在pe头的垃圾字段
void TestAddImageNewSec3();

// 扩大最后一个节  扩大其它节修改的偏移太多
void TestExpandLastSection();

// 存盘
void MemeryToFile(void *, unsigned int, const char*);

// 打印导出表信息
void PrintExportTable();

// 打印导入表信息
void PrintImportTable();

// 打印重定位表信息
void PrintRelocationTable();

// 移动导出表 
void MoveExportTable();

// 移动重定位表
void MoveRelocationTable();

// 计算重定位表总共大小
void demo1();
