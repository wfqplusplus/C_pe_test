#include "func.h"

BYTE shellCode[] = {
	0x6A, 00, 0x6A, 00, 0x6A, 00, 0x6A, 00,
	0xE8, 00, 00, 00, 00,
	0xE9, 00, 00, 00, 00
};

#define FILEPATH_IN                     "D:\\gdi42.dll"
#define FILEPATH_OUT                    "D:\\new.dll"
#define SHELL_CODE_LENGTH				0X12
#define MESSAGEBOX_ADDR                 0x75710E80   // 0x75A11290  76B40E80  76EB1290

DWORD ReadPEFile(LPCSTR lpszFile, LPVOID *pFileBuffer) {

	FILE *pFile = nullptr;
	DWORD fileSize = 0;
	LPVOID pTempFileBuffer = nullptr;

	pFile = fopen(lpszFile, "rb");
	if (!pFile) {
		printf("无法打开文件\n");
		return 0;
	}

	// 读取文件大小
	fseek(pFile, 0, SEEK_END);
	fileSize = ftell(pFile);
	fseek(pFile, 0, SEEK_SET);

	// 分配缓冲区
	pTempFileBuffer = malloc(fileSize);

	if (!pTempFileBuffer) {
		printf("分配空间失败！\n");
		fclose(pFile);
		return 0;
	}

	/*PIMAGE_DOS_HEADER        pDosHeader = nullptr;
	PIMAGE_NT_HEADERS        pNTHeader = nullptr;
	PIMAGE_FILE_HEADER       pPEHeader = nullptr;

	pDosHeader = (PIMAGE_DOS_HEADER)pTempFileBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pTempFileBuffer + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 4);*/

	/*pPEHeader->Characteristics = IMAGE_FILE_RELOCS_STRIPPED;*/

	size_t n = fread(pTempFileBuffer, fileSize, 1, pFile);

	if (!n) {
		printf("读取数据失败！\n");
		free(pTempFileBuffer);
		fclose(pFile);
		return 0;
	}

	*pFileBuffer = pTempFileBuffer;
	pTempFileBuffer = nullptr;
	fclose(pFile);

	return fileSize;
}

DWORD CopyFileBufferToImageBuffer(LPVOID pFileBuffer, LPVOID *pImageBuffer) {

	PIMAGE_DOS_HEADER        pDosHeader = nullptr;
	PIMAGE_NT_HEADERS        pNTHeader = nullptr;
	PIMAGE_FILE_HEADER       pPEHeader = nullptr;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = nullptr;
	PIMAGE_SECTION_HEADER    pSectionHeader = nullptr;

	LPVOID pTempImageBuffer = nullptr;

	if (pFileBuffer == nullptr) {
		printf("缓冲区指针无效\n");
		return 0;
	}

	// 判断有效的mz标志
	if (*(PWORD)pFileBuffer != IMAGE_DOS_SIGNATURE) {
		printf("无效的mz标志\n");
		return 0;
	}

	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;

	if (*((PDWORD)((DWORD)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE) {
		printf("无效的pe标志\n");
		return 0;
	}

	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	// 申请空间
	pTempImageBuffer = malloc(pOptionHeader->SizeOfImage);

	if (!pTempImageBuffer) {
		printf("分配空间失败\n");
		return 0;
	}

	// 初始化新的缓冲区
	memset(pTempImageBuffer, 0, pOptionHeader->SizeOfImage);
	// Copy头
	memcpy(pTempImageBuffer, pDosHeader, pOptionHeader->SizeOfHeaders);
	// 根据节表 循环Copy节
	PIMAGE_SECTION_HEADER ptempSectionHeader = pSectionHeader;

	for (int i = 0; i < pPEHeader->NumberOfSections; i++, ptempSectionHeader++) {
		memcpy((void*)((DWORD)pTempImageBuffer + ptempSectionHeader->VirtualAddress),
			(const void*)((DWORD)pDosHeader + ptempSectionHeader->PointerToRawData),
			ptempSectionHeader->SizeOfRawData);
	}

	ptempSectionHeader = nullptr;

	*pImageBuffer = pTempImageBuffer;
	pTempImageBuffer = nullptr;

	return pOptionHeader->SizeOfImage;
}

DWORD CopyImageBufferToNewBuffer(LPVOID pImageBuffer, LPVOID *pNewBuffer) {

	if (pImageBuffer == nullptr) {
		printf("ImageBuffer缓冲区无效\n");
		return 0;
	}

	PIMAGE_DOS_HEADER              pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	PIMAGE_NT_HEADERS              pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pImageBuffer + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER             pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 4);
	PIMAGE_OPTIONAL_HEADER32       pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER          pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	// 节的个数
	DWORD numberOfSection = pPEHeader->NumberOfSections;

	PIMAGE_SECTION_HEADER tmp_sec = pSectionHeader;
	tmp_sec = tmp_sec + (numberOfSection - 1);        // 跳转到最后一个节

	// 计算还原后文件大小
	DWORD sizeOfFile = tmp_sec->PointerToRawData + tmp_sec->SizeOfRawData;
	tmp_sec = nullptr;

	// 分配newbuffer
	LPVOID pTempNewBuffer = malloc(sizeOfFile);

	if (!pTempNewBuffer) {
		printf("分配空间失败\n");
		return 0;
	}

	// 初始化新的缓冲区
	memset(pTempNewBuffer, 0, sizeOfFile);
	// Copy头
	memcpy(pTempNewBuffer, pDosHeader, pOptionHeader->SizeOfHeaders);

	// Copy节
	PIMAGE_SECTION_HEADER ptempSectionHeader = pSectionHeader;

	for (int i = 0; i < pPEHeader->NumberOfSections; i++, ptempSectionHeader++) {
		memcpy((void*)((DWORD)pTempNewBuffer + ptempSectionHeader->PointerToRawData),
			(const void*)((DWORD)pDosHeader + ptempSectionHeader->VirtualAddress),
			ptempSectionHeader->SizeOfRawData);
	}

	ptempSectionHeader = nullptr;

	*pNewBuffer = pTempNewBuffer;
	pTempNewBuffer = nullptr;

	return sizeOfFile;

}

void MemeryToFile(void *memery, unsigned int size, const char *fileName) {
	FILE *file = fopen(fileName, "wb");

	if (file == nullptr) {
		perror("无法打开文件");
		return;
	}

	fwrite((const void*)memery, sizeof(BYTE), size, file);

	printf("存盘成功\n");
}

DWORD RvaToFileOffset(LPVOID pFileBuffer, DWORD dwRva) {

	PIMAGE_DOS_HEADER        pDosHeader = nullptr;
	PIMAGE_NT_HEADERS        pNTHeader = nullptr;
	PIMAGE_FILE_HEADER       pPEHeader = nullptr;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = nullptr;
	PIMAGE_SECTION_HEADER    pSectionHeader = nullptr;

	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	// 得到拉伸后内存中的偏移量
	DWORD rva = dwRva - pOptionHeader->ImageBase;
	// 判断rva 是否在 pe头中 是 foa == rva
	if (rva <= pOptionHeader->SizeOfHeaders)
		return dwRva;

	// 判断位于哪个节
	PIMAGE_SECTION_HEADER tmp_sec = pSectionHeader;
	for (int i = 0; i < pPEHeader->NumberOfSections; i++) {
		if (rva >= tmp_sec->VirtualAddress && rva < (tmp_sec->VirtualAddress + tmp_sec->SizeOfRawData)) {
			// 确定所在节后，计算在节中的偏移
			DWORD sec_rva = rva - tmp_sec->VirtualAddress;
			// 算出在文件中的偏移
			return tmp_sec->PointerToRawData + sec_rva;
		}
		tmp_sec++;
	}

	return 0;
}

DWORD RvaToFoa(LPVOID pFileBuffer, DWORD Rva) {
	PIMAGE_DOS_HEADER        pDosHeader = nullptr;
	PIMAGE_NT_HEADERS        pNTHeader = nullptr;
	PIMAGE_FILE_HEADER       pPEHeader = nullptr;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = nullptr;
	PIMAGE_SECTION_HEADER    pSectionHeader = nullptr;

	/*DWORD real_image_base;

	HMODULE hModule = GetModuleHandle(L"C:\\appverifUI.dll");
	if (!hModule) {
		return 0;
	}

	real_image_base = (DWORD)hModule;*/

	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	//pOptionHeader->ImageBase = real_image_base;

	// 判断rva 是否在 pe头中 是 foa == rva
	if (Rva <= pOptionHeader->SizeOfHeaders)
		return Rva;

	// 判断位于哪个节
	PIMAGE_SECTION_HEADER tmp_sec = pSectionHeader;
	for (int i = 0; i < pPEHeader->NumberOfSections; i++) {
		if (Rva >= tmp_sec->VirtualAddress && Rva < (tmp_sec->VirtualAddress + tmp_sec->Misc.VirtualSize)) {
			// 确定所在节后，计算在节中的偏移
			DWORD sec_rva = Rva - tmp_sec->VirtualAddress;
			// 算出在文件中的偏移
			return tmp_sec->PointerToRawData + sec_rva;
		}
		tmp_sec++;
	}

	return 0;
}

DWORD FoaToRva(LPVOID pFileBuffer, DWORD foa) {
	PIMAGE_DOS_HEADER pDosHeader = nullptr;
	PIMAGE_NT_HEADERS pNTHeader = nullptr;
	PIMAGE_SECTION_HEADER pSectionHeader = nullptr;

	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	pSectionHeader = IMAGE_FIRST_SECTION(pNTHeader);

	// 判断foa是否在PE头中
	if (foa < pNTHeader->OptionalHeader.SizeOfHeaders)
		return foa;

	// 判断位于哪个节
	for (int i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++) {
		if (foa >= pSectionHeader[i].PointerToRawData && foa < (pSectionHeader[i].PointerToRawData + pSectionHeader[i].SizeOfRawData)) {
			// 确定所在节后，计算在节中的偏移
			DWORD sec_foa = foa - pSectionHeader[i].PointerToRawData;
			// 算出在虚拟内存中的偏移
			return pSectionHeader[i].VirtualAddress + sec_foa;
		}
	}

	return 0;
}

DWORD RvaToFoa2(LPVOID pFileBuffer, DWORD Rva) {
	PIMAGE_DOS_HEADER pDosHeader = nullptr;
	PIMAGE_NT_HEADERS pNTHeader = nullptr;
	PIMAGE_SECTION_HEADER pSectionHeader = nullptr;

	// 检查文件缓冲区是否为空
	if (pFileBuffer == nullptr)
		return 0;

	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	// 检查 DOS 头是否有效
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return 0;

	// 计算 NT 头的偏移量
	DWORD ntHeaderOffset = pDosHeader->e_lfanew;
	if (ntHeaderOffset + sizeof(IMAGE_NT_HEADERS) > pDosHeader->e_lfanew)
		return 0;

	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + ntHeaderOffset);
	// 检查 NT 头是否有效
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
		return 0;

	// 计算节头表的偏移量
	DWORD sectionHeaderOffset = ntHeaderOffset + sizeof(IMAGE_NT_HEADERS);
	if (sectionHeaderOffset + sizeof(IMAGE_SECTION_HEADER) * pNTHeader->FileHeader.NumberOfSections > pDosHeader->e_lfanew)
		return 0;

	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pFileBuffer + sectionHeaderOffset);

	// 判断 RVA 是否在节的范围内
	for (int i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++) {
		if (Rva >= pSectionHeader[i].VirtualAddress && Rva < pSectionHeader[i].VirtualAddress + pSectionHeader[i].Misc.VirtualSize) {
			// 计算在节中的偏移
			DWORD secRva = Rva - pSectionHeader[i].VirtualAddress;
			// 计算在文件中的偏移并返回
			return pSectionHeader[i].PointerToRawData + secRva;
		}
	}

	// 如果未找到对应节，返回 0
	return 0;
}


void TestAddCodeInCodeSec() {

	LPVOID pFileBuffer = nullptr;
	LPVOID pImageBuffer = nullptr;
	LPVOID pNewBuffer = nullptr;

	PIMAGE_DOS_HEADER        pDosHeader = nullptr;
	PIMAGE_FILE_HEADER       pPEHeader = nullptr;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = nullptr;
	PIMAGE_SECTION_HEADER    pSectionHeader = nullptr;

	// File -> FileBuffer
	ReadPEFile(FILEPATH_IN, &pFileBuffer);
	if (!pFileBuffer) {
		printf("File -> FileBuffer Fail!\n");
		return;
	}

	// FileBuffer -> FileImageBuffer
	CopyFileBufferToImageBuffer(pFileBuffer, &pImageBuffer);
	if (!pImageBuffer) {
		printf("FileBuffer -> FileImageBuffer Fail!\n");
		free(pFileBuffer);
		return;
	}

	// 判断代码段的空闲区是否足够存储 ShellCode 代码
	pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + sizeof(IMAGE_OPTIONAL_HEADER32));

	if (((pSectionHeader->SizeOfRawData) - (pSectionHeader->Misc.VirtualSize)) < SHELL_CODE_LENGTH) {
		printf("test段代码空间不足\n");
		free(pFileBuffer);
		free(pImageBuffer);
		return;
	}

	// 寻找代码区   一般第一个节是代码段

	// 将代码复制空闲区
	PBYTE codeBegin = (PBYTE)
		((DWORD)pImageBuffer + pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize);
	memcpy(codeBegin, shellCode, SHELL_CODE_LENGTH);

	// 修正E8 call xxx           xxx = 真正的跳转地址 - 下一条指令地址
	DWORD callAddr = MESSAGEBOX_ADDR
		- (pOptionHeader->ImageBase + ((DWORD)(codeBegin + 0xD)) - (DWORD)pImageBuffer);
	*(PDWORD)(codeBegin + 9) = callAddr;

	// 修正E9  jmp oep
	DWORD jmpAddr = (pOptionHeader->ImageBase + pOptionHeader->AddressOfEntryPoint)
		- (pOptionHeader->ImageBase + ((DWORD)codeBegin + SHELL_CODE_LENGTH - (DWORD)pImageBuffer));
	*(PDWORD)(codeBegin + 0xE) = jmpAddr;

	// 修改oep
	pOptionHeader->AddressOfEntryPoint = (DWORD)codeBegin - (DWORD)pImageBuffer;

	// FileImageBuffer -> NewBuffer
	DWORD size = CopyImageBufferToNewBuffer(pImageBuffer, &pNewBuffer);
	if (size == 0 || !pNewBuffer) {
		printf("FileImageBuffer -> NewBuffer Fail!\n");
		free(pFileBuffer);
		free(pImageBuffer);
		return;
	}

	/*FILE *file = fopen(FILEPATH_OUT, "wb");
	if (file == nullptr) {
		perror("无法打开文件");
		return;
	}

	fwrite((const void*)pNewBuffer, sizeof(BYTE), size, file);*/

	MemeryToFile(pNewBuffer, size, FILEPATH_OUT);

	free(pFileBuffer);
	free(pImageBuffer);
	free(pNewBuffer);

}


void TestAddImageNewSec2() {

	LPVOID pFileBuffer = nullptr;
	LPVOID pImageBuffer = nullptr;
	LPVOID pNewImageBuffer = nullptr;
	LPVOID pNewBuffer = nullptr;

	PIMAGE_DOS_HEADER pDosHeader = nullptr;
	PIMAGE_FILE_HEADER pPEHeader = nullptr;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = nullptr;
	PIMAGE_SECTION_HEADER pSectionHeader = nullptr;

	DWORD size = 0;

	// File -> FileBuffer
	ReadPEFile(FILEPATH_IN, &pFileBuffer);
	if (!pFileBuffer) {
		printf("File -> FileBuffer Fail!\n");
		return;
	}

	// FileBuffer -> FileImageBuffer
	CopyFileBufferToImageBuffer(pFileBuffer, &pImageBuffer);
	if (!pImageBuffer) {
		printf("FileBuffer -> FileImageBuffer Fail!\n");
		free(pFileBuffer);
		return;
	}

	// 判断头部是否有空间可以新增一个节
	pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + sizeof(IMAGE_OPTIONAL_HEADER32));

	DWORD space
		= pOptionHeader->SizeOfHeaders
		- (pDosHeader->e_lfanew + 0x4 + IMAGE_SIZEOF_FILE_HEADER + pPEHeader->SizeOfOptionalHeader + sizeof(IMAGE_SECTION_HEADER) * pPEHeader->NumberOfSections);

	if (space < 2 * sizeof(IMAGE_SECTION_HEADER))
	{
		printf("空间不够!\n");
		free(pFileBuffer);
		free(pImageBuffer);
		return;
	}

	// 新增一个节的数据 1000对齐 加1000字节
	pNewImageBuffer = malloc(pOptionHeader->SizeOfImage + 0x1000);
	if (!pNewImageBuffer) {
		printf("分配空间失败!\n");
		free(pFileBuffer);
		free(pImageBuffer);
		return;
	}

	// 新分配的空间 +0x1000  初始化0
	memset(pNewImageBuffer, 0, pOptionHeader->SizeOfImage + 0x1000);
	// 复制之前的拉伸后的pe
	memcpy(pNewImageBuffer, pImageBuffer, pOptionHeader->SizeOfImage);
	// 指向新的
	pDosHeader = (PIMAGE_DOS_HEADER)pNewImageBuffer;
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 0x4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)
		(((DWORD)pNewImageBuffer + pDosHeader->e_lfanew) + 4 + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + sizeof(IMAGE_OPTIONAL_HEADER32));

	// 在旧表的后面新增一个节表（复制第一个）， 并修改内容
	memcpy(pSectionHeader + pPEHeader->NumberOfSections, pSectionHeader, IMAGE_SIZEOF_SECTION_HEADER);

	// 设置下一个节表空间为0 新增节表的后面
	memset(pSectionHeader + pPEHeader->NumberOfSections + 1, 0, IMAGE_SIZEOF_SECTION_HEADER);

	// 修改pOptionHeader->SizeOfImage的大小 新pe文件变大
	pOptionHeader->SizeOfImage = pOptionHeader->SizeOfImage + 0x1000;

	// 设置节的属性
	strcpy((char*)(pSectionHeader + pPEHeader->NumberOfSections), ".wfq");
	(pSectionHeader + (pPEHeader->NumberOfSections))->Misc.VirtualSize = 0x1000;// 内存大小
	(pSectionHeader + (pPEHeader->NumberOfSections))->SizeOfRawData = 0x1000;     // 文件大小

	//PIMAGE_SECTION_HEADER endpSectionHeader = pSectionHeader + (pPEHeader->NumberOfSections - 1);
	(pSectionHeader + (pPEHeader->NumberOfSections))->VirtualAddress = 0x27000;   // rva
	(pSectionHeader + (pPEHeader->NumberOfSections))->PointerToRawData = 0x27000;

	/*memcpy((LPVOID)((DWORD)pNewImageBuffer + ((pSectionHeader + pPEHeader->NumberOfSections)->VirtualAddress)),
		pSectionHeader, (pSectionHeader + pPEHeader->NumberOfSections)->Misc.VirtualSize);*/

	PBYTE codeBegin = (PBYTE)((DWORD)pNewImageBuffer + (pSectionHeader + pPEHeader->NumberOfSections)->VirtualAddress);
	memcpy(codeBegin, shellCode, SHELL_CODE_LENGTH);

	// 修正E8 call xxx           xxx = 真正的跳转地址 - 下一条指令地址
	DWORD callAddr = MESSAGEBOX_ADDR
		- (pOptionHeader->ImageBase + ((DWORD)(codeBegin + 0xD) - (DWORD)pNewImageBuffer));
	*(PDWORD)(codeBegin + 9) = callAddr;

	// 修正E9  jmp oep
	DWORD jmpAddr = (pOptionHeader->ImageBase + pOptionHeader->AddressOfEntryPoint)
		- (pOptionHeader->ImageBase + ((DWORD)codeBegin + SHELL_CODE_LENGTH - (DWORD)pNewImageBuffer));
	*(PDWORD)(codeBegin + 0xE) = jmpAddr;

	// 修改oep
	pOptionHeader->AddressOfEntryPoint = (DWORD)codeBegin - (DWORD)pNewImageBuffer;

	// 节表数量 + 1
	(pPEHeader->NumberOfSections)++;

	size = CopyImageBufferToNewBuffer(pNewImageBuffer, &pNewBuffer);

	MemeryToFile(pNewBuffer, size, FILEPATH_OUT);

}


void TestAddImageNewSec3() {
	LPVOID pFileBuffer = nullptr;
	LPVOID pImageBuffer = nullptr;
	LPVOID pNewImageBuffer = nullptr;
	LPVOID pNewBuffer = nullptr;

	PIMAGE_DOS_HEADER pDosHeader = nullptr;
	PIMAGE_FILE_HEADER pPEHeader = nullptr;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = nullptr;
	PIMAGE_SECTION_HEADER pSectionHeader = nullptr;

	DWORD size = 0;

	// File -> FileBuffer
	ReadPEFile(FILEPATH_IN, &pFileBuffer);
	if (!pFileBuffer) {
		printf("File -> FileBuffer Fail!\n");
		return;
	}

	// FileBuffer -> FileImageBuffer
	CopyFileBufferToImageBuffer(pFileBuffer, &pImageBuffer);
	if (!pImageBuffer) {
		printf("FileBuffer -> FileImageBuffer Fail!\n");
		free(pFileBuffer);
		return;
	}

	// 判断头部是否有空间可以新增一个节
	pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + sizeof(IMAGE_OPTIONAL_HEADER32));

	// 判断垃圾段大小
	DWORD space = pDosHeader->e_lfanew - sizeof(IMAGE_DOS_HEADER);

	if (space < 2 * sizeof(IMAGE_SECTION_HEADER))
	{
		printf("空间不够!\n");
		free(pFileBuffer);
		free(pImageBuffer);
		return;
	}

	// 新增一个节的数据 1000对齐 加1000字节
	pNewImageBuffer = malloc(pOptionHeader->SizeOfImage + 0x1000);
	if (!pNewImageBuffer) {
		printf("分配空间失败!\n");
		free(pFileBuffer);
		free(pImageBuffer);
		return;
	}

	// 新分配的空间 +0x1000  初始化0
	memset(pNewImageBuffer, 0, pOptionHeader->SizeOfImage + 0x1000);

	// 复制之前的拉伸后的pe
	memcpy(pNewImageBuffer, pImageBuffer, pOptionHeader->SizeOfImage);

	// 指向新的
	pDosHeader = (PIMAGE_DOS_HEADER)pNewImageBuffer;
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 0x4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)
		(((DWORD)pNewImageBuffer + pDosHeader->e_lfanew) + 4 + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + sizeof(IMAGE_OPTIONAL_HEADER32));

	// 计算要抬数据的大小
	size_t pe_size = 0x4 + IMAGE_SIZEOF_FILE_HEADER + pPEHeader->SizeOfOptionalHeader
		+ IMAGE_SIZEOF_SECTION_HEADER * pPEHeader->NumberOfSections;

	// 将以pe字段偏移包括pe后面的数据，pe头,可选头，节表一起向上抬
	memcpy((void*)((DWORD)pNewImageBuffer + sizeof(IMAGE_DOS_HEADER)),
		(const void*)((DWORD)pNewImageBuffer + pDosHeader->e_lfanew),
		pe_size);

	// 更新头指针数据
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + sizeof(IMAGE_DOS_HEADER) + 0X4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + sizeof(IMAGE_OPTIONAL_HEADER32));

	// ! 修改pDosHeader->e_lfanew
	pDosHeader->e_lfanew = sizeof(IMAGE_DOS_HEADER);

	memset(pSectionHeader + pPEHeader->NumberOfSections, 0, pe_size);

	// 在旧表的后面新增一个节表（复制第一个）， 并修改内容
	memcpy(pSectionHeader + pPEHeader->NumberOfSections, pSectionHeader, IMAGE_SIZEOF_SECTION_HEADER);

	// 设置下一个节表空间为0 新增节表的后面
	memset(pSectionHeader + pPEHeader->NumberOfSections + 1, 0, IMAGE_SIZEOF_SECTION_HEADER);

	// 修改pOptionHeader->SizeOfImage的大小 新pe文件变大
	pOptionHeader->SizeOfImage = pOptionHeader->SizeOfImage + 0x1000;

	// 设置节的属性
	strcpy((char*)(pSectionHeader + pPEHeader->NumberOfSections), ".wfq");
	(pSectionHeader + (pPEHeader->NumberOfSections))->Misc.VirtualSize = 0x1000;// 内存大小
	(pSectionHeader + (pPEHeader->NumberOfSections))->SizeOfRawData = 0x1000;     // 文件大小

	//PIMAGE_SECTION_HEADER endpSectionHeader = pSectionHeader + (pPEHeader->NumberOfSections - 1);
	(pSectionHeader + (pPEHeader->NumberOfSections))->VirtualAddress = 0x27000;   // rva
	(pSectionHeader + (pPEHeader->NumberOfSections))->PointerToRawData = 0x27000;

	PBYTE codeBegin = (PBYTE)((DWORD)pNewImageBuffer + (pSectionHeader + pPEHeader->NumberOfSections)->VirtualAddress);
	memcpy(codeBegin, shellCode, SHELL_CODE_LENGTH);

	// 修正E8 call xxx           xxx = 真正的跳转地址 - 下一条指令地址
	DWORD callAddr = MESSAGEBOX_ADDR
		- (pOptionHeader->ImageBase + ((DWORD)(codeBegin + 0xD) - (DWORD)pNewImageBuffer));
	*(PDWORD)(codeBegin + 9) = callAddr;

	// 修正E9  jmp oep
	DWORD jmpAddr = (pOptionHeader->ImageBase + pOptionHeader->AddressOfEntryPoint)
		- (pOptionHeader->ImageBase + ((DWORD)codeBegin + SHELL_CODE_LENGTH - (DWORD)pNewImageBuffer));
	*(PDWORD)(codeBegin + 0xE) = jmpAddr;

	// 修改oep
	pOptionHeader->AddressOfEntryPoint = (DWORD)codeBegin - (DWORD)pNewImageBuffer;

	// 节表数量 + 1
	(pPEHeader->NumberOfSections)++;

	size = CopyImageBufferToNewBuffer(pNewImageBuffer, &pNewBuffer);

	MemeryToFile(pNewBuffer, size, FILEPATH_OUT);
}


void TestExpandLastSection() {

	LPVOID pFileBuffer = nullptr;
	LPVOID pImageBuffer = nullptr;
	LPVOID pNewImageBuffer = nullptr;
	LPVOID pNewBuffer = nullptr;

	PIMAGE_DOS_HEADER pDosHeader = nullptr;
	PIMAGE_FILE_HEADER pPEHeader = nullptr;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = nullptr;
	PIMAGE_SECTION_HEADER pSectionHeader = nullptr;

	DWORD size = 0;

	// File -> FileBuffer
	ReadPEFile(FILEPATH_IN, &pFileBuffer);
	if (!pFileBuffer) {
		printf("File -> FileBuffer Fail!\n");
		return;
	}

	// FileBuffer -> FileImageBuffer
	CopyFileBufferToImageBuffer(pFileBuffer, &pImageBuffer);
	if (!pImageBuffer) {
		printf("FileBuffer -> FileImageBuffer Fail!\n");
		free(pFileBuffer);
		return;
	}

	pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + sizeof(IMAGE_OPTIONAL_HEADER32));

	// 新增一个节的数据 1000对齐 加1000字节
	pNewImageBuffer = malloc(pOptionHeader->SizeOfImage + 0x1000);
	if (!pNewImageBuffer) {
		printf("分配空间失败!\n");
		free(pFileBuffer);
		free(pImageBuffer);
		return;
	}

	// 新分配的空间 +0x1000  初始化0
	memset(pNewImageBuffer, 0, pOptionHeader->SizeOfImage + 0x1000);

	// 复制之前的拉伸后的pe
	memcpy(pNewImageBuffer, pImageBuffer, pOptionHeader->SizeOfImage);

	// 修改sizeofImage



}

void PrintExportTable() {

	LPVOID pFileBuffer = nullptr;
	LPVOID pNewImageBuffer = nullptr;

	PIMAGE_DOS_HEADER pDosHeader = nullptr;
	PIMAGE_FILE_HEADER pPEHeader = nullptr;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = nullptr;

	// File -> FileBuffer
	ReadPEFile(FILEPATH_IN, &pFileBuffer);
	if (!pFileBuffer) {
		printf("File -> FileBuffer Fail!\n");
		return;
	}

	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);

	IMAGE_DATA_DIRECTORY data_import = pOptionHeader->DataDirectory[0];

	printf("导出表的RVA : %0x\n", data_import.VirtualAddress);
	printf("导出表的size: %0x\n", data_import.Size);

	DWORD data_im_foa = RvaToFoa(pFileBuffer, data_import.VirtualAddress);
	printf("导出表的FOA : %0x\n", data_im_foa);

	PIMAGE_EXPORT_DIRECTORY pImageExport = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pFileBuffer + data_im_foa);
	printf("导出表信息如下：\n");
	printf("Base: %d\n", pImageExport->Base);
	printf("所有导出函数的个数：%0x\n", pImageExport->NumberOfFunctions);
	printf("以函数名字导出的函数个数：%0x\n", pImageExport->NumberOfNames);

	printf("导出函数地址表的RVA： %0x\n", pImageExport->AddressOfFunctions);
	DWORD aOf_foa = RvaToFoa(pFileBuffer, pImageExport->AddressOfFunctions);
	printf("导出函数地址表的FOA： %0x\n", aOf_foa);

	printf("导出函数名称表的RVA:  %0x\n", pImageExport->AddressOfNames);
	DWORD aOn_foa = RvaToFoa(pFileBuffer, pImageExport->AddressOfNames);
	printf("导出函数名称表的FOA:  %0x\n", aOn_foa);

	printf("导出函数序号表的RVA:  %0x\n", pImageExport->AddressOfNameOrdinals);
	DWORD aOo_foa = RvaToFoa(pFileBuffer, pImageExport->AddressOfNameOrdinals);
	printf("导出函数序号表的FOA:  %0x\n", aOo_foa);

	PDWORD fun_name = (PDWORD)((DWORD)pFileBuffer + aOn_foa);
	PWORD fun_ordi = (PWORD)((DWORD)pFileBuffer + aOo_foa);
	PDWORD fun_add = (PDWORD)((DWORD)pFileBuffer + aOf_foa);

	for (int i = 0; i < pImageExport->NumberOfNames; i++) {
		DWORD tmp_foa = RvaToFoa(pFileBuffer, *fun_name);
		printf("%s\n", (char*)((DWORD)pFileBuffer + tmp_foa));
		int tmp_ordinals = i;
		WORD tmp_ret = *(fun_ordi + i);
		printf("函数的地址: %p \n", *(fun_add + tmp_ret));
		fun_name++;
	}

	free(pFileBuffer);
}

void PrintRelocationTable() {

	LPVOID pFileBuffer = nullptr;
	LPVOID pNewImageBuffer = nullptr;

	PIMAGE_DOS_HEADER pDosHeader = nullptr;
	PIMAGE_FILE_HEADER pPEHeader = nullptr;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = nullptr;

	// File -> FileBuffer
	ReadPEFile(FILEPATH_IN, &pFileBuffer);
	if (!pFileBuffer) {
		printf("File -> FileBuffer Fail!\n");
		return;
	}

	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);

	IMAGE_DATA_DIRECTORY elocationTable = pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	using std::cout, std::endl;

	DWORD base_reloc_foa = RvaToFoa(pFileBuffer, elocationTable.VirtualAddress);
	cout << "重定位表的RVA： " << elocationTable.VirtualAddress << endl;
	cout << "重定位表的FOA： " << base_reloc_foa << endl;
	cout << "重定位表的SIZE：" << elocationTable.Size << endl;

	if (!elocationTable.VirtualAddress) {
		cout << "重定位表不存在\n" << endl;
		return;
	}

	// 指向第一个重定位表内存
	PIMAGE_BASE_RELOCATION image_base_relocation = (PIMAGE_BASE_RELOCATION)((DWORD)pFileBuffer + base_reloc_foa);
	PIMAGE_BASE_RELOCATION tmp = image_base_relocation;

	for (int i = 1; ; i++) {

		if (!tmp->VirtualAddress || !tmp->SizeOfBlock) {
			cout << "没有数据块!" << endl;
			break;
		}

		// 把一页的数据块放一起 1000h  4096byte 4kb  2^12 = 4096
		cout << "第" << i << "个数据块的基地址:   " << tmp->VirtualAddress << endl;
		cout << "第" << i << "个数据块的内存大小：" << tmp->SizeOfBlock << endl;

		// 计算块数
		DWORD block_num = (tmp->SizeOfBlock - 8) / 2;
		cout << "块内地址的数量: " << block_num << endl;

		// 打印 该数据块中 需要修改的RVA
		PWORD addr_tmp = (PWORD)((PBYTE)tmp + 8);
		for (int j = 0; j < block_num; j++) {

			// 先取出高4位数据 判断是否是3
			if (((*addr_tmp >> 12) & 0xf) == 3) {
				DWORD real_addr = tmp->VirtualAddress + (*addr_tmp & 0xfff);
				cout << real_addr << endl;
			}

			addr_tmp++;
		}

		// 指向下一个数据块
		tmp = (PIMAGE_BASE_RELOCATION)((PBYTE)tmp + tmp->SizeOfBlock);

	}

}

void MoveExportTable() {

	LPVOID pFileBuffer = nullptr;
	// File -> FileBuffer
	ReadPEFile(FILEPATH_IN, &pFileBuffer);
	if (!pFileBuffer) {
		printf("File -> FileBuffer Fail!\n");
		return;
	}

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + sizeof(IMAGE_OPTIONAL_HEADER32));

	// 获取第一个目录项 导出表
	IMAGE_DATA_DIRECTORY table1 = pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	// 获取真正导出表的foa
	DWORD exportTableFoa = RvaToFoa(pFileBuffer, table1.VirtualAddress);

	// 指向导出表的指针
	PIMAGE_EXPORT_DIRECTORY pExportTable = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pFileBuffer + exportTableFoa);

	DWORD fun_num = pExportTable->NumberOfFunctions;
	DWORD name_num = pExportTable->NumberOfNames;

	std::cout << "所有导出函数的个数：" << fun_num << ", 以函数名字导出的函数个数: " << name_num << std::endl;

	// 计算增加节的大小
	// DWORD sec = sizeof(DWORD) * fun_num + sizeof(WORD) * name_num + sizeof(DWORD) * name_num;

	DWORD space
		= pOptionHeader->SizeOfHeaders
		- (pDosHeader->e_lfanew + 0x4 + IMAGE_SIZEOF_FILE_HEADER + pPEHeader->SizeOfOptionalHeader + sizeof(IMAGE_SECTION_HEADER) * pPEHeader->NumberOfSections);

	if (space < 2 * sizeof(IMAGE_SECTION_HEADER))
	{
		printf("空间不够!\n");
		free(pFileBuffer);
		return;
	}

	// 新增一个节的数据 1000对齐 加1000字节
	LPVOID tmp_pFileBuf = realloc(pFileBuffer, 0x94E400 + 0x200);

	if (tmp_pFileBuf == nullptr) {
		printf("分配空间失败!\n");
		free(pFileBuffer);
		return;
	}

	pFileBuffer = tmp_pFileBuf;
	tmp_pFileBuf = nullptr;

	// 新分配的空间 +0x200  初始化0
	memset((void*)((DWORD)pFileBuffer + 0x94E400), 0, 0x200);

	// 在旧表的后面新增一个节表（复制第一个）， 并修改内容
	memcpy(pSectionHeader + pPEHeader->NumberOfSections, pSectionHeader, IMAGE_SIZEOF_SECTION_HEADER);

	// 设置下一个节表空间为0 新增节表的后面
	memset(pSectionHeader + pPEHeader->NumberOfSections + 1, 0, IMAGE_SIZEOF_SECTION_HEADER);

	// 设置节的属性
	strcpy((char*)(pSectionHeader + pPEHeader->NumberOfSections), ".export");
	(pSectionHeader + (pPEHeader->NumberOfSections))->Misc.VirtualSize = 0x1000;// 内存大小
	(pSectionHeader + (pPEHeader->NumberOfSections))->SizeOfRawData = 0x200;     // 文件大小

	(pSectionHeader + (pPEHeader->NumberOfSections))->VirtualAddress = 0x979000;   // rva
	(pSectionHeader + (pPEHeader->NumberOfSections))->PointerToRawData = 0x94E400;

	// 增加节的数量
	pPEHeader->NumberOfSections++;
	// 修改pOptionHeader->SizeOfImage的大小 新pe文件变大
	pOptionHeader->SizeOfImage = pOptionHeader->SizeOfImage + 0x1000;

	// 指向新增的节区
	LPVOID new_sec = (LPVOID)((DWORD)pFileBuffer + 0x94E400);

	// 导出函数的地址foa
	DWORD addrOfFun_foa = RvaToFoa(pFileBuffer, pExportTable->AddressOfFunctions);
	// 拷贝AddressOfFunctions
	size_t copy_num1 = sizeof(DWORD) * fun_num;
	memcpy(new_sec, (const void*)((DWORD)pFileBuffer + addrOfFun_foa), copy_num1);
	// 记录所有导出函数表的偏移
	DWORD addrOffun_vr = FoaToRva(pFileBuffer, (DWORD)new_sec - (DWORD)pFileBuffer);

	// 导出函数序号表foa
	DWORD addrOfNameOrd_foa = RvaToFoa(pFileBuffer, pExportTable->AddressOfNameOrdinals);
	// 拷贝AddressOfNameOrdinals
	size_t copy_num2 = sizeof(WORD) * name_num;
	memcpy((void*)((DWORD)new_sec + copy_num1), (const void*)((DWORD)pFileBuffer + addrOfNameOrd_foa), copy_num2);
	// 记录序号表的偏移
	DWORD addrOfNaOrd_vr = FoaToRva(pFileBuffer, (DWORD)new_sec + copy_num1 - (DWORD)pFileBuffer);

	// 导出函数名字表foa
	DWORD addrOfName_foa = RvaToFoa(pFileBuffer, pExportTable->AddressOfNames);
	// 拷贝AddressOfNames
	DWORD copy_num3 = sizeof(DWORD) * name_num;
	memcpy((void*)((DWORD)new_sec + copy_num2 + copy_num1), (const void*)((DWORD)pFileBuffer + addrOfName_foa), copy_num3);
	// 记录导出名字表的偏移
	DWORD addrName_av = FoaToRva(pFileBuffer, (DWORD)new_sec + copy_num2 + copy_num1 - (DWORD)pFileBuffer);

	// 记录导出函数名字表地址
	PDWORD fun_name_table = (PDWORD)((DWORD)new_sec + copy_num2 + copy_num1);
	// 记录第一个名字的地址
	PDWORD addrNames = (PDWORD)((DWORD)pFileBuffer + addrOfName_foa);
	// 记录拷贝到了哪里
	PVOID now_addr = (LPVOID)((DWORD)new_sec + copy_num2 + copy_num1 + copy_num3);

	for (int i = 0; i < name_num; i++) {
		DWORD name_addr = RvaToFoa(pFileBuffer, addrNames[i]);
		const char* name = (const char*)((DWORD)pFileBuffer + name_addr);
		size_t name_len = strlen(name);
		// 拷贝名字
		memcpy(now_addr, (const void*)((DWORD)pFileBuffer + name_addr), name_len);
		// 修改原先的函数名字表的地址
		DWORD tmp_rva = FoaToRva(pFileBuffer, (DWORD)now_addr - (DWORD)pFileBuffer);
		fun_name_table[i] = tmp_rva;
		// 地址 + name_len
		now_addr = (PVOID)((DWORD)now_addr + name_len + 1);

	}

	// 拷贝导出表结构
	memcpy(now_addr, (const void*)pExportTable, sizeof(IMAGE_EXPORT_DIRECTORY));
	// 新的结构的位置
	DWORD new_ptr_rva = FoaToRva(pFileBuffer, (DWORD)now_addr - (DWORD)pFileBuffer);
	// 修复目录项[0]的值,指向新的
	pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = new_ptr_rva;

	pExportTable = (PIMAGE_EXPORT_DIRECTORY)now_addr;
	// 修改导出表结构
	pExportTable->AddressOfFunctions = addrOffun_vr;
	pExportTable->AddressOfNameOrdinals = addrOfNaOrd_vr;
	pExportTable->AddressOfNames = addrName_av;

	MemeryToFile(pFileBuffer, 0x94E400 + 0x200, FILEPATH_OUT);
}


void MoveRelocationTable() {

	LPVOID pFileBuffer = nullptr;
	// File -> FileBuffer
	ReadPEFile(FILEPATH_IN, &pFileBuffer);
	if (!pFileBuffer) {
		printf("File -> FileBuffer Fail!\n");
		return;
	}

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + sizeof(IMAGE_OPTIONAL_HEADER32));

	// 计算剩余空间
	DWORD space
		= pOptionHeader->SizeOfHeaders
		- (pDosHeader->e_lfanew + 0x4 + IMAGE_SIZEOF_FILE_HEADER + pPEHeader->SizeOfOptionalHeader + sizeof(IMAGE_SECTION_HEADER) * pPEHeader->NumberOfSections);

	if (space < 2 * sizeof(IMAGE_SECTION_HEADER))
	{
		printf("空间不够!\n");
		free(pFileBuffer);
		return;
	}

	// 新增一个节的数据 1000对齐 
	LPVOID tmp_pFileBuf = realloc(pFileBuffer, 0x25C800 + 277 * 0x200);

	if (tmp_pFileBuf == nullptr) {
		printf("分配空间失败!\n");
		free(pFileBuffer);
		return;
	}

	pFileBuffer = tmp_pFileBuf;
	tmp_pFileBuf = nullptr;

	// pFileBuffer改变 重新分配
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + sizeof(IMAGE_OPTIONAL_HEADER32));

	// 新分配的空间 +0x200  初始化0
	memset((void*)((DWORD)pFileBuffer + 0x25C800), 0, 277 * 0x200);

	// 在旧表的后面新增一个节表（复制第一个）， 并修改内容
	memcpy(pSectionHeader + pPEHeader->NumberOfSections, pSectionHeader, IMAGE_SIZEOF_SECTION_HEADER);

	// 设置下一个节表空间为0 新增节表的后面
	memset(pSectionHeader + pPEHeader->NumberOfSections + 1, 0, IMAGE_SIZEOF_SECTION_HEADER);

	// 设置节的属性
	strcpy((char*)(pSectionHeader + pPEHeader->NumberOfSections), ".wfq_re");
	(pSectionHeader + (pPEHeader->NumberOfSections))->Misc.VirtualSize = 0x200 * 277;// 内存大小
	(pSectionHeader + (pPEHeader->NumberOfSections))->SizeOfRawData = 0x200 * 277;     // 文件大小

	(pSectionHeader + (pPEHeader->NumberOfSections))->VirtualAddress = 0x264000;   // rva
	(pSectionHeader + (pPEHeader->NumberOfSections))->PointerToRawData = 0x25C800;

	// 增加节的数量
	pPEHeader->NumberOfSections++;
	// 修改pOptionHeader->SizeOfImage的大小 新pe文件变大
	pOptionHeader->SizeOfImage = pOptionHeader->SizeOfImage + 0x200 * 277;

	// 获取第6个目录项 指向重定位表
	IMAGE_DATA_DIRECTORY &table1 = pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	// 计算foa
	DWORD relo_foa = RvaToFoa(pFileBuffer, table1.VirtualAddress);
	// 指向第一个重定位表结构
	PIMAGE_BASE_RELOCATION first_relo = (PIMAGE_BASE_RELOCATION)((DWORD)pFileBuffer + relo_foa);
	// 指向新增的节
	LPBYTE my_sec = (LPBYTE)((DWORD)pFileBuffer + 0x25C800);

	// 修改目录项【5】的rva
	DWORD new_rva = FoaToRva(pFileBuffer, (DWORD)my_sec - (DWORD)pFileBuffer);
	table1.VirtualAddress = new_rva;

	// 为循环复制 做准备
	PBYTE tmp_relo = (PBYTE)first_relo;

	for (; ;) {

		PIMAGE_BASE_RELOCATION flag_sec = (PIMAGE_BASE_RELOCATION)tmp_relo;

		DWORD block_num = flag_sec->SizeOfBlock;
		DWORD blo_rva = flag_sec->VirtualAddress;

		if (!block_num || !blo_rva) {
			break;
		}

		memcpy(my_sec, flag_sec, block_num);

		my_sec += block_num;
		tmp_relo += block_num;
	}

	MemeryToFile(pFileBuffer, 0x25C800 + 0x200 * 277, FILEPATH_OUT);
}


void demo1() {
	LPVOID pFileBuffer = nullptr;
	// File -> FileBuffer
	ReadPEFile(FILEPATH_IN, &pFileBuffer);
	if (!pFileBuffer) {
		printf("File -> FileBuffer Fail!\n");
		return;
	}

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);

	IMAGE_DATA_DIRECTORY elocationTable = pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	DWORD one_foa = RvaToFoa(pFileBuffer, elocationTable.VirtualAddress);

	PIMAGE_BASE_RELOCATION one = (PIMAGE_BASE_RELOCATION)((DWORD)pFileBuffer + one_foa);

	DWORD num = 0;
	PBYTE tmp_rel = (PBYTE)one;

	for (; ;) {

		PIMAGE_BASE_RELOCATION tmp = (PIMAGE_BASE_RELOCATION)tmp_rel;

		DWORD i = tmp->SizeOfBlock;

		if (!tmp->SizeOfBlock || !tmp->VirtualAddress) {
			break;
		}

		num += tmp->SizeOfBlock;
		tmp_rel += i;
	}

	printf("%d\n", num);

}

void PrintImportTable() {

	LPVOID pFileBuffer = nullptr;
	// File -> FileBuffer
	ReadPEFile("D:\\mygames\\PlantsVsZombies\\PlantsVsZombies.exe", &pFileBuffer);
	if (!pFileBuffer) {
		printf("File -> FileBuffer Fail!\n");
		return;
	}

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + sizeof(IMAGE_OPTIONAL_HEADER32));

	// 获取第二个目录项 导入表
	IMAGE_DATA_DIRECTORY dir_two = pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	// 找到第一个导入表结构
	DWORD real_foa = RvaToFoa(pFileBuffer, dir_two.VirtualAddress);
	PIMAGE_IMPORT_DESCRIPTOR first_imp = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pFileBuffer + real_foa);

	int flag = 1;
	while (true)
	{
		// 当导入表结构没有INT和IAT时退出
		if (!first_imp->OriginalFirstThunk || !first_imp->FirstThunk) {
			break;
		}

		std::cout << "第" << flag++ << "个导入表信息如下: " << std::endl;
		std::cout << "TimeDateStamp: " << first_imp->TimeDateStamp << std::endl;

		DWORD dll_foa = RvaToFoa(pFileBuffer, first_imp->Name);
		const char* dll_name = (const char*)((DWORD)pFileBuffer + dll_foa);
		std::cout << "DLL的名字: " << dll_name << std::endl;

		std::cout << "INT 信息如下：" << std::endl;
		//  指向INT
		DWORD int_foa = RvaToFoa(pFileBuffer, first_imp->OriginalFirstThunk);
		PIMAGE_THUNK_DATA32 thunk_data = (PIMAGE_THUNK_DATA32)((DWORD)pFileBuffer + int_foa);
		// 遍历INT
		for (; *((PDWORD)thunk_data);) {
			// 先判断最高位的值
			DWORD var = *((PDWORD)thunk_data);
			DWORD hig_pos = sizeof(DWORD) * 8 - 1;
			DWORD hig_bit = (var >> hig_pos) & 1;
			if (hig_bit == 1) {							// 函数的导出序号
				DWORD low31_bit = var & 0x7fffffff;
				std::cout << "导入函数的序号: " << low31_bit << std::endl;
			}
			else {										// 函数的导出名字
				DWORD name_var = RvaToFoa(pFileBuffer, var);
				PIMAGE_IMPORT_BY_NAME fun_name = (PIMAGE_IMPORT_BY_NAME)((DWORD)pFileBuffer + name_var);
				const char* p_name = fun_name->Name;
				std::cout << "导入函数的名字: " << p_name << std::endl;
			}

			// 指向下一个
			thunk_data++;
		}

		std::cout << "IAT 信息如下：" << std::endl;
		// 指向IAT
		DWORD iat_foa = RvaToFoa(pFileBuffer, first_imp->FirstThunk);
		PIMAGE_THUNK_DATA32 thunk_data2 = (PIMAGE_THUNK_DATA32)((DWORD)pFileBuffer + iat_foa);
		// 遍历IAT
		for (; *((PDWORD)thunk_data2);) {
			// 先判断最高位的值
			DWORD var = *((PDWORD)thunk_data2);
			DWORD hig_pos = sizeof(DWORD) * 8 - 1;
			DWORD hig_bit = (var >> hig_pos) & 1;
			if (hig_bit == 1) {							// 函数的导出序号
				DWORD low31_bit = var & 0x7fffffff;
				std::cout << "导入函数的序号: " << low31_bit << std::endl;
			}
			else {										// 函数的导出名字
				DWORD name_var = RvaToFoa(pFileBuffer, var);
				PIMAGE_IMPORT_BY_NAME fun_name = (PIMAGE_IMPORT_BY_NAME)((DWORD)pFileBuffer + name_var);
				const char* p_name = fun_name->Name;
				std::cout << "导入函数的名字: " << p_name << std::endl;
			}

			// 指向下一个
			thunk_data2++;
		}

		first_imp++;

	}

}



