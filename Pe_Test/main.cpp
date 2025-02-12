#include "func.h"
#include <fstream>

bool areFilesEqual(const std::string & file1, const std::string & file2);

int main() {

	/*LPVOID pFileBuffer;
	ReadPEFile("D:\\PETool 1.0.0.5.exe", &pFileBuffer);

	LPVOID pImageBuffer;
	CopyFileBufferToImageBuffer(pFileBuffer, &pImageBuffer);

	LPVOID pNewBuffer;
	DWORD new_size = CopyImageBufferToNewBuffer(pImageBuffer, &pNewBuffer);

	MemeryToFile(pNewBuffer, new_size, "D:\\new_pe.exe");*/

	//TestAddCodeInCodeSec();
	//TestAddImageNewSec2();
	//TestAddImageNewSec3();
	//PrintExportTable();
	//PrintRelocationTable(); 

	//MoveExportTable();
	// MoveRelocationTable();
	// demo1(); 141788
	// PrintImportTable();
	//PE pe("D:\\01esp寻址.exe");


	return 0;

}

void test1() {
	/*printf("%p\n", &g_a);

	LPVOID pFileBuffer;
	DWORD res = ReadPEFile(const_cast<LPSTR>("F:\\C++\\Win逆向\\Window_PE\\Debug\\01pe读写.exe"), &pFileBuffer);

	FILE *file = fopen("F:\\C++\\Win逆向\\Window_PE\\Debug\\new.exe", "wb");
	if (file == nullptr) {
		perror("无法打开文件");
		return -1;
	}

	fwrite((const void*)pFileBuffer, sizeof(BYTE), res, file);*/

	/*printf("%p\n", &g_a);
	LPVOID pFileBuffer;
	ReadPEFile(const_cast<LPSTR>("F:\\C++\\Win逆向\\Window_PE\\Debug\\01pe读写.exe"), &pFileBuffer);

	DWORD tmp_addr = (DWORD)&g_a;
	DWORD foa = RvaToFileOffset(pFileBuffer, tmp_addr);

	printf("%d\n", foa);*/

	//PrintExportTable();

	//PrintRelocationTable();
	/*std::shared_ptr<void> m = std::make_shared<void>();*/
}


bool areFilesEqual(const std::string & file1, const std::string & file2) {
	std::ifstream ifs1(file1, std::ios::binary | std::ios::ate);
	std::ifstream ifs2(file2, std::ios::binary | std::ios::ate);

	if (ifs1.fail() || ifs2.fail()) {
		// 处理文件打开失败的情况
		std::cerr << "Error opening files." << std::endl;
		return false;
	}

	std::ifstream::pos_type fileSize1 = ifs1.tellg();
	std::ifstream::pos_type fileSize2 = ifs2.tellg();

	if (fileSize1 != fileSize2) {
		// 如果文件大小不同，它们肯定不相同
		return false;
	}

	ifs1.seekg(0);
	ifs2.seekg(0);

	// 逐个字节比较文件内容
	return std::equal(std::istreambuf_iterator<char>(ifs1.rdbuf()),
		std::istreambuf_iterator<char>(),
		std::istreambuf_iterator<char>(ifs2.rdbuf()));

	/*if (areFilesEqual("D:\\PETool 1.0.0.5.exe", "D:\\new_pe.exe")) {
		std::cout << "Files are equal." << std::endl;
	}
	else {
		std::cout << "Files are not equal." << std::endl;*/
	//}
}





