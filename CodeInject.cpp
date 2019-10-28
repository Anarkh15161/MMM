// CodeInject.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include <stdio.h>
#include<Windows.h>
#pragma warning(disable : 4996)
#define CodeLength  0x12
#define WinBox   0x752D7E60
//定义输入和输出的文件目录
LPSTR InFilePath = (LPSTR)"D:\\朱航\\自己的东西\\010Editor\\010Editor.exe";
LPSTR OutFilePath = (LPSTR)"D:\\朱航\\自己的东西\\010Editor\\010Editor2.exe";
BYTE Code[] = {
	0x6A,0x00,0x6A,0x00,
	0x6A,0x00,0x6A,0x00,
	0xE8,0x00,0x00,0x00,
	0x00,0xE9,0x00,0x00,
	0x00,0x00
};

//读入文件
size_t FileSize = NULL;
PVOID ReadFile(LPSTR filepath) {
	FILE* inFile = NULL;
	size_t inFileSize = NULL;
	LPVOID inFileBuffer = NULL;
	inFile = fopen(filepath, "rb");
	if (!inFile) {
		printf("打开EXE失败！\n");
		return NULL;
	}
	fseek(inFile, 0, SEEK_END);
	inFileSize = ftell(inFile);
	FileSize = inFileSize;
	fseek(inFile, 0, SEEK_SET);
	//申请缓存
	inFileBuffer = malloc(inFileSize);
	if (!inFileBuffer) {
		printf("申请内存空间失败！\n");
		fclose(inFile);
		return NULL;
	}
	//读取文件到内存
	size_t n = fread(inFileBuffer, inFileSize, 1, inFile);
	if (!n) {
		printf("文件导入到内存失败！\n");
		fclose(inFile);
		free(inFileBuffer);
		return NULL;
	}
	fclose(inFile);
	return inFileBuffer;
}

//把文件在内存中拉伸
LPVOID CopyFileToImageBuffer(LPVOID infilebuffer) {
	PIMAGE_DOS_HEADER pImageDosHeader = NULL;
	PIMAGE_NT_HEADERS pImageNTHeader = NULL;
	PIMAGE_FILE_HEADER pimageFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;//节头

	size_t imageFileOptionalSize = NULL;
	size_t imageFileHeaderSize = NULL;
	size_t sectionNumber = NULL;
	LPVOID imageBuffer = NULL;

	size_t imageOfSize = NULL;
	//判断指针是不是有效
	if (infilebuffer == NULL) {
		printf("传入的文件指针有误！\n");
		return 0;
	}
	//开始判断是不是pe文件
	pImageDosHeader = (PIMAGE_DOS_HEADER)infilebuffer;
	if ((pImageDosHeader->e_magic) != IMAGE_DOS_SIGNATURE) {
		printf("该文件不是MZ开头的文件\n");
		free(infilebuffer);
		return 0;
	}
	if (*((PWORD)((DWORD)infilebuffer + pImageDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE) {
		printf("该文件不是PE文件！\n");
		free(infilebuffer);
		return 0;
	}
	pImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD)infilebuffer + pImageDosHeader->e_lfanew);
	pimageFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pImageNTHeader + 4);
	sectionNumber = pimageFileHeader->NumberOfSections;//多少个节
	imageFileOptionalSize = pimageFileHeader->SizeOfOptionalHeader;//可选PE的大小
	pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pimageFileHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + imageFileOptionalSize);
	imageOfSize = pOptionalHeader->SizeOfImage;
	imageFileHeaderSize = pOptionalHeader->SizeOfHeaders;
	//申请拉伸的内存
	imageBuffer = malloc(imageOfSize);
	if (!imageBuffer) {
		printf("申请拉伸空间失败！\n");
		free(infilebuffer);
		return 0;
	}
	//拷贝PE头
	memset(imageBuffer, 0, pOptionalHeader->SizeOfImage);//初始化新的内存
	LPVOID n = memcpy(imageBuffer, infilebuffer, imageFileHeaderSize);
	if (!n) {
		printf("拷贝拉伸内存失败！\n");
		free(infilebuffer);
		free(imageBuffer);
		return 0;
	}
	//开始循环拷贝节
	for (size_t i = 0; i < sectionNumber; i++, pSectionHeader++) {

		memcpy((void*)((DWORD)imageBuffer + pSectionHeader->VirtualAddress), (void*)((DWORD)infilebuffer + pSectionHeader->PointerToRawData), pSectionHeader->SizeOfRawData);

	}
	free(infilebuffer);
	return imageBuffer;
}
//代码注入
//获取可选表找到基址，获取第一个节的地址获得节的大小和内存偏移
//注入代码的偏移，拉伸基址+内存偏移+节的大小。在计算新OEP的时候把拉伸地址换成基址
LPVOID CodeInjection(LPVOID imageBuffer) {
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)imageBuffer;
	PIMAGE_FILE_HEADER pImageFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pImageDosHeader + pImageDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pImageOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pImageFileHeader + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER pImageSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pImageOptionalHeader + pImageFileHeader->SizeOfOptionalHeader);
	//注入代码开始的位置
	
	
	if ((pImageSectionHeader->SizeOfRawData - pImageSectionHeader->Misc.VirtualSize)>(BYTE)0x12) {
		printf("开始注入。。。。\n");
		LPVOID CodeBegin = (LPVOID)((DWORD)imageBuffer + pImageSectionHeader->VirtualAddress + pImageSectionHeader->Misc.VirtualSize);
		printf("$$$$$$$$  %x\n", (DWORD)(CodeBegin)-(DWORD)imageBuffer+pImageOptionalHeader->ImageBase+0x0D);
		//修正E8
		DWORD callAddr = (DWORD)(WinBox - (pImageOptionalHeader->ImageBase + ((DWORD)CodeBegin + 0x0D) - (DWORD)imageBuffer));
		*(PDWORD)(Code + 0x09) = callAddr;
		printf("-----  %x\n", callAddr);
		//修正E9
		DWORD JmpAddr = (DWORD)((pImageOptionalHeader->AddressOfEntryPoint + pImageOptionalHeader->ImageBase) - (pImageOptionalHeader->ImageBase + ((DWORD)CodeBegin + (BYTE)0x12) - (DWORD)imageBuffer));
			* (PDWORD)(Code + 0x0E) = JmpAddr;
			printf("======== %x\n", JmpAddr);
	    //修改OEP
			pImageOptionalHeader->AddressOfEntryPoint = (DWORD)CodeBegin - (DWORD)imageBuffer;
			memcpy(CodeBegin, Code, CodeLength);
			return imageBuffer;
	}
	else
	{
		printf("空间不足！\n");
		free(imageBuffer);
		return NULL;
	}




}


//将内存拉伸后的文件再次还原并存盘
DWORD SaveLocal(LPVOID imageBuffer) {
	if (imageBuffer == NULL) {
		printf("内存拉伸后的指针错误！\n");
		free(imageBuffer);
		return 0;
	}
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)imageBuffer;
	size_t LocalFileSize = ((PIMAGE_OPTIONAL_HEADER32)((DWORD)((PIMAGE_FILE_HEADER)((DWORD)imageBuffer + pDosHeader->e_lfanew + 4)) + IMAGE_SIZEOF_FILE_HEADER))->SizeOfHeaders;
	LPVOID localBuffer = malloc(FileSize);
	size_t sectionNumber = ((PIMAGE_FILE_HEADER)((DWORD)imageBuffer + pDosHeader->e_lfanew + 4))->NumberOfSections;
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)(((PIMAGE_FILE_HEADER)((DWORD)imageBuffer + pDosHeader->e_lfanew + 4))->SizeOfOptionalHeader + ((DWORD)imageBuffer + pDosHeader->e_lfanew + 4) + IMAGE_SIZEOF_FILE_HEADER);
	if (!localBuffer) {
		printf("申请内存失败！\n");
		free(imageBuffer);
		return 0;
	}
	//拷贝PE头
	memset(localBuffer, 0, FileSize);
	memcpy(localBuffer, imageBuffer, LocalFileSize);
	for (size_t i = 0; i < sectionNumber; i++, pSectionHeader++) {
		memcpy((void*)((DWORD)localBuffer + pSectionHeader->PointerToRawData), (void*)((DWORD)imageBuffer + pSectionHeader->VirtualAddress), pSectionHeader->SizeOfRawData);
	}
	FILE* outFile = fopen(OutFilePath, "wb");
	if (!outFile) {
		printf("指定路径不正确！\n");
		free(imageBuffer);
		return 0;
	}
	size_t y = fwrite(localBuffer, FileSize, 1, outFile);
	if (!y) {
		printf("读写失败！\n");
		free(imageBuffer);
		fclose(outFile);
		return 0;
	}
	free(imageBuffer);
	free(localBuffer);
	fclose(outFile);
	return 1;
}

int main()
{

	size_t result = SaveLocal(CodeInjection(CopyFileToImageBuffer(ReadFile(InFilePath))));
	if (!result) {
		printf("程序复制失败！\n");
	}
	else

	{
		printf("程序复制成功！\n");
	}
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
