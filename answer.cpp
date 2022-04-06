#include <stdio.h>
#include <windows.h>
#include <stdlib.h>

#define PE_PATH "xxx.exe"

//#define PE_PATH "C:\\Documents and Settings\\桌面\\kernel32.dll"
#define PEDUMP_PATH "C:\\Documents and Settings\\桌面\\1_deump.exe"
#define PEWITHSHELLCODE_PATH "C:\\Documents and Settings\\桌面\\1_withShellcode.exe"
#define PEADDSEC_PATH "C:\\Documents and Settings\\桌面\\1_ADDSEC.exe"
#define PEEXPANDSEC_PATH "C:\\Documents and Settings\\桌面\\1_EXPANDSEC.exe"
#define PECOMBINSEC_PATH "C:\\Documents and Settings\\桌面\\1_COMBINSEC.exe"
#define PEMOVEEXPOPRT_PATH "C:\\Documents and Settings\\桌面\\1_MOVEEXPOPRT.dll"
#define PEMOVEIMPOPRT_PATH "C:\\Documents and Settings\\桌面\\1_MOVEIMPOPRT.dll"

BYTE ShellCode[] = {0x6A, 0x00, 0x6A, 0x00, 0x6A, 0x00, 0x6A, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0xE9, 0x00, 0x00, 0x00, 0x00};

void *ReadPE(IN const char *pPEPath, OUT DWORD *SizeOfFile);
void UnReadPE(IN void *pFileBuf);
void PrasePE(IN void *pFileBuf);
void *ReadToImageBuf(IN const char *pPEPath);
void UnReadToImageBuf(IN void *pImageBuf);
void ReadToFileBuf(IN void *pImageBuf, IN const char *pSavePath);
DWORD RVATORAW(IN const char *pPEPath, DWORD dwOffset, IN BOOL bRVATORAW);
DWORD RVATORAWEx(IN const void *pFileBuf, IN DWORD dwOffset, IN BOOL bRVATORAW);
BOOL AddShellCode(IN const char *pPEPath, IN BYTE *pShellCode, IN DWORD dwShellCodeSize, IN DWORD SecIndex, IN const char *pOutPath);
BOOL AddSection(IN const char *pPEPath, IN const char *pSecName, DWORD dwRawDataSize /*就是没有进行任何对齐的大小*/, IN void *pDataBuf, IN const char *pOutPath);
BOOL ExtendLastSec(IN const char *pPEPath, DWORD dwRawDataSize /*扩大之后没有进行任何对齐的大小*/, IN const char *pOutPath);
BOOL CombinSec(IN const char *pPEPath, IN const char *pOutPath);
BOOL ExportInfo(IN const char *pPEPath);
BOOL RelocInfo(IN const char *pPEPath);
BOOL ImportInfo(IN const char *pPEPath);
BOOL MoveExportTable(IN const char *pPEPath, IN const char *pSecName, IN const char *pOutPath);

int main(int argc, char *argv[])
{
	//练习一 读exe到内存
	// void *pFileBuf = ReadPE(PE_PATH, NULL);
	// PrasePE(pFileBuf);
	// UnReadPE(pFileBuf);

	//练习二 拉伸PE
	// void *pImageBuf = ReadToImageBuf(PE_PATH);
	// UnReadToImageBuf(pImageBuf);

	//练习三 DumpImagePE到硬盘文件保证可执行
	// void *pImageBuf = ReadToImageBuf(PE_PATH);
	// ReadToFileBuf(pImageBuf, "1.exe");
	// UnReadToImageBuf(pImageBuf);

	//练习四 RVA---->RAW函数的编写
	// DWORD dwRAW = RVATORAW(PE_PATH, 0x3794, TRUE);
	// printf("RAW:%p\n", dwRAW);

	//习五 往指定节里添加代码
	//     AddShellCode(PE_PATH,ShellCode,sizeof(ShellCode),1,PEWITHSHELLCODE_PATH);

	//练习六 添加节
	//    AddSection(PE_PATH,".zll",100/*就是没有进行任何对齐的大小*/,NULL,PEADDSEC_PATH);
	//    ExtendLastSec(PE_PATH,0x8500,PEEXPANDSEC_PATH);
	//    CombinSec(PE_PATH,PECOMBINSEC_PATH);

	// 练习七 打印导出表
	// ExportInfo("kernel32.dll");

	//练习八 打印重定位块
	// 	RelocInfo(PE_PATH);

	//练习九 打印导入表
	ImportInfo("kernel32.dll");

	//练习十 移动导出表
	//	MoveExportTable(PE_PATH,"MyExport",PEMOVEEXPOPRT_PATH);

	return 0;
}

//功能：加载PE文件到内存
//参数：pPEPath为exe文件路径
//返回值:文件缓存
void *ReadPE(IN const char *pPEPath, OUT DWORD *SizeOfFile)
{
	FILE *fp = fopen(pPEPath, "rb");
	if (fp == NULL)
	{
		printf("打开文件失败 Error_Code:%u\t LINE:%u\n", GetLastError(), __LINE__);
		return NULL;
	}
	fseek(fp, 0, SEEK_END);
	DWORD dwSizeOfFile = ftell(fp);
	if (SizeOfFile)
	{
		*SizeOfFile = dwSizeOfFile;
	}
	fseek(fp, 0, SEEK_SET);
	void *pFileBuf = (void *)malloc(dwSizeOfFile);
	fread(pFileBuf, dwSizeOfFile, 1, fp);
	fclose(fp);
	return pFileBuf;
}

//功能：释放PE所分配的堆空间
//参数：PE的文件缓存地址
//返回值:无
void UnReadPE(IN void *pFileBuf)
{
	if (pFileBuf == NULL)
	{
		printf("输入参数为空\n");
	}
	else
	{
		free(pFileBuf);
	}
	return;
}

//功能：解析PE文件
//参数：PE的文件缓存地址
//返回值:无
void PrasePE(IN void *pFileBuf)
{
	if (!pFileBuf)
	{
		printf("输入参数无效\n");
		return;
	}
	IMAGE_DOS_HEADER *pIDH = (IMAGE_DOS_HEADER *)pFileBuf;

	printf("c\nmagic:%X\nlfanew:%X\n", pIDH->e_magic, pIDH->e_lfanew);

	IMAGE_NT_HEADERS *pINHS = (IMAGE_NT_HEADERS *)((DWORD)pFileBuf + pIDH->e_lfanew);
	printf("Signature:%X\n", pINHS->Signature);

	IMAGE_FILE_HEADER IFH = pINHS->FileHeader;

	printf("\n--------------IMAGE_FILE_HEADER--------------\nMachine:%X\nNumberOfSections:%u\nTimeDateStamp:%u\nPointerToSymbolTable:%X\nNumberOfSymbols:%u\nSizeOfOptionalHeader:%u\nCharacteristics:%X\n",
		   IFH.Machine, IFH.NumberOfSections, IFH.TimeDateStamp, IFH.PointerToSymbolTable,
		   IFH.NumberOfSymbols, IFH.SizeOfOptionalHeader, IFH.Characteristics);

	IMAGE_OPTIONAL_HEADER pIOH = pINHS->OptionalHeader;
	printf("\n--------------IMAGE_OPTIONAL_HEADER--------------\nMagic:%X\nSizeOfCode:%X\n\
SizeOfInitializedData:%X\nSizeOfUninitializedData:%X\nAddressOfEntryPoint:%X\nImageBase:%X\nSectionAlignment:%X\n\
FileAlignment:%X\nSizeOfImage:%X\nSizeOfHeaders:%X\nCheckSum:%X\nSubsystem:%X\nSizeOfStackReserve:%X\nSizeOfStackCommit:%X\n\
SizeOfHeapReserve:%X\nSizeOfHeapCommit:%X\nNumberOfRvaAndSizes:%X\n",
		   pIOH.Magic, pIOH.SizeOfCode, pIOH.SizeOfInitializedData, pIOH.SizeOfUninitializedData,
		   pIOH.AddressOfEntryPoint, pIOH.ImageBase, pIOH.SectionAlignment, pIOH.FileAlignment,
		   pIOH.SizeOfImage, pIOH.SizeOfHeaders, pIOH.CheckSum, pIOH.Subsystem, pIOH.SizeOfStackReserve,
		   pIOH.SizeOfStackCommit, pIOH.SizeOfHeapReserve, pIOH.SizeOfHeapCommit, pIOH.NumberOfRvaAndSizes);

	IMAGE_SECTION_HEADER *pISH = (IMAGE_SECTION_HEADER *)((DWORD)pFileBuf + pIDH->e_lfanew + sizeof(IMAGE_NT_HEADERS));
	char szBufName[9] = {0};
	printf("\n--------------IMAGE_SECTION_HEADER--------------\n");
	for (DWORD i = 0; i < IFH.NumberOfSections; i++)
	{
		printf("++++++++++++++++++++++%u Section++++++++++++++++++++++++++\n", i + 1);
		memcpy(szBufName, pISH->Name, IMAGE_SIZEOF_SHORT_NAME);
		printf("Name:%s\n", szBufName);
		printf("VirtualSize:%p\nSizeOfRawData:%p\nVirtualSize:%p\nPointerToRawData:%p\n", pISH->Misc.VirtualSize, pISH->SizeOfRawData, pISH->VirtualAddress, pISH->PointerToRawData);
		memset(szBufName, 0, 9);
		pISH++;
	}
	return;
}

//功能：拉伸PE至内存,从FileBuf--->ImageBuf
//参数：exe文件路径
//返回值:拉伸后的堆地址
void *ReadToImageBuf(IN const char *pPEPath)
{
	void *pFileBuf = ReadPE(pPEPath, NULL);
	if (pFileBuf == NULL)
		return NULL;

	IMAGE_DOS_HEADER *pIDH = (IMAGE_DOS_HEADER *)pFileBuf;
	IMAGE_NT_HEADERS *pINGS = (IMAGE_NT_HEADERS *)((DWORD)pFileBuf + pIDH->e_lfanew);
	IMAGE_FILE_HEADER IFH = pINGS->FileHeader;
	IMAGE_OPTIONAL_HEADER IOH = pINGS->OptionalHeader;
	IMAGE_SECTION_HEADER *pISH = (IMAGE_SECTION_HEADER *)((DWORD)pFileBuf + pIDH->e_lfanew + sizeof(IMAGE_NT_HEADERS));
	DWORD dwNumberOfSecs = IFH.NumberOfSections;

	void *pImageBuf = (void *)malloc(IOH.SizeOfImage);
	memset(pImageBuf, 0, IOH.SizeOfImage);

	DWORD dwSecAlign = IOH.SectionAlignment;
	DWORD dwFileAlign = IOH.FileAlignment;
	void *pFileBufTmp = pFileBuf, *pImageBufTmp = pImageBuf;
	//拷贝PE头
	memcpy(pImageBufTmp, pFileBufTmp, IOH.SizeOfHeaders);
	//拷贝节
	for (DWORD i = 0; i < dwNumberOfSecs; i++)
	{
		pFileBufTmp = (void *)((DWORD)pFileBuf + pISH->PointerToRawData);
		pImageBufTmp = (void *)((DWORD)pImageBuf + pISH->VirtualAddress);
		memcpy(pImageBufTmp, pFileBufTmp, pISH->SizeOfRawData);
		pISH++;
	}
	UnReadPE(pFileBuf);
	return pImageBuf;
}

//功能：释放拉伸PE所占据的内存
//参数：exe文件路径
//返回值:拉伸后的堆地址
void UnReadToImageBuf(IN void *pImageBuf)
{
	if (pImageBuf == NULL)
	{
		printf("输入参数为空\n");
	}
	else
	{
		free(pImageBuf);
	}
	return;
}

//功能：反拉伸PE至内存并存盘，ImageBuf ----->FileBuf------->保存到硬盘文件
//参数：exe文件路径
//返回值:反拉伸后的堆地址
void ReadToFileBuf(IN void *pImageBuf, IN const char *pSavePath)
{
	IMAGE_DOS_HEADER *pIDH = (IMAGE_DOS_HEADER *)pImageBuf;
	IMAGE_NT_HEADERS *pINGS = (IMAGE_NT_HEADERS *)((DWORD)pImageBuf + pIDH->e_lfanew);
	IMAGE_FILE_HEADER IFH = pINGS->FileHeader;
	IMAGE_OPTIONAL_HEADER IOH = pINGS->OptionalHeader;
	IMAGE_SECTION_HEADER *pISH = (IMAGE_SECTION_HEADER *)((DWORD)pImageBuf + pIDH->e_lfanew + sizeof(IMAGE_NT_HEADERS));

	DWORD SectionNumber = IFH.NumberOfSections;
	DWORD dwFileSize = IOH.SizeOfHeaders;

	//计算需要分配的FileBuf大小;
	IMAGE_SECTION_HEADER *pISHTmp = pISH;

	for (DWORD i = 0; i < SectionNumber; i++)
	{
		dwFileSize += pISHTmp->SizeOfRawData;
		pISHTmp++;
	}
	void *pFileBuf = (void *)malloc(dwFileSize);
	void *pFileBufTmp = pFileBuf, *pImageBufTmp = pImageBuf;
	memset(pFileBuf, 0, dwFileSize);
	//拷贝PE头
	memcpy(pFileBufTmp, pImageBufTmp, IOH.SizeOfHeaders);
	//拷贝节
	for (DWORD j = 0; j < SectionNumber; j++)
	{
		pFileBufTmp = (void *)((DWORD)pFileBuf + pISH->PointerToRawData);
		pImageBufTmp = (void *)((DWORD)pImageBuf + pISH->VirtualAddress);
		memcpy(pFileBufTmp, pImageBufTmp, pISH->SizeOfRawData);
		pISH++;
	}
	FILE *fp = fopen(pSavePath, "wb");
	fwrite(pFileBuf, dwFileSize, 1, fp);
	fclose(fp);
	free(pFileBuf);
	return;
}

//功能：RVA与RAW的相互转换
//参数：pPEPath:PE文件路径，
//        bRVATORAW: TRUE, RVA to RAW
//			         FALSE,RAW to RVA
//返回值:转换后的值，为0则转换失败

DWORD RVATORAW(IN const char *pPEPath, IN DWORD dwOffset, IN BOOL bRVATORAW)
{
	void *pFileBuf = ReadPE(pPEPath, NULL);
	if (pFileBuf == NULL)
		return FALSE;
	IMAGE_DOS_HEADER *pIDH = (IMAGE_DOS_HEADER *)pFileBuf;
	IMAGE_NT_HEADERS *pINGS = (IMAGE_NT_HEADERS *)((DWORD)pFileBuf + pIDH->e_lfanew);
	IMAGE_FILE_HEADER IFH = pINGS->FileHeader;
	DWORD dwNumberOfSecs = IFH.NumberOfSections;
	IMAGE_OPTIONAL_HEADER IOH = pINGS->OptionalHeader;
	IMAGE_SECTION_HEADER *pISH = (IMAGE_SECTION_HEADER *)((DWORD)pFileBuf + pIDH->e_lfanew + sizeof(IMAGE_NT_HEADERS));
	//计算需要分配的FileBuf大小;
	IMAGE_SECTION_HEADER *pISHTmp = pISH;

	//若dwOffset，则说明在PE头中，RVA==RAW
	if (dwOffset < IOH.SizeOfHeaders)
		return dwOffset;
	//进行RVA---->RAW
	if (bRVATORAW)
	{
		for (DWORD i = 0; i < dwNumberOfSecs; i++)
		{ //这个比较公式很重要  好好理解为何是SizeOfRawData，哈哈这才是精髓
			if (pISHTmp->VirtualAddress <= dwOffset && dwOffset <= pISHTmp->VirtualAddress + pISHTmp->SizeOfRawData)
			{
				return dwOffset - pISHTmp->VirtualAddress + pISHTmp->PointerToRawData;
			}
			pISHTmp++;
		}
	}
	//进行RAW---->RVA
	else
	{
		for (DWORD i = 0; i < dwNumberOfSecs; i++)
		{ //这个比较公式很重要  好好理解为何是取pISHTmp->SizeOfRawData   pISHTmp->Misc.VirtualSize中大的，哈哈这才是精髓
			if (pISHTmp->PointerToRawData <= dwOffset && dwOffset <= pISHTmp->VirtualAddress + (pISHTmp->SizeOfRawData > pISHTmp->Misc.VirtualSize ? pISHTmp->SizeOfRawData : pISHTmp->Misc.VirtualSize))
			{
				return dwOffset - pISHTmp->PointerToRawData + pISHTmp->VirtualAddress;
			}
			pISHTmp++;
		}
	}
	UnReadPE(pFileBuf);
	return NULL;
}

//功能：RVA与RAW的相互转换
//参数：pFileBuf:PE文件加载到的内存地址，
//        bRVATORAW: TRUE, RVA to RAW
//			         FALSE,RAW to RVA
//返回值:转换后的值，为0则转换失败
//说明：RVATORAW比之根据有独立性，但RVATORAW多次调用时速度明显很慢
DWORD RVATORAWEx(IN const void *pFileBuf, IN DWORD dwOffset, IN BOOL bRVATORAW)
{
	IMAGE_DOS_HEADER *pIDH = (IMAGE_DOS_HEADER *)pFileBuf;
	IMAGE_NT_HEADERS *pINGS = (IMAGE_NT_HEADERS *)((DWORD)pFileBuf + pIDH->e_lfanew);
	IMAGE_FILE_HEADER IFH = pINGS->FileHeader;
	DWORD dwNumberOfSecs = IFH.NumberOfSections;
	IMAGE_OPTIONAL_HEADER IOH = pINGS->OptionalHeader;
	IMAGE_SECTION_HEADER *pISH = (IMAGE_SECTION_HEADER *)((DWORD)pFileBuf + pIDH->e_lfanew + sizeof(IMAGE_NT_HEADERS));
	//计算需要分配的FileBuf大小;
	IMAGE_SECTION_HEADER *pISHTmp = pISH;
	//若dwOffset，则说明在PE头中，RVA==RAW
	if (dwOffset < IOH.SizeOfHeaders)
		return dwOffset;
	//进行RVA---->RAW
	if (bRVATORAW)
	{
		for (DWORD i = 0; i < dwNumberOfSecs; i++)
		{ //这个比较公式很重要  好好理解为何是SizeOfRawData，哈哈这才是精髓
			if (pISHTmp->VirtualAddress <= dwOffset && dwOffset <= pISHTmp->VirtualAddress + pISHTmp->SizeOfRawData)
			{
				return dwOffset - pISHTmp->VirtualAddress + pISHTmp->PointerToRawData;
			}
			pISHTmp++;
		}
	}
	//进行RAW---->RVA
	else
	{
		for (DWORD i = 0; i < dwNumberOfSecs; i++)
		{ //这个比较公式很重要  好好理解为何是取pISHTmp->SizeOfRawData   pISHTmp->Misc.VirtualSize中大的，哈哈这才是精髓
			if (pISHTmp->PointerToRawData <= dwOffset && dwOffset <= pISHTmp->VirtualAddress + (pISHTmp->SizeOfRawData > pISHTmp->Misc.VirtualSize ? pISHTmp->SizeOfRawData : pISHTmp->Misc.VirtualSize))
			{
				return dwOffset - pISHTmp->PointerToRawData + pISHTmp->VirtualAddress;
			}
			pISHTmp++;
		}
	}
	return NULL;
}

//功能：往节里添加ShellCode
//参数：pShellCode:指向ShellCode数据
//返回值:指示是否添加成功

BOOL AddShellCode(IN const char *pPEPath, IN BYTE *pShellCode, IN DWORD dwShellCodeSize, IN DWORD SecIndex, IN const char *pOutPath)
{
	void *pImageBuf = ReadToImageBuf(pPEPath);
	if (pImageBuf == NULL)
		return FALSE;
	IMAGE_DOS_HEADER *pIDH = (IMAGE_DOS_HEADER *)pImageBuf;
	IMAGE_NT_HEADERS *pINGS = (IMAGE_NT_HEADERS *)((DWORD)pImageBuf + pIDH->e_lfanew);
	IMAGE_FILE_HEADER IFH = pINGS->FileHeader;
	DWORD dwNumberOfSecs = IFH.NumberOfSections;
	IMAGE_OPTIONAL_HEADER IOH = pINGS->OptionalHeader;
	DWORD AddressOfEntryPoint = IOH.AddressOfEntryPoint;
	DWORD ImageBase = IOH.ImageBase;
	IMAGE_SECTION_HEADER *pISH = (IMAGE_SECTION_HEADER *)((DWORD)pImageBuf + pIDH->e_lfanew + sizeof(IMAGE_NT_HEADERS));
	DWORD dwFileSize = IOH.SizeOfHeaders; //初始化为PE头的大小
										  //计算需要分配的FileBuf大小;
	IMAGE_SECTION_HEADER *pISHTmp = pISH;
	for (DWORD i = 0; i < dwNumberOfSecs; i++)
	{
		dwFileSize += pISHTmp->SizeOfRawData;
		pISHTmp++;
	}
	if (SecIndex > dwNumberOfSecs)
	{
		printf("Section Number Is %u You Have Over It!\n", dwNumberOfSecs);
		return FALSE;
	}
	//获取代码节的属性
	DWORD Characteristics = pISH->Characteristics;
	pISH += SecIndex - 1;
	//修改添加代码的段 的属性
	pISH->Characteristics |= Characteristics;
	//这边要注意，因为你最终的代码数据要保存到硬盘文件上，所以必须要使得SizeOfRawData大于VirtualSize
	if (pISH->SizeOfRawData < pISH->Misc.VirtualSize + dwShellCodeSize)
	{ //不能写成pISH->SizeOfRawData - pISH->Misc.VirtualSize < dwShellCodeSize,因为
		// DWORD - DWORD 溢出了还是按照DWORD来考虑，当SizeOfRawData<VirtualSize就悲剧了
		printf("没有足够的空间来容纳ShellCode 请更换节\n");
		return FALSE;
	}
	void *pAddAddress = (void *)((DWORD)pImageBuf + pISH->VirtualAddress + pISH->Misc.VirtualSize);
	memcpy(pAddAddress, pShellCode, dwShellCodeSize);
	//进行地址修正，注意这边没有写成通用的，这边的修正只满足于当前的ShellCode，等以后有时间写成万能型
	HMODULE hMod = LoadLibrary(TEXT("User32.dll"));
	*(DWORD *)((BYTE *)pAddAddress + 9) = (DWORD)GetProcAddress(hMod, "MessageBoxA") - ((DWORD)ImageBase + pISH->VirtualAddress + pISH->Misc.VirtualSize + 8) - 5;
	*(DWORD *)((BYTE *)pAddAddress + 14) = ImageBase + AddressOfEntryPoint - ((DWORD)ImageBase + pISH->VirtualAddress + pISH->Misc.VirtualSize + 13) - 5;
	pINGS->OptionalHeader.AddressOfEntryPoint = pISH->VirtualAddress + pISH->Misc.VirtualSize;
	FreeLibrary(hMod);
	ReadToFileBuf(pImageBuf, pOutPath);
	UnReadToImageBuf(pImageBuf);
	return TRUE;
}

//功能：增加一个节
//参数：pPEPath:EXE文件
//      pSecName:新增节名
//      dwRawDataSize:新增节的原始数据大小
//      pDataBuf:新增节加入的数据,若其为NULL，则程序使用默认的数据0填充
//      pOutPath:新的EXE的输出路径
//返回值:指示是否添加成功

BOOL AddSection(IN const char *pPEPath, IN const char *pSecName, DWORD dwRawDataSize /*就是没有进行任何对齐的大小*/, IN void *pDataBuf, IN const char *pOutPath)
{ //读取原EXE文件到内存
	DWORD dwSizeOfFile = 0;
	void *pFileBuf = ReadPE(pPEPath, &dwSizeOfFile);
	if (pFileBuf == NULL)
	{
		return FALSE;
	}
	IMAGE_DOS_HEADER *pIDH = (IMAGE_DOS_HEADER *)pFileBuf;
	IMAGE_NT_HEADERS *pINGS = (IMAGE_NT_HEADERS *)((DWORD)pFileBuf + pIDH->e_lfanew);
	IMAGE_SECTION_HEADER *pISH = (IMAGE_SECTION_HEADER *)((DWORD)pFileBuf + pIDH->e_lfanew + sizeof(IMAGE_NT_HEADERS));
	DWORD dwNumOfSecs = pINGS->FileHeader.NumberOfSections;
	if (memcmp(pISH + dwNumOfSecs, pISH + dwNumOfSecs + 1, sizeof(IMAGE_SECTION_HEADER)) != 0)
	{ //说明IMAGE_SECTION_HEADER数据以后有其他数据，这种情况下，我们需要挪动PE头
		memcpy((void *)((DWORD)pFileBuf + sizeof(IMAGE_DOS_HEADER)), (void *)((DWORD)pFileBuf + pIDH->e_lfanew), sizeof(IMAGE_NT_HEADERS) + dwNumOfSecs * sizeof(IMAGE_SECTION_HEADER));
		pIDH->e_lfanew = sizeof(IMAGE_DOS_HEADER);
		pINGS = (IMAGE_NT_HEADERS *)((DWORD)pFileBuf + pIDH->e_lfanew);
		pISH = (IMAGE_SECTION_HEADER *)((DWORD)pFileBuf + pIDH->e_lfanew + sizeof(IMAGE_NT_HEADERS));
	}
	DWORD dwSizeofImage = pINGS->OptionalHeader.SizeOfImage;
	DWORD dwFileAlign = pINGS->OptionalHeader.FileAlignment;
	DWORD dwSecAlign = pINGS->OptionalHeader.SectionAlignment;
	pINGS->FileHeader.NumberOfSections++;
	//这边假设VirtualSize <= SizeOfRawData,这种情况的概率99.99%
	pINGS->OptionalHeader.SizeOfImage += (dwRawDataSize + dwSecAlign - 1) / dwSecAlign * dwSecAlign;

	pISH += dwNumOfSecs;
	//设置IMAGE_SECTION_HEADER
	IMAGE_SECTION_HEADER ISH = {0};
	char pNameBuf[9] = {0};
	memcpy(pNameBuf, pSecName, 8);
	memcpy(ISH.Name, pNameBuf, 8);
	ISH.Misc.VirtualSize = dwRawDataSize; //这边乱写的,反正这个值也没多大用
	ISH.VirtualAddress = dwSizeofImage;
	ISH.SizeOfRawData = (dwRawDataSize + dwFileAlign - 1) / dwFileAlign * dwFileAlign;
	ISH.PointerToRawData = dwSizeOfFile;
	ISH.Characteristics = pISH->Characteristics | 0x60000020 | 0xC0000040; //属性取代码节和数据节的属性，方便我们操作  哈哈
	memcpy((void *)pISH, &ISH, sizeof(ISH));
	//向原exe文件添加节数据
	void *pBuf = pDataBuf;
	if (pDataBuf == NULL)
	{
		pBuf = malloc(ISH.SizeOfRawData);
		memset(pBuf, 0, ISH.SizeOfRawData);
	}
	FILE *fp_New = fopen(pOutPath, "wb");
	fwrite(pFileBuf, dwSizeOfFile, 1, fp_New);
	fwrite(pBuf, ISH.SizeOfRawData, 1, fp_New);
	fclose(fp_New);
	free(pBuf);
	UnReadPE(pFileBuf);
	return TRUE;
}

//功能：扩大最后一个节
//参数：pPEPath:EXE文件
//      dwRawDataSize:新增节的原始数据大小
//      pOutPath:新的EXE的输出路径
//返回值:指示是否扩大成功

BOOL ExtendLastSec(IN const char *pPEPath, DWORD dwRawDataSize /*扩大之后没有进行任何对齐的大小*/, IN const char *pOutPath)
{
	FILE *fp = fopen(pPEPath, "rb");
	if (fp == NULL)
	{
		printf("Error_Code:%u\t LINE:", GetLastError(), __LINE__);
		return NULL;
	}
	fseek(fp, 0, SEEK_END);
	DWORD dwSizeOfFile = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	void *pFileBuf = (void *)malloc(dwSizeOfFile);
	fread(pFileBuf, dwSizeOfFile, 1, fp);
	fclose(fp);

	IMAGE_DOS_HEADER *pIDH = (IMAGE_DOS_HEADER *)pFileBuf;
	IMAGE_NT_HEADERS *pINGS = (IMAGE_NT_HEADERS *)((DWORD)pFileBuf + pIDH->e_lfanew);
	IMAGE_SECTION_HEADER *pISH = (IMAGE_SECTION_HEADER *)((DWORD)pFileBuf + pIDH->e_lfanew + sizeof(IMAGE_NT_HEADERS));
	DWORD dwNumOfSecs = pINGS->FileHeader.NumberOfSections;

	DWORD dwFileAlign = pINGS->OptionalHeader.FileAlignment;
	pISH += dwNumOfSecs - 1;
	//设置最后一个节的IMAGE_SECTION_HEADER
	if (dwRawDataSize < pISH->SizeOfRawData)
	{
		printf("dwRawDataSize小于原始大小，请重新设定改值!\n");
		free(pFileBuf);
		return FALSE;
	}
	pINGS->OptionalHeader.SizeOfImage += (dwRawDataSize + dwFileAlign - 1) / dwFileAlign * dwFileAlign - pISH->SizeOfRawData;
	pISH->SizeOfRawData = (dwRawDataSize + dwFileAlign - 1) / dwFileAlign * dwFileAlign;
	pISH->Characteristics |= 0x60000020 | 0xC0000040; //属性取代码节和数据节的属性，方便我们操作  哈哈
	pISH->Misc.VirtualSize = 0;
	//向原exe文件添加节数据
	void *pBuf = malloc((dwRawDataSize + dwFileAlign - 1) / dwFileAlign * dwFileAlign);
	memset(pBuf, 0, (dwRawDataSize + dwFileAlign - 1) / dwFileAlign * dwFileAlign);
	FILE *fp_New = fopen(pOutPath, "wb");
	fwrite(pFileBuf, dwSizeOfFile, 1, fp_New);
	fwrite(pBuf, (dwRawDataSize + dwFileAlign - 1) / dwFileAlign * dwFileAlign, 1, fp_New);
	fclose(fp_New);
	free(pBuf);
	free(pFileBuf);
	return TRUE;
}

//功能：合并所有节
//参数：pPEPath:EXE文件
//      pOutPath:新的EXE的输出路径
//返回值:指示是否添加成功

//我这里不作特殊处理了，直接合并掉所有节
BOOL CombinSec(IN const char *pPEPath, IN const char *pOutPath)
{
	void *pImageBuf = ReadToImageBuf(pPEPath);
	if (pImageBuf == NULL)
		return FALSE;
	IMAGE_DOS_HEADER *pIDH = (IMAGE_DOS_HEADER *)pImageBuf;
	IMAGE_NT_HEADERS *pINGS = (IMAGE_NT_HEADERS *)((DWORD)pImageBuf + pIDH->e_lfanew);
	IMAGE_SECTION_HEADER *pISH = (IMAGE_SECTION_HEADER *)((DWORD)pImageBuf + pIDH->e_lfanew + sizeof(IMAGE_NT_HEADERS));
	DWORD dwNumOfSecs = pINGS->FileHeader.NumberOfSections;
	DWORD dwFileAlign = pINGS->OptionalHeader.FileAlignment;
	DWORD dwSizeOfImage = pINGS->OptionalHeader.SizeOfImage;
	pINGS->FileHeader.NumberOfSections = 1;
	pISH->Characteristics |= 0x60000020 | 0xC0000040 | 0x40000040; //属性取代码节和数据节的属性，方便我们操作  哈哈
	pISH->SizeOfRawData = dwSizeOfImage - pISH->VirtualAddress;
	//或者pISH->Misc.VirtualSize = dwSizeOfImage - pISH->VirtualAddress;//看我的笔记，讲的可谓入木三分，妙哉！
	pISH->Misc.VirtualSize = 0; //这两种选一种即可，不写肯定不行

	memset(++pISH, 0, sizeof(IMAGE_SECTION_HEADER));
	ReadToFileBuf(pImageBuf, pOutPath);
	UnReadToImageBuf(pImageBuf);
	return TRUE;
}

//功能：打印出导出表的所有表的信息
//参数：pPEPath:EXE文件
//返回值:指示是否读取成功

//说明：这里使用RVATORAWEx明显加快了速度

BOOL ExportInfo(IN const char *pPEPath)
{
	void *pFileBuf = ReadPE(pPEPath, NULL);
	if (pFileBuf == NULL)
		return FALSE;
	IMAGE_DOS_HEADER *pIDH = (IMAGE_DOS_HEADER *)pFileBuf;
	IMAGE_NT_HEADERS *pINGS = (IMAGE_NT_HEADERS *)((DWORD)pFileBuf + pIDH->e_lfanew);
	IMAGE_OPTIONAL_HEADER IOH = pINGS->OptionalHeader;
	DWORD dwSize = IOH.DataDirectory[0].Size;
	DWORD RvaAddress = IOH.DataDirectory[0].VirtualAddress;
	if (dwSize == 0 || RvaAddress == 0)
	{
		printf("改文件没有导出表\n");
		UnReadPE(pFileBuf);
		return TRUE;
	}
	DWORD RawAddress = RVATORAWEx(pFileBuf, RvaAddress, TRUE);
	IMAGE_EXPORT_DIRECTORY *pIED = (IMAGE_EXPORT_DIRECTORY *)((DWORD)pFileBuf + RawAddress);
	DWORD NameRawAdd = (DWORD)pFileBuf + RVATORAWEx(pFileBuf, pIED->Name, TRUE);
	//打印导出表的表头信息
	printf("Characteristics:%u\n", pIED->Characteristics);
	printf("---------------------导出表头信息------------------\n");
	printf("TimeDateStamp:%u\n", pIED->TimeDateStamp);
	printf("MajorVersion:%u\n", pIED->MajorVersion);
	printf("MinorVersion:%u\n", pIED->MinorVersion);
	printf("Name:%s\n", NameRawAdd);
	printf("Base:%u\n", pIED->Base);
	printf("NumberOfFunctions:%u\n", pIED->NumberOfFunctions);
	printf("NumberOfNames:%u\n", pIED->NumberOfNames);
	printf("AddressOfFunctions(RVA):%u\n", pIED->AddressOfFunctions);
	printf("AddressOfNames(RVA):%u\n", pIED->AddressOfNames);
	printf("AddressOfNameOrdinals(RVA):%u\n", pIED->AddressOfNameOrdinals);

	//打印AddressOfFuncations表
	DWORD *pAddOfFun_Raw = (DWORD *)((DWORD)pFileBuf + RVATORAW(pPEPath, pIED->AddressOfFunctions, TRUE));
	DWORD *pAddOfNames_Raw = (DWORD *)((DWORD)pFileBuf + RVATORAW(pPEPath, pIED->AddressOfNames, TRUE));
	WORD *pAddOfOrd_Raw = (WORD *)((DWORD)pFileBuf + RVATORAW(pPEPath, pIED->AddressOfNameOrdinals, TRUE));
	printf("%X %X %X\n", *pAddOfFun_Raw, *pAddOfNames_Raw, *pAddOfOrd_Raw);
	BOOL bOrdNameFun = FALSE; //用于判断是不是AddressOfFunctions表中的项在AddressOfNameOrdinals都有
	printf("FunAddress\tOrdinal\tName\n");

	for (DWORD i = 0; i < pIED->NumberOfFunctions; i++)
	{
		DWORD j;
		for (j = 0; j < pIED->NumberOfNames; j++)
		{
			if (pAddOfOrd_Raw[j] == i)
			{
				bOrdNameFun = TRUE;
				break;
			}
		}
		if (bOrdNameFun)
		{
			bOrdNameFun = FALSE;
			DWORD NameAdd = RVATORAW(pPEPath, pAddOfNames_Raw[j], TRUE);
			printf("%X\t%X\t%s\n", pAddOfFun_Raw[i], j + pIED->Base, (DWORD)pFileBuf + NameAdd);
		}
		else
		{
			printf("%X\t--\t--\n");
		}
	}
	UnReadPE(pFileBuf);
	return TRUE;
}

//功能：打印出导出表的所有表的信息
//参数：pPEPath:EXE文件
//返回值:指示是否读取成功

//说明：这里使用RVATORAWEx明显加快了速度

BOOL RelocInfo(IN const char *pPEPath)
{
	void *pFileBuf = ReadPE(pPEPath, NULL);
	if (pFileBuf == NULL)
		return FALSE;
	IMAGE_DOS_HEADER *pIDH = (IMAGE_DOS_HEADER *)pFileBuf;
	IMAGE_NT_HEADERS *pINGS = (IMAGE_NT_HEADERS *)((DWORD)pFileBuf + pIDH->e_lfanew);
	IMAGE_OPTIONAL_HEADER IOH = pINGS->OptionalHeader;
	DWORD dwSize = IOH.DataDirectory[5].Size;
	DWORD RvaAddress = IOH.DataDirectory[5].VirtualAddress;
	if (dwSize == 0 || RvaAddress == 0)
	{
		printf("该文件没有重定位表\n");
		UnReadPE(pFileBuf);
		return TRUE;
	}
	DWORD RawAddress = RVATORAWEx(pFileBuf, RvaAddress, TRUE);
	IMAGE_BASE_RELOCATION *pIRD = (IMAGE_BASE_RELOCATION *)((DWORD)pFileBuf + RawAddress);
	DWORD dwCnt = 1;
	WORD *pRelocItem = NULL;
	while (pIRD->SizeOfBlock && pIRD->VirtualAddress)
	{

		printf("\n------------第 %u 个重定位块-------------\n", dwCnt);
		pRelocItem = (WORD *)((DWORD)pIRD + sizeof(IMAGE_BASE_RELOCATION));
		DWORD dwCycs = (pIRD->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) >> 1;
		DWORD dwNewLine = 0;
		for (DWORD i = 0; i < dwCycs; i++)
		{
			if ((*pRelocItem & 0x3000) == 0x3000)
			{
				if (dwNewLine == 10)
				{
					dwNewLine = 0;
					printf("\n");
				}
				printf("%X ", pIRD->VirtualAddress + (*pRelocItem & 0x0fff));
				dwNewLine++;
			}
			pRelocItem++;
		}
		dwCnt++;
		pIRD = (IMAGE_BASE_RELOCATION *)((DWORD)pIRD + pIRD->SizeOfBlock);
	}
	UnReadPE(pFileBuf);
	return TRUE;
}

//功能：打印出导入表的所有表的信息
//参数：pPEPath:EXE文件
//返回值:指示是否读取成功

//说明：这里使用RVATORAWEx明显加快了速度

BOOL ImportInfo(IN const char *pPEPath)
{
	void *pFileBuf = ReadPE(pPEPath, NULL);
	if (pFileBuf == NULL)
		return FALSE;
	IMAGE_DOS_HEADER *pIDH = (IMAGE_DOS_HEADER *)pFileBuf;
	IMAGE_NT_HEADERS *pINGS = (IMAGE_NT_HEADERS *)((DWORD)pFileBuf + pIDH->e_lfanew);
	IMAGE_OPTIONAL_HEADER IOH = pINGS->OptionalHeader;
	DWORD dwSize = IOH.DataDirectory[1].Size;
	DWORD RvaAddress = IOH.DataDirectory[1].VirtualAddress;

	if (dwSize == 0 || RvaAddress == 0)
	{
		printf("改文件没有导表\n");
		UnReadPE(pFileBuf);
		return TRUE;
	}
	DWORD RawAddress = RVATORAWEx(pFileBuf, RvaAddress, TRUE);
	IMAGE_IMPORT_DESCRIPTOR *pIID = (IMAGE_IMPORT_DESCRIPTOR *)((DWORD)pFileBuf + RawAddress);
	DWORD dwNumOfImport = 1;

	while (pIID->Name != NULL)
	{
		//打印导入表的表头信息
		DWORD OriginalFirstThunk_Raw = (DWORD)pFileBuf + RVATORAWEx(pFileBuf, pIID->OriginalFirstThunk, TRUE);
		DWORD FirstThunk_Raw = (DWORD)pFileBuf + RVATORAWEx(pFileBuf, pIID->FirstThunk, TRUE);
		DWORD Name_Raw = (DWORD)pFileBuf + RVATORAWEx(pFileBuf, pIID->Name, TRUE);
		printf("---------------------%u# 导入表头信息------------------\n", dwNumOfImport++);
		printf("OriginalFirstThunk:%u\n", pIID->OriginalFirstThunk);
		printf("TimeDateStamp:%u\n", pIID->TimeDateStamp);
		printf("ForwarderChain:%u\n", pIID->ForwarderChain);
		printf("Name:%s\n", Name_Raw);
		printf("FirstThunk:%u\n", pIID->FirstThunk);

		//解析INT表
		printf("--------------------------INT表----------------------------\n");
		DWORD *pThunkData = (DWORD *)OriginalFirstThunk_Raw;
		while (*pThunkData)
		{
			if ((*pThunkData) & 0x80000000)
			{
				printf("以序号导入，Ord:%X\n", (*pThunkData) & 0x7fffffff);
			}
			else
			{
				IMAGE_IMPORT_BY_NAME *pIIBN = (IMAGE_IMPORT_BY_NAME *)((DWORD)pFileBuf + RVATORAWEx(pFileBuf, *pThunkData, TRUE));
				printf("%Hint:%X\tName:%s\n", pIIBN->Hint, pIIBN->Name);
			}
			pThunkData++;
		}
		//解析IAT表
		printf("--------------------------IAT表----------------------------\n");
		pThunkData = (DWORD *)FirstThunk_Raw;
		if (pIID->TimeDateStamp == 0xffffffff)
		{
			printf("该导入表使用了绑定导入表，IAT表已是地址了\n");
			while (*pThunkData)
			{
				printf("%X\n", *pThunkData);
				pThunkData++;
			}
		}
		else
		{
			while (*pThunkData)
			{
				if ((*pThunkData) & 0x80000000)
				{
					printf("以序号导入，Ord:%X\n", (*pThunkData) & 0x7fffffff);
				}
				else
				{
					IMAGE_IMPORT_BY_NAME *pIIBN = (IMAGE_IMPORT_BY_NAME *)((DWORD)pFileBuf + RVATORAWEx(pFileBuf, *pThunkData, TRUE));
					printf("%Hint:%X\tName:%s\n", pIIBN->Hint, pIIBN->Name);
				}
				pThunkData++;
			}
		}
		pIID++;
	}
	UnReadPE(pFileBuf);
	return TRUE;
}

//功能：移动导出表
//参数：pPEPath:EXE文件
// 		pSecName:新增节的名字
// 		pOutPath:移动后的文件的输出路径
//返回值:指示是否移动成功

//说明：为了最大限度的减少对其他数据的干扰，我自己新增一个节来存放导出表
BOOL MoveExportTable(IN const char *pPEPath, IN const char *pSecName, IN const char *pOutPath)
{
	DWORD dwSizeOfFile = 0;
	void *pFileBuf = ReadPE(pPEPath, &dwSizeOfFile);
	if (pFileBuf == NULL)
		return FALSE;
	//当变换到NewFileBuf时，这边设计地址的指针变量要更新
	IMAGE_DOS_HEADER *pIDH = (IMAGE_DOS_HEADER *)pFileBuf;
	IMAGE_NT_HEADERS *pINGS = (IMAGE_NT_HEADERS *)((DWORD)pFileBuf + pIDH->e_lfanew);

	IMAGE_OPTIONAL_HEADER IOH = pINGS->OptionalHeader;
	DWORD dwSize = IOH.DataDirectory[0].Size;
	DWORD RvaAddress = IOH.DataDirectory[0].VirtualAddress;
	DWORD dwFileAlign = pINGS->OptionalHeader.FileAlignment;
	DWORD dwSecAlign = pINGS->OptionalHeader.SectionAlignment;
	if (dwSize == 0 || RvaAddress == 0)
	{
		printf("改文件没有导出表\n");
		UnReadPE(pFileBuf);
		return TRUE;
	}
	//当变换到NewFileBuf时，这边设计地址的指针变量要更新
	DWORD RawAddress = RVATORAWEx(pFileBuf, RvaAddress, TRUE);
	IMAGE_EXPORT_DIRECTORY *pIED = (IMAGE_EXPORT_DIRECTORY *)((DWORD)pFileBuf + RawAddress);
	DWORD NameRawAdd = (DWORD)pFileBuf + RVATORAWEx(pFileBuf, pIED->Name, TRUE);
	DWORD *pAddOfFun_Raw = (DWORD *)((DWORD)pFileBuf + RVATORAWEx(pFileBuf, pIED->AddressOfFunctions, TRUE));
	WORD *pAddOfOrd_Raw = (WORD *)((DWORD)pFileBuf + RVATORAWEx(pFileBuf, pIED->AddressOfNameOrdinals, TRUE));
	DWORD *pAddOfNames_Raw = (DWORD *)((DWORD)pFileBuf + RVATORAWEx(pFileBuf, pIED->AddressOfNames, TRUE));

	//计算需要的存储空间
	DWORD dwSizeOfDllName = strlen((const char *)NameRawAdd) + 1;
	DWORD dwSizeOfFunAdd = sizeof(DWORD) * pIED->NumberOfFunctions;
	DWORD dwSizeOfOrd = sizeof(WORD) * pIED->NumberOfNames;
	DWORD dwSizeOfName = 0;
	for (DWORD i = 0; i < pIED->NumberOfNames; i++)
	{
		DWORD NameAdd = RVATORAWEx(pFileBuf, pAddOfNames_Raw[i], TRUE);
		dwSizeOfName += strlen((const char *)((DWORD)pFileBuf + NameAdd)) + 1;
	}
	//移动整个导出表所需要的空间总和
	DWORD dwSumSize = sizeof(IMAGE_EXPORT_DIRECTORY) + dwSizeOfDllName + dwSizeOfFunAdd + dwSizeOfOrd + dwSizeOfName;

	//分配新的FileBuf，这个FileBuf是算上导出表的大小的,这样会带来非常大的方便
	void *pNewFileBuf = malloc(dwSizeOfFile + (dwSumSize + dwFileAlign - 1) / dwFileAlign * dwFileAlign);
	memset(pNewFileBuf, 0, dwSizeOfFile + (dwSumSize + dwFileAlign - 1) / dwFileAlign * dwFileAlign);
	memcpy(pNewFileBuf, pFileBuf, dwSizeOfFile);
	UnReadPE(pFileBuf);
	pFileBuf = NULL;

	//更新相关变量,因为存储空间变更了，所以涉及到地址的地方都要换
	pIDH = (IMAGE_DOS_HEADER *)pNewFileBuf;
	pINGS = (IMAGE_NT_HEADERS *)((DWORD)pNewFileBuf + pIDH->e_lfanew);
	pIED = (IMAGE_EXPORT_DIRECTORY *)((DWORD)pNewFileBuf + RawAddress);
	NameRawAdd = (DWORD)pNewFileBuf + RVATORAWEx(pNewFileBuf, pIED->Name, TRUE);
	pAddOfFun_Raw = (DWORD *)((DWORD)pNewFileBuf + RVATORAWEx(pNewFileBuf, pIED->AddressOfFunctions, TRUE));
	pAddOfOrd_Raw = (WORD *)((DWORD)pNewFileBuf + RVATORAWEx(pNewFileBuf, pIED->AddressOfNameOrdinals, TRUE));
	pAddOfNames_Raw = (DWORD *)((DWORD)pNewFileBuf + RVATORAWEx(pNewFileBuf, pIED->AddressOfNames, TRUE));

	//设置新增节的相关属性
	IMAGE_SECTION_HEADER *pISH = (IMAGE_SECTION_HEADER *)((DWORD)pNewFileBuf + pIDH->e_lfanew + sizeof(IMAGE_NT_HEADERS));
	DWORD dwNumOfSecs = pINGS->FileHeader.NumberOfSections;
	if (memcmp(pISH + dwNumOfSecs, pISH + dwNumOfSecs + 1, sizeof(IMAGE_SECTION_HEADER)) != 0)
	{ //说明IMAGE_SECTION_HEADER数据以后有其他数据，这种情况下，我们需要挪动PE头
		memcpy((void *)((DWORD)pNewFileBuf + sizeof(IMAGE_DOS_HEADER)), (void *)((DWORD)pNewFileBuf + pIDH->e_lfanew), sizeof(IMAGE_NT_HEADERS) + dwNumOfSecs * sizeof(IMAGE_SECTION_HEADER));
		pIDH->e_lfanew = sizeof(IMAGE_DOS_HEADER);
		pINGS = (IMAGE_NT_HEADERS *)((DWORD)pNewFileBuf + pIDH->e_lfanew);
		pISH = (IMAGE_SECTION_HEADER *)((DWORD)pNewFileBuf + pIDH->e_lfanew + sizeof(IMAGE_NT_HEADERS));
	}
	DWORD dwSizeofImage = pINGS->OptionalHeader.SizeOfImage;
	pINGS->FileHeader.NumberOfSections++;
	//这边假设VirtualSize <= SizeOfRawData,这种情况的概率99.99%
	pINGS->OptionalHeader.SizeOfImage += (dwSumSize + dwSecAlign - 1) / dwSecAlign * dwSecAlign;
	pISH += dwNumOfSecs;
	//设置IMAGE_SECTION_HEADER
	IMAGE_SECTION_HEADER ISH = {0};
	char pNameBuf[9] = {0};
	memcpy(pNameBuf, pSecName, 8);
	memcpy(ISH.Name, pNameBuf, 8);
	ISH.Misc.VirtualSize = 0; //这边乱写的,反正这个值也没多大用
	ISH.VirtualAddress = dwSizeofImage;
	ISH.SizeOfRawData = (dwSumSize + dwFileAlign - 1) / dwFileAlign * dwFileAlign;
	ISH.PointerToRawData = dwSizeOfFile;
	ISH.Characteristics = pISH->Characteristics | 0x60000020 | 0xC0000040; //属性取代码节和数据节的属性，方便我们操作  哈哈
	memcpy((void *)pISH, &ISH, sizeof(ISH));

	//拷贝导出表的数据到新节里边
	void *pExportTableBuf = (void *)((DWORD)pNewFileBuf + dwSizeOfFile);
	IMAGE_EXPORT_DIRECTORY *pExportTableBuf_Beg = (IMAGE_EXPORT_DIRECTORY *)pExportTableBuf;

	//拷贝头
	memcpy(pExportTableBuf, pIED, sizeof(IMAGE_EXPORT_DIRECTORY));
	pExportTableBuf = (void *)((DWORD)pExportTableBuf + sizeof(IMAGE_EXPORT_DIRECTORY));
	//拷贝FunctionAddress
	memcpy(pExportTableBuf, pAddOfFun_Raw, dwSizeOfFunAdd);
	pExportTableBuf = (void *)((DWORD)pExportTableBuf + dwSizeOfFunAdd);
	pExportTableBuf_Beg->AddressOfFunctions = RVATORAWEx(pNewFileBuf, (DWORD)pExportTableBuf - (DWORD)pNewFileBuf, FALSE);
	//拷贝OrdNames
	memcpy(pExportTableBuf, pAddOfOrd_Raw, dwSizeOfOrd);
	pExportTableBuf = (void *)((DWORD)pExportTableBuf + dwSizeOfOrd);
	pExportTableBuf_Beg->AddressOfNameOrdinals = RVATORAWEx(pNewFileBuf, (DWORD)pExportTableBuf - (DWORD)pNewFileBuf, FALSE);
	//拷贝Names
	for (DWORD j = 0; j < pIED->NumberOfNames; j++)
	{
		DWORD NameAdd = (DWORD)pNewFileBuf + RVATORAWEx(pNewFileBuf, pAddOfNames_Raw[j], TRUE);
		DWORD NameLen = strlen((const char *)NameAdd) + 1;
		memcpy(pExportTableBuf, (const char *)NameAdd, NameLen);
		pAddOfNames_Raw[j] = RVATORAWEx(pNewFileBuf, (DWORD)pExportTableBuf - (DWORD)pNewFileBuf, FALSE);
		pExportTableBuf = (void *)((DWORD)pExportTableBuf + NameLen);
	}
	//拷贝DllName
	memcpy(pExportTableBuf, (const char *)NameRawAdd, dwSizeOfDllName);
	pExportTableBuf_Beg->Name = RVATORAWEx(pNewFileBuf, (DWORD)pExportTableBuf - (DWORD)pNewFileBuf, FALSE);

	//修正目录表
	pINGS->OptionalHeader.DataDirectory[0].VirtualAddress = dwSizeofImage; //原始映像文件大小

	FILE *fp = fopen(pOutPath, "wb");
	fwrite(pNewFileBuf, dwSizeOfFile + (dwSumSize + dwFileAlign - 1) / dwFileAlign * dwFileAlign, 1, fp);
	fclose(fp);
	free(pNewFileBuf);
	return TRUE;
}
