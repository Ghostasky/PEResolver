#include <stdio.h>
#include <windows.h>
#include <stdlib.h>

#define PE_PATH "xxx.exe"

//#define PE_PATH "C:\\Documents and Settings\\����\\kernel32.dll"
#define PEDUMP_PATH "C:\\Documents and Settings\\����\\1_deump.exe"
#define PEWITHSHELLCODE_PATH "C:\\Documents and Settings\\����\\1_withShellcode.exe"
#define PEADDSEC_PATH "C:\\Documents and Settings\\����\\1_ADDSEC.exe"
#define PEEXPANDSEC_PATH "C:\\Documents and Settings\\����\\1_EXPANDSEC.exe"
#define PECOMBINSEC_PATH "C:\\Documents and Settings\\����\\1_COMBINSEC.exe"
#define PEMOVEEXPOPRT_PATH "C:\\Documents and Settings\\����\\1_MOVEEXPOPRT.dll"
#define PEMOVEIMPOPRT_PATH "C:\\Documents and Settings\\����\\1_MOVEIMPOPRT.dll"

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
BOOL AddSection(IN const char *pPEPath, IN const char *pSecName, DWORD dwRawDataSize /*����û�н����κζ���Ĵ�С*/, IN void *pDataBuf, IN const char *pOutPath);
BOOL ExtendLastSec(IN const char *pPEPath, DWORD dwRawDataSize /*����֮��û�н����κζ���Ĵ�С*/, IN const char *pOutPath);
BOOL CombinSec(IN const char *pPEPath, IN const char *pOutPath);
BOOL ExportInfo(IN const char *pPEPath);
BOOL RelocInfo(IN const char *pPEPath);
BOOL ImportInfo(IN const char *pPEPath);
BOOL MoveExportTable(IN const char *pPEPath, IN const char *pSecName, IN const char *pOutPath);

int main(int argc, char *argv[])
{
	//��ϰһ ��exe���ڴ�
	// void *pFileBuf = ReadPE(PE_PATH, NULL);
	// PrasePE(pFileBuf);
	// UnReadPE(pFileBuf);

	//��ϰ�� ����PE
	// void *pImageBuf = ReadToImageBuf(PE_PATH);
	// UnReadToImageBuf(pImageBuf);

	//��ϰ�� DumpImagePE��Ӳ���ļ���֤��ִ��
	// void *pImageBuf = ReadToImageBuf(PE_PATH);
	// ReadToFileBuf(pImageBuf, "1.exe");
	// UnReadToImageBuf(pImageBuf);

	//��ϰ�� RVA---->RAW�����ı�д
	// DWORD dwRAW = RVATORAW(PE_PATH, 0x3794, TRUE);
	// printf("RAW:%p\n", dwRAW);

	//ϰ�� ��ָ��������Ӵ���
	//     AddShellCode(PE_PATH,ShellCode,sizeof(ShellCode),1,PEWITHSHELLCODE_PATH);

	//��ϰ�� ��ӽ�
	//    AddSection(PE_PATH,".zll",100/*����û�н����κζ���Ĵ�С*/,NULL,PEADDSEC_PATH);
	//    ExtendLastSec(PE_PATH,0x8500,PEEXPANDSEC_PATH);
	//    CombinSec(PE_PATH,PECOMBINSEC_PATH);

	// ��ϰ�� ��ӡ������
	// ExportInfo("kernel32.dll");

	//��ϰ�� ��ӡ�ض�λ��
	// 	RelocInfo(PE_PATH);

	//��ϰ�� ��ӡ�����
	ImportInfo("kernel32.dll");

	//��ϰʮ �ƶ�������
	//	MoveExportTable(PE_PATH,"MyExport",PEMOVEEXPOPRT_PATH);

	return 0;
}

//���ܣ�����PE�ļ����ڴ�
//������pPEPathΪexe�ļ�·��
//����ֵ:�ļ�����
void *ReadPE(IN const char *pPEPath, OUT DWORD *SizeOfFile)
{
	FILE *fp = fopen(pPEPath, "rb");
	if (fp == NULL)
	{
		printf("���ļ�ʧ�� Error_Code:%u\t LINE:%u\n", GetLastError(), __LINE__);
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

//���ܣ��ͷ�PE������Ķѿռ�
//������PE���ļ������ַ
//����ֵ:��
void UnReadPE(IN void *pFileBuf)
{
	if (pFileBuf == NULL)
	{
		printf("�������Ϊ��\n");
	}
	else
	{
		free(pFileBuf);
	}
	return;
}

//���ܣ�����PE�ļ�
//������PE���ļ������ַ
//����ֵ:��
void PrasePE(IN void *pFileBuf)
{
	if (!pFileBuf)
	{
		printf("���������Ч\n");
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

//���ܣ�����PE���ڴ�,��FileBuf--->ImageBuf
//������exe�ļ�·��
//����ֵ:�����Ķѵ�ַ
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
	//����PEͷ
	memcpy(pImageBufTmp, pFileBufTmp, IOH.SizeOfHeaders);
	//������
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

//���ܣ��ͷ�����PE��ռ�ݵ��ڴ�
//������exe�ļ�·��
//����ֵ:�����Ķѵ�ַ
void UnReadToImageBuf(IN void *pImageBuf)
{
	if (pImageBuf == NULL)
	{
		printf("�������Ϊ��\n");
	}
	else
	{
		free(pImageBuf);
	}
	return;
}

//���ܣ�������PE���ڴ沢���̣�ImageBuf ----->FileBuf------->���浽Ӳ���ļ�
//������exe�ļ�·��
//����ֵ:�������Ķѵ�ַ
void ReadToFileBuf(IN void *pImageBuf, IN const char *pSavePath)
{
	IMAGE_DOS_HEADER *pIDH = (IMAGE_DOS_HEADER *)pImageBuf;
	IMAGE_NT_HEADERS *pINGS = (IMAGE_NT_HEADERS *)((DWORD)pImageBuf + pIDH->e_lfanew);
	IMAGE_FILE_HEADER IFH = pINGS->FileHeader;
	IMAGE_OPTIONAL_HEADER IOH = pINGS->OptionalHeader;
	IMAGE_SECTION_HEADER *pISH = (IMAGE_SECTION_HEADER *)((DWORD)pImageBuf + pIDH->e_lfanew + sizeof(IMAGE_NT_HEADERS));

	DWORD SectionNumber = IFH.NumberOfSections;
	DWORD dwFileSize = IOH.SizeOfHeaders;

	//������Ҫ�����FileBuf��С;
	IMAGE_SECTION_HEADER *pISHTmp = pISH;

	for (DWORD i = 0; i < SectionNumber; i++)
	{
		dwFileSize += pISHTmp->SizeOfRawData;
		pISHTmp++;
	}
	void *pFileBuf = (void *)malloc(dwFileSize);
	void *pFileBufTmp = pFileBuf, *pImageBufTmp = pImageBuf;
	memset(pFileBuf, 0, dwFileSize);
	//����PEͷ
	memcpy(pFileBufTmp, pImageBufTmp, IOH.SizeOfHeaders);
	//������
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

//���ܣ�RVA��RAW���໥ת��
//������pPEPath:PE�ļ�·����
//        bRVATORAW: TRUE, RVA to RAW
//			         FALSE,RAW to RVA
//����ֵ:ת�����ֵ��Ϊ0��ת��ʧ��

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
	//������Ҫ�����FileBuf��С;
	IMAGE_SECTION_HEADER *pISHTmp = pISH;

	//��dwOffset����˵����PEͷ�У�RVA==RAW
	if (dwOffset < IOH.SizeOfHeaders)
		return dwOffset;
	//����RVA---->RAW
	if (bRVATORAW)
	{
		for (DWORD i = 0; i < dwNumberOfSecs; i++)
		{ //����ȽϹ�ʽ����Ҫ  �ú����Ϊ����SizeOfRawData����������Ǿ���
			if (pISHTmp->VirtualAddress <= dwOffset && dwOffset <= pISHTmp->VirtualAddress + pISHTmp->SizeOfRawData)
			{
				return dwOffset - pISHTmp->VirtualAddress + pISHTmp->PointerToRawData;
			}
			pISHTmp++;
		}
	}
	//����RAW---->RVA
	else
	{
		for (DWORD i = 0; i < dwNumberOfSecs; i++)
		{ //����ȽϹ�ʽ����Ҫ  �ú����Ϊ����ȡpISHTmp->SizeOfRawData   pISHTmp->Misc.VirtualSize�д�ģ���������Ǿ���
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

//���ܣ�RVA��RAW���໥ת��
//������pFileBuf:PE�ļ����ص����ڴ��ַ��
//        bRVATORAW: TRUE, RVA to RAW
//			         FALSE,RAW to RVA
//����ֵ:ת�����ֵ��Ϊ0��ת��ʧ��
//˵����RVATORAW��֮�����ж����ԣ���RVATORAW��ε���ʱ�ٶ����Ժ���
DWORD RVATORAWEx(IN const void *pFileBuf, IN DWORD dwOffset, IN BOOL bRVATORAW)
{
	IMAGE_DOS_HEADER *pIDH = (IMAGE_DOS_HEADER *)pFileBuf;
	IMAGE_NT_HEADERS *pINGS = (IMAGE_NT_HEADERS *)((DWORD)pFileBuf + pIDH->e_lfanew);
	IMAGE_FILE_HEADER IFH = pINGS->FileHeader;
	DWORD dwNumberOfSecs = IFH.NumberOfSections;
	IMAGE_OPTIONAL_HEADER IOH = pINGS->OptionalHeader;
	IMAGE_SECTION_HEADER *pISH = (IMAGE_SECTION_HEADER *)((DWORD)pFileBuf + pIDH->e_lfanew + sizeof(IMAGE_NT_HEADERS));
	//������Ҫ�����FileBuf��С;
	IMAGE_SECTION_HEADER *pISHTmp = pISH;
	//��dwOffset����˵����PEͷ�У�RVA==RAW
	if (dwOffset < IOH.SizeOfHeaders)
		return dwOffset;
	//����RVA---->RAW
	if (bRVATORAW)
	{
		for (DWORD i = 0; i < dwNumberOfSecs; i++)
		{ //����ȽϹ�ʽ����Ҫ  �ú����Ϊ����SizeOfRawData����������Ǿ���
			if (pISHTmp->VirtualAddress <= dwOffset && dwOffset <= pISHTmp->VirtualAddress + pISHTmp->SizeOfRawData)
			{
				return dwOffset - pISHTmp->VirtualAddress + pISHTmp->PointerToRawData;
			}
			pISHTmp++;
		}
	}
	//����RAW---->RVA
	else
	{
		for (DWORD i = 0; i < dwNumberOfSecs; i++)
		{ //����ȽϹ�ʽ����Ҫ  �ú����Ϊ����ȡpISHTmp->SizeOfRawData   pISHTmp->Misc.VirtualSize�д�ģ���������Ǿ���
			if (pISHTmp->PointerToRawData <= dwOffset && dwOffset <= pISHTmp->VirtualAddress + (pISHTmp->SizeOfRawData > pISHTmp->Misc.VirtualSize ? pISHTmp->SizeOfRawData : pISHTmp->Misc.VirtualSize))
			{
				return dwOffset - pISHTmp->PointerToRawData + pISHTmp->VirtualAddress;
			}
			pISHTmp++;
		}
	}
	return NULL;
}

//���ܣ����������ShellCode
//������pShellCode:ָ��ShellCode����
//����ֵ:ָʾ�Ƿ���ӳɹ�

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
	DWORD dwFileSize = IOH.SizeOfHeaders; //��ʼ��ΪPEͷ�Ĵ�С
										  //������Ҫ�����FileBuf��С;
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
	//��ȡ����ڵ�����
	DWORD Characteristics = pISH->Characteristics;
	pISH += SecIndex - 1;
	//�޸���Ӵ���Ķ� ������
	pISH->Characteristics |= Characteristics;
	//���Ҫע�⣬��Ϊ�����յĴ�������Ҫ���浽Ӳ���ļ��ϣ����Ա���Ҫʹ��SizeOfRawData����VirtualSize
	if (pISH->SizeOfRawData < pISH->Misc.VirtualSize + dwShellCodeSize)
	{ //����д��pISH->SizeOfRawData - pISH->Misc.VirtualSize < dwShellCodeSize,��Ϊ
		// DWORD - DWORD ����˻��ǰ���DWORD�����ǣ���SizeOfRawData<VirtualSize�ͱ�����
		printf("û���㹻�Ŀռ�������ShellCode �������\n");
		return FALSE;
	}
	void *pAddAddress = (void *)((DWORD)pImageBuf + pISH->VirtualAddress + pISH->Misc.VirtualSize);
	memcpy(pAddAddress, pShellCode, dwShellCodeSize);
	//���е�ַ������ע�����û��д��ͨ�õģ���ߵ�����ֻ�����ڵ�ǰ��ShellCode�����Ժ���ʱ��д��������
	HMODULE hMod = LoadLibrary(TEXT("User32.dll"));
	*(DWORD *)((BYTE *)pAddAddress + 9) = (DWORD)GetProcAddress(hMod, "MessageBoxA") - ((DWORD)ImageBase + pISH->VirtualAddress + pISH->Misc.VirtualSize + 8) - 5;
	*(DWORD *)((BYTE *)pAddAddress + 14) = ImageBase + AddressOfEntryPoint - ((DWORD)ImageBase + pISH->VirtualAddress + pISH->Misc.VirtualSize + 13) - 5;
	pINGS->OptionalHeader.AddressOfEntryPoint = pISH->VirtualAddress + pISH->Misc.VirtualSize;
	FreeLibrary(hMod);
	ReadToFileBuf(pImageBuf, pOutPath);
	UnReadToImageBuf(pImageBuf);
	return TRUE;
}

//���ܣ�����һ����
//������pPEPath:EXE�ļ�
//      pSecName:��������
//      dwRawDataSize:�����ڵ�ԭʼ���ݴ�С
//      pDataBuf:�����ڼ��������,����ΪNULL�������ʹ��Ĭ�ϵ�����0���
//      pOutPath:�µ�EXE�����·��
//����ֵ:ָʾ�Ƿ���ӳɹ�

BOOL AddSection(IN const char *pPEPath, IN const char *pSecName, DWORD dwRawDataSize /*����û�н����κζ���Ĵ�С*/, IN void *pDataBuf, IN const char *pOutPath)
{ //��ȡԭEXE�ļ����ڴ�
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
	{ //˵��IMAGE_SECTION_HEADER�����Ժ����������ݣ���������£�������ҪŲ��PEͷ
		memcpy((void *)((DWORD)pFileBuf + sizeof(IMAGE_DOS_HEADER)), (void *)((DWORD)pFileBuf + pIDH->e_lfanew), sizeof(IMAGE_NT_HEADERS) + dwNumOfSecs * sizeof(IMAGE_SECTION_HEADER));
		pIDH->e_lfanew = sizeof(IMAGE_DOS_HEADER);
		pINGS = (IMAGE_NT_HEADERS *)((DWORD)pFileBuf + pIDH->e_lfanew);
		pISH = (IMAGE_SECTION_HEADER *)((DWORD)pFileBuf + pIDH->e_lfanew + sizeof(IMAGE_NT_HEADERS));
	}
	DWORD dwSizeofImage = pINGS->OptionalHeader.SizeOfImage;
	DWORD dwFileAlign = pINGS->OptionalHeader.FileAlignment;
	DWORD dwSecAlign = pINGS->OptionalHeader.SectionAlignment;
	pINGS->FileHeader.NumberOfSections++;
	//��߼���VirtualSize <= SizeOfRawData,��������ĸ���99.99%
	pINGS->OptionalHeader.SizeOfImage += (dwRawDataSize + dwSecAlign - 1) / dwSecAlign * dwSecAlign;

	pISH += dwNumOfSecs;
	//����IMAGE_SECTION_HEADER
	IMAGE_SECTION_HEADER ISH = {0};
	char pNameBuf[9] = {0};
	memcpy(pNameBuf, pSecName, 8);
	memcpy(ISH.Name, pNameBuf, 8);
	ISH.Misc.VirtualSize = dwRawDataSize; //�����д��,�������ֵҲû�����
	ISH.VirtualAddress = dwSizeofImage;
	ISH.SizeOfRawData = (dwRawDataSize + dwFileAlign - 1) / dwFileAlign * dwFileAlign;
	ISH.PointerToRawData = dwSizeOfFile;
	ISH.Characteristics = pISH->Characteristics | 0x60000020 | 0xC0000040; //����ȡ����ں����ݽڵ����ԣ��������ǲ���  ����
	memcpy((void *)pISH, &ISH, sizeof(ISH));
	//��ԭexe�ļ���ӽ�����
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

//���ܣ��������һ����
//������pPEPath:EXE�ļ�
//      dwRawDataSize:�����ڵ�ԭʼ���ݴ�С
//      pOutPath:�µ�EXE�����·��
//����ֵ:ָʾ�Ƿ�����ɹ�

BOOL ExtendLastSec(IN const char *pPEPath, DWORD dwRawDataSize /*����֮��û�н����κζ���Ĵ�С*/, IN const char *pOutPath)
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
	//�������һ���ڵ�IMAGE_SECTION_HEADER
	if (dwRawDataSize < pISH->SizeOfRawData)
	{
		printf("dwRawDataSizeС��ԭʼ��С���������趨��ֵ!\n");
		free(pFileBuf);
		return FALSE;
	}
	pINGS->OptionalHeader.SizeOfImage += (dwRawDataSize + dwFileAlign - 1) / dwFileAlign * dwFileAlign - pISH->SizeOfRawData;
	pISH->SizeOfRawData = (dwRawDataSize + dwFileAlign - 1) / dwFileAlign * dwFileAlign;
	pISH->Characteristics |= 0x60000020 | 0xC0000040; //����ȡ����ں����ݽڵ����ԣ��������ǲ���  ����
	pISH->Misc.VirtualSize = 0;
	//��ԭexe�ļ���ӽ�����
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

//���ܣ��ϲ����н�
//������pPEPath:EXE�ļ�
//      pOutPath:�µ�EXE�����·��
//����ֵ:ָʾ�Ƿ���ӳɹ�

//�����ﲻ�����⴦���ˣ�ֱ�Ӻϲ������н�
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
	pISH->Characteristics |= 0x60000020 | 0xC0000040 | 0x40000040; //����ȡ����ں����ݽڵ����ԣ��������ǲ���  ����
	pISH->SizeOfRawData = dwSizeOfImage - pISH->VirtualAddress;
	//����pISH->Misc.VirtualSize = dwSizeOfImage - pISH->VirtualAddress;//���ҵıʼǣ����Ŀ�ν��ľ���֣����գ�
	pISH->Misc.VirtualSize = 0; //������ѡһ�ּ��ɣ���д�϶�����

	memset(++pISH, 0, sizeof(IMAGE_SECTION_HEADER));
	ReadToFileBuf(pImageBuf, pOutPath);
	UnReadToImageBuf(pImageBuf);
	return TRUE;
}

//���ܣ���ӡ������������б����Ϣ
//������pPEPath:EXE�ļ�
//����ֵ:ָʾ�Ƿ��ȡ�ɹ�

//˵��������ʹ��RVATORAWEx���Լӿ����ٶ�

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
		printf("���ļ�û�е�����\n");
		UnReadPE(pFileBuf);
		return TRUE;
	}
	DWORD RawAddress = RVATORAWEx(pFileBuf, RvaAddress, TRUE);
	IMAGE_EXPORT_DIRECTORY *pIED = (IMAGE_EXPORT_DIRECTORY *)((DWORD)pFileBuf + RawAddress);
	DWORD NameRawAdd = (DWORD)pFileBuf + RVATORAWEx(pFileBuf, pIED->Name, TRUE);
	//��ӡ������ı�ͷ��Ϣ
	printf("Characteristics:%u\n", pIED->Characteristics);
	printf("---------------------������ͷ��Ϣ------------------\n");
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

	//��ӡAddressOfFuncations��
	DWORD *pAddOfFun_Raw = (DWORD *)((DWORD)pFileBuf + RVATORAW(pPEPath, pIED->AddressOfFunctions, TRUE));
	DWORD *pAddOfNames_Raw = (DWORD *)((DWORD)pFileBuf + RVATORAW(pPEPath, pIED->AddressOfNames, TRUE));
	WORD *pAddOfOrd_Raw = (WORD *)((DWORD)pFileBuf + RVATORAW(pPEPath, pIED->AddressOfNameOrdinals, TRUE));
	printf("%X %X %X\n", *pAddOfFun_Raw, *pAddOfNames_Raw, *pAddOfOrd_Raw);
	BOOL bOrdNameFun = FALSE; //�����ж��ǲ���AddressOfFunctions���е�����AddressOfNameOrdinals����
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

//���ܣ���ӡ������������б����Ϣ
//������pPEPath:EXE�ļ�
//����ֵ:ָʾ�Ƿ��ȡ�ɹ�

//˵��������ʹ��RVATORAWEx���Լӿ����ٶ�

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
		printf("���ļ�û���ض�λ��\n");
		UnReadPE(pFileBuf);
		return TRUE;
	}
	DWORD RawAddress = RVATORAWEx(pFileBuf, RvaAddress, TRUE);
	IMAGE_BASE_RELOCATION *pIRD = (IMAGE_BASE_RELOCATION *)((DWORD)pFileBuf + RawAddress);
	DWORD dwCnt = 1;
	WORD *pRelocItem = NULL;
	while (pIRD->SizeOfBlock && pIRD->VirtualAddress)
	{

		printf("\n------------�� %u ���ض�λ��-------------\n", dwCnt);
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

//���ܣ���ӡ�����������б����Ϣ
//������pPEPath:EXE�ļ�
//����ֵ:ָʾ�Ƿ��ȡ�ɹ�

//˵��������ʹ��RVATORAWEx���Լӿ����ٶ�

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
		printf("���ļ�û�е���\n");
		UnReadPE(pFileBuf);
		return TRUE;
	}
	DWORD RawAddress = RVATORAWEx(pFileBuf, RvaAddress, TRUE);
	IMAGE_IMPORT_DESCRIPTOR *pIID = (IMAGE_IMPORT_DESCRIPTOR *)((DWORD)pFileBuf + RawAddress);
	DWORD dwNumOfImport = 1;

	while (pIID->Name != NULL)
	{
		//��ӡ�����ı�ͷ��Ϣ
		DWORD OriginalFirstThunk_Raw = (DWORD)pFileBuf + RVATORAWEx(pFileBuf, pIID->OriginalFirstThunk, TRUE);
		DWORD FirstThunk_Raw = (DWORD)pFileBuf + RVATORAWEx(pFileBuf, pIID->FirstThunk, TRUE);
		DWORD Name_Raw = (DWORD)pFileBuf + RVATORAWEx(pFileBuf, pIID->Name, TRUE);
		printf("---------------------%u# �����ͷ��Ϣ------------------\n", dwNumOfImport++);
		printf("OriginalFirstThunk:%u\n", pIID->OriginalFirstThunk);
		printf("TimeDateStamp:%u\n", pIID->TimeDateStamp);
		printf("ForwarderChain:%u\n", pIID->ForwarderChain);
		printf("Name:%s\n", Name_Raw);
		printf("FirstThunk:%u\n", pIID->FirstThunk);

		//����INT��
		printf("--------------------------INT��----------------------------\n");
		DWORD *pThunkData = (DWORD *)OriginalFirstThunk_Raw;
		while (*pThunkData)
		{
			if ((*pThunkData) & 0x80000000)
			{
				printf("����ŵ��룬Ord:%X\n", (*pThunkData) & 0x7fffffff);
			}
			else
			{
				IMAGE_IMPORT_BY_NAME *pIIBN = (IMAGE_IMPORT_BY_NAME *)((DWORD)pFileBuf + RVATORAWEx(pFileBuf, *pThunkData, TRUE));
				printf("%Hint:%X\tName:%s\n", pIIBN->Hint, pIIBN->Name);
			}
			pThunkData++;
		}
		//����IAT��
		printf("--------------------------IAT��----------------------------\n");
		pThunkData = (DWORD *)FirstThunk_Raw;
		if (pIID->TimeDateStamp == 0xffffffff)
		{
			printf("�õ����ʹ���˰󶨵����IAT�����ǵ�ַ��\n");
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
					printf("����ŵ��룬Ord:%X\n", (*pThunkData) & 0x7fffffff);
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

//���ܣ��ƶ�������
//������pPEPath:EXE�ļ�
// 		pSecName:�����ڵ�����
// 		pOutPath:�ƶ�����ļ������·��
//����ֵ:ָʾ�Ƿ��ƶ��ɹ�

//˵����Ϊ������޶ȵļ��ٶ��������ݵĸ��ţ����Լ�����һ��������ŵ�����
BOOL MoveExportTable(IN const char *pPEPath, IN const char *pSecName, IN const char *pOutPath)
{
	DWORD dwSizeOfFile = 0;
	void *pFileBuf = ReadPE(pPEPath, &dwSizeOfFile);
	if (pFileBuf == NULL)
		return FALSE;
	//���任��NewFileBufʱ�������Ƶ�ַ��ָ�����Ҫ����
	IMAGE_DOS_HEADER *pIDH = (IMAGE_DOS_HEADER *)pFileBuf;
	IMAGE_NT_HEADERS *pINGS = (IMAGE_NT_HEADERS *)((DWORD)pFileBuf + pIDH->e_lfanew);

	IMAGE_OPTIONAL_HEADER IOH = pINGS->OptionalHeader;
	DWORD dwSize = IOH.DataDirectory[0].Size;
	DWORD RvaAddress = IOH.DataDirectory[0].VirtualAddress;
	DWORD dwFileAlign = pINGS->OptionalHeader.FileAlignment;
	DWORD dwSecAlign = pINGS->OptionalHeader.SectionAlignment;
	if (dwSize == 0 || RvaAddress == 0)
	{
		printf("���ļ�û�е�����\n");
		UnReadPE(pFileBuf);
		return TRUE;
	}
	//���任��NewFileBufʱ�������Ƶ�ַ��ָ�����Ҫ����
	DWORD RawAddress = RVATORAWEx(pFileBuf, RvaAddress, TRUE);
	IMAGE_EXPORT_DIRECTORY *pIED = (IMAGE_EXPORT_DIRECTORY *)((DWORD)pFileBuf + RawAddress);
	DWORD NameRawAdd = (DWORD)pFileBuf + RVATORAWEx(pFileBuf, pIED->Name, TRUE);
	DWORD *pAddOfFun_Raw = (DWORD *)((DWORD)pFileBuf + RVATORAWEx(pFileBuf, pIED->AddressOfFunctions, TRUE));
	WORD *pAddOfOrd_Raw = (WORD *)((DWORD)pFileBuf + RVATORAWEx(pFileBuf, pIED->AddressOfNameOrdinals, TRUE));
	DWORD *pAddOfNames_Raw = (DWORD *)((DWORD)pFileBuf + RVATORAWEx(pFileBuf, pIED->AddressOfNames, TRUE));

	//������Ҫ�Ĵ洢�ռ�
	DWORD dwSizeOfDllName = strlen((const char *)NameRawAdd) + 1;
	DWORD dwSizeOfFunAdd = sizeof(DWORD) * pIED->NumberOfFunctions;
	DWORD dwSizeOfOrd = sizeof(WORD) * pIED->NumberOfNames;
	DWORD dwSizeOfName = 0;
	for (DWORD i = 0; i < pIED->NumberOfNames; i++)
	{
		DWORD NameAdd = RVATORAWEx(pFileBuf, pAddOfNames_Raw[i], TRUE);
		dwSizeOfName += strlen((const char *)((DWORD)pFileBuf + NameAdd)) + 1;
	}
	//�ƶ���������������Ҫ�Ŀռ��ܺ�
	DWORD dwSumSize = sizeof(IMAGE_EXPORT_DIRECTORY) + dwSizeOfDllName + dwSizeOfFunAdd + dwSizeOfOrd + dwSizeOfName;

	//�����µ�FileBuf�����FileBuf�����ϵ�����Ĵ�С��,����������ǳ���ķ���
	void *pNewFileBuf = malloc(dwSizeOfFile + (dwSumSize + dwFileAlign - 1) / dwFileAlign * dwFileAlign);
	memset(pNewFileBuf, 0, dwSizeOfFile + (dwSumSize + dwFileAlign - 1) / dwFileAlign * dwFileAlign);
	memcpy(pNewFileBuf, pFileBuf, dwSizeOfFile);
	UnReadPE(pFileBuf);
	pFileBuf = NULL;

	//������ر���,��Ϊ�洢�ռ����ˣ������漰����ַ�ĵط���Ҫ��
	pIDH = (IMAGE_DOS_HEADER *)pNewFileBuf;
	pINGS = (IMAGE_NT_HEADERS *)((DWORD)pNewFileBuf + pIDH->e_lfanew);
	pIED = (IMAGE_EXPORT_DIRECTORY *)((DWORD)pNewFileBuf + RawAddress);
	NameRawAdd = (DWORD)pNewFileBuf + RVATORAWEx(pNewFileBuf, pIED->Name, TRUE);
	pAddOfFun_Raw = (DWORD *)((DWORD)pNewFileBuf + RVATORAWEx(pNewFileBuf, pIED->AddressOfFunctions, TRUE));
	pAddOfOrd_Raw = (WORD *)((DWORD)pNewFileBuf + RVATORAWEx(pNewFileBuf, pIED->AddressOfNameOrdinals, TRUE));
	pAddOfNames_Raw = (DWORD *)((DWORD)pNewFileBuf + RVATORAWEx(pNewFileBuf, pIED->AddressOfNames, TRUE));

	//���������ڵ��������
	IMAGE_SECTION_HEADER *pISH = (IMAGE_SECTION_HEADER *)((DWORD)pNewFileBuf + pIDH->e_lfanew + sizeof(IMAGE_NT_HEADERS));
	DWORD dwNumOfSecs = pINGS->FileHeader.NumberOfSections;
	if (memcmp(pISH + dwNumOfSecs, pISH + dwNumOfSecs + 1, sizeof(IMAGE_SECTION_HEADER)) != 0)
	{ //˵��IMAGE_SECTION_HEADER�����Ժ����������ݣ���������£�������ҪŲ��PEͷ
		memcpy((void *)((DWORD)pNewFileBuf + sizeof(IMAGE_DOS_HEADER)), (void *)((DWORD)pNewFileBuf + pIDH->e_lfanew), sizeof(IMAGE_NT_HEADERS) + dwNumOfSecs * sizeof(IMAGE_SECTION_HEADER));
		pIDH->e_lfanew = sizeof(IMAGE_DOS_HEADER);
		pINGS = (IMAGE_NT_HEADERS *)((DWORD)pNewFileBuf + pIDH->e_lfanew);
		pISH = (IMAGE_SECTION_HEADER *)((DWORD)pNewFileBuf + pIDH->e_lfanew + sizeof(IMAGE_NT_HEADERS));
	}
	DWORD dwSizeofImage = pINGS->OptionalHeader.SizeOfImage;
	pINGS->FileHeader.NumberOfSections++;
	//��߼���VirtualSize <= SizeOfRawData,��������ĸ���99.99%
	pINGS->OptionalHeader.SizeOfImage += (dwSumSize + dwSecAlign - 1) / dwSecAlign * dwSecAlign;
	pISH += dwNumOfSecs;
	//����IMAGE_SECTION_HEADER
	IMAGE_SECTION_HEADER ISH = {0};
	char pNameBuf[9] = {0};
	memcpy(pNameBuf, pSecName, 8);
	memcpy(ISH.Name, pNameBuf, 8);
	ISH.Misc.VirtualSize = 0; //�����д��,�������ֵҲû�����
	ISH.VirtualAddress = dwSizeofImage;
	ISH.SizeOfRawData = (dwSumSize + dwFileAlign - 1) / dwFileAlign * dwFileAlign;
	ISH.PointerToRawData = dwSizeOfFile;
	ISH.Characteristics = pISH->Characteristics | 0x60000020 | 0xC0000040; //����ȡ����ں����ݽڵ����ԣ��������ǲ���  ����
	memcpy((void *)pISH, &ISH, sizeof(ISH));

	//��������������ݵ��½����
	void *pExportTableBuf = (void *)((DWORD)pNewFileBuf + dwSizeOfFile);
	IMAGE_EXPORT_DIRECTORY *pExportTableBuf_Beg = (IMAGE_EXPORT_DIRECTORY *)pExportTableBuf;

	//����ͷ
	memcpy(pExportTableBuf, pIED, sizeof(IMAGE_EXPORT_DIRECTORY));
	pExportTableBuf = (void *)((DWORD)pExportTableBuf + sizeof(IMAGE_EXPORT_DIRECTORY));
	//����FunctionAddress
	memcpy(pExportTableBuf, pAddOfFun_Raw, dwSizeOfFunAdd);
	pExportTableBuf = (void *)((DWORD)pExportTableBuf + dwSizeOfFunAdd);
	pExportTableBuf_Beg->AddressOfFunctions = RVATORAWEx(pNewFileBuf, (DWORD)pExportTableBuf - (DWORD)pNewFileBuf, FALSE);
	//����OrdNames
	memcpy(pExportTableBuf, pAddOfOrd_Raw, dwSizeOfOrd);
	pExportTableBuf = (void *)((DWORD)pExportTableBuf + dwSizeOfOrd);
	pExportTableBuf_Beg->AddressOfNameOrdinals = RVATORAWEx(pNewFileBuf, (DWORD)pExportTableBuf - (DWORD)pNewFileBuf, FALSE);
	//����Names
	for (DWORD j = 0; j < pIED->NumberOfNames; j++)
	{
		DWORD NameAdd = (DWORD)pNewFileBuf + RVATORAWEx(pNewFileBuf, pAddOfNames_Raw[j], TRUE);
		DWORD NameLen = strlen((const char *)NameAdd) + 1;
		memcpy(pExportTableBuf, (const char *)NameAdd, NameLen);
		pAddOfNames_Raw[j] = RVATORAWEx(pNewFileBuf, (DWORD)pExportTableBuf - (DWORD)pNewFileBuf, FALSE);
		pExportTableBuf = (void *)((DWORD)pExportTableBuf + NameLen);
	}
	//����DllName
	memcpy(pExportTableBuf, (const char *)NameRawAdd, dwSizeOfDllName);
	pExportTableBuf_Beg->Name = RVATORAWEx(pNewFileBuf, (DWORD)pExportTableBuf - (DWORD)pNewFileBuf, FALSE);

	//����Ŀ¼��
	pINGS->OptionalHeader.DataDirectory[0].VirtualAddress = dwSizeofImage; //ԭʼӳ���ļ���С

	FILE *fp = fopen(pOutPath, "wb");
	fwrite(pNewFileBuf, dwSizeOfFile + (dwSumSize + dwFileAlign - 1) / dwFileAlign * dwFileAlign, 1, fp);
	fclose(fp);
	free(pNewFileBuf);
	return TRUE;
}
