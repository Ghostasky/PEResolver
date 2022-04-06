// ����Ϊ GBK
#include <stdio.h>
#include <windows.h>
#include <stdlib.h>
#include <iostream>

#define PE_PATH "1.exe"
using namespace std;
//////////////////////////////////////////////////////////

void *ReadPEToMemory(IN const char *pPEPath, OUT DWORD *SizeOfPE);
void UnReadPEToMemory(IN void *pFileBuf);
void PrintPEInfomatiaon(IN void *pFileBuf);
void *ReadFileBufToImageBuf(IN const char *pPEPath);
void UnReadFileBufToImageBuf(IN void *pImageBuf);
void DumpImageBufToDisk(IN void *pImageBuf, IN const char *outName);
DWORD RVATORAW(IN const char *pPEPath, DWORD offset, IN BOOL RVA2RAW);
DWORD RVATORAWEx(IN const void *pFileBuf, IN DWORD dwOffset, IN BOOL bRVATORAW);
BOOL AddShellCode(IN const char *pPEPath, IN BYTE *pShellCode, IN int SectionIndex, IN const char *outName);
BOOL PrintExportTable(IN const char *pPEPath);
BOOL PrintImportTable(IN const char *pPEPath);
BOOL PrintRelocateTable(IN const char *pPEPath);
//////////////////////////////////////////////////////////
int main()
{
    // 1.PE -> FileBuf, ��ӡ�����Ϣ
    // void *pFileBuf = ReadPEToMemory(PE_PATH, NULL);
    // PrintPEInfomatiaon(pFileBuf);
    // UnReadPEToMemory(pFileBuf);

    // 2.��չ FileBuf -> ImageBuf
    // void *pImageBuf = ReadFileBufToImageBuf(PE_PATH);
    // UnReadFileBufToImageBuf(pImageBuf);

    // 3. ImageBuf -> Ӳ�� ����ִ��
    // void *pImageBuf = ReadFileBufToImageBuf(PE_PATH);
    // DumpImageBufToDisk(pImageBuf, "3.exe");
    // UnReadFileBufToImageBuf(pImageBuf);

    // 4.RVA -> RAW(FOA)
    // DWORD a = RVATORAW(PE_PATH, 0xA0E1, true);
    // printf("RAW:%p\n", a);

    // 5.��ָ���������Shellcode(����)��δ��ɣ�
    // 6.��ӽڣ�δ��ɣ�

    // 7. ��ӡ������
    // PrintExportTable("kernel32.dll");

    // 8.��ӡ�ض�λ

    // 9. ��ӡ�����
    // PrintImportTable("kernel32.dll");

    // 10.�ƶ�������
    return 0;
}

//���ܣ�����PE�ļ����ڴ�
//������pPEPath:�ļ�·��
//����ֵ:�ļ�����
void *ReadPEToMemory(const char *pPEPath, OUT DWORD *SizeOfPE)
{
    FILE *fp = fopen(pPEPath, "rb");
    if (fp == NULL)
    {
        cout << "ReadPeToMemory:����Ϊ��" << endl;
        return NULL;
    }
    fseek(fp, 0, SEEK_END);
    DWORD dwSizeOfFile = ftell(fp);

    if (SizeOfPE)
        *SizeOfPE = dwSizeOfFile;

    fseek(fp, 0, SEEK_SET);
    void *pFileBuf = (void *)malloc(dwSizeOfFile);
    fread(pFileBuf, dwSizeOfFile, 1, fp);

    fclose(fp);
    return pFileBuf;
}

//���ܣ��ͷ�PE������Ķѿռ�
//������pFileBuf
//����ֵ:��
void UnReadPEToMemory(IN void *pFileBuf)
{
    if (pFileBuf == NULL)
        cout << "FreePEFromMemory:����Ϊ��" << endl;
    else
        free(pFileBuf);
}

//���ܣ�����PE�ļ�
//������PE���ļ������ַ
//����ֵ:��
void PrintPEInfomatiaon(IN void *pFileBuf)
{
    if (!pFileBuf)
    {
        cout << "PrintPEInfomatiaon:����Ϊ��" << endl;
        return;
    }
    IMAGE_DOS_HEADER *pIDH = (IMAGE_DOS_HEADER *)pFileBuf;
    cout << "\n--------------IMAGE_DOS_HEADER--------------" << endl;
    printf("magic:0x%X\nlfanew:0x%X(NTͷ��ƫ��)\n", pIDH->e_magic, pIDH->e_lfanew);

    IMAGE_NT_HEADERS *pINH = (IMAGE_NT_HEADERS *)((DWORD)pIDH + pIDH->e_lfanew);
    cout << "\n--------------IMAGE_NT_HEADER--------------" << endl;
    printf("Signature(4550:PE):0x%X\n", pINH->Signature);

    IMAGE_FILE_HEADER IFH = pINH->FileHeader;
    cout << "\n--------------IMAGE_FILE_HEADER--------------" << endl;
    printf("NumberOfSections:%d(��������)\n", IFH.NumberOfSections);
    printf("SizeOfOptionalHeader:%d(IMAGE_OPTIONAL_HEADER��С)\n", IFH.SizeOfOptionalHeader);

    IMAGE_OPTIONAL_HEADER IOH = pINH->OptionalHeader;
    cout << "\n--------------IMAGE_OPTIONAL_HEADER--------------" << endl;
    printf("Magic:0x%X\n", IOH.Magic);
    printf("SizeOfCode:0x%X(�����(.test)��С���ж���Ļ����ܺ�)\n");
    printf("SizeOfInitializedData:0x%X(�ѳ�ʼ�����ݽڵĴ�С���ж���Ļ����ܺ�)\n", IOH.SizeOfInitializedData);
    printf("SizeOfUninitializedData:0x%X(δ��ʼ�����ݽڵĴ�С���ж���Ļ����ܺ�)\n", IOH.SizeOfUninitializedData);
    printf("AddressOfEntryPoint:0x%X(EntryPoint,RVA)\n", IOH.AddressOfEntryPoint);
    printf("BaseOfCode:0x%X(�ڴ��д���ڵĿ�ͷ�����ӳ���ַImageBase��ƫ�Ƶ�ַ)\n", IOH.BaseOfCode);
    printf("ImageBase:0x%X(�����ڴ�ʱ����װ�صĵ�ַ)\n", IOH.ImageBase);
    printf("SectionAlignment:0x%X(�������ڴ��е���С��λ)\n", IOH.SectionAlignment);
    printf("FileAlignment:0x%X(�����ڴ����ļ��е���С��λ)\n", IOH.FileAlignment);
    printf("SizeOfImage:0x%X(ָ����PE Image�������ڴ�����ռ�ռ�Ĵ�С)\n", IOH.SizeOfImage);
    printf("SizeOfHeaders:0x%X(����PEͷ�Ĵ�С)\n", IOH.SizeOfHeaders);
    printf("NumberOfRvaAndSizes:0x%X(DataDirectory����)\n", IOH.NumberOfRvaAndSizes);

    IMAGE_SECTION_HEADER *pISH = (IMAGE_SECTION_HEADER *)((DWORD)pFileBuf + pIDH->e_lfanew + sizeof(IMAGE_NT_HEADERS));
    printf("\n--------------IMAGE_SECTION_HEADER--------------\n");
    for (int i = 0; i < IFH.NumberOfSections; i++)
    {
        printf("++++++++++++++++++++++%u Section++++++++++++++++++++++++++\n", i + 1);
        printf("Section name: %s\n", pISH->Name);
        printf("VirtualSize:0x%X(�����ڴ�ʱ�˽����Ĵ�С)\n", pISH->Misc.VirtualSize);
        printf("VirtualAddress:0x%X(�ڴ��н�����ʼ��ַ(RVA))\n", pISH->VirtualAddress);
        printf("SizeOfRawData:0x%X(�����н�����ռ��С)\n", pISH->SizeOfRawData);
        printf("PointerToRawData:0x%X(�����б��ڶ����ļ�ͷ�ľ���)\n", pISH->PointerToRawData);
        pISH++;
    }
}

//���ܣ�����PE���ڴ�,��FileBuf--->ImageBuf
//������exe�ļ�·��
//����ֵ:�����Ķѵ�ַ
void *ReadFileBufToImageBuf(IN const char *pPEPath)
{
    void *pFileBuf = ReadPEToMemory(PE_PATH, NULL);
    void *pImageBuf;
    if (pFileBuf == NULL)
        return NULL;
    IMAGE_DOS_HEADER *pIDH = (IMAGE_DOS_HEADER *)pFileBuf;
    IMAGE_NT_HEADERS *pINH = (IMAGE_NT_HEADERS *)((DWORD)pIDH + pIDH->e_lfanew);
    IMAGE_FILE_HEADER IFH = pINH->FileHeader;
    IMAGE_OPTIONAL_HEADER IOH = pINH->OptionalHeader;
    IMAGE_SECTION_HEADER *pISH = (IMAGE_SECTION_HEADER *)((DWORD)pFileBuf + pIDH->e_lfanew + sizeof(IMAGE_NT_HEADERS));
    DWORD SectionNumber = IFH.NumberOfSections;
    pImageBuf = (void *)malloc(IOH.SizeOfImage);
    memset(pImageBuf, 0, IOH.SizeOfImage);
    DWORD SectionAlignment = IOH.SectionAlignment;
    DWORD FileAlignment = IOH.FileAlignment;

    void *pFileBufTmp = pFileBuf;
    void *pImageBufTmp = pImageBuf;
    // copy PEͷ
    memcpy(pImageBufTmp, pFileBuf, IOH.SizeOfHeaders);

    // copy ����
    for (int i = 0; i < SectionNumber; i++)
    {
        pFileBufTmp = (void *)((DWORD)pFileBuf + pISH->PointerToRawData);
        pImageBufTmp = (void *)((DWORD)pImageBuf + pISH->VirtualAddress);
        memcpy(pImageBufTmp, pFileBufTmp, pISH->SizeOfRawData);
        pISH++;
    }
    UnReadPEToMemory(pFileBuf);
    return pImageBuf;
}
//���ܣ��ͷ�����PE��ռ�ݵ��ڴ�(pImageBuf)
//������pImageBuf
//����ֵ:��
void UnReadFileBufToImageBuf(IN void *pImageBuf)
{
    if (!pImageBuf)
        printf("UnReadFileBufToImageBuf:����Ϊ��");
    else
        free(pImageBuf);
}
//���ܣ���ImageBuf Dump ������
//������pImageBuf��Dump����
//����ֵ:��
void DumpImageBufToDisk(IN void *pImageBuf, IN const char *outName)
{

    IMAGE_DOS_HEADER *pIDH = (IMAGE_DOS_HEADER *)pImageBuf;
    IMAGE_NT_HEADERS *pINH = (IMAGE_NT_HEADERS *)((DWORD)pIDH + pIDH->e_lfanew);
    IMAGE_FILE_HEADER IFH = pINH->FileHeader;
    IMAGE_OPTIONAL_HEADER IOH = pINH->OptionalHeader;
    IMAGE_SECTION_HEADER *pISH = (IMAGE_SECTION_HEADER *)((DWORD)pImageBuf + pIDH->e_lfanew + sizeof(IMAGE_NT_HEADERS));

    DWORD SectionNumber = IFH.NumberOfSections;
    IMAGE_SECTION_HEADER *pISHTmp = pISH;
    DWORD FileSize = IOH.SizeOfHeaders; //ͷ + ������������������

    for (int i = 0; i < SectionNumber; i++)
    {
        FileSize += pISHTmp->SizeOfRawData;
        pISHTmp++;
    }

    void *pFileBuf = (void *)malloc(FileSize);
    void *pFileBufTmp = pFileBuf;
    void *pImageBufTmp = pImageBuf;

    memset(pFileBuf, 0, FileSize);
    memcpy(pFileBufTmp, pImageBufTmp, IOH.SizeOfHeaders);

    for (int i = 0; i < SectionNumber; i++)
    {
        pFileBufTmp = (void *)((DWORD)pFileBuf + pISH->PointerToRawData);
        pImageBufTmp = (void *)((DWORD)pImageBuf + pISH->VirtualAddress);
        memcpy(pFileBufTmp, pImageBufTmp, pISH->SizeOfRawData);
        pISH++;
    }
    FILE *fp = fopen(outName, "wb");
    fwrite(pFileBuf, FileSize, 1, fp);
    fclose(fp);
    free(pFileBuf);
    return;
}
//���ܣ�RVA��RAW���໥ת��
//������pPEPath:PE�ļ�·����
//        bRVATORAW: TRUE, RVA to RAW
//			         FALSE,RAW to RVA
//����ֵ:ת�����ֵ��Ϊ0��ת��ʧ��
DWORD RVATORAW(IN const char *pPEPath, DWORD offset, IN BOOL RVA2RAW)
{
    void *pFileBuf = ReadPEToMemory(pPEPath, NULL);
    if (pFileBuf == NULL)
    {
        printf("RVATORAW:�ļ�����\n");
        return 0;
    }
    IMAGE_DOS_HEADER *pIDH = (IMAGE_DOS_HEADER *)pFileBuf;
    IMAGE_NT_HEADERS *pINH = (IMAGE_NT_HEADERS *)((DWORD)pIDH + pIDH->e_lfanew);
    IMAGE_FILE_HEADER IFH = pINH->FileHeader;
    IMAGE_OPTIONAL_HEADER IOH = pINH->OptionalHeader;
    IMAGE_SECTION_HEADER *pISH = (IMAGE_SECTION_HEADER *)((DWORD)pFileBuf + pIDH->e_lfanew + sizeof(IMAGE_NT_HEADERS));
    DWORD SectionNumber = IFH.NumberOfSections;

    IMAGE_SECTION_HEADER *pISHTmp = pISH;
    // ������������offsetС��PEͷ����RVA==FOA
    if (offset == IOH.SizeOfHeaders)
        return offset;
    // RVA --> FOA
    if (RVA2RAW)
    {
        for (int i = 0; i < SectionNumber; i++)
        {
            if (pISHTmp->VirtualAddress <= offset && offset <= pISHTmp->VirtualAddress + pISHTmp->SizeOfRawData)
                return offset - pISHTmp->VirtualAddress + pISHTmp->PointerToRawData;
            pISHTmp++;
        }
    }
    else // FOA -> RVA
    {

        for (DWORD i = 0; i < SectionNumber; i++)
        {
            if (pISHTmp->VirtualAddress <= offset && offset <= pISHTmp->VirtualAddress + pISHTmp->SizeOfRawData)
                return offset + pISHTmp->VirtualAddress - pISHTmp->PointerToRawData;
            pISHTmp++;
        }
    }
    UnReadPEToMemory(pFileBuf);
    return offset;
}
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
BOOL AddShellCode(IN const char *pPEPath, IN BYTE *pShellCode, IN int SectionIndex, IN const char *outName)
{
    void *pImageBuf = ReadFileBufToImageBuf(pPEPath);
    if (!pImageBuf)
        return FALSE;

    IMAGE_DOS_HEADER *pIDH = (IMAGE_DOS_HEADER *)pImageBuf;
    IMAGE_NT_HEADERS *pINH = (IMAGE_NT_HEADERS *)((DWORD)pIDH + pIDH->e_lfanew);
    IMAGE_FILE_HEADER IFH = pINH->FileHeader;
    IMAGE_OPTIONAL_HEADER IOH = pINH->OptionalHeader;
    IMAGE_SECTION_HEADER *pISH = (IMAGE_SECTION_HEADER *)((DWORD)pImageBuf + pIDH->e_lfanew + sizeof(IMAGE_NT_HEADERS));

    DWORD SectionNumber = IFH.NumberOfSections;
    IMAGE_SECTION_HEADER *pISHTmp = pISH;
    DWORD FileSize = IOH.SizeOfHeaders; //ͷ + ������������������
    return true;
}
// ��ӡ������
BOOL PrintExportTable(IN const char *pPEPath)
{
    void *pFileBuf = ReadPEToMemory(pPEPath, NULL);
    if (!pFileBuf)
        return false;

    IMAGE_DOS_HEADER *pIDH = (IMAGE_DOS_HEADER *)pFileBuf;
    IMAGE_NT_HEADERS *pINH = (IMAGE_NT_HEADERS *)((DWORD)pIDH + pIDH->e_lfanew);
    IMAGE_OPTIONAL_HEADER IOH = pINH->OptionalHeader;
    // ��һ�������ض�λ��
    DWORD Size = IOH.DataDirectory[0].Size;
    DWORD RVAVirtualAddresss = IOH.DataDirectory[0].VirtualAddress;
    if (Size == 0 || RVAVirtualAddresss == 0)
    {
        printf("û�е�����\n");
        UnReadPEToMemory(pFileBuf);
        return false;
    }
    DWORD RWAAddress = RVATORAWEx(pFileBuf, RVAVirtualAddresss, true);
    IMAGE_EXPORT_DIRECTORY *pIED = (IMAGE_EXPORT_DIRECTORY *)((DWORD)pFileBuf + RWAAddress);

    printf("---------------------������ͷ��Ϣ------------------\n");
    printf("Name:%s\n", (DWORD)pFileBuf + RVATORAWEx(pFileBuf, pIED->Name, true));
    printf("NumberOfFunctions:0x%X\n", pIED->NumberOfFunctions);
    printf("NumberOfNames:0x%X\n", pIED->NumberOfNames);
    printf("Base:%u\n", pIED->Base);
    printf("AddressOfFunctions(RVA):0x%X(����������ַ������)\n", pIED->AddressOfFunctions);
    printf("AddressOfNames(RVA):0x%X(����������������)\n", pIED->AddressOfNames);

    printf("AddressOfNameOrdinals(RVA):0x%X(Ordinals��ַ������)\n", pIED->AddressOfNameOrdinals);

    DWORD *pAddFunRAW = (DWORD *)((DWORD)pFileBuf + RVATORAWEx(pFileBuf, pIED->AddressOfFunctions, true));
    DWORD *pAddNameRAW = (DWORD *)((DWORD)pFileBuf + RVATORAWEx(pFileBuf, pIED->AddressOfNames, true));
    // ע��������word
    WORD *pAddNameOrdRAW = (WORD *)((DWORD)pFileBuf + RVATORAWEx(pFileBuf, pIED->AddressOfNameOrdinals, true));
    BOOL bOrdNameFun = FALSE; //�����ж��ǲ���AddressOfFunctions���е�����AddressOfNameOrdinals����
    printf("%X %X %X\n", *pAddFunRAW, *pAddNameOrdRAW, *pAddNameOrdRAW);
    printf("FunAddress\t\tOrdinal\t\tName\n");

    for (DWORD i = 0; i < pIED->NumberOfFunctions; i++)
    {
        DWORD j;
        for (j = 0; j < pIED->NumberOfNames; j++)
        {
            if (pAddNameOrdRAW[j] == i)
            {
                bOrdNameFun = TRUE;
                break;
            }
        }
        if (bOrdNameFun)
        {
            bOrdNameFun = false;
            DWORD AddName = RVATORAWEx(pFileBuf, pAddNameRAW[j], TRUE);

            printf("%X\t\t%X\t\t%s\n", pAddFunRAW[i], pIED->Base + j, (DWORD)pFileBuf + AddName);
        }
        else
        {
            printf("%X\t\t--\t\t--\n");
        }
    }

    UnReadPEToMemory(pFileBuf);

    return TRUE;
}
BOOL PrintImportTable(IN const char *pPEPath)
{
    void *pFileBuf = ReadPEToMemory(pPEPath, NULL);
    if (!pFileBuf)
        return false;

    IMAGE_DOS_HEADER *pIDH = (IMAGE_DOS_HEADER *)pFileBuf;
    IMAGE_NT_HEADERS *pINH = (IMAGE_NT_HEADERS *)((DWORD)pIDH + pIDH->e_lfanew);
    IMAGE_OPTIONAL_HEADER IOH = pINH->OptionalHeader;
    // �ڶ����ǵ����
    DWORD Size = IOH.DataDirectory[1].Size;
    DWORD RVAVirtualAddresss = IOH.DataDirectory[1].VirtualAddress;

    if (Size == 0 || RVAVirtualAddresss == 0)
    {
        printf("û�е����\n");
        UnReadPEToMemory(pFileBuf);
        return false;
    }
    DWORD RWAAddress = RVATORAWEx(pFileBuf, RVAVirtualAddresss, true);
    IMAGE_IMPORT_DESCRIPTOR *pIID = (IMAGE_IMPORT_DESCRIPTOR *)((DWORD)pFileBuf + RWAAddress);
    DWORD NumOfImport = 1;

    while (pIID->Name != NULL)
    {
        printf("---------------------������ͷ��Ϣ:%d------------------\n", NumOfImport++);
        printf("INT address(RVA):0x%X\n", pIID->OriginalFirstThunk);
        printf("Name:%s\n", (DWORD)pFileBuf + RVATORAWEx(pFileBuf, pIID->Name, true));
        printf("FirstThunk(RVA:0x%X)\n", pIID->FirstThunk);

        printf("---------------------INTͷ��Ϣ------------------\n");
        DWORD *INT = (DWORD *)((DWORD)pFileBuf + RVATORAWEx(pFileBuf, pIID->OriginalFirstThunk, true));
        while (*INT)
        {
            //�ж����λ�������1��������ŵ��룬���������ֵ���
            // IMAGE_THUNK_DATA32 ��һ��4�ֽ�����
            // ������λ��1����ô��ȥ���λ���ǵ������
            // ������λ��0����ô���ֵ��RVA ָ�� IMAGE_IMPORT_BY_NAME
            if (((*INT) & 0x80000000) == 0x80000000)
                printf("����ŵ���:0x%X\n", (*INT) & (0x7fffffff));
            else
            {
                IMAGE_IMPORT_BY_NAME *pIIBN = (IMAGE_IMPORT_BY_NAME *)((DWORD)pFileBuf + RVATORAWEx(pFileBuf, *INT, true));
                printf("Hint:%X  name:%s\n", pIIBN->Hint, pIIBN->Name);
            }
            INT++;
        }

        printf("---------------------IATͷ��Ϣ------------------\n");
        DWORD *IAT = (DWORD *)((DWORD)pFileBuf + RVATORAWEx(pFileBuf, pIID->FirstThunk, true));
        while (*IAT)
        {
            // IMAGE_THUNK_DATA32 ��һ��4�ֽ�����
            // ������λ��1����ô��ȥ���λ���ǵ������
            // ������λ��0����ô���ֵ��RVA ָ�� IMAGE_IMPORT_BY_NAME
            if (((*INT) & 0x80000000) == 0x80000000)

                printf("����ŵ���:0x%X\n", (*IAT) & (0x7fffffff));

            else
            {
                IMAGE_IMPORT_BY_NAME *pIIBN = (IMAGE_IMPORT_BY_NAME *)((DWORD)pFileBuf + RVATORAWEx(pFileBuf, *IAT, true));
                printf("Hint:%X  name:%s\n", pIIBN->Hint, pIIBN->Name);
            }
            IAT++;
        }
        pIID++;
    }
    UnReadPEToMemory(pFileBuf);
    return TRUE;
}
BOOL PrintRelocateTable(IN const char *pPEPath)
{
    void *pFileBuf = ReadPEToMemory(pPEPath, NULL);
    if (!pFileBuf)
        return false;

    IMAGE_DOS_HEADER *pIDH = (IMAGE_DOS_HEADER *)pFileBuf;
    IMAGE_NT_HEADERS *pINH = (IMAGE_NT_HEADERS *)((DWORD)pIDH + pIDH->e_lfanew);
    IMAGE_OPTIONAL_HEADER IOH = pINH->OptionalHeader;
    // ���������ض�λ
    DWORD Size = IOH.DataDirectory[6].Size;
    DWORD RVAVirtualAddresss = IOH.DataDirectory[6].VirtualAddress;

    if (Size == 0 || RVAVirtualAddresss == 0)
    {
        printf("û���ض�λ\n");
        UnReadPEToMemory(pFileBuf);
        return false;
    }
}