// 编码为 GBK
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
    // 1.PE -> FileBuf, 打印相关信息
    // void *pFileBuf = ReadPEToMemory(PE_PATH, NULL);
    // PrintPEInfomatiaon(pFileBuf);
    // UnReadPEToMemory(pFileBuf);

    // 2.扩展 FileBuf -> ImageBuf
    // void *pImageBuf = ReadFileBufToImageBuf(PE_PATH);
    // UnReadFileBufToImageBuf(pImageBuf);

    // 3. ImageBuf -> 硬盘 ，可执行
    // void *pImageBuf = ReadFileBufToImageBuf(PE_PATH);
    // DumpImageBufToDisk(pImageBuf, "3.exe");
    // UnReadFileBufToImageBuf(pImageBuf);

    // 4.RVA -> RAW(FOA)
    // DWORD a = RVATORAW(PE_PATH, 0xA0E1, true);
    // printf("RAW:%p\n", a);

    // 5.往指定节里添加Shellcode(代码)（未完成）
    // 6.添加节（未完成）

    // 7. 打印导出表
    // PrintExportTable("kernel32.dll");

    // 8.打印重定位

    // 9. 打印导入表
    // PrintImportTable("kernel32.dll");

    // 10.移动导出表
    return 0;
}

//功能：加载PE文件到内存
//参数：pPEPath:文件路径
//返回值:文件缓存
void *ReadPEToMemory(const char *pPEPath, OUT DWORD *SizeOfPE)
{
    FILE *fp = fopen(pPEPath, "rb");
    if (fp == NULL)
    {
        cout << "ReadPeToMemory:参数为空" << endl;
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

//功能：释放PE所分配的堆空间
//参数：pFileBuf
//返回值:无
void UnReadPEToMemory(IN void *pFileBuf)
{
    if (pFileBuf == NULL)
        cout << "FreePEFromMemory:参数为空" << endl;
    else
        free(pFileBuf);
}

//功能：解析PE文件
//参数：PE的文件缓存地址
//返回值:无
void PrintPEInfomatiaon(IN void *pFileBuf)
{
    if (!pFileBuf)
    {
        cout << "PrintPEInfomatiaon:参数为空" << endl;
        return;
    }
    IMAGE_DOS_HEADER *pIDH = (IMAGE_DOS_HEADER *)pFileBuf;
    cout << "\n--------------IMAGE_DOS_HEADER--------------" << endl;
    printf("magic:0x%X\nlfanew:0x%X(NT头的偏移)\n", pIDH->e_magic, pIDH->e_lfanew);

    IMAGE_NT_HEADERS *pINH = (IMAGE_NT_HEADERS *)((DWORD)pIDH + pIDH->e_lfanew);
    cout << "\n--------------IMAGE_NT_HEADER--------------" << endl;
    printf("Signature(4550:PE):0x%X\n", pINH->Signature);

    IMAGE_FILE_HEADER IFH = pINH->FileHeader;
    cout << "\n--------------IMAGE_FILE_HEADER--------------" << endl;
    printf("NumberOfSections:%d(节区数量)\n", IFH.NumberOfSections);
    printf("SizeOfOptionalHeader:%d(IMAGE_OPTIONAL_HEADER大小)\n", IFH.SizeOfOptionalHeader);

    IMAGE_OPTIONAL_HEADER IOH = pINH->OptionalHeader;
    cout << "\n--------------IMAGE_OPTIONAL_HEADER--------------" << endl;
    printf("Magic:0x%X\n", IOH.Magic);
    printf("SizeOfCode:0x%X(代码节(.test)大小，有多个的话是总和)\n");
    printf("SizeOfInitializedData:0x%X(已初始化数据节的大小，有多个的话是总和)\n", IOH.SizeOfInitializedData);
    printf("SizeOfUninitializedData:0x%X(未初始化数据节的大小，有多个的话是总和)\n", IOH.SizeOfUninitializedData);
    printf("AddressOfEntryPoint:0x%X(EntryPoint,RVA)\n", IOH.AddressOfEntryPoint);
    printf("BaseOfCode:0x%X(内存中代码节的开头相对于映像基址ImageBase的偏移地址)\n", IOH.BaseOfCode);
    printf("ImageBase:0x%X(载入内存时优先装载的地址)\n", IOH.ImageBase);
    printf("SectionAlignment:0x%X(节区在内存中的最小单位)\n", IOH.SectionAlignment);
    printf("FileAlignment:0x%X(节区在磁盘文件中的最小单位)\n", IOH.FileAlignment);
    printf("SizeOfImage:0x%X(指定了PE Image在虚拟内存中所占空间的大小)\n", IOH.SizeOfImage);
    printf("SizeOfHeaders:0x%X(整个PE头的大小)\n", IOH.SizeOfHeaders);
    printf("NumberOfRvaAndSizes:0x%X(DataDirectory数量)\n", IOH.NumberOfRvaAndSizes);

    IMAGE_SECTION_HEADER *pISH = (IMAGE_SECTION_HEADER *)((DWORD)pFileBuf + pIDH->e_lfanew + sizeof(IMAGE_NT_HEADERS));
    printf("\n--------------IMAGE_SECTION_HEADER--------------\n");
    for (int i = 0; i < IFH.NumberOfSections; i++)
    {
        printf("++++++++++++++++++++++%u Section++++++++++++++++++++++++++\n", i + 1);
        printf("Section name: %s\n", pISH->Name);
        printf("VirtualSize:0x%X(载入内存时此节区的大小)\n", pISH->Misc.VirtualSize);
        printf("VirtualAddress:0x%X(内存中节区起始地址(RVA))\n", pISH->VirtualAddress);
        printf("SizeOfRawData:0x%X(磁盘中节区所占大小)\n", pISH->SizeOfRawData);
        printf("PointerToRawData:0x%X(磁盘中本节对于文件头的距离)\n", pISH->PointerToRawData);
        pISH++;
    }
}

//功能：拉伸PE至内存,从FileBuf--->ImageBuf
//参数：exe文件路径
//返回值:拉伸后的堆地址
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
    // copy PE头
    memcpy(pImageBufTmp, pFileBuf, IOH.SizeOfHeaders);

    // copy 节区
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
//功能：释放拉伸PE所占据的内存(pImageBuf)
//参数：pImageBuf
//返回值:无
void UnReadFileBufToImageBuf(IN void *pImageBuf)
{
    if (!pImageBuf)
        printf("UnReadFileBufToImageBuf:参数为空");
    else
        free(pImageBuf);
}
//功能：将ImageBuf Dump 到磁盘
//参数：pImageBuf，Dump名字
//返回值:无
void DumpImageBufToDisk(IN void *pImageBuf, IN const char *outName)
{

    IMAGE_DOS_HEADER *pIDH = (IMAGE_DOS_HEADER *)pImageBuf;
    IMAGE_NT_HEADERS *pINH = (IMAGE_NT_HEADERS *)((DWORD)pIDH + pIDH->e_lfanew);
    IMAGE_FILE_HEADER IFH = pINH->FileHeader;
    IMAGE_OPTIONAL_HEADER IOH = pINH->OptionalHeader;
    IMAGE_SECTION_HEADER *pISH = (IMAGE_SECTION_HEADER *)((DWORD)pImageBuf + pIDH->e_lfanew + sizeof(IMAGE_NT_HEADERS));

    DWORD SectionNumber = IFH.NumberOfSections;
    IMAGE_SECTION_HEADER *pISHTmp = pISH;
    DWORD FileSize = IOH.SizeOfHeaders; //头 + 各节区，节区在下面

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
//功能：RVA与RAW的相互转换
//参数：pPEPath:PE文件路径，
//        bRVATORAW: TRUE, RVA to RAW
//			         FALSE,RAW to RVA
//返回值:转换后的值，为0则转换失败
DWORD RVATORAW(IN const char *pPEPath, DWORD offset, IN BOOL RVA2RAW)
{
    void *pFileBuf = ReadPEToMemory(pPEPath, NULL);
    if (pFileBuf == NULL)
    {
        printf("RVATORAW:文件出错\n");
        return 0;
    }
    IMAGE_DOS_HEADER *pIDH = (IMAGE_DOS_HEADER *)pFileBuf;
    IMAGE_NT_HEADERS *pINH = (IMAGE_NT_HEADERS *)((DWORD)pIDH + pIDH->e_lfanew);
    IMAGE_FILE_HEADER IFH = pINH->FileHeader;
    IMAGE_OPTIONAL_HEADER IOH = pINH->OptionalHeader;
    IMAGE_SECTION_HEADER *pISH = (IMAGE_SECTION_HEADER *)((DWORD)pFileBuf + pIDH->e_lfanew + sizeof(IMAGE_NT_HEADERS));
    DWORD SectionNumber = IFH.NumberOfSections;

    IMAGE_SECTION_HEADER *pISHTmp = pISH;
    // 两种情况，如果offset小于PE头，则RVA==FOA
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
    DWORD FileSize = IOH.SizeOfHeaders; //头 + 各节区，节区在下面
    return true;
}
// 打印导出表
BOOL PrintExportTable(IN const char *pPEPath)
{
    void *pFileBuf = ReadPEToMemory(pPEPath, NULL);
    if (!pFileBuf)
        return false;

    IMAGE_DOS_HEADER *pIDH = (IMAGE_DOS_HEADER *)pFileBuf;
    IMAGE_NT_HEADERS *pINH = (IMAGE_NT_HEADERS *)((DWORD)pIDH + pIDH->e_lfanew);
    IMAGE_OPTIONAL_HEADER IOH = pINH->OptionalHeader;
    // 第一个就是重定位表
    DWORD Size = IOH.DataDirectory[0].Size;
    DWORD RVAVirtualAddresss = IOH.DataDirectory[0].VirtualAddress;
    if (Size == 0 || RVAVirtualAddresss == 0)
    {
        printf("没有导出表\n");
        UnReadPEToMemory(pFileBuf);
        return false;
    }
    DWORD RWAAddress = RVATORAWEx(pFileBuf, RVAVirtualAddresss, true);
    IMAGE_EXPORT_DIRECTORY *pIED = (IMAGE_EXPORT_DIRECTORY *)((DWORD)pFileBuf + RWAAddress);

    printf("---------------------导出表头信息------------------\n");
    printf("Name:%s\n", (DWORD)pFileBuf + RVATORAWEx(pFileBuf, pIED->Name, true));
    printf("NumberOfFunctions:0x%X\n", pIED->NumberOfFunctions);
    printf("NumberOfNames:0x%X\n", pIED->NumberOfNames);
    printf("Base:%u\n", pIED->Base);
    printf("AddressOfFunctions(RVA):0x%X(导出函数地址，数组)\n", pIED->AddressOfFunctions);
    printf("AddressOfNames(RVA):0x%X(导出函数名，数组)\n", pIED->AddressOfNames);

    printf("AddressOfNameOrdinals(RVA):0x%X(Ordinals地址，数组)\n", pIED->AddressOfNameOrdinals);

    DWORD *pAddFunRAW = (DWORD *)((DWORD)pFileBuf + RVATORAWEx(pFileBuf, pIED->AddressOfFunctions, true));
    DWORD *pAddNameRAW = (DWORD *)((DWORD)pFileBuf + RVATORAWEx(pFileBuf, pIED->AddressOfNames, true));
    // 注意这里是word
    WORD *pAddNameOrdRAW = (WORD *)((DWORD)pFileBuf + RVATORAWEx(pFileBuf, pIED->AddressOfNameOrdinals, true));
    BOOL bOrdNameFun = FALSE; //用于判断是不是AddressOfFunctions表中的项在AddressOfNameOrdinals都有
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
    // 第二个是导入表
    DWORD Size = IOH.DataDirectory[1].Size;
    DWORD RVAVirtualAddresss = IOH.DataDirectory[1].VirtualAddress;

    if (Size == 0 || RVAVirtualAddresss == 0)
    {
        printf("没有导入表\n");
        UnReadPEToMemory(pFileBuf);
        return false;
    }
    DWORD RWAAddress = RVATORAWEx(pFileBuf, RVAVirtualAddresss, true);
    IMAGE_IMPORT_DESCRIPTOR *pIID = (IMAGE_IMPORT_DESCRIPTOR *)((DWORD)pFileBuf + RWAAddress);
    DWORD NumOfImport = 1;

    while (pIID->Name != NULL)
    {
        printf("---------------------导出表头信息:%d------------------\n", NumOfImport++);
        printf("INT address(RVA):0x%X\n", pIID->OriginalFirstThunk);
        printf("Name:%s\n", (DWORD)pFileBuf + RVATORAWEx(pFileBuf, pIID->Name, true));
        printf("FirstThunk(RVA:0x%X)\n", pIID->FirstThunk);

        printf("---------------------INT头信息------------------\n");
        DWORD *INT = (DWORD *)((DWORD)pFileBuf + RVATORAWEx(pFileBuf, pIID->OriginalFirstThunk, true));
        while (*INT)
        {
            //判断最高位，如果是1，则是序号导入，否则是名字导入
            // IMAGE_THUNK_DATA32 是一个4字节数据
            // 如果最高位是1，那么除去最高位就是导出序号
            // 如果最高位是0，那么这个值是RVA 指向 IMAGE_IMPORT_BY_NAME
            if (((*INT) & 0x80000000) == 0x80000000)
                printf("以序号导入:0x%X\n", (*INT) & (0x7fffffff));
            else
            {
                IMAGE_IMPORT_BY_NAME *pIIBN = (IMAGE_IMPORT_BY_NAME *)((DWORD)pFileBuf + RVATORAWEx(pFileBuf, *INT, true));
                printf("Hint:%X  name:%s\n", pIIBN->Hint, pIIBN->Name);
            }
            INT++;
        }

        printf("---------------------IAT头信息------------------\n");
        DWORD *IAT = (DWORD *)((DWORD)pFileBuf + RVATORAWEx(pFileBuf, pIID->FirstThunk, true));
        while (*IAT)
        {
            // IMAGE_THUNK_DATA32 是一个4字节数据
            // 如果最高位是1，那么除去最高位就是导出序号
            // 如果最高位是0，那么这个值是RVA 指向 IMAGE_IMPORT_BY_NAME
            if (((*INT) & 0x80000000) == 0x80000000)

                printf("以序号导入:0x%X\n", (*IAT) & (0x7fffffff));

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
    // 第六个是重定位
    DWORD Size = IOH.DataDirectory[6].Size;
    DWORD RVAVirtualAddresss = IOH.DataDirectory[6].VirtualAddress;

    if (Size == 0 || RVAVirtualAddresss == 0)
    {
        printf("没有重定位\n");
        UnReadPEToMemory(pFileBuf);
        return false;
    }
}