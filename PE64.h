#include "wind_struct.h"
class PE64
{
public:
    PE64(char* _NAME, FILE* _Ppefile) {
        NAME = _NAME;
        Ppefile = _Ppefile;

        ParseFile();
    }

    void PrintInfo(){
        PrintDOSHeaderInfo();
        PrintRichHeaderInfo();
        PrintNTHeadersInfo();
        PrintSectionHeadersInfo();
        PrintImportTableInfo();
    }

private:
    char* NAME;
    FILE* Ppefile;
    int _import_directory_count, _import_directory_size;
    int _basreloc_directory_count;

    // HEADERS
    IMAGE_DOS_HEADER     PEFILE_DOS_HEADER;
    IMAGE_NT_HEADERS64   PEFILE_NT_HEADERS;

    // DOS HEADER
    DWORD PEFILE_DOS_HEADER_EMAGIC;
    LONG  PEFILE_DOS_HEADER_LFANEW;

    // RICH HEADER
    RICH_HEADER_INFO PEFILE_RICH_HEADER_INFO;
    RICH_HEADER PEFILE_RICH_HEADER;

    // NT_HEADERS.Signature
    DWORD PEFILE_NT_HEADERS_SIGNATURE;

    // NT_HEADERS.FileHeader
    WORD PEFILE_NT_HEADERS_FILE_HEADER_MACHINE;
    WORD PEFILE_NT_HEADERS_FILE_HEADER_NUMBER0F_SECTIONS;
    WORD PEFILE_NT_HEADERS_FILE_HEADER_SIZEOF_OPTIONAL_HEADER;

    // NT_HEADERS.OptionalHeader
    DWORD PEFILE_NT_HEADERS_OPTIONAL_HEADER_MAGIC;
    DWORD PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_CODE;
    DWORD PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_INITIALIZED_DATA;
    DWORD PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_UNINITIALIZED_DATA;
    DWORD PEFILE_NT_HEADERS_OPTIONAL_HEADER_ADDRESSOF_ENTRYPOINT;
    DWORD PEFILE_NT_HEADERS_OPTIONAL_HEADER_BASEOF_CODE;
    ULONGLONG PEFILE_NT_HEADERS_OPTIONAL_HEADER_IMAGEBASE;
    DWORD PEFILE_NT_HEADERS_OPTIONAL_HEADER_SECTION_ALIGNMENT;
    DWORD PEFILE_NT_HEADERS_OPTIONAL_HEADER_FILE_ALIGNMENT;
    DWORD PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_IMAGE;
    DWORD PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_HEADERS;

    IMAGE_DATA_DIRECTORY PEFILE_EXPORT_DIRECTORY;
    IMAGE_DATA_DIRECTORY PEFILE_IMPORT_DIRECTORY;
    IMAGE_DATA_DIRECTORY PEFILE_RESOURCE_DIRECTORY;
    IMAGE_DATA_DIRECTORY PEFILE_EXCEPTION_DIRECTORY;
    IMAGE_DATA_DIRECTORY PEFILE_SECURITY_DIRECTORY;
    IMAGE_DATA_DIRECTORY PEFILE_BASERELOC_DIRECTORY;
    IMAGE_DATA_DIRECTORY PEFILE_DEBUG_DIRECTORY;
    IMAGE_DATA_DIRECTORY PEFILE_ARCHITECTURE_DIRECTORY;
    IMAGE_DATA_DIRECTORY PEFILE_GLOBALPTR_DIRECTORY;
    IMAGE_DATA_DIRECTORY PEFILE_TLS_DIRECTORY;
    IMAGE_DATA_DIRECTORY PEFILE_LOAD_CONFIG_DIRECTORY;
    IMAGE_DATA_DIRECTORY PEFILE_BOUND_IMPORT_DIRECTORY;
    IMAGE_DATA_DIRECTORY PEFILE_IAT_DIRECTORY;
    IMAGE_DATA_DIRECTORY PEFILE_DELAY_IMPORT_DIRECTORY;
    IMAGE_DATA_DIRECTORY PEFILE_COM_DESCRIPTOR_DIRECTORY;

    // SECTION HEADERS
    PIMAGE_SECTION_HEADER PEFILE_SECTION_HEADERS;

    // IMPORT TABLE
    PIMAGE_IMPORT_DESCRIPTOR PEFILE_IMPORT_TABLE;

    // BASE RELOCATION TABLE
    PIMAGE_BASE_RELOCATION PEFILE_BASERELOC_TABLE;

    // FUNCTIONS

    // ADDRESS RESOLVERS
    int  locate(DWORD VA) {
        int in;
        for (int i = 0; i < PEFILE_NT_HEADERS_FILE_HEADER_NUMBER0F_SECTIONS; i++) {
            if (VA >= PEFILE_SECTION_HEADERS[i].VirtualAddress && VA < PEFILE_SECTION_HEADERS[i].VirtualAddress + PEFILE_SECTION_HEADERS[i].Misc.VirtualSize) {
                in = i;
                break;
            }
        }
        return in;
    }
    DWORD resolve(DWORD VA, int index) {
        return (VA - PEFILE_SECTION_HEADERS[index].VirtualAddress) + PEFILE_SECTION_HEADERS[index].PointerToRawData;
    }

    // PARSERS
    void ParseFile() {
        ParseDOSHeader();
        ParseRichHeader();
        ParseNTHeaders();
        ParseSectionHeaders();
        ParseImportDirectory();
    }
    void ParseDOSHeader() {
        fseek(Ppefile, 0, 0);
        fread(&PEFILE_DOS_HEADER, sizeof(IMAGE_DOS_HEADER), 1, Ppefile);
        PEFILE_DOS_HEADER_EMAGIC = PEFILE_DOS_HEADER.e_magic;
        PEFILE_DOS_HEADER_LFANEW = PEFILE_DOS_HEADER.e_lfanew;
    }
    void ParseNTHeaders(){
        fseek(Ppefile,PEFILE_DOS_HEADER_LFANEW,SEEK_SET);
        fread(&PEFILE_NT_HEADERS,sizeof(IMAGE_NT_HEADERS64),1,Ppefile);

        PEFILE_NT_HEADERS_SIGNATURE=PEFILE_NT_HEADERS.Signature;

        PEFILE_NT_HEADERS_FILE_HEADER_MACHINE=PEFILE_NT_HEADERS.FileHeader.Machine;
        PEFILE_NT_HEADERS_FILE_HEADER_NUMBER0F_SECTIONS=PEFILE_NT_HEADERS.FileHeader.NumberOfSections;
        PEFILE_NT_HEADERS_FILE_HEADER_SIZEOF_OPTIONAL_HEADER=PEFILE_NT_HEADERS.FileHeader.SizeOfOptionalHeader;

        PEFILE_NT_HEADERS_OPTIONAL_HEADER_MAGIC=PEFILE_NT_HEADERS.OptionalHeader.Magic;
        PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_CODE=PEFILE_NT_HEADERS.OptionalHeader.SizeOfCode;
        PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_INITIALIZED_DATA=PEFILE_NT_HEADERS.OptionalHeader.SizeOfInitializedData;
        PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_UNINITIALIZED_DATA=PEFILE_NT_HEADERS.OptionalHeader.SizeOfUninitializedData;
        PEFILE_NT_HEADERS_OPTIONAL_HEADER_ADDRESSOF_ENTRYPOINT=PEFILE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint;
        PEFILE_NT_HEADERS_OPTIONAL_HEADER_BASEOF_CODE=PEFILE_NT_HEADERS.OptionalHeader.BaseOfCode;
        PEFILE_NT_HEADERS_OPTIONAL_HEADER_IMAGEBASE=PEFILE_NT_HEADERS.OptionalHeader.ImageBase;
        PEFILE_NT_HEADERS_OPTIONAL_HEADER_SECTION_ALIGNMENT=PEFILE_NT_HEADERS.OptionalHeader.SectionAlignment;
        PEFILE_NT_HEADERS_OPTIONAL_HEADER_FILE_ALIGNMENT=PEFILE_NT_HEADERS.OptionalHeader.FileAlignment;
        PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_IMAGE=PEFILE_NT_HEADERS.OptionalHeader.SizeOfImage;
        PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_HEADERS=PEFILE_NT_HEADERS.OptionalHeader.SizeOfHeaders;

        PEFILE_EXPORT_DIRECTORY=PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        PEFILE_IMPORT_DIRECTORY=PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        PEFILE_RESOURCE_DIRECTORY=PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
        PEFILE_EXCEPTION_DIRECTORY=PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        PEFILE_SECURITY_DIRECTORY=PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
        PEFILE_BASERELOC_DIRECTORY=PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        PEFILE_DEBUG_DIRECTORY=PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
        PEFILE_ARCHITECTURE_DIRECTORY=PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE];
        PEFILE_GLOBALPTR_DIRECTORY=PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_GLOBALPTR];
        PEFILE_TLS_DIRECTORY=PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        PEFILE_LOAD_CONFIG_DIRECTORY=PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
        PEFILE_BOUND_IMPORT_DIRECTORY=PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT];
        PEFILE_IAT_DIRECTORY=PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
        PEFILE_DELAY_IMPORT_DIRECTORY=PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
        PEFILE_COM_DESCRIPTOR_DIRECTORY=PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
    }
    void ParseSectionHeaders(){
        PEFILE_SECTION_HEADERS=new IMAGE_SECTION_HEADER[PEFILE_NT_HEADERS_FILE_HEADER_NUMBER0F_SECTIONS];
        long offset=PEFILE_DOS_HEADER_LFANEW+sizeof(IMAGE_NT_HEADERS64);
        for (int i=0;i<PEFILE_NT_HEADERS_FILE_HEADER_NUMBER0F_SECTIONS;i++){
            fseek(Ppefile,offset,SEEK_SET);
            fread(PEFILE_SECTION_HEADERS+i,IMAGE_SIZEOF_SECTION_HEADER,1,Ppefile);
            offset+=IMAGE_SIZEOF_SECTION_HEADER;
        }
    }
    void ParseImportDirectory(){
        _import_directory_count=0;
        int inSection=locate(PEFILE_IMPORT_DIRECTORY.VirtualAddress);
        DWORD offsetIt= resolve(PEFILE_IMPORT_DIRECTORY.VirtualAddress,inSection);
        DWORD offset=offsetIt;
        while(true){
            IMAGE_IMPORT_DESCRIPTOR tmpIID;
            fseek(Ppefile,offset,SEEK_SET);
            fread(&tmpIID,sizeof(IMAGE_IMPORT_DESCRIPTOR),1,Ppefile);
            if (tmpIID.OriginalFirstThunk==0 && tmpIID.Name==0 && tmpIID.TimeDateStamp==0 && tmpIID.ForwarderChain==0 && tmpIID.FirstThunk==0){
                break;
            }
            offset+=sizeof(IMAGE_IMPORT_DESCRIPTOR);
            _import_directory_count+=1;
        }
        _import_directory_size=_import_directory_count*sizeof(IMAGE_IMPORT_DESCRIPTOR);
        PEFILE_IMPORT_TABLE = new IMAGE_IMPORT_DESCRIPTOR[_import_directory_count];
        offset=offsetIt;
        for(int i=0;i<_import_directory_count;i++){
            fseek(Ppefile,offset,SEEK_SET);
            fread(PEFILE_IMPORT_TABLE+i,sizeof(IMAGE_IMPORT_DESCRIPTOR),1,Ppefile);
            offset+=sizeof(IMAGE_IMPORT_DESCRIPTOR);
        }

    }
    void ParseBaseReloc();
    void ParseRichHeader() {
        char BeforeNewHeader[PEFILE_DOS_HEADER_LFANEW];
        fseek(Ppefile,0,0);
        fread(&BeforeNewHeader,PEFILE_DOS_HEADER_LFANEW,1,Ppefile);

        int rich=0;
        for (int i=0;i<PEFILE_DOS_HEADER_LFANEW-1;i+=4){
            if(BeforeNewHeader[i]==0x52 && BeforeNewHeader[i+1]==0x69)
                rich=i;
        }
        if (rich==0) {
            PEFILE_RICH_HEADER_INFO.entries=0;
            return;
        }
        else{
            char key[4];
            memcpy(key, &(BeforeNewHeader[rich + 4]), 4);
            int offsetRich=rich;
            while(offsetRich>0){
                offsetRich-=4;
                char tmp[4];
                memcpy(tmp,&BeforeNewHeader[offsetRich],4);
                for (int j=0;j<4;j++){
                    tmp[j]=tmp[j]^key[j];
                }
                if (tmp[3]==0x53 && tmp[2]==0x6e){
                    break;
                }
            }
            int sizeRich=(rich-offsetRich-4);
            char dataRich[sizeRich];
            memcpy(dataRich,&(BeforeNewHeader[offsetRich]),sizeRich);

            for (int i; i < sizeRich; i++)
                dataRich[i] = dataRich[i] ^ key[i % 4];

            PEFILE_RICH_HEADER_INFO.size=sizeRich;
            PEFILE_RICH_HEADER_INFO.ptrToBuffer=dataRich;
            PEFILE_RICH_HEADER_INFO.entries=(sizeRich-16)/8;

            PEFILE_RICH_HEADER.entries=new RICH_HEADER_ENTRY[PEFILE_RICH_HEADER_INFO.entries];

            for (int i=16;i<sizeRich;i+=8){
                int entryIndex=i/8 - 2;
                PEFILE_RICH_HEADER.entries[entryIndex].buildID= (unsigned char)dataRich[i+3]<<8 | (unsigned char)dataRich[i+2];
                PEFILE_RICH_HEADER.entries[entryIndex].prodID= (unsigned char)dataRich[i+1]<<8 | (unsigned char)dataRich[i];
                PEFILE_RICH_HEADER.entries[entryIndex].useCount= (unsigned char)dataRich[i+7]<<24 | (unsigned char)dataRich[i+6]<<16 | (unsigned char)dataRich[i+5]<<8 | (unsigned char)dataRich[i+4];

            }
        }
        PEFILE_RICH_HEADER_INFO.ptrToBuffer=0;
    }

    // PRINT INFO
    void PrintFileInfo();
    void PrintDOSHeaderInfo() {
        printf("<<< DOS Header >>>\n");
        printf(" Magic: 0x%X\n", PEFILE_DOS_HEADER_EMAGIC);
        printf(" Pointer to PE header: 0x%X\n", PEFILE_DOS_HEADER_EMAGIC);
    }
    void PrintRichHeaderInfo() {
        if (PEFILE_RICH_HEADER_INFO.entries!=0){
            printf("<<< Rich Header >>>\n");
            printf(" Entries:\n");
            for (int i=0;i<PEFILE_RICH_HEADER_INFO.entries;i++)
                printf(" \t+The BuildId: 0x%X\t+The ProductID: 0x%X\t+The count: 0x%X\n", PEFILE_RICH_HEADER.entries[i].buildID, PEFILE_RICH_HEADER.entries[i].prodID,
                       PEFILE_RICH_HEADER.entries[i].useCount);
        }


    }
    void PrintNTHeadersInfo(){
        printf("<<< NT Header >>>\n");
        printf(" PE Signature: 0x%lX\n", PEFILE_NT_HEADERS_SIGNATURE);

        printf("\n File Header:\n\n");
        printf("   Machine: 0x%X\n", PEFILE_NT_HEADERS_FILE_HEADER_MACHINE);
        printf("   Number of sections: 0x%X\n", PEFILE_NT_HEADERS_FILE_HEADER_NUMBER0F_SECTIONS);
        printf("   Size of optional header: 0x%X\n", PEFILE_NT_HEADERS_FILE_HEADER_SIZEOF_OPTIONAL_HEADER);

        printf("\n Optional Header:\n\n");
        printf("   Magic: 0x%lX\n", PEFILE_NT_HEADERS_OPTIONAL_HEADER_MAGIC);
        printf("   Size of code section: 0x%lX\n", PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_CODE);
        printf("   Size of initialized data: 0x%lX\n", PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_INITIALIZED_DATA);
        printf("   Size of uninitialized data: 0x%lX\n", PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_UNINITIALIZED_DATA);
        printf("   Address of entry point: 0x%lX\n", PEFILE_NT_HEADERS_OPTIONAL_HEADER_ADDRESSOF_ENTRYPOINT);
        printf("   RVA of start of code section: 0x%lX\n", PEFILE_NT_HEADERS_OPTIONAL_HEADER_BASEOF_CODE);
        printf("   Desired image base: 0x%llX\n", PEFILE_NT_HEADERS_OPTIONAL_HEADER_IMAGEBASE);
        printf("   Section alignment: 0x%lX\n", PEFILE_NT_HEADERS_OPTIONAL_HEADER_SECTION_ALIGNMENT);
        printf("   File alignment: 0x%lX\n", PEFILE_NT_HEADERS_OPTIONAL_HEADER_FILE_ALIGNMENT);
        printf("   Size of image: 0x%lX\n", PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_IMAGE);
        printf("   Size of headers: 0x%lX\n", PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_HEADERS);

        printf("\n Data Directories:\n");
        printf("\n   * Export Directory:\n");
        printf("       RVA: 0x%lX\n", PEFILE_EXPORT_DIRECTORY.VirtualAddress);
        printf("       Size: 0x%lX\n", PEFILE_EXPORT_DIRECTORY.Size);

        printf("\n   * Import Directory:\n");
        printf("       RVA: 0x%lX\n", PEFILE_IMPORT_DIRECTORY.VirtualAddress);
        printf("       Size: 0x%lX\n", PEFILE_IMPORT_DIRECTORY.Size);

        printf("\n   * Resource Directory:\n");
        printf("       RVA: 0x%lX\n", PEFILE_RESOURCE_DIRECTORY.VirtualAddress);
        printf("       Size: 0x%lX\n", PEFILE_RESOURCE_DIRECTORY.Size);

        printf("\n   * Exception Directory:\n");
        printf("       RVA: 0x%lX\n", PEFILE_EXCEPTION_DIRECTORY.VirtualAddress);
        printf("       Size: 0x%lX\n", PEFILE_EXCEPTION_DIRECTORY.Size);

        printf("\n   * Security Directory:\n");
        printf("       RVA: 0x%lX\n", PEFILE_SECURITY_DIRECTORY.VirtualAddress);
        printf("       Size: 0x%lX\n", PEFILE_SECURITY_DIRECTORY.Size);

        printf("\n   * Base Relocation Table:\n");
        printf("       RVA: 0x%lX\n", PEFILE_BASERELOC_DIRECTORY.VirtualAddress);
        printf("       Size: 0x%lX\n", PEFILE_BASERELOC_DIRECTORY.Size);

        printf("\n   * Debug Directory:\n");
        printf("       RVA: 0x%lX\n", PEFILE_DEBUG_DIRECTORY.VirtualAddress);
        printf("       Size: 0x%lX\n", PEFILE_DEBUG_DIRECTORY.Size);

        printf("\n   * Architecture Specific Data:\n");
        printf("       RVA: 0x%lX\n", PEFILE_ARCHITECTURE_DIRECTORY.VirtualAddress);
        printf("       Size: 0x%lX\n", PEFILE_ARCHITECTURE_DIRECTORY.Size);

        printf("\n   * RVA of GlobalPtr:\n");
        printf("       RVA: 0x%lX\n", PEFILE_GLOBALPTR_DIRECTORY.VirtualAddress);
        printf("       Size: 0x%lX\n", PEFILE_GLOBALPTR_DIRECTORY.Size);

        printf("\n   * TLS Directory:\n");
        printf("       RVA: 0x%lX\n", PEFILE_TLS_DIRECTORY.VirtualAddress);
        printf("       Size: 0x%lX\n", PEFILE_TLS_DIRECTORY.Size);

        printf("\n   * Load Configuration Directory:\n");
        printf("       RVA: 0x%lX\n", PEFILE_LOAD_CONFIG_DIRECTORY.VirtualAddress);
        printf("       Size: 0x%lX\n", PEFILE_LOAD_CONFIG_DIRECTORY.Size);

        printf("\n   * Bound Import Directory:\n");
        printf("       RVA: 0x%lX\n", PEFILE_BOUND_IMPORT_DIRECTORY.VirtualAddress);
        printf("       Size: 0x%lX\n", PEFILE_BOUND_IMPORT_DIRECTORY.Size);

        printf("\n   * Import Address Table:\n");
        printf("       RVA: 0x%lX\n", PEFILE_IAT_DIRECTORY.VirtualAddress);
        printf("       Size: 0x%lX\n", PEFILE_IAT_DIRECTORY.Size);

        printf("\n   * Delay Load Import Descriptors:\n");
        printf("       RVA: 0x%lX\n", PEFILE_DELAY_IMPORT_DIRECTORY.VirtualAddress);
        printf("       Size: 0x%lX\n", PEFILE_IAT_DIRECTORY.Size);

        printf("\n   * COM Runtime Descriptor:\n");
        printf("       RVA: 0x%lX\n", PEFILE_COM_DESCRIPTOR_DIRECTORY.VirtualAddress);
        printf("       Size: 0x%lX\n", PEFILE_COM_DESCRIPTOR_DIRECTORY.Size);




    }
    void PrintSectionHeadersInfo(){
        printf("<<< Section Headers >>>\n");
        for (int i=0;i<PEFILE_NT_HEADERS_FILE_HEADER_NUMBER0F_SECTIONS;i++){
            printf("\n\t ** Name: %.8s **\n",PEFILE_SECTION_HEADERS[i].Name);
            printf(" * Virtual Size: 0x%lX\n",PEFILE_SECTION_HEADERS[i].Misc.VirtualSize);
            printf(" * Virtual Address: 0x%lX\n",PEFILE_SECTION_HEADERS[i].VirtualAddress);
            printf(" * Size Of Raw Data: 0x%lX\n",PEFILE_SECTION_HEADERS[i].SizeOfRawData);
            printf(" * RawData Address: 0x%lX\n",PEFILE_SECTION_HEADERS[i].PointerToRawData);

        }
    }
    void PrintImportTableInfo(){
        printf("<<< Import Table >>>\n");
        for (int i=0;i<_import_directory_count;i++){
            int nameAddr=resolve(PEFILE_IMPORT_TABLE[i].Name,locate(PEFILE_IMPORT_TABLE[i].Name));
            int sizeName=0;
            char tmpChar;
            fseek(Ppefile,nameAddr,SEEK_SET);
            fread(&tmpChar,sizeof(char),1,Ppefile);
            while (tmpChar!='\0'){
                sizeName++;
                fseek(Ppefile,nameAddr+sizeName,SEEK_SET);
                fread(&tmpChar,sizeof(char),1,Ppefile);
            }

            char Name[++sizeName];
            fseek(Ppefile,nameAddr,SEEK_SET);
            fread(&Name,sizeName,1,Ppefile);

            printf(" * Name: %s\n\tFunctions:\n",Name);

            DWORD ILTAddr=resolve(PEFILE_IMPORT_TABLE[i].OriginalFirstThunk,locate(PEFILE_IMPORT_TABLE[i].OriginalFirstThunk));

            while(true){
                u_int64 tmpILT;
                fseek(Ppefile,ILTAddr,SEEK_SET);
                fread(&tmpILT,sizeof(u_int64),1,Ppefile);
                if(tmpILT==0){
                    break;
                }
                else if ((tmpILT>>63 & 1)==1){
                    int ordinal = tmpILT>>48 & 0xFFF;
                    printf(" \t** Call By Ordinal: 0x%X\n",ordinal);

                }
                else if ((tmpILT>>63 & 1)==0){
                    int sizeFuncName=0;
                    long addrFuncName= resolve(tmpILT,locate(tmpILT));
                    while(true){
                        char tmpChar;
                        fseek(Ppefile,addrFuncName+sizeFuncName,SEEK_SET);
                        fread(&tmpChar,sizeof(char),1,Ppefile);
                        if(tmpChar=='\0') {
                            fseek(Ppefile,addrFuncName+sizeFuncName+1,SEEK_SET);
                            fread(&tmpChar,sizeof(char),1,Ppefile);
                            if (tmpChar=='\0'){
                                break;
                            }
                             }
                        sizeFuncName++;
                    }
                    char funcName[++sizeFuncName];
                    fseek(Ppefile,addrFuncName +sizeof(WORD),SEEK_SET);
                    fread(&funcName,sizeFuncName,1,Ppefile);
                    printf("\t ** %s\n",funcName);
                }
                ILTAddr+=sizeof(u_int64);

        }
        }
    }
    void PrintBaseRelocationsInfo();
};

