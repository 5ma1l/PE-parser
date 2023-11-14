#include "PE.h"


int isPE(FILE* PpeFile) {
    IMAGE_DOS_HEADER TMP;
    fseek(PpeFile, 0, SEEK_SET);
    fread(&TMP, sizeof(IMAGE_DOS_HEADER), 1, PpeFile);
    if (TMP.e_magic == IMAGE_DOS_SIGNATURE) {
        return TMP.e_lfanew;
    }
    else {
        printf("Error. Unknown Type!\n");
        return 0;
    }
}

int is32(FILE* PpeFile) {
    LONG PpeHeader = isPE(PpeFile);
    if (PpeHeader != 0) {
        WORD signature;
        fseek(PpeFile, PpeHeader +sizeof(IMAGE_FILE_HEADER)+sizeof(DWORD), SEEK_SET);
        fread(&signature, sizeof(WORD), 1, PpeFile);
        if (signature == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            return 32;
        }
    }
    return 0;
}

int is64(FILE* PpeFile) {
    LONG PpeHeader = isPE(PpeFile);
    if (PpeHeader != 0) {
        WORD signature;
        fseek(PpeFile, PpeHeader+sizeof(IMAGE_FILE_HEADER)+sizeof(DWORD), SEEK_SET);
        fread(&signature, sizeof(WORD), 1, PpeFile);
        if (signature == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            return 64;
        }
    }
    return 0;
}

int main(int argc, char* argv[])
{
    if (argc != 2) {
        printf("[?] Usage: %s [Path PE file]", argv[0]);
        return 1;//indicate that some errors occur during excution
    }
    FILE* Ppefile;

    fopen_s(&Ppefile, argv[1], "rb");


    if (Ppefile == NULL) {
        printf("[!] Error, Cannot Open File.");
        return 1;
    }
    else if (is32(Ppefile)==32){
        PE32 peFile32(argv[1], Ppefile);
        peFile32.PrintInfo();
    }
    else if (is64(Ppefile) == 64) {
        PE64 peFile64(argv[1], Ppefile);
        peFile64.PrintInfo();
    }
    else {
        printf("Unknown Type!");
    }


}
