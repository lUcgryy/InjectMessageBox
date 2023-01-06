<div align='center'>

# **Inject Message Box**
 
</div>
 
## **Language:** C++

## **Requirement:** A C++ Compiler (g++)

## **Description:**

This repository has two programs

-   `shellcode.exe`: Inject Message Box into a exe file
-   `shellcode_dir.exe`: Inject Message Box into all exe file in a directory.

Both programs use the shellcode which is assembled from the assembly code in [asm.txt](asm.txt). Run `run.bat` to get both the executable file (`shellcode.exe` and `shellcode_dir.exe`)

## **Usage:**

Inject Message Box: shellcode.exe \<filepath\>

Restore file: shellcode.exe --restore \<filepath\> 