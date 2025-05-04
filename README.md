# PE-Loader-No-API
# Manual Kernel32 API Resolver (No Imported WinAPI)

This project is a hands-on exploration into how Windows executables and DLLs function internally. Instead of relying on the typical Windows API calls like `LoadLibrary` or `GetProcAddress`, this code manually resolves exported functions from `kernel32.dll` by walking through the process's memory structures and parsing the PE (Portable Executable) format directly.

## Purpose

This was created as a personal challenge and a learning milestone. I wanted to move beyond surface-level development and understand how things really work beneath the operating system's abstractions. By removing dependencies on the Windows API, this project helped me deeply understand:

- How Windows loads and tracks DLLs using the PEB (Process Environment Block)
- How PE headers are structured and used at runtime
- How export tables store function names, ordinals, and addresses

Although I received help while learning and coding this, every line of this project has been carefully understood, tested, and studied. It's not about writing everything alone—it's about truly knowing what the code is doing and why.

## How It Works

1. Accesses the PEB via inline assembly (`fs:0x30` on x86).
2. Locates the `kernel32.dll` base address from the InMemoryOrderModuleList.
3. Parses the PE headers, validating DOS and NT signatures.
4. Locates the Export Directory and iterates through exported function names.
5. Resolves actual addresses of the functions manually in memory.

## Technical Details

- Language: C (compiled for 32-bit Windows)
- Platform: Windows (x86)(x64)
- No external libraries or Windows API calls are used to locate or resolve any function.
- PE parsing is done purely by pointer arithmetic and structure definitions.

## How to Build and Run

1. Compile the C source file using any Windows-compatible C compiler (MSVC or MinGW recommended):
2. or am giving a compiled form for example!

##SAMPLE RUN
![image](https://github.com/user-attachments/assets/34a7c468-ec4b-4ae2-9187-45029f367c44)


##FUTURE UPDATES
I'll now continue developing system level programs and you are also welcome from heart for contributions!



adios!
