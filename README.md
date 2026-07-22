### `DLLSideLoading`

- Applications installed in %LOCALAPPDATA% inherit standard user write permissions. If the executable loads dependencies without restricting the search path, a local attacker can drop a malicious DLL into the installation directory.
  
- When the application launches, the operating system loads the attacker's code, resulting in arbitrary code execution in the context of the user. This tool determines if a specific application is vulnerable to this attack vector.

### `Overview`

- Validates the target directory and locates the primary executable. It verifies the process is running as a standard, non-elevated user to ensure write-access tests reflect actual user privileges.
  
- Scans the installation tree for missing classic sideloading targets, including ***version.dll, winmm.dll, and dwmapi.dll. Missing DLLs*** represent prime candidates for the active test.
  
- Evaluates the system configuration and application manifest to determine how the operating system will resolve dependencies. It checks the ***SafeDllSearchMode registry value***, enumerates KnownDLLs to identify kernel-protected modules, and extracts the application manifest using LoadLibraryEx with ***LOAD_LIBRARY_AS_DATAFILE.***

- Attempts to create and immediately delete a zero-byte marker file in the installation root, the assets directory, and any subdirectories containing existing DLLs.

- If a writable directory and a missing classic target exist, the tool generates and compiles a benign proxy DLL.

- Instead of hardcoding export lists, the tool parses the PE Export Directory of the legitimate system DLL. It calculates the RVA-to-file-offset translation, extracts every export name, and generates a .def file that forwards them all to the module. 

### `Use`

- Compile the tool using Visual Studio or MinGW. C++17 is required for the standard filesystem library.
  

              cl /EHsc /std:c++17 sideload.cpp /link /OUT:assess.exe

MinGW:

              g++ -std:c++17 sideload_assessment.cpp -o assess.exe
            

- Run the executable from a non-elevated command prompt. Elevation will skew the write-access tests. Pass the target application's installation directory as the only argument.

              assess.exe "C:\Users\Public\TargetApp"
