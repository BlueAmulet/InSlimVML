/*
 * main.cpp -- The main "entry point" and the main logic of the DLL.
 *
 * Here, we do the main magic of the whole DLL
 * 
 * The main procedure goes as follows:
 * 0. Initialize the proxy functions
 * 1. Read configuration (whether to enable Doorstop, what .NET assembly to execute, etc)
 * 2. Find the Unity player module (it's either the game EXE or UnityPlayer.dll)
 * 3. Install IAT hook to GetProcAddress into the Unity player
 * 4. When Unity tries to resolve mono_jit_init_version, grab the mono module and return the address to init_doorstop
 * 
 * Then, the loader waits until Unity creates its root domain for mono (which is done with mono_jit_init_version).
 * 
 * Inside mono_jit_init_version hook (i.e. init_doorstop):
 * 1. Call the original mono_jit_init_version to get the Unity root domain
 * 2. Load the .NET assembly we want to run into the root domain
 * 3. Find Main() method inside the target assembly and invoke it
 * 
 * Rest of the work is done on the managed side.
 *
 */

#include "winapi_util.h"
#include <windows.h>

#include "config.h"
#include "mono.h"
#include "il2cpp.h"
#include "hook.h"
#include "assert_util.h"
#include "proxy.h"

BOOLEAN using_bepinex = FALSE;
int ignored_mods_len;
wchar_t ignored_mods[MAX_PATH * 64];

int get_ignored_mods(const wchar_t *a1, wchar_t* a2) {
    lstrcpyW(a2, L"0Harmony.dll");
    lstrcpyW(a2 + MAX_PATH, L"Vale-UI-Library.dll");
    return 2;
}

BOOLEAN check_ignored(const wchar_t* file_name, const wchar_t* ignored_mods, int len) {
    for (int i = 0; i < len; i++) {
        if (!lstrcmpiW(&ignored_mods[MAX_PATH * i], file_name)) {
            return TRUE;
        }
    }
    return FALSE;
}

// The hook for mono_jit_init_version
// We use this since it will always be called once to initialize Mono's JIT
void doorstop_invoke(void *domain) {
    size_t mods_loaded = 0;
    if (!config.ignore_disabled_env && GetEnvironmentVariableW(L"DOORSTOP_INITIALIZED", NULL, 0) != 0) {
        LOG("DOORSTOP_INITIALIZED is set! Skipping!");
        free_logger();
        return;
    }
    SetEnvironmentVariableW(L"DOORSTOP_INITIALIZED", L"TRUE");

    mono_thread_set_main(mono_thread_current());

    if (mono_domain_set_config) {
#define CONFIG_EXT L".config"

        wchar_t *exe_path = NULL;
        const size_t real_len = get_module_path(NULL, &exe_path, NULL, STR_LEN(CONFIG_EXT));
        wchar_t *folder_name = get_folder_name(exe_path, real_len, TRUE);
        wmemcpy(exe_path + real_len, CONFIG_EXT, STR_LEN(CONFIG_EXT));

        char *exe_path_n = narrow(exe_path);
        char *folder_path_n = narrow(folder_name);

        LOG("Setting config paths: base dir: %s; config path: %s\n", folder_path_n, exe_path_n);

        mono_domain_set_config(domain, folder_path_n, exe_path_n);

        free(exe_path);
        free(folder_name);
        free(exe_path_n);
        free(folder_path_n);

#undef CONFIG_EXT
    }

    ignored_mods_len = get_ignored_mods(L"0Harmony.dll, Vale-UI-Library.dll", ignored_mods);

    // Set path to managed folder dir as an env variable
    char *assembly_dir = mono_assembly_getrootdir();
    LOG("Assembly dir: %s\n", assembly_dir);

    wchar_t *wide_assembly_dir = widen(assembly_dir);
    SetEnvironmentVariableW(L"DOORSTOP_MANAGED_FOLDER_DIR", wide_assembly_dir);
    free(wide_assembly_dir);

    wchar_t *app_path = NULL;
    get_module_path(NULL, &app_path, NULL, 0);
    SetEnvironmentVariableW(L"DOORSTOP_PROCESS_PATH", app_path);

    SetEnvironmentVariableW(L"INSLIM_DISPLAY_ALTERNATE", !config.show_alternate_menu ? L"false" : L"true");
    LOG("Config Variables Set\n");

    wchar_t bepinex_path[MAX_PATH];
    memcpy(bepinex_path, BEPINEX_PATH, sizeof(BEPINEX_PATH));
    memset(&bepinex_path[_countof(BEPINEX_PATH)], 0, sizeof(bepinex_path) - sizeof(BEPINEX_PATH));

    DWORD length = GetFullPathNameW(bepinex_path, 0, NULL, NULL);
    wchar_t* bepinex_full_path = malloc(sizeof(wchar_t) * length);
    GetFullPathNameW(bepinex_path, length, bepinex_full_path, NULL);

    const int len = WideCharToMultiByte(CP_UTF8, 0, bepinex_full_path, -1, NULL, 0, NULL, NULL);
    char* dll_path = malloc(sizeof(char) * len);
    WideCharToMultiByte(CP_UTF8, 0, bepinex_full_path, -1, dll_path, len, NULL, NULL);

    LOG("\nChecking BepInEx Assembly: %s\n", dll_path);
    // Load our custom assembly into the domain
    void* assembly = mono_domain_assembly_open(domain, dll_path);

    if (assembly == NULL) {
        LOG("BepInEx Not Installed - Skipping\n");
        using_bepinex = FALSE;
        if (config.show_modded_message)
            MessageBoxW(HWND_MESSAGE, L"Modded Valheim Client Launching...\n     InSlimVML", L"InSlimVML v0.2.0", MB_SYSTEMMODAL);
        SetEnvironmentVariableW(L"INSLIM_USING_BEPINEX", L"false");
    } else {
        // Set target assembly as an environment variable for use in the managed world
        SetEnvironmentVariableW(L"DOORSTOP_INVOKE_DLL_PATH", L"BepInEx\\core\\BepInEx.Preloader.dll");

        using_bepinex = TRUE;
        LOG("Beginning BepInEx Loader...\n");

        free(dll_path);
        ASSERT_SOFT(assembly != NULL);

        // Get assembly's image that contains CIL code
        void* image = mono_assembly_get_image(assembly);
        ASSERT_SOFT(image != NULL);

        // Create a descriptor for a random Main method
        void* desc = mono_method_desc_new("*:Main", FALSE);

        // Find the first possible Main method in the assembly
        void* method = mono_method_desc_search_in_image(desc, image);
        ASSERT_SOFT(method != NULL);

        void* signature = mono_method_signature(method);

        // Get the number of parameters in the signature
        UINT32 params = mono_signature_get_param_count(signature);

        // Note: we use the runtime_invoke route since jit_exec will not work on DLLs
        LOG("Invoking Entry Method %p\n", method);
        void* exc = NULL;
        mono_runtime_invoke(method, NULL, NULL, &exc);
        if (exc != NULL) {
            LOG("Error invoking code!\n");
            if (mono_object_to_string)
            {
                void* str = mono_object_to_string(exc, NULL);
                char* exc_str = mono_string_to_utf8(str);
                LOG("Error message: %s\n", exc_str);
            }
        }
        LOG("BepInEx Load Is Done!\n");

        // cleanup method_desc
        mono_method_desc_free(desc);
        if (using_bepinex) {
            if (config.show_modded_message)
                MessageBoxW(NULL, L"Modded Valheim Client Launching...\n     InSlimVML + BepInEx", L"InSlimVML v0.2.0", MB_SYSTEMMODAL);
            SetEnvironmentVariableW(L"INSLIM_USING_BEPINEX", L"true");
        } else {
            if (config.show_modded_message)
                MessageBoxW(HWND_MESSAGE, L"Modded Valheim Client Launching...\n     InSlimVML", L"InSlimVML v0.2.0", MB_SYSTEMMODAL);
            SetEnvironmentVariableW(L"INSLIM_USING_BEPINEX", L"false");
        }
    }

    WIN32_FIND_DATAW ffd;
    HANDLE hFind = FindFirstFileW(config.mod_folder_name, &ffd);
    if (hFind != INVALID_HANDLE_VALUE) {
        LOG("\nBeginning InSlimVML Loader...!\n");
        do {
            if (check_ignored(ffd.cFileName, ignored_mods, ignored_mods_len) == TRUE) {
                LOG("Ignoring mod: %s\n", ffd.cFileName);
            } else {
                wchar_t mod_path[MAX_PATH];
                memcpy(mod_path, MOD_FOLDER, sizeof(MOD_FOLDER));
                memset(&mod_path[_countof(MOD_FOLDER)], 0, sizeof(mod_path) - sizeof(MOD_FOLDER));

                wchar_t *mod_path2 = lstrcatW(mod_path, ffd.cFileName);
                DWORD length = GetFullPathNameW(mod_path2, 0, NULL, NULL);
                wchar_t* mod_full_path = malloc(sizeof(wchar_t) * length);
                GetFullPathNameW(mod_path2, length, mod_full_path, NULL);

                const int len = WideCharToMultiByte(CP_UTF8, 0, mod_full_path, -1, NULL, 0, NULL, NULL);
                char* dll_path = malloc(sizeof(char) * len);
                WideCharToMultiByte(CP_UTF8, 0, mod_full_path, -1, dll_path, len, NULL, NULL);

                LOG("Loading InSlim Assembly: %s\n", dll_path);
                // Load our custom assembly into the domain
                void* assembly = mono_domain_assembly_open(domain, dll_path);

                if (assembly == NULL)
                    LOG("Failed to load assembly\n");

                free(dll_path);
                ASSERT_SOFT(assembly != NULL);

                // Get assembly's image that contains CIL code
                void* image = mono_assembly_get_image(assembly);
                ASSERT_SOFT(image != NULL);

                // Create a descriptor for a random Main method
                LOG("Entrypoint Attempt: %s\n", "*:Main");
                void* desc = mono_method_desc_new("*:Main", FALSE);

                // Find the first possible Main method in the assembly
                void* method = mono_method_desc_search_in_image(desc, image);
                if (method == NULL)
                    LOG("Method Not Found: %p\n", method);
                ASSERT_SOFT(method != NULL);

                void* signature = mono_method_signature(method);

                // Get the number of parameters in the signature
                UINT32 params = mono_signature_get_param_count(signature);

                void** args = NULL;
                if (params == 1) {
                    // If there is a parameter, it's most likely a string[].
                    void* args_array = mono_array_new(domain, mono_get_string_class(), 0);
                    args = malloc(sizeof(void*) * 1);
                    args[0] = args_array;
                }

                // Note: we use the runtime_invoke route since jit_exec will not work on DLLs
                LOG("Invoking method %p\n", method);
                void* exc = NULL;
                mono_runtime_invoke(method, NULL, args, &exc);
                if (exc != NULL) {
                    LOG("Error invoking code!\n");
                    if (mono_object_to_string)
                    {
                        void* str = mono_object_to_string(exc, NULL);
                        char* exc_str = mono_string_to_utf8(str);
                        LOG("Error message: %s\n", exc_str);
                    }
                }

                // cleanup method_desc
                mono_method_desc_free(desc);

                if (args != NULL) {
                    free(args);
                    args = NULL;
                }

                mods_loaded++;
                VERBOSE_ONLY({
                    DWORD length = GetFullPathNameW(ffd.cFileName, 0, NULL, NULL);
                    wchar_t* mod_full_path = malloc(sizeof(wchar_t) * length);
                    GetFullPathNameW(ffd.cFileName, length, mod_full_path, NULL);
                    LOG("%s: InSlim Mod Loaded #%d\n", mod_full_path, mods_loaded);
                    });
            }
        } while (FindNextFileW(hFind, &ffd) != 0);
        LOG("\nInSlim Mods Loaded! [%d]\n", mods_loaded);
    }
    FindClose(hFind);

    free(app_path);
    free_logger();
}

int init_doorstop_il2cpp(const char *domain_name) {
    LOG("Starting IL2CPP domain \"%s\"\n", domain_name);
    const int orig_result = il2cpp_init(domain_name);

    wchar_t *mono_lib_dir = get_full_path(config.mono_lib_dir);
    wchar_t *mono_corlib_dir = get_full_path(config.mono_corlib_dir);
    wchar_t *mono_config_dir = get_full_path(config.mono_config_dir);

    LOG("Mono lib: %S\n", mono_lib_dir);
    LOG("Mono mscorlib dir: %S\n", mono_corlib_dir);
    LOG("Mono confgi dir: %S\n", mono_config_dir);

    if (!file_exists(mono_lib_dir) || !folder_exists(mono_corlib_dir) || !folder_exists(mono_config_dir)) {
        LOG("Mono startup dirs are not set up, skipping invoking Doorstop\n");
        return orig_result;
    }

    const HMODULE mono_module = LoadLibraryW(mono_lib_dir);
    LOG("Loaded mono.dll: %p\n", mono_module);
    if (!mono_module) {
        LOG("Failed to load mono.dll! Skipping!");
        return orig_result;
    }

    load_mono_functions(mono_module);
    LOG("Loaded mono.dll functions\n");

    char *mono_corlib_dir_narrow = narrow(mono_corlib_dir);
    char *mono_config_dir_narrow = narrow(mono_config_dir);
    mono_set_dirs(mono_corlib_dir_narrow, mono_config_dir_narrow);
    mono_set_assemblies_path(mono_corlib_dir_narrow);
    mono_config_parse(NULL);

    void *domain = mono_jit_init_version("Doorstop Root Domain", NULL);
    LOG("Created domain: %p\n", domain);

    doorstop_invoke(domain);

    return orig_result;
}

void *init_doorstop_mono(const char *root_domain_name, const char *runtime_version) {
    LOG("Starting Mono domain \"%s\"\n", root_domain_name);
    void *domain = mono_jit_init_version(root_domain_name, runtime_version);
    doorstop_invoke(domain);
    return domain;
}

static BOOL initialized = FALSE;

void * WINAPI get_proc_address_detour(HMODULE module, char const *name) {
#define REDIRECT_INIT(init_name, init_func, target)                 \
    if (lstrcmpA(name, init_name) == 0) {                           \
        if (!initialized) {                                         \
            initialized = TRUE;                                     \
            LOG("Got %s at %p\n", init_name, module);               \
            init_func(module);                                      \
            LOG("Loaded all runtime functions\n")                   \
        }                                                           \
        return (void*)(target);                                     \
    }
    REDIRECT_INIT("il2cpp_init", load_il2cpp_functions, init_doorstop_il2cpp);
    REDIRECT_INIT("mono_jit_init_version", load_mono_functions, init_doorstop_mono);
    return (void*)GetProcAddress(module, name);

#undef REDIRECT_INIT
}

HANDLE stdout_handle = NULL;
BOOL WINAPI close_handle_hook(HANDLE handle) {
    if (stdout_handle && handle == stdout_handle)
        return TRUE;
    return CloseHandle(handle);
}

wchar_t *new_cmdline_args = NULL;
char *cmdline_args_narrow = NULL;
LPWSTR WINAPI get_command_line_hook() {
    if (new_cmdline_args)
        return new_cmdline_args;
    return GetCommandLineW();
}

LPSTR WINAPI get_command_line_hook_narrow() {
    if (cmdline_args_narrow)
        return cmdline_args_narrow;
    return GetCommandLineA();
}

#define LOG_FILE_CMD_START L" -logFile \""
#define LOG_FILE_CMD_START_LEN STR_LEN(LOG_FILE_CMD_START)

#define LOG_FILE_CMD_END L"\\output_log.txt\""
#define LOG_FILE_CMD_END_LEN STR_LEN(LOG_FILE_CMD_END)

// ReSharper disable once CppParameterNeverUsed
BOOL WINAPI DllEntry(HINSTANCE hInstDll, DWORD reasonForDllLoad, LPVOID reserved) {
    if (reasonForDllLoad == DLL_PROCESS_DETACH)
        SetEnvironmentVariableW(L"DOORSTOP_DISABLE", NULL);
    if (reasonForDllLoad != DLL_PROCESS_ATTACH)
        return TRUE;

    h_heap = GetProcessHeap();

    wchar_t *app_path = NULL;
    const size_t app_path_len = get_module_path(NULL, &app_path, NULL, 0);
    wchar_t *app_dir = get_folder_name(app_path, app_path_len, FALSE);
    BOOL fixedCWD = FALSE;

    wchar_t *working_dir = NULL;
    get_working_dir(&working_dir);

    if (lstrcmpiW(app_dir, working_dir) != 0) {
        fixedCWD = TRUE;
        SetCurrentDirectoryW(app_dir);
    }

    init_logger();

    LOG("InSlimVML started!\n");

    LOG("EXE Path: %S\n", app_path);
    LOG("App dir: %S\n", app_dir);
    LOG("Working dir: %S\n", working_dir);

    if (fixedCWD) { LOG("WARNING: Working directory is not the same as app directory! Fixing working directory!\n"); }

    stdout_handle = GetStdHandle(STD_OUTPUT_HANDLE);

    wchar_t *dll_path = NULL;
    const size_t dll_path_len = get_module_path(hInstDll, &dll_path, NULL, 0);
    LOG("DLL Path: %S\n", dll_path);

    wchar_t *dll_name = get_file_name_no_ext(dll_path, dll_path_len);
    LOG("Doorstop DLL Name: %S\n", dll_name);

    load_proxy(dll_name);
    LOG("Proxy loaded\n");
    load_config();
    LOG("Config loaded\n");

    if (config.redirect_output_log) {
        wchar_t *cmd = GetCommandLineW();
        const size_t app_dir_len = wcslen(app_dir);
        const size_t cmd_len = wcslen(cmd);
        const size_t new_cmd_size = cmd_len + LOG_FILE_CMD_START_LEN + app_path_len + LOG_FILE_CMD_END_LEN + 1024;
        new_cmdline_args = calloc(new_cmd_size, sizeof(wchar_t));
        // Add some padding in case some hook does the "conventional" replace
        wmemcpy(new_cmdline_args, cmd, cmd_len);
        wmemcpy(new_cmdline_args + cmd_len, LOG_FILE_CMD_START, LOG_FILE_CMD_START_LEN);
        wmemcpy(new_cmdline_args + cmd_len + LOG_FILE_CMD_START_LEN - 1, app_dir, app_dir_len);
        wmemcpy(new_cmdline_args + cmd_len + LOG_FILE_CMD_START_LEN + app_dir_len - 1, LOG_FILE_CMD_END,
                LOG_FILE_CMD_END_LEN);
        cmdline_args_narrow = narrow(new_cmdline_args);

        LOG("Redirected output log!\n");
        LOG("CMDLine: %S\n", new_cmdline_args);
    }

    // If the loader is disabled, don't inject anything.
    if (config.enabled) {
        LOG("InSlimVML enabled!\n");

        HMODULE target_module = GetModuleHandleA("UnityPlayer");
        const HMODULE app_module = GetModuleHandleA(NULL);

        if (!target_module) {
            LOG("No UnityPlayer.dll; using EXE as the hook target.");
            target_module = app_module;
        }

        LOG("Installing IAT hook\n");
        if (!iat_hook(target_module, "kernel32.dll", &GetProcAddress, &get_proc_address_detour) ||
            !iat_hook(target_module, "kernel32.dll", &CloseHandle, &close_handle_hook) ||
            !iat_hook(app_module, "kernel32.dll", &GetCommandLineW, &get_command_line_hook) ||
            !iat_hook(app_module, "kernel32.dll", &GetCommandLineA, &get_command_line_hook_narrow) ||
            target_module != app_module && (
                !iat_hook(target_module, "kernel32.dll", &GetCommandLineW, &get_command_line_hook) ||
                !iat_hook(target_module, "kernel32.dll", &GetCommandLineA, &get_command_line_hook_narrow)
            )) {
            LOG("Failed to install IAT hook!\n");
            free_logger();
        }
        else {
            LOG("Hook installed!!\n");
            // Prevent other instances of Doorstop running in the same process
            SetEnvironmentVariableW(L"DOORSTOP_DISABLE", L"TRUE");
        }
    }
    else {
        LOG("InSlimVML disabled! freeing resources\n");
        free_logger();
    }

    free(dll_name);
    free(dll_path);
    free(app_dir);
    free(app_path);
    free(working_dir);

    return TRUE;
}
