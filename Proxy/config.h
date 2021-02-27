#pragma once

#include <windows.h>

#define CONFIG_NAME L"inslimvml.ini"
#define BEPINEX_PATH L"BepInEx\\core\\BepInEx.Preloader.dll"
#define MOD_FOLDER L"InSlimVML\\Mods\\"
#define EXE_EXTENSION_LENGTH 4

struct {
    BOOL enabled;
    BOOL redirect_output_log;
    BOOL ignore_disabled_env;
    BOOL show_modded_message;
    BOOL show_alternate_menu;
    wchar_t *mod_folder_name;
    wchar_t *mono_lib_dir;
    wchar_t *mono_config_dir;
    wchar_t *mono_corlib_dir;
} config;


void load_config();
void cleanup_config();
