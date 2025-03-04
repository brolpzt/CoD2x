#include "game.h"
#include "shared.h"
#include "../shared/common.h"
#include "hwid.h"

#include <windows.h>
#include <stdio.h>
#include <string>
#include <iostream>
#include <chrono>

#include "screenshot.h"


#define clientState (*((clientState_e *)0x00609fe0))
#define sv_cheats (*((dvar_t **)0x00c5c5cc))

#define cls_realtime ((int *)0x0068A520)
#define svr_players ((int *)0x001518F80)
#define clc_stringData ((PCHAR)0x0096FD5C)
#define clc_stringOffsets ((PINT)0x0096DD5C)

#define cs0 (clc_stringData + clc_stringOffsets[0])
#define cs1 (clc_stringData + clc_stringOffsets[1])

static int clientStateLast = -1;
dvar_t *g_cod2x = NULL;
dvar_t *g_hwid = NULL;
bool firstTime = true;

// Called when the game initializes cvars (Com_Init)
void game_hook_init_cvars()
{
    //  Register USERINFO cvar that is automatically appended to the client's userinfo string sent to the server
    Dvar_RegisterInt("protocol_cod2x", APP_VERSION_PROTOCOL, APP_VERSION_PROTOCOL, APP_VERSION_PROTOCOL, (enum dvarFlags_e)(DVAR_USERINFO | DVAR_ROM));

    // Register shared cvar between client and server
    g_cod2x = Dvar_RegisterInt("g_cod2x", 0, 0, APP_VERSION_PROTOCOL, (dvarFlags_e)(DVAR_NOWRITE));
    g_hwid = Dvar_RegisterString("g_hwid", generateHWID(), (dvarFlags_e)(DVAR_NOWRITE));

    firstTime = false;
}

// Called every frame, before the original function
void game_hook_frame()
{   
    if (clientState != clientStateLast)
    {
        Com_DPrintf("Client state changed from %d:%s to %d:%s\n", clientStateLast, get_client_state_name(clientStateLast), clientState, get_client_state_name(clientState));
    }

    // Cvar is not defined yet or player disconnected from the server
    if (g_cod2x != NULL)
    {

        // Player disconnected from the server, reset the cvar
        if (g_cod2x->value.integer > 0 && clientState != clientStateLast && clientState <= CLIENT_STATE_CONNECTED)
        {
            Dvar_SetInt(g_cod2x, 0);
            g_cod2x->modified = true;
        }

        // Player just connected to 1.3 server (g_cod2x == 0)
        // Set the cvar modified so the text is printed in the console again below
        if (g_cod2x->value.integer == 0 && clientState != clientStateLast && clientState == CLIENT_STATE_ACTIVE && clientStateLast <= CLIENT_STATE_PRIMED)
        {
            g_cod2x->modified = true;
        }

        // Cvar changed (by server, init or disconenct), apply the appropriate bug fixes
        if (g_cod2x->modified)
        {
            g_cod2x->modified = false;

            Com_Printf("---------------------------------------------------------------------------------\n");
            if (g_cod2x->value.integer == 0)
            {
                Com_Printf("CoD2x: Changes turned off, using legacy CoD2 1.3\n");
            }
            else
            {
                Com_Printf("CoD2x: Changes turned on, using changes according to server version 1.4.%d.x\n", g_cod2x->value.integer);
                if (g_cod2x->value.integer != APP_VERSION_PROTOCOL)
                    Com_Printf("CoD2x: ^3Server is running older version 1.4.%d.x, your version is %s\n", g_cod2x->value.integer, APP_VERSION);
            }
            Com_Printf("---------------------------------------------------------------------------------\n");

            // Fix animation time from crouch to stand
            common_fix_clip_bug(g_cod2x->value.integer >= 1);
        }
    }

    // Enable cheats when player disconnects from the server
    // It would allow to play demos without the need to do devmap
    if (clientState != clientStateLast && clientState == CLIENT_STATE_DISCONNECTED)
    {
        Dvar_SetBool(sv_cheats, true);
    }

    clientStateLast = clientState;
}

// 00463e70  void* __stdcall Sys_ListFiles(char* directory @ eax, char* extension, char* filter @ edx, int32_t* numFiles, int32_t wantsubs)
char **Sys_ListFiles(char *extension, int32_t *numFiles, int32_t wantsubs)
{
    // Load parameters from registers
    char *directory;
    char *filter;
    ASM(movr, directory, "eax");
    ASM(movr, filter, "edx");

    // Call the original function
    const void *original_func = (void *)(0x00463e70);
    char **result;
    ASM(push, wantsubs);        // 5nd argument
    ASM(push, numFiles);        // 4nd argument
    ASM(push, extension);       // 3nd argument
    ASM(mov, "edx", filter);    // 2st argument
    ASM(mov, "eax", directory); // 1st argument
    ASM(call, original_func);
    ASM(add_esp, 12);         // Clean up the stack (3 argument × 4 bytes = 12)
    ASM(movr, result, "eax"); // Store the return value in the 'result' variable

    // When the game starts for the first time, load only the original IWD files
    // The main folder might contain mix of mods from different servers that might cause "iwd sum mismatch" errors when running the game
    // This will make sure these mods are not loaded at startup, but will be loaded when connecting to the game
    if (firstTime)
    {
        int writeIndex = 0;
        for (int i = 0; i < *numFiles; i++)
        {
            // Com_Printf("File: %s\n", result[i]);
            //  Check if file starts with "iw_00" - "iw_15" or starts with "localized_"
            if (strncmp(result[i], "iw_", 3) == 0 || strncmp(result[i], "localized_", 10) == 0)
            {
                result[writeIndex] = result[i];
                writeIndex++;
            }
        }
        *numFiles = writeIndex;
    }

    return result;
}

void game_hook()
{

    patch_call(0x00424869, (unsigned int)Sys_ListFiles);
}

char *Com_CleanHostnameColors(const char *hostname)
{
    int i = 0, j = 0;
    char *cleanedHostname = (char *)malloc(strlen(hostname) + 1); // Aloca memória para a string processada

    if (cleanedHostname == NULL)
    {
        return NULL; // Se não conseguir alocar memória, retorna NULL
    }

    while (hostname[i] != '\0')
    {
        if ((hostname[i] == '^') && ((hostname[i + 1] >= '0' && hostname[i + 1] <= '9') || (hostname[i + 1] >= 'a' && hostname[i + 1] <= 'z') || (hostname[i + 1] >= 'A' && hostname[i + 1] <= 'Z')))
        {
            i += 2; // Ignora o código de cor
        }
        else
        {
            cleanedHostname[j++] = hostname[i++]; // Copia o caractere para a nova string
        }
    }

    cleanedHostname[j] = '\0'; // Garante que a string final está terminada com '\0'
    return cleanedHostname;
}

char *Com_CleanMapName(const char *mapName)
{
    char *cleanedMapName = (char *)malloc(strlen(mapName) + 1); // Aloca memória para a string processada

    if (cleanedMapName == NULL)
    {
        return NULL; // Se não conseguir alocar memória, retorna NULL
    }

    strcpy(cleanedMapName, mapName); // Copia o conteúdo original para a nova variável

    // Verifica se o nome do mapa começa com 'mp_'
    if (strncmp(cleanedMapName, "mp_", 3) == 0)
    {
        // Remove o 'mp_' (desloca o ponteiro 3 posições)
        memmove(cleanedMapName, cleanedMapName + 3, strlen(cleanedMapName) - 2);
    }

    // Coloca a primeira letra em maiúscula e o restante em minúscula
    if (cleanedMapName[0] != '\0')
    {
        cleanedMapName[0] = toupper(cleanedMapName[0]); // Primeira letra em maiúscula
        for (int i = 1; cleanedMapName[i] != '\0'; i++)
        {
            cleanedMapName[i] = tolower(cleanedMapName[i]); // Restante em minúscula
        }
    }

    return cleanedMapName;
}