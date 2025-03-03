#include "discord.h"
#include <cstring>
#include <cstdio>
#include <cassert>
#include "game.h"
#include "shared.h"
#include "../shared/common.h"
#include <tlhelp32.h>
#include <stdbool.h>
#include <stdio.h>


#define DISCORD_REQUIRE(x) assert(x == DiscordResult_Ok)
#define clientState (*((clientState_e *)0x00609fe0))

#define svr_players ((int *)0x001518F80)
#define clc_stringData ((PCHAR)0x0096FD5C)
#define clc_stringOffsets ((PINT)0x0096DD5C)

#define cs0 (clc_stringData + clc_stringOffsets[0])
#define cs1 (clc_stringData + clc_stringOffsets[1])

static struct Application discord;
static bool discordInitialized = false;

CRITICAL_SECTION criticalSection;
bool stopThreads = false;
HANDLE threadHandles[3];

struct ActivityData
{
    char details[256];
    char state[256];
    char largeImage[256];
    char map[128];
    char gametype[128];
    char hostname[128];
};

// Declaração global da estrutura
ActivityData ActivityData;

bool is_discord_running()
{
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    bool found = false;

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
        return false;

    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hProcessSnap, &pe32))
    {
        do
        {
            if (_stricmp(pe32.szExeFile, "Discord.exe") == 0)
            {
                found = true;
                break;
            }
        } while (Process32Next(hProcessSnap, &pe32));
    }
    CloseHandle(hProcessSnap);
    return found;
}

void UpdateActivityCallback(void *data, enum EDiscordResult result)
{
    DISCORD_REQUIRE(result);
}

void SetActivity(struct Application *discord)
{
    struct DiscordActivity activity;
    memset(&activity, 0, sizeof(activity));

    // Definindo detalhes e estado da atividade
    sprintf(activity.name, "Call of Duty 2 X");
    sprintf(activity.details, ActivityData.details);
    sprintf(activity.assets.large_image, "cod2_fw");
    sprintf(activity.state, ActivityData.state);

    // Atualiza a atividade no Discord
    discord->activities->update_activity(discord->activities, &activity, discord, UpdateActivityCallback);
}

// Inicializa o Discord e define a atividade
void discord_init()
{
    if (!discordInitialized)
    {
        memset(&discord, 0, sizeof(discord));

        // Inicializa o Discord
        struct DiscordCreateParams params;
        DiscordCreateParamsSetDefault(&params);
        params.client_id = 1345907074638417991; // Substitua com seu client_id
        params.flags = DiscordCreateFlags_Default;
        DISCORD_REQUIRE(DiscordCreate(DISCORD_VERSION, &params, &discord.core));

        // Obtém o gerenciador de atividades
        discord.activities = discord.core->get_activity_manager(discord.core);

        discordInitialized = true;
    }
}

void start_discord_thread()
{
    int numThreads = 3;
    StartThreads(numThreads);
}

void discord_loop()
{
    if (is_discord_running()) {
        discord_init();
    }

    if (discordInitialized)
    {
        // Atualiza a imagem grande e os detalhes padrões
        snprintf(ActivityData.largeImage, sizeof(ActivityData.largeImage), "cod2_fw");

        strcpy(ActivityData.hostname, Com_CleanHostnameColors(Info_ValueForKey(cs0, "sv_hostname")));
        strcpy(ActivityData.map, Com_CleanMapName(Info_ValueForKey(cs0, "mapname")));
        strcpy(ActivityData.gametype, Info_ValueForKey(cs0, "g_gametype")); // Coloque a lógica real para definir o tipo de jogo

        // Atualiza o estado dependendo do clientState
        switch (clientState)
        {
        case CLIENT_STATE_DISCONNECTED:
            snprintf(ActivityData.details, sizeof(ActivityData.details), "Looking to play");
            break;
        case CLIENT_STATE_CINEMATIC:
            memset(ActivityData.details, 0, sizeof(ActivityData.details));
            break;
        case CLIENT_STATE_AUTHORIZING:
            snprintf(ActivityData.details, sizeof(ActivityData.details), "Authorizing server");
            break;
        case CLIENT_STATE_CONNECTING:
            snprintf(ActivityData.details, sizeof(ActivityData.details), "Connecting to a server");
            break;
        case CLIENT_STATE_CHALLENGING:
            snprintf(ActivityData.details, sizeof(ActivityData.details), "Challenging with a server");
            break;
        case CLIENT_STATE_CONNECTED:
            snprintf(ActivityData.details, sizeof(ActivityData.details), "Connected to a server");
            break;
        case CLIENT_STATE_LOADING:
            snprintf(ActivityData.details, sizeof(ActivityData.details), "Loading to a server");
            break;
        case CLIENT_STATE_PRIMED:
            memset(ActivityData.details, 0, sizeof(ActivityData.details));
            break;
        case CLIENT_STATE_ACTIVE:
            snprintf(ActivityData.details, sizeof(ActivityData.details), "Playing %s (%s) on %s", ActivityData.map, ActivityData.gametype, ActivityData.hostname);
            snprintf(ActivityData.state, sizeof(ActivityData.largeImage), "Players Online: %d/%s\n", *svr_players, Info_ValueForKey(cs0, "sv_maxclients"));
            break;
        default:
            memset(ActivityData.details, 0, sizeof(ActivityData.details));
            break;
        }

        // Atualiza a atividade no Discord
        SetActivity(&discord);

        // Chama os callbacks do Discord
        DISCORD_REQUIRE(discord.core->run_callbacks(discord.core));
    }
}

// Função executada por cada thread
DWORD WINAPI DiscordThread(LPVOID lpParam) {
    while (!stopThreads) {
        EnterCriticalSection(&criticalSection);
        discord_loop();
        LeaveCriticalSection(&criticalSection);
        Sleep(15000);
    }
    return 0;
}

void StartThreads(int numThreads) {
    InitializeCriticalSection(&criticalSection);
    for (int i = 0; i < numThreads; ++i) {
        int* threadID = (int*)malloc(sizeof(int));
        *threadID = i + 1;
        threadHandles[i] = CreateThread(NULL, 0, DiscordThread, threadID, 0, NULL);
        if (!threadHandles[i]) {
            free(threadID);
        }
    }
}

void StopThreads(int numThreads) {
    stopThreads = true;
    WaitForMultipleObjects(numThreads, threadHandles, TRUE, INFINITE);
    for (int i = 0; i < numThreads; ++i) {
        CloseHandle(threadHandles[i]);
    }
    DeleteCriticalSection(&criticalSection);
}