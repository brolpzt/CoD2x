#ifndef DISCORD_H
#define DISCORD_H

#include "discord_game_sdk.h"

struct Application
{
    struct IDiscordCore *core;
    struct IDiscordActivityManager *activities;
};

void UpdateActivityCallback(void *data, enum EDiscordResult result);
void SetActivity(struct Application *discord);
void discord_init();
void discord_loop();
void start_discord_thread();
void StartThreads(int numThreads);
bool is_discord_running();

#endif // DISCORD_H
