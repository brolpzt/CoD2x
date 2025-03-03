#ifndef GAME_H
#define GAME_H

void game_hook_init_cvars();
void game_hook_frame();
void game_hook();

char* Com_CleanHostnameColors(const char *hostname);
char* Com_CleanMapName(const char *mapName);

#endif