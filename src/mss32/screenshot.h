#ifndef SCREENSHOT_H
#define SCREENSHOT_H

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

// Função para salvar os dados de imagem em formato JPEG
// Retorna 0 em caso de sucesso, -1 em caso de erro
int save_as_jpeg(const char *filename, unsigned char *imageData, int width, int height);

int screenshot_init();

#endif // SCREENSHOT_H
