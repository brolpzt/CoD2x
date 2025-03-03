#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <iphlpapi.h>
#include <netioapi.h>
#include <assert.h>
#include "hwid.h"
#include <cpuid.h>
#include <wincrypt.h>  // Para criptografia MD5

#define BUFFER_SIZE 256

// Função para obter o número de série do disco rígido
char* getHardDriveSerial() {
    static char serialNumber[BUFFER_SIZE] = {0};
    DWORD serialNumberDWORD = 0;

    // Chama GetVolumeInformation para obter o número de série
    if (GetVolumeInformation(
            "C:\\",              // Caminho da unidade (C:\)
            NULL,                // Não precisamos do nome do volume
            0,                   // Tamanho do nome do volume
            &serialNumberDWORD,  // Ponteiro para o número de série
            NULL,                // Não precisamos do comprimento máximo do componente
            NULL,                // Não precisamos de flags do sistema de arquivos
            NULL,                // Não precisamos do nome do sistema de arquivos
            0                     // Tamanho do nome do sistema de arquivos
    )) {
        // Converte o número de série para uma string hexadecimal
        snprintf(serialNumber, BUFFER_SIZE, "%08lX", serialNumberDWORD);
        return serialNumber;
    } else {
        return NULL; // Retorna NULL se falhar
    }
}

// Função para obter o ID da CPU
char* getCPUId() {
    static char cpuId[BUFFER_SIZE] = {0};
    unsigned int cpuInfo[4] = {0};

    // Verifica se __cpuid está disponível, senão utiliza uma alternativa
    __get_cpuid(0, &cpuInfo[0], &cpuInfo[1], &cpuInfo[2], &cpuInfo[3]);
    snprintf(cpuId, BUFFER_SIZE, "%X%X%X%X", cpuInfo[0], cpuInfo[1], cpuInfo[2], cpuInfo[3]);

    return cpuId;
}


// Função para gerar o HWID combinando os dados e retornando o MD5
char* generateHWID() {
    static char hwid[BUFFER_SIZE * 2] = {0};

    char* hardDriveSerial = getHardDriveSerial();
    char* cpuId = getCPUId();

    if (hardDriveSerial && cpuId) {
        snprintf(hwid, sizeof(hwid), "%s-%s", hardDriveSerial, cpuId); // Combinando os dois valores
    } else {
        snprintf(hwid, sizeof(hwid), "ERROR");
    }

    // Agora retorna o hash MD5 do HWID
    return hwid;
}
