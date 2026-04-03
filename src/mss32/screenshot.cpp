#include "screenshot.h"

#include <windows.h>
#include <wincodec.h>
#include <d3d9.h>
#include <oleauto.h>
#include <cstdio>
#include <cstring>
#include <vector>

#include "hook.h"
#include "main.h"
#include "shared.h"
#include "../shared/cod2_cmd.h"
#include "../shared/cod2_dvars.h"
#include "../shared/cod2_client.h"

/* IDirect3DDevice9* em gfx_d3d_mp_x86_s.dll (R_GetScreenshot) */
#define GFX_D3D_DEVICE_RVA 0x001d1bf8

static dvar_t* cl_screenshotJpegQuality = nullptr;

static bool s_captureRequested = false;
static uint32_t s_shotSeq = 0;
static char s_pendingTag[48];

static void qpath_safe_tag(char* dest, size_t destSize, const char* src, size_t maxSrc) {
    if (destSize == 0)
        return;
    size_t n = 0;
    while (n + 1 < destSize && n < maxSrc && src[n] && src[n] != '/' && src[n] != '\\' && src[n] != ':') {
        unsigned char c = (unsigned char)src[n];
        if (c >= 32 && c != '"' && c != '*' && c != '?' && c != '<' && c != '>' && c != '|')
            dest[n] = (char)c;
        else
            dest[n] = '_';
        n++;
    }
    dest[n] = '\0';
}

/** JPEG via WIC: BGRA (D3D9), topo-esquerda. */
static bool screenshot_save_jpeg_wic(const wchar_t* wpath, const uint8_t* abgra, int srcPitch, UINT width, UINT height, float quality01) {
    IWICImagingFactory* factory = nullptr;
    IWICStream* stream = nullptr;
    IWICBitmapEncoder* encoder = nullptr;
    IWICBitmapFrameEncode* frame = nullptr;
    IPropertyBag2* props = nullptr;

    HRESULT hr = CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER, IID_IWICImagingFactory, (void**)&factory);
    if (FAILED(hr) || !factory)
        return false;

    bool ok = false;
    do {
        hr = factory->CreateStream(&stream);
        if (FAILED(hr) || !stream)
            break;
        hr = stream->InitializeFromFilename(wpath, GENERIC_WRITE);
        if (FAILED(hr))
            break;

        hr = factory->CreateEncoder(GUID_ContainerFormatJpeg, nullptr, &encoder);
        if (FAILED(hr) || !encoder)
            break;
        hr = encoder->Initialize(stream, WICBitmapEncoderNoCache);
        if (FAILED(hr))
            break;

        hr = encoder->CreateNewFrame(&frame, &props);
        if (FAILED(hr) || !frame)
            break;

        if (props && quality01 > 0.f && quality01 <= 1.f) {
            PROPBAG2 option = {};
            option.dwType = PROPBAG2_TYPE_DATA;
            option.vt = VT_R4;
            option.pstrName = L"ImageQuality";
            VARIANT var;
            VariantInit(&var);
            var.vt = VT_R4;
            var.fltVal = quality01;
            props->Write(1, &option, &var);
            VariantClear(&var);
        }

        hr = frame->Initialize(props);
        if (props) {
            props->Release();
            props = nullptr;
        }
        if (FAILED(hr))
            break;

        hr = frame->SetSize(width, height);
        if (FAILED(hr))
            break;

        WICPixelFormatGUID pixelFormat = GUID_WICPixelFormat24bppBGR;
        hr = frame->SetPixelFormat(&pixelFormat);
        if (FAILED(hr))
            break;

        const UINT stride24 = ((width * 24u + 31u) / 32u) * 4u;
        std::vector<BYTE> row(stride24);
        for (UINT y = 0; y < height; y++) {
            const uint8_t* src = abgra + (size_t)y * (size_t)srcPitch;
            for (UINT x = 0; x < width; x++) {
                row[x * 3 + 0] = src[x * 4 + 0];
                row[x * 3 + 1] = src[x * 4 + 1];
                row[x * 3 + 2] = src[x * 4 + 2];
            }
            for (UINT p = width * 3; p < stride24; p++)
                row[p] = 0;
            hr = frame->WritePixels(1, stride24, stride24, row.data());
            if (FAILED(hr))
                break;
        }
        if (FAILED(hr))
            break;

        hr = frame->Commit();
        if (FAILED(hr))
            break;
        hr = encoder->Commit();
        if (FAILED(hr))
            break;
        ok = true;
    } while (0);

    if (props)
        props->Release();
    if (frame)
        frame->Release();
    if (encoder)
        encoder->Release();
    if (stream)
        stream->Release();
    if (factory)
        factory->Release();

    return ok;
}

static bool screenshot_save_to_game_root_jpeg(const char* fileName, const uint8_t* bgra, int srcPitch, UINT width, UINT height) {
    if (!EXE_DIRECTORY_PATH[0] || !fileName || !fileName[0])
        return false;

    char dir[MAX_PATH + 16];
    if ((size_t)snprintf(dir, sizeof(dir), "%s\\screenshots", EXE_DIRECTORY_PATH) >= sizeof(dir))
        return false;

    if (!CreateDirectoryA(dir, nullptr)) {
        DWORD err = GetLastError();
        if (err != ERROR_ALREADY_EXISTS)
            return false;
    }

    char fullPath[MAX_PATH + 80];
    if ((size_t)snprintf(fullPath, sizeof(fullPath), "%s\\%s", dir, fileName) >= sizeof(fullPath))
        return false;

    wchar_t wpath[MAX_PATH + 80];
    if (MultiByteToWideChar(CP_ACP, 0, fullPath, -1, wpath, (int)(sizeof(wpath) / sizeof(wpath[0]))) <= 0)
        return false;

    int q = cl_screenshotJpegQuality ? cl_screenshotJpegQuality->value.integer : 85;
    if (q < 1)
        q = 1;
    if (q > 100)
        q = 100;
    float qf = (float)q * 0.01f;

    if (!screenshot_save_jpeg_wic(wpath, bgra, srcPitch, width, height, qf)) {
        Com_Printf("cod2x_screenshot: WIC JPEG encode failed for '%s'.\n", fullPath);
        return false;
    }

    Com_Printf("cod2x_screenshot: saved '%s'.\n", fullPath);
    return true;
}

static void cmd_cod2x_screenshot() {
    if (dedicated && dedicated->value.integer != 0) {
        Com_Printf("cod2x_screenshot: client only (renderer required).\n");
        return;
    }
    if (!gfx_module_addr) {
        Com_Printf("cod2x_screenshot: renderer not loaded yet.\n");
        return;
    }
    if (s_captureRequested) {
        Com_Printf("cod2x_screenshot: capture already scheduled.\n");
        return;
    }

    s_pendingTag[0] = '\0';
    if (Cmd_Argc() >= 2)
        qpath_safe_tag(s_pendingTag, sizeof(s_pendingTag), Cmd_Argv(1), sizeof(s_pendingTag) - 1);

    s_shotSeq++;
    s_captureRequested = true;
    if (s_pendingTag[0])
        Com_Printf("cod2x_screenshot: scheduled #%u (tag '%s').\n", s_shotSeq, s_pendingTag);
    else
        Com_Printf("cod2x_screenshot: scheduled #%u.\n", s_shotSeq);
}

void screenshot_on_drawing_end() {
    if (!s_captureRequested)
        return;
    s_captureRequested = false;

    if (dedicated && dedicated->value.integer != 0)
        return;
    if (!gfx_module_addr) {
        Com_Printf("cod2x_screenshot: gfx_module_addr is null.\n");
        return;
    }

    IDirect3DDevice9* dev = *reinterpret_cast<IDirect3DDevice9**>(gfx_module_addr + GFX_D3D_DEVICE_RVA);
    if (!dev) {
        Com_Printf("cod2x_screenshot: IDirect3DDevice9 is null.\n");
        return;
    }

    IDirect3DSurface9* backBuf = nullptr;
    HRESULT hr = dev->GetBackBuffer(0, 0, D3DBACKBUFFER_TYPE_MONO, &backBuf);
    if (FAILED(hr) || !backBuf) {
        Com_Printf("cod2x_screenshot: GetBackBuffer failed (0x%08lx).\n", (unsigned long)hr);
        return;
    }

    D3DSURFACE_DESC desc ={};
    backBuf->GetDesc(&desc);

    IDirect3DSurface9* sysMem = nullptr;
    hr = dev->CreateOffscreenPlainSurface(desc.Width, desc.Height, desc.Format, D3DPOOL_SYSTEMMEM, &sysMem, nullptr);
    if (FAILED(hr) || !sysMem) {
        Com_Printf("cod2x_screenshot: CreateOffscreenPlainSurface failed (0x%08lx).\n", (unsigned long)hr);
        backBuf->Release();
        return;
    }

    hr = dev->GetRenderTargetData(backBuf, sysMem);
    backBuf->Release();
    if (FAILED(hr)) {
        Com_Printf("cod2x_screenshot: GetRenderTargetData failed (0x%08lx).\n", (unsigned long)hr);
        sysMem->Release();
        return;
    }

    D3DLOCKED_RECT lr ={};
    hr = sysMem->LockRect(&lr, nullptr, D3DLOCK_READONLY);
    if (FAILED(hr)) {
        Com_Printf("cod2x_screenshot: LockRect failed (0x%08lx).\n", (unsigned long)hr);
        sysMem->Release();
        return;
    }

    char fileName[80];
    if (s_pendingTag[0])
        snprintf(fileName, sizeof(fileName), "cod2x_%04u_%s.jpg", s_shotSeq, s_pendingTag);
    else
        snprintf(fileName, sizeof(fileName), "cod2x_%04u.jpg", s_shotSeq);

    screenshot_save_to_game_root_jpeg(
        fileName,
        reinterpret_cast<const uint8_t*>(lr.pBits),
        lr.Pitch,
        desc.Width,
        desc.Height
    );

    sysMem->UnlockRect();
    sysMem->Release();
}

void screenshot_init() {
    s_captureRequested = false;
    s_shotSeq = 0;
    s_pendingTag[0] = '\0';
    cl_screenshotJpegQuality = Dvar_RegisterInt(
        "cl_screenshotJpegQuality",
        85,
        1,
        100,
        (enum dvarFlags_e)(DVAR_CHANGEABLE_RESET | DVAR_ARCHIVE)
    );
    Cmd_AddCommand("cod2x_screenshot", cmd_cod2x_screenshot);
}

void screenshot_unload() {
    s_captureRequested = false;
}
