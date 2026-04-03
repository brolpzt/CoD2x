#include "screenshot.h"

#include <windows.h>
#include <objidl.h>
#include <wincodec.h>
#include <d3d9.h>
#include <oleauto.h>
#include <cstdio>
#include <cstring>
#include <vector>
#include <atomic>
#include <thread>

#include "hook.h"
#include "shared.h"
#include "../shared/cod2_dvars.h"
#include "../shared/cod2_client.h"
#include "../shared/cod2_net.h"

#define cl_serverAddress (*((netaddr_s*)0x0064a1a8))

extern dvar_t* sv_screenshotQuality;
extern dvar_t* sv_screenshotJpgPaceMs;
extern dvar_t* sv_screenshotJpgLowPriority;
extern dvar_t* cl_hwid;
extern dvar_t* cl_hwid2;

/**
 * Client screenshot console: off when NDEBUG is set (Release / production mss32 build).
 * Debug builds omit NDEBUG so messages still appear. Use: mingw32-make build_win DEBUG=1
 */
#if !defined(NDEBUG)
#define SCREENSHOT_CLIENT_LOG(...) Com_Printf(__VA_ARGS__)
#define SCREENSHOT_CLIENT_DLOG(...) Com_DPrintf(__VA_ARGS__)
#else
#define SCREENSHOT_CLIENT_LOG(...) ((void)0)
#define SCREENSHOT_CLIENT_DLOG(...) ((void)0)
#endif

static constexpr uint32_t SCREENSHOT_JPG_CHUNK = 1200;

static std::atomic<bool> s_screenshotJpgSendBusy{false};

/* IDirect3DDevice9* in gfx_d3d_mp_x86_s.dll (see R_GetScreenshot). */
#define GFX_D3D_DEVICE_RVA 0x001d1bf8

static bool s_captureRequested = false;

static void screenshot_start_background_jpeg_upload(std::vector<uint8_t> bgra, int pitch, UINT w, UINT h, netaddr_s adr);

/** dedicated 0 = client/listen; 1 = LAN dedicated; 2 = internet dedicated — no client renderer. */
static bool screenshot_disabled_on_dedicated(void)
{
    return dedicated != nullptr && dedicated->value.integer != 0;
}

/** Strip control characters and tabs for a single COM segment (TAB-separated fields). */
static void screenshot_com_sanitize_field(char* dst, size_t dstCap, const char* src)
{
    if (dstCap == 0)
        return;
    size_t w = 0;
    if (src) {
        for (; *src && w + 1 < dstCap; ++src) {
            unsigned char c = (unsigned char)*src;
            if (c == '\t' || c == '\n' || c == '\r')
                dst[w++] = ' ';
            else if (c >= 32u && c != 127u)
                dst[w++] = (char)c;
        }
    }
    dst[w] = '\0';
}

/**
 * Insert JPEG COM segment (0xFFFE) immediately after SOI. UTF-8 text payload, kept small.
 * Ls = 2 + payloadLen (big-endian); includes the 2-byte Ls field.
 */
static bool screenshot_jpeg_insert_com_after_soi(std::vector<uint8_t>& jpeg, const uint8_t* payload, size_t payloadLen)
{
    if (jpeg.size() < 2 || jpeg[0] != 0xFF || jpeg[1] != 0xD8)
        return false;
    if (payloadLen > 65533u)
        return false;
    const uint32_t Ls = (uint32_t)(2u + payloadLen);
    if (Ls > 65535u)
        return false;
    uint8_t seg[4];
    seg[0] = 0xFF;
    seg[1] = 0xFE;
    seg[2] = (uint8_t)((Ls >> 8) & 0xFF);
    seg[3] = (uint8_t)(Ls & 0xFF);
    jpeg.insert(jpeg.begin() + 2, seg, seg + 4);
    jpeg.insert(jpeg.begin() + 6, payload, payload + payloadLen);
    return true;
}

/**
 * Format: C2x2\\t<name>\\t<cl_hwid>\\t<cl_hwid2> (HWID2 max 32).
 * Player ip:port (UDP source) is appended to this COM by the server when saving the file.
 */
static void screenshot_jpeg_embed_player_com(std::vector<uint8_t>& jpeg)
{
    char nameBuf[96];
    char h2Buf[40];
    screenshot_com_sanitize_field(nameBuf, sizeof(nameBuf), Dvar_GetString("name"));
    const int h1 = cl_hwid ? cl_hwid->value.integer : 0;
    const char* raw2 = (cl_hwid2 && cl_hwid2->value.string) ? cl_hwid2->value.string : "";
    screenshot_com_sanitize_field(h2Buf, sizeof(h2Buf), raw2);
    if (strlen(h2Buf) > 32)
        h2Buf[32] = '\0';

    char payload[512];
    const int n = snprintf(payload, sizeof(payload), "C2x2\t%s\t%d\t%s", nameBuf, h1, h2Buf);
    if (n <= 0 || (size_t)n >= sizeof(payload))
        return;
    if (!screenshot_jpeg_insert_com_after_soi(jpeg, reinterpret_cast<const uint8_t*>(payload), (size_t)n))
        SCREENSHOT_CLIENT_DLOG("screenshot: COM segment not inserted.\n");
}

/** Encode JPEG in memory (WIC + IStream). */
static bool screenshot_encode_jpeg_wic_memory(const uint8_t* abgra, int srcPitch, UINT width, UINT height, float quality01,
                                              std::vector<uint8_t>& out)
{
    out.clear();
    IStream* istream = nullptr;
    if (FAILED(CreateStreamOnHGlobal(nullptr, TRUE, &istream)) || !istream)
        return false;

    IWICImagingFactory* factory = nullptr;
    IWICStream* wstream = nullptr;
    IWICBitmapEncoder* encoder = nullptr;
    IWICBitmapFrameEncode* frame = nullptr;
    IPropertyBag2* props = nullptr;

    HRESULT hr = CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER, IID_IWICImagingFactory,
                                  (void**)&factory);
    if (FAILED(hr) || !factory) {
        istream->Release();
        return false;
    }

    bool ok = false;
    do {
        hr = factory->CreateStream(&wstream);
        if (FAILED(hr) || !wstream)
            break;
        hr = wstream->InitializeFromIStream(istream);
        if (FAILED(hr))
            break;

        hr = factory->CreateEncoder(GUID_ContainerFormatJpeg, nullptr, &encoder);
        if (FAILED(hr) || !encoder)
            break;
        hr = encoder->Initialize(wstream, WICBitmapEncoderNoCache);
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
    if (wstream)
        wstream->Release();
    if (factory)
        factory->Release();

    if (!ok) {
        istream->Release();
        return false;
    }

    LARGE_INTEGER zero{};
    ULARGE_INTEGER uli{};
    hr = istream->Seek(zero, STREAM_SEEK_END, &uli);
    if (FAILED(hr) || uli.QuadPart == 0 || uli.QuadPart > (ULONGLONG)(8 * 1024 * 1024)) {
        istream->Release();
        return false;
    }
    hr = istream->Seek(zero, STREAM_SEEK_SET, nullptr);
    if (FAILED(hr)) {
        istream->Release();
        return false;
    }
    out.resize((size_t)uli.QuadPart);
    ULONG br = 0;
    hr = istream->Read(out.data(), (ULONG)uli.QuadPart, &br);
    istream->Release();
    if (FAILED(hr) || br != uli.QuadPart) {
        out.clear();
        return false;
    }
    return true;
}

/** Copy backbuffer to RAM (BGRA). */
static bool screenshot_grab_backbuffer(std::vector<uint8_t>& bgra, int* outPitch, UINT* outW, UINT* outH)
{
    if (screenshot_disabled_on_dedicated() || !gfx_module_addr)
        return false;

    IDirect3DDevice9* dev = *reinterpret_cast<IDirect3DDevice9**>(gfx_module_addr + GFX_D3D_DEVICE_RVA);
    if (!dev)
        return false;

    IDirect3DSurface9* backBuf = nullptr;
    HRESULT hr = dev->GetBackBuffer(0, 0, D3DBACKBUFFER_TYPE_MONO, &backBuf);
    if (FAILED(hr) || !backBuf)
        return false;

    D3DSURFACE_DESC desc = {};
    backBuf->GetDesc(&desc);

    IDirect3DSurface9* sysMem = nullptr;
    hr = dev->CreateOffscreenPlainSurface(desc.Width, desc.Height, desc.Format, D3DPOOL_SYSTEMMEM, &sysMem, nullptr);
    if (FAILED(hr) || !sysMem) {
        backBuf->Release();
        return false;
    }

    hr = dev->GetRenderTargetData(backBuf, sysMem);
    backBuf->Release();
    if (FAILED(hr)) {
        sysMem->Release();
        return false;
    }

    D3DLOCKED_RECT lr = {};
    hr = sysMem->LockRect(&lr, nullptr, D3DLOCK_READONLY);
    if (FAILED(hr)) {
        sysMem->Release();
        return false;
    }

    const size_t nbytes = (size_t)lr.Pitch * (size_t)desc.Height;
    bgra.resize(nbytes);
    memcpy(bgra.data(), lr.pBits, nbytes);

    *outPitch = lr.Pitch;
    *outW = desc.Width;
    *outH = desc.Height;

    sysMem->UnlockRect();
    sysMem->Release();
    return true;
}

void screenshot_schedule_capture(void)
{
    if (screenshot_disabled_on_dedicated())
        return;
    if (!gfx_module_addr) {
        SCREENSHOT_CLIENT_LOG("screenshot: gfx not loaded yet; join a map and try again.\n");
        return;
    }
    if (s_captureRequested)
        return;

    s_captureRequested = true;
}

void screenshot_on_drawing_end() {
    if (!s_captureRequested)
        return;
    s_captureRequested = false;

    if (clientState < CLIENT_STATE_CONNECTED) {
        SCREENSHOT_CLIENT_LOG("screenshot (getss): ignored — not connected to a server.\n");
        return;
    }

    const netaddr_s adr = cl_serverAddress;
    if (adr.type == NA_BAD || adr.type == NA_INIT) {
        SCREENSHOT_CLIENT_LOG("screenshot (getss): invalid server address.\n");
        return;
    }

    if (s_screenshotJpgSendBusy.exchange(true)) {
        SCREENSHOT_CLIENT_LOG("screenshot (getss): ignored — JPEG upload already in progress (another getss).\n");
        return;
    }

    std::vector<uint8_t> bgra;
    int pitch = 0;
    UINT width = 0, height = 0;
    if (!screenshot_grab_backbuffer(bgra, &pitch, &width, &height)) {
        s_screenshotJpgSendBusy.store(false);
        SCREENSHOT_CLIENT_LOG("screenshot (getss): capture failed (join a map with a 3D view).\n");
        return;
    }

    SCREENSHOT_CLIENT_LOG("screenshot (getss): encoding and uploading to server...\n");
    screenshot_start_background_jpeg_upload(std::move(bgra), pitch, width, height, adr);
}

void screenshot_init() {
    s_captureRequested = false;
    /* Quality / pacing / thread priority: sv_* cvars registered in server_init() (DVAR_SYSTEMINFO). */
}

void screenshot_unload() {
    s_captureRequested = false;
    s_screenshotJpgSendBusy.store(false);
}

static bool screenshot_net_send_jpeg_chunks(netaddr_s adr, const uint8_t* data, uint32_t total_size)
{
    if (!data || total_size == 0 || total_size > (uint32_t)(8 * 1024 * 1024))
        return false;

    const uint32_t total_chunks = (total_size + SCREENSHOT_JPG_CHUNK - 1u) / SCREENSHOT_JPG_CHUNK;
    const uint32_t sid = (uint32_t)GetTickCount() ^ ((uint32_t)GetCurrentProcessId() << 16);
    uint8_t packet[4 + 128 + SCREENSHOT_JPG_CHUNK];

    for (uint32_t seq = 0; seq < total_chunks; seq++) {
        const uint32_t offset = seq * SCREENSHOT_JPG_CHUNK;
        uint32_t chunk_len = total_size - offset;
        if (chunk_len > SCREENSHOT_JPG_CHUNK)
            chunk_len = SCREENSHOT_JPG_CHUNK;

        char line[112];
        const int ln = snprintf(line, sizeof(line), "screenshot_jpg %u %u %u %u %u\n",
            sid, seq, total_chunks, total_size, chunk_len);
        if (ln <= 0 || ln >= (int)sizeof(line)) {
            SCREENSHOT_CLIENT_LOG("screenshot_jpg: OOB line too long.\n");
            return false;
        }

        const int line_len = (int)strlen(line);
        const int pktlen = 4 + line_len + (int)chunk_len;
        if (pktlen > (int)sizeof(packet)) {
            SCREENSHOT_CLIENT_LOG("screenshot_jpg: internal packet too large.\n");
            return false;
        }

        memcpy(packet, "\xff\xff\xff\xff", 4);
        memcpy(packet + 4, line, (size_t)line_len);
        memcpy(packet + 4 + (size_t)line_len, data + offset, chunk_len);

        if (!NET_SendPacket(NS_CLIENT, pktlen, packet, adr)) {
            SCREENSHOT_CLIENT_LOG("screenshot_jpg: NET_SendPacket failed on chunk %u\n", seq);
            return false;
        }

        int paceMs = sv_screenshotJpgPaceMs ? sv_screenshotJpgPaceMs->value.integer : 2;
        if (paceMs < 0)
            paceMs = 0;
        if (paceMs > 50)
            paceMs = 50;
        if (paceMs > 0 && seq + 1u < total_chunks)
            Sleep((DWORD)paceMs);
        else if (paceMs == 0 && (seq & 7u) == 7u)
            Sleep(0);
    }

    SCREENSHOT_CLIENT_LOG("screenshot_jpg: upload finished %u bytes (%u chunks), session %u.\n",
               total_size, total_chunks, sid);
    return true;
}

static void screenshot_start_background_jpeg_upload(std::vector<uint8_t> bgra, int pitch, UINT w, UINT h, netaddr_s adr)
{
    std::thread([bgra = std::move(bgra), pitch, w, h, adr]() {
        struct BusyClear {
            std::atomic<bool>& flag;
            explicit BusyClear(std::atomic<bool>& b) : flag(b) {}
            ~BusyClear() { flag.store(false); }
        } clear(s_screenshotJpgSendBusy);

        CoInitializeEx(nullptr, COINIT_MULTITHREADED);

        if (sv_screenshotJpgLowPriority && sv_screenshotJpgLowPriority->value.boolean)
            SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);

        int q = sv_screenshotQuality ? sv_screenshotQuality->value.integer : 85;
        if (q < 1)
            q = 1;
        if (q > 100)
            q = 100;
        const float qf = (float)q * 0.01f;

        std::vector<uint8_t> jpeg;
        if (!screenshot_encode_jpeg_wic_memory(bgra.data(), pitch, w, h, qf, jpeg)) {
            SCREENSHOT_CLIENT_LOG("screenshot: JPEG encoding failed.\n");
            CoUninitialize();
            return;
        }

        screenshot_jpeg_embed_player_com(jpeg);

        screenshot_net_send_jpeg_chunks(adr, jpeg.data(), (uint32_t)jpeg.size());
        CoUninitialize();
    }).detach();
}

