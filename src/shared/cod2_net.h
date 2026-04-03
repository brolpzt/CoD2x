#ifndef COD2_NET_H
#define COD2_NET_H

#include "shared.h"
#include "assembly.h"
#include "cod2_common.h"
#include <limits.h>


enum netadrtype_e
{
    NA_INIT = 0x0,
    NA_BAD = 0x1, // set when the address was unable to be resolved
    NA_LOOPBACK = 0x2,
    NA_BROADCAST = 0x3,
    NA_IP = 0x4,
    NA_IPX = 0x5, // IPX protocol, probably not used
    NA_BROADCAST_IPX = 0x6
};

inline const char* get_netadrtype_name(int type) {
    switch (type) {
        case NA_INIT: return "INIT";
        case NA_BAD: return "BAD";
        case NA_LOOPBACK: return "LOOPBACK";
        case NA_BROADCAST: return "BROADCAST";
        case NA_IP: return "IP";
        case NA_IPX: return "IPX";
        case NA_BROADCAST_IPX: return "BROADCAST_IPX";
        default: return "UNKNOWN";
    }
}

struct netaddr_s
{
    enum netadrtype_e type;
    uint8_t ip[0x4];
    uint16_t port;
	uint8_t ipx[10];
};
static_assert(sizeof(netaddr_s) == 0x14);

typedef struct
{
	int overflowed;
	uint8_t *data;
	int maxsize;
	int cursize;
	int readcount;
	int bit;
} msg_t;

enum netsrc_e
{
	NS_CLIENT,
	NS_SERVER
};

#define MAX_MSGLEN 0x4000
typedef struct
{
	int			outgoingSequence;
	netsrc_e	sock;
	int			dropped;
	int			incomingSequence;
	netaddr_s	remoteAddress;
	int 		qport;
	int			fragmentSequence;
	int			fragmentLength;
	byte		fragmentBuffer[MAX_MSGLEN];
	int	        unsentFragments;
	int			unsentFragmentStart;
	int			unsentLength;
	byte		unsentBuffer[MAX_MSGLEN];
	void *      pProf;
} netchan_t;
static_assert(sizeof(netchan_t) == 0x8040);



// Send UDP packet to a server or client. Sender is NS_SERVER or NS_CLIENT
inline int NET_OutOfBandPrint(netsrc_e sender, struct netaddr_s addr, const char* msg) {
    #if COD2X_WIN32
        int result;
        ASM_CALL(RETURN(result), 0x00448910, 6, EAX(msg), PUSH(sender), PUSH_STRUCT(addr, 5));
        return result;
    #endif
    #if COD2X_LINUX
        return ((int (*)(int, netaddr_s, const char*))0x0806c8cc)(sender, addr, msg);
    #endif
}


inline int NET_CompareBaseAdrSigned(netaddr_s *a, netaddr_s *b)
{
	if ( a->type != b->type )
		return a->type - b->type;

	switch ( a->type )
	{
        case NA_INIT:
        case NA_LOOPBACK:
            return a->port - b->port;
        case NA_IP:
            return memcmp(a->ip, b->ip, 4);
        case NA_IPX:
            return memcmp(a->ipx, b->ipx, 10);
        default:
            Com_Printf("NET_CompareBaseAdrSigned: bad address type\n");
            return 0;
	}
}

// Returns true if the address is the same (does not compare ports)
inline bool NET_CompareBaseAdr(netaddr_s a, netaddr_s b)
{
	return NET_CompareBaseAdrSigned(&a, &b) == 0;
}

inline int NET_CompareAdrSigned(netaddr_s *a, netaddr_s *b)
{
	if ( a->type != b->type )
		return a->type - b->type;

	switch ( a->type )
	{
	case NA_LOOPBACK:
		return 0;
	case NA_IP:
		if ( a->port == b->port )
			return memcmp(a->ip, b->ip, 4);
		else
			return a->port - b->port;
	case NA_IPX:
		if ( a->port == b->port )
			return memcmp(a->ipx, b->ipx, 10);
		else
			return a->port - b->port;
	default:
		Com_Printf("NET_CompareAdrSigned: bad address type\n");
		return 0;
	}
}

// Returns true if the address and port are the same
inline bool NET_CompareAdr(netaddr_s a, netaddr_s b)
{
	return NET_CompareAdrSigned(&a, &b) == 0;
}

inline int NET_IsLocalAddress( netaddr_s adr )
{
	return adr.type == NA_LOOPBACK || adr.type == NA_INIT;
}


inline int NET_StringToAdr(const char *updateServerUri, struct netaddr_s* a) {
    #if COD2X_WIN32
        const void* original_func = (void*)0x00448d50;
        int result;
        ASM( mov,   "eax", updateServerUri  );
        ASM( mov,   "ebx", a                );
        ASM( call,  original_func           );
        ASM( movr,  result, "eax"           ); // Store the return value in the 'result' variable
        return result;
    #endif
    #if COD2X_LINUX
        return ((int32_t (*)(const char *, struct netaddr_s*))0x0806cd98)(updateServerUri, a);
    #endif
}

// Convert netadr_s to string %i.%i.%i.%i:%i
inline char* NET_AdrToString(struct netaddr_s addr) {
    return ((char* (*)(struct netaddr_s addr))ADDR(0x004476e0, 0x0806b1d4))(addr);
}

inline int Sys_IsLANAddress(struct netaddr_s addr) {
    return ((int (*)(struct netaddr_s addr))ADDR(0x00467100, 0x080d5638))(addr);
}



inline short BigShort(short l) {
    void* func = *((void**)ADDR(0x00c93bc4, 0x085bc800));
    short ret = (*(short(__cdecl*)(short))func)(l);
    return ret;
}







inline void MSG_BeginReading(msg_t* msg) {
    #if COD2X_WIN32
        const void* original_func = (void*)0x00443e20;
        ASM( mov,   "eax", msg      );
        ASM( call,  original_func   );
    #endif
    #if COD2X_LINUX
        ((void(__cdecl*)(msg_t*))(0x08067c1c))(msg);
    #endif
}

inline int MSG_ReadLong(msg_t* msg) {
    #if COD2X_WIN32
        const void* original_func = (void*)0x00444410;
        int ret;
        ASM( mov,   "ecx", msg      );
        ASM( call,  original_func   );
        ASM( movr,  ret, "eax"      );
        return ret;
    #endif
    #if COD2X_LINUX
        return ((int(__cdecl*)(msg_t*))(0x08068450))(msg);
    #endif
}

inline void SV_Netchan_AddOOBProfilePacket(int len) {
    ((void(__cdecl*)(int))(ADDR(0x0045c9d0, 0x0809766e)))(len);
}

inline char* MSG_ReadStringLine(msg_t* msg) {
    #if COD2X_WIN32
        const void* original_func = (void*)0x00444540;
        char* ret;
        ASM( mov,   "edx", msg      );
        ASM( call,  original_func   );
        ASM( movr,  ret, "eax"      );
        return ret;
    #endif
    #if COD2X_LINUX
        return ((char*(__cdecl*)(msg_t*))(0x08068606))(msg);
    #endif
}

#if COD2X_WIN32
inline char* MSG_ReadString(msg_t* msg) {
    char* ret;
    ASM_CALL(RETURN(ret), 0x00444480, 0, EDX(msg));
    return ret;
}
#endif

/** Byte-aligned read (equivalent to engine MSG_ReadData). */
inline bool MSG_ReadData(msg_t* msg, void* dest, size_t len) {
	if (!msg || !dest || msg->overflowed)
		return false;
	if (len > (size_t)INT_MAX || msg->readcount > msg->cursize || (int)len > msg->cursize - msg->readcount) {
		msg->overflowed = 1;
		return false;
	}
	memcpy(dest, msg->data + msg->readcount, len);
	msg->readcount += (int)len;
	return true;
}

int NET_SendPacket(netsrc_e sock, int length, const void* data, netaddr_s addr_to);

#endif