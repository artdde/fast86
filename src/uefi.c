#define _GNU_SOURCE
#include "f86.h"

#include <dirent.h>
#include <limits.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define STUB_SIZE 16
#define MAX_BS    112
#define MAX_HND   64
#define EFI_SUCCESS     0ull
#define EFI_LOAD_ERROR  0x8000000000000001ull
#define EFI_INVALID     0x8000000000000002ull
#define EFI_UNSUPPORTED 0x8000000000000003ull
#define EFI_INVALID_PARAM 0x8000000000000002ull
#define EFI_BAD_BUFFER  0x8000000000000005ull
#define EFI_NOT_READY   0x8000000000000006ull
#define EFI_NO_MEDIA    0x800000000000000cull
#define EFI_OUT_OF_RESOURCES 0x8000000000000009ull
#define EFI_NOT_FOUND   0x800000000000000eull
#define EFI_NOT_STARTED 0x8000000000000013ull

/* Boot-service indices (header is 24 bytes, then these). */
enum {
	BS_RaiseTPL = 0, BS_RestoreTPL, BS_AllocatePages, BS_FreePages,
	BS_GetMemoryMap, BS_AllocatePool, BS_FreePool, BS_CreateEvent,
	BS_SetTimer, BS_WaitForEvent, BS_SignalEvent, BS_CloseEvent,
	BS_CheckEvent, BS_InstallProtocol, BS_ReinstallProtocol,
	BS_UninstallProtocol, BS_HandleProtocol, BS_Reserved,
	BS_RegisterProtocolNotify, BS_LocateHandle, BS_LocateDevicePath,
	BS_InstallConfigTable, BS_LoadImage, BS_StartImage, BS_Exit,
	BS_UnloadImage, BS_ExitBootServices, BS_GetNextMonotonic,
	BS_Stall, BS_SetWatchdog, BS_ConnectController, BS_DisconnectController,
	BS_OpenProtocol, BS_CloseProtocol, BS_OpenProtocolInfo,
	BS_ProtocolsPerHandle, BS_LocateHandleBuffer, BS_LocateProtocol,
	BS_InstallMultiple, BS_UninstallMultiple, BS_CalculateCrc32,
	BS_CopyMem, BS_SetMem, BS_CreateEventEx,
	/* extra protocol methods, not in the BS table */
	PR_OpenVolume = 50, PR_FileOpen, PR_FileClose, PR_FileDelete,
	PR_FileRead, PR_FileWrite, PR_FileGetPos, PR_FileSetPos,
	PR_FileGetInfo, PR_FileSetInfo, PR_FileFlush,
	PR_ConInReset = 61, PR_ConReset = 62, PR_ConOutput = 63,
	RT_GetTime = 64, RT_SetTime, RT_GetWakeup, RT_SetWakeup,
	RT_SetVAMap, RT_ConvertPtr, RT_GetVariable, RT_GetNextVariable,
	RT_SetVariable, RT_GetNextMono, RT_ResetSystem, RT_UpdateCapsule,
	RT_QueryCapsule, RT_QueryVariable,
	PR_ConInRead = 80,
	PR_GopQuery = 81, PR_GopSet = 82, PR_GopBlt = 83,
	PR_BlkReset = 84, PR_BlkRead = 85, PR_BlkWrite = 86, PR_BlkFlush = 87,
	PR_ConCtlGet = 88, PR_ConCtlSet = 89, PR_ConCtlLock = 90,
	PR_AcpiInstall = 91, PR_AcpiUninstall = 92,
	PR_DevPropGet = 93, PR_DevPropSet = 94, PR_DevPropDel = 95, PR_DevPropAll = 96,
	PR_DxeStub = 97, /* every DXE Services entry: EFI_UNSUPPORTED */
};

/* Standard GUIDs */
static const uint8_t GUID_LOADED_IMAGE[16] = {
	0xa1,0x31,0x1b,0x5b, 0x62,0x95, 0xd2,0x11,
	0x8e,0x3f,0x00,0xa0,0xc9,0x69,0x72,0x3b
};
static const uint8_t GUID_SIMPLE_FS[16] = {
	0x22,0x5b,0x4e,0x96, 0x59,0x64, 0xd2,0x11,
	0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b
};
static const uint8_t GUID_DEVICE_PATH[16] = {
	0x91,0x6e,0x57,0x09, 0x3f,0x6d, 0xd2,0x11,
	0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b
};
static const uint8_t GUID_FILE_INFO[16] = {
	0x92,0x6e,0x57,0x09, 0x3f,0x6d, 0xd2,0x11,
	0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b
};
static const uint8_t GUID_ACPI_TABLE[16] = {
	0xb1,0xcc,0xba,0x26, 0x42,0x6f, 0xd4,0x11,
	0xbc,0xe7,0x00,0x80,0xc7,0x3c,0x88,0x81
};
static const uint8_t GUID_APPLE_DEVPROP[16] = {
	0xfe,0x12,0xbd,0x91, 0xc3,0xf6, 0xfb,0x44,
	0xa5,0xb7,0x51,0x22,0xab,0x30,0x3a,0xe0
};
static const uint8_t GUID_FILE_SYS_INFO[16] = {
	0x93,0x6e,0x57,0x09, 0x3f,0x6d, 0xd2,0x11,
	0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b
};
static const uint8_t GUID_GOP[16] = {
	0xde,0xa9,0x42,0x90, 0xdc,0x23, 0x38,0x4a,
	0x96,0xfb,0x7a,0xde,0xd0,0x80,0x51,0x6a
};
static const uint8_t GUID_TEXT_IN[16] = {
	0xc1,0x77,0x74,0x38, 0xc7,0x69, 0xd2,0x11,
	0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b
};
static const uint8_t GUID_TEXT_OUT[16] = {
	0xc2,0x77,0x74,0x38, 0xc7,0x69, 0xd2,0x11,
	0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b
};
/* EFI_LOADED_IMAGE_DEVICE_PATH_PROTOCOL_GUID
 *   {0xbc62157e, 0x3e33, 0x4fec, {0x99,0x20,0x2d,0x3b,0x36,0xd7,0x50,0xdf}}
 * NB: 0x1f3c963d-f9dc-4537 is NOT this GUID — it is OpenCore's
 * mOcLoadedImageProtocolGuid (an OC_LOADED_IMAGE_PROTOCOL, whose first field
 * is the image EntryPoint). Returning a device path for it made OpenCore
 * call the device-path bytes as a function pointer. */
static const uint8_t GUID_LI_DP[16] = {
	0x7e,0x15,0x62,0xbc, 0x33,0x3e, 0xec,0x4f,
	0x99,0x20,0x2d,0x3b,0x36,0xd7,0x50,0xdf
};
static const uint8_t GUID_BLOCK_IO[16] = {
	0x21,0x5b,0x4e,0x96, 0x59,0x64, 0xd2,0x11,
	0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b
};
static const uint8_t GUID_CONSOLE_CTL[16] = {
	0x82,0x77,0x2f,0xf4, 0x2e,0x01, 0x12,0x4c,
	0x99,0x56,0x49,0xf9,0x43,0x04,0xf7,0x21
};
static uint64_t g_conctl;

#define GOP_W 1024
#define GOP_H 768
static uint64_t g_gop_fb;

void f86_uefi_dump_fb(const char *path)
{
	if (!g_gop_fb || !f86_ram())
		return;
	uint64_t fbsz = (uint64_t)GOP_W * GOP_H * 4;
	if (g_gop_fb + fbsz > f86_ram_size())
		return;
	const char *out = path ? path : "/tmp/f86-gop.ppm";
	FILE *f = fopen(out, "w");
	if (!f)
		return;
	fprintf(f, "P6\n%d %d\n255\n", GOP_W, GOP_H);
	uint32_t *px = (uint32_t *)(f86_ram() + g_gop_fb);
	int nz = 0;
	for (int i = 0; i < GOP_W * GOP_H; i++) {
		unsigned p = px[i];
		if (p & 0x00ffffff)
			nz++;
		fputc((int)(p & 0xff), f);
		fputc((int)((p >> 8) & 0xff), f);
		fputc((int)((p >> 16) & 0xff), f);
	}
	fclose(f);
	static int nd;
	if (nd++ < 8)
		fprintf(stderr, "fast86: fb dump %s nonzero=%d\n", out, nz);
}

extern uint8_t *f86_ram(void);
extern size_t   f86_ram_size(void);
extern uint64_t f86_uefi_alloc(uint64_t pages);
extern const char *f86_sys_root(void);
extern void f86_emit_stub(uint8_t *p, uint32_t id);

static uint64_t g_stub_base, g_bs_table, g_st_table, g_rt_table;
static uint64_t g_conout, g_conin;
static uint64_t g_fs_proto, g_li_proto, g_vol_dp, g_file_dp, g_mac_vol_dp;
static uint64_t g_gop, g_gop_mode, g_gop_info, g_blk_io, g_blk_media;
static uint64_t g_acpi_proto, g_devprop;
static uint64_t g_vol_handle = 0x20;
static uint64_t g_img_handle = 0x10;
static uint64_t g_conout_handle = 1;
static uint64_t g_conin_handle = 2;

typedef struct {
	uint8_t guid[16];
	uint64_t iface;
} Proto;

typedef struct {
	int used;
	int persistent; /* volume handle: do not free on FileClose */
	char host_path[512];
	int fd;
	uint64_t pos, size;
	int is_dir;
	uint64_t proto_gpa; /* file protocol instance in guest RAM */
	uint64_t entry, image_base, image_size;
	Proto proto[8];
	int nproto;
	char dents[64][256];
	int ndent, ident;
	char dev_path[256];  /* EFI FilePath of this image, e.g. \\EFI\\OC\\OpenCore.efi */
	uint64_t dev_dp;     /* guest GPA of this image's FilePath device path */
} Hnd;

static Hnd g_h[MAX_HND];

typedef struct {
	int used;
	char name[128];
	uint8_t guid[16];
	uint32_t attrs;
	uint32_t size;
	uint8_t data[4096];
} EfiVar;

static EfiVar g_var[64];

static uint64_t g_disk_handle = 0x40;

#define MAX_AP 80
static struct {
	uint64_t phys, pages;
	uint32_t type;
} g_ap[MAX_AP];
static int g_nap;

static void note_pages(uint64_t phys, uint64_t pages, uint32_t type)
{
	if (!pages || g_nap >= MAX_AP)
		return;
	g_ap[g_nap].phys = phys;
	g_ap[g_nap].pages = pages;
	g_ap[g_nap].type = type;
	g_nap++;
}

static uint32_t efi_crc32(const uint8_t *p, size_t n)
{
	static uint32_t tab[256];
	static int once;
	if (!once) {
		for (uint32_t i = 0; i < 256; i++) {
			uint32_t c = i;
			for (int k = 0; k < 8; k++)
				c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
			tab[i] = c;
		}
		once = 1;
	}
	uint32_t c = 0xffffffffu;
	for (size_t i = 0; i < n; i++)
		c = tab[(c ^ p[i]) & 0xff] ^ (c >> 8);
	return c ^ 0xffffffffu;
}

/* Host pointer for [gpa, gpa+len) only if the whole range is guest RAM. */
static void *gpa_range(uint64_t gpa, uint64_t len)
{
	if (!gpa || len > f86_ram_size() || gpa > f86_ram_size() - len)
		return NULL;
	if (f86_sys_is_mmio(gpa) || (len && f86_sys_is_mmio(gpa + len - 1)))
		return NULL;
	return f86_ram() + gpa;
}

static int hnd_idx(uint64_t h)
{
	if (h == g_img_handle) return 0;
	if (h == g_vol_handle) return 1;
	if (h == g_disk_handle) return 2;
	if (h == g_conout_handle) return 3;
	if (h == g_conin_handle) return 4;
	if (h >= 0x100 && h < 0x100 + MAX_HND)
		return (int)(h - 0x100);
	return -1;
}

static uint64_t hnd_val(int i)
{
	if (i == 0) return g_img_handle;
	if (i == 1) return g_vol_handle;
	if (i == 2) return g_disk_handle;
	if (i == 3) return g_conout_handle;
	if (i == 4) return g_conin_handle;
	return 0x100 + (uint64_t)i;
}

static int guid_at(uint64_t gpa, const uint8_t *want)
{
	void *p = f86_gpa_hva(gpa);
	if (!p)
		return 0;
	return memcmp(p, want, 16) == 0;
}

static void utf16_to_utf8(const uint16_t *s, char *out, size_t cap)
{
	size_t j = 0;
	for (size_t i = 0; s && s[i] && j + 1 < cap; i++) {
		unsigned c = s[i];
		if (c == '\\')
			c = '/';
		if (c < 0x80)
			out[j++] = (char)c;
		else
			out[j++] = '?';
	}
	out[j] = 0;
}

static void host_join(char *dst, size_t cap, const char *base, const char *rel)
{
	while (*rel == '/')
		rel++;
	if (base && base[0])
		snprintf(dst, cap, "%s/%s", base, rel);
	else
		snprintf(dst, cap, "%s", rel);
}

/* SimpleFileSystem protocol instance: OpenVolume vtable, no per-volume state
   (the handle is recovered from the instance address in find_hnd_by_sfs). */
static uint64_t make_sfs_proto(void)
{
	uint64_t gpa = f86_uefi_alloc(1);
	if (!gpa)
		return 0;
	uint64_t *fs = f86_gpa_hva(gpa);
	memset(fs, 0, 4096);
	fs[0] = 0x00010000;
	fs[1] = g_stub_base + (uint64_t)PR_OpenVolume * STUB_SIZE;
	return gpa;
}

static uint64_t make_file_proto(int hi)
{
	uint64_t gpa = f86_uefi_alloc(1);
	if (!gpa)
		return 0;
	uint64_t *fp = f86_gpa_hva(gpa);
	memset(fp, 0, 4096);
	fp[0] = 0x00010000; /* Revision */
	fp[1] = g_stub_base + (uint64_t)PR_FileOpen * STUB_SIZE;
	fp[2] = g_stub_base + (uint64_t)PR_FileClose * STUB_SIZE;
	fp[3] = g_stub_base + (uint64_t)PR_FileDelete * STUB_SIZE;
	fp[4] = g_stub_base + (uint64_t)PR_FileRead * STUB_SIZE;
	fp[5] = g_stub_base + (uint64_t)PR_FileWrite * STUB_SIZE;
	fp[6] = g_stub_base + (uint64_t)PR_FileGetPos * STUB_SIZE;
	fp[7] = g_stub_base + (uint64_t)PR_FileSetPos * STUB_SIZE;
	fp[8] = g_stub_base + (uint64_t)PR_FileGetInfo * STUB_SIZE;
	fp[9] = g_stub_base + (uint64_t)PR_FileSetInfo * STUB_SIZE;
	fp[10] = g_stub_base + (uint64_t)PR_FileFlush * STUB_SIZE;
	/* stash handle index after the vtable so Open can recover `this` */
	fp[16] = (uint64_t)hi;
	g_h[hi].proto_gpa = gpa;
	return gpa;
}

static int alloc_hnd(void)
{
	for (int i = 5; i < MAX_HND; i++) {
		if (!g_h[i].used) {
			memset(&g_h[i], 0, sizeof(g_h[i]));
			g_h[i].used = 1;
			g_h[i].fd = -1;
			return i;
		}
	}
	return -1;
}

static int find_hnd_by_proto(uint64_t this_gpa)
{
	for (int i = 0; i < MAX_HND; i++)
		if (g_h[i].used && g_h[i].proto_gpa == this_gpa)
			return i;
	/* fallback: read stashed index */
	uint64_t *fp = f86_gpa_hva(this_gpa);
	if (fp && fp[16] > 0 && fp[16] < MAX_HND)
		return (int)fp[16];
	return -1;
}

/* Map a SimpleFileSystem protocol instance (the OpenVolume `this`) back to
   its volume handle. The ESP volume's SimpleFS lives in g_fs_proto; extra
   volumes (e.g. the extracted macOS tree) get their own instance. */
static int find_hnd_by_sfs(uint64_t sfs_gpa)
{
	for (int i = 0; i < MAX_HND; i++) {
		if (!g_h[i].used)
			continue;
		for (int j = 0; j < g_h[i].nproto; j++)
			if (memcmp(g_h[i].proto[j].guid, GUID_SIMPLE_FS, 16) == 0 &&
			    g_h[i].proto[j].iface == sfs_gpa)
				return i;
	}
	return -1;
}

static uint64_t write_filepath_dp(uint64_t gpa, const char *path)
{
	uint8_t *dpp = f86_gpa_hva(gpa);
	if (!dpp)
		return 0;
	memset(dpp, 0, 256);
	dpp[0] = 4;
	dpp[1] = 4; /* Media / FilePath */
	int nch = (int)strlen(path) + 1;
	uint16_t len = (uint16_t)(4 + nch * 2);
	memcpy(dpp + 2, &len, 2);
	for (int i = 0; i < nch; i++) {
		dpp[4 + i * 2] = (uint8_t)path[i];
		dpp[5 + i * 2] = 0;
	}
	dpp[4 + nch * 2] = 0x7f;
	dpp[5 + nch * 2] = 0xff;
	dpp[6 + nch * 2] = 4;
	dpp[7 + nch * 2] = 0;
	return gpa;
}

/* Walk a guest device path and return the concatenated FilePath node string
   (backslashes converted to '/'). Returns 0 on success. */
static int device_path_extract(uint64_t dp_gpa, char *out, size_t cap)
{
	uint8_t *p = f86_gpa_hva(dp_gpa);
	if (!p)
		return -1;
	char full[512];
	size_t used = 0;
	full[0] = 0;
	for (int i = 0; i < 24; i++) {
		uint8_t type = p[0], sub = p[1];
		uint16_t len = (uint16_t)(p[2] | (p[3] << 8));
		if (len < 4 || len > 512)
			break;
		if (type == 0x7f) /* End of hardware device path */
			break;
		if (type == 4 && sub == 4) {
			const uint16_t *s = (const uint16_t *)(p + 4);
			size_t n = (len - 4) / 2;
			for (size_t k = 0; k < n && s[k]; k++) {
				unsigned ch = s[k];
				if (ch == '\\')
					ch = '/';
				if (used + 1 < sizeof full)
					full[used++] = (ch < 0x80) ? (char)ch : '?';
			}
		}
		p += len;
	}
	full[used] = 0;
	if (!full[0])
		return -1;
	snprintf(out, cap, "%s", full);
	return 0;
}

static void write_vendor_dp(uint64_t gpa)
{
	/* HARDDRIVE node so bless/scan treat this as a partition, plus End.
	   AbsoluteDevicePath(vol, FilePath) yields HD + FilePath. */
	uint8_t *p = f86_gpa_hva(gpa);
	if (!p)
		return;
	memset(p, 0, 64);
	p[0] = 4; /* Media */
	p[1] = 1; /* HardDrive */
	p[2] = 42;
	p[3] = 0;
	uint32_t part = 1;
	uint64_t start = 0x28, nblk = 0x20000;
	memcpy(p + 4, &part, 4);
	memcpy(p + 8, &start, 8);
	memcpy(p + 16, &nblk, 8);
	/* signature GUID */
	static const uint8_t sig[16] = {
		0x11,0x22,0x33,0x44, 0x55,0x66, 0x77,0x88,
		0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x01
	};
	memcpy(p + 24, sig, 16);
	p[40] = 2; /* GPT */
	p[41] = 2; /* GUID signature */
	p[42] = 0x7f;
	p[43] = 0xff;
	p[44] = 4;
	p[45] = 0;
}

static void log_guid(const char *tag, uint64_t gpa)
{
	uint8_t *g = f86_gpa_hva(gpa);
	if (!g) {
		fprintf(stderr, "%s guid@%lx <unmapped>\n", tag, (unsigned long)gpa);
		return;
	}
	fprintf(stderr, "%s %02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
	        tag, g[3],g[2],g[1],g[0], g[5],g[4], g[7],g[6],
	        g[8],g[9], g[10],g[11],g[12],g[13],g[14],g[15]);
}

static void install_proto(int hi, const uint8_t *guid, uint64_t iface)
{
	if (hi < 0 || hi >= MAX_HND || g_h[hi].nproto >= 8)
		return;
	int n = g_h[hi].nproto++;
	memcpy(g_h[hi].proto[n].guid, guid, 16);
	g_h[hi].proto[n].iface = iface;
}

int f86_uefi_stub_id(uint64_t rip, uint32_t *id)
{
	if (!g_stub_base || rip < g_stub_base)
		return 0;
	uint64_t off = rip - g_stub_base;
	if (off >= (uint64_t)MAX_BS * STUB_SIZE)
		return 0;
	if (id)
		*id = (uint32_t)(off / STUB_SIZE);
	return 1;
}

int f86_uefi_install(uint64_t *out_st)
{
	g_stub_base = 0x00100000ull;
	f86_sys_plant_fw();
	uint8_t *p = f86_ram() + g_stub_base;
	memset(p, 0, 0x20000);
	for (int i = 0; i < MAX_BS; i++)
		f86_emit_stub(p + (size_t)i * STUB_SIZE, (uint32_t)i);

	g_bs_table = g_stub_base + 0x1000;
	g_st_table = g_stub_base + 0x2000;
	g_rt_table = g_stub_base + 0x2800;
	g_conout   = g_stub_base + 0x3000;
	g_conin    = g_stub_base + 0x3080;
	g_fs_proto = g_stub_base + 0x3100;
	g_li_proto = g_stub_base + 0x3200;
	g_vol_dp   = g_stub_base + 0x3400;
	g_file_dp  = g_stub_base + 0x3480;
	g_mac_vol_dp = g_stub_base + 0x3b00;
	g_gop      = g_stub_base + 0x3600;
	g_gop_mode = g_stub_base + 0x3680;
	g_gop_info = g_stub_base + 0x3700;
	g_blk_io   = g_stub_base + 0x3780;
	g_blk_media= g_stub_base + 0x3800;
	g_conctl   = g_stub_base + 0x3880;
	g_acpi_proto = g_stub_base + 0x3a00;
	g_devprop  = g_stub_base + 0x3a40;

	uint8_t *bsb = f86_ram() + g_bs_table;
	memset(bsb, 0, 0x200);
	{
		uint64_t bsig = 0x56524553544f4f42ull;
		uint32_t brev = 0x0002001e, bhsz = 24 + 44 * 8;
		memcpy(bsb + 0, &bsig, 8);
		memcpy(bsb + 8, &brev, 4);
		memcpy(bsb + 12, &bhsz, 4);
		for (int i = 0; i < 44; i++) {
			uint64_t fp = g_stub_base + (uint64_t)i * STUB_SIZE;
			memcpy(bsb + 24 + (size_t)i * 8, &fp, 8);
		}
	}

	uint8_t *rtb = f86_ram() + g_rt_table;
	memset(rtb, 0, 0x100);
	{
		uint64_t rsig = 0x56524553544e5552ull; /* RUNTSERV */
		uint32_t rrev = 0x0002001e, rhsz = 24 + 14 * 8;
		memcpy(rtb + 0, &rsig, 8);
		memcpy(rtb + 8, &rrev, 4);
		memcpy(rtb + 12, &rhsz, 4);
		for (int i = 0; i < 14; i++) {
			uint64_t fp = g_stub_base + (uint64_t)(RT_GetTime + i) * STUB_SIZE;
			memcpy(rtb + 24 + (size_t)i * 8, &fp, 8);
		}
	}

	uint64_t *co = (uint64_t *)(f86_ram() + g_conout);
	memset(co, 0, 64);
	co[0] = g_stub_base + (uint64_t)PR_ConReset * STUB_SIZE;
	co[1] = g_stub_base + (uint64_t)PR_ConOutput * STUB_SIZE;

	uint64_t *ci = (uint64_t *)(f86_ram() + g_conin);
	memset(ci, 0, 64);
	ci[0] = g_stub_base + (uint64_t)PR_ConInReset * STUB_SIZE;
	ci[1] = g_stub_base + (uint64_t)PR_ConInRead * STUB_SIZE;
	ci[2] = 0x81; /* WaitForKey dummy event */

	/* SimpleFileSystem protocol */
	uint64_t *fs = (uint64_t *)(f86_ram() + g_fs_proto);
	fs[0] = 0x00010000;
	fs[1] = g_stub_base + (uint64_t)PR_OpenVolume * STUB_SIZE;

	write_vendor_dp(g_vol_dp);
	{
		const char *ipath = f86_sys_image_path();
		char uefi[256];
		if (ipath && ipath[0]) {
			if (ipath[0] != '/' && ipath[0] != '\\')
				snprintf(uefi, sizeof uefi, "\\%s", ipath);
			else
				snprintf(uefi, sizeof uefi, "%s", ipath);
			for (char *q = uefi; *q; q++)
				if (*q == '/')
					*q = '\\';
		} else
			snprintf(uefi, sizeof uefi, "\\EFI\\OC\\OpenCore.efi");
		write_filepath_dp(g_file_dp, uefi);
		fprintf(stderr, "fast86: image path %s\n", uefi);
	}

	/* LoadedImage for the primary image */
	memset(g_h, 0, sizeof(g_h));
	memset(g_var, 0, sizeof(g_var));
	g_nap = 0;
	/* Seed Apple firmware-feature NVRAM so boot.efi GFWF succeeds. */
	{
		static const uint8_t apple_nv[16] = {
			0x10,0x61,0x43,0x7c, 0x2a,0xab, 0xbb,0x4b,
			0xa8,0x80,0xfe,0x41,0x99,0x5c,0x9f,0x82
		};
		uint32_t feat = 0x8ff6ffff;
		uint64_t ext = 0x00000008;
		g_var[0].used = 1;
		snprintf(g_var[0].name, sizeof g_var[0].name, "FirmwareFeatures");
		memcpy(g_var[0].guid, apple_nv, 16);
		g_var[0].attrs = 7;
		g_var[0].size = 4;
		memcpy(g_var[0].data, &feat, 4);
		g_var[1].used = 1;
		snprintf(g_var[1].name, sizeof g_var[1].name, "FirmwareFeaturesMask");
		memcpy(g_var[1].guid, apple_nv, 16);
		g_var[1].attrs = 7;
		g_var[1].size = 4;
		memcpy(g_var[1].data, &feat, 4);
		g_var[2].used = 1;
		snprintf(g_var[2].name, sizeof g_var[2].name, "ExtendedFirmwareFeatures");
		memcpy(g_var[2].guid, apple_nv, 16);
		g_var[2].attrs = 7;
		g_var[2].size = 8;
		memcpy(g_var[2].data, &ext, 8);
		g_var[3].used = 1;
		snprintf(g_var[3].name, sizeof g_var[3].name, "ExtendedFirmwareFeaturesMask");
		memcpy(g_var[3].guid, apple_nv, 16);
		g_var[3].attrs = 7;
		g_var[3].size = 8;
		memcpy(g_var[3].data, &ext, 8);
		g_var[4].used = 1;
		snprintf(g_var[4].name, sizeof g_var[4].name, "HW_BID");
		memcpy(g_var[4].guid, apple_nv, 16);
		g_var[4].attrs = 7;
		{
			const char *bid = "Mac-7BA5B2D9E42DDD94";
			g_var[4].size = 20;
			memcpy(g_var[4].data, bid, 20);
		}
		g_var[5].used = 1;
		snprintf(g_var[5].name, sizeof g_var[5].name, "MLB");
		memcpy(g_var[5].guid, apple_nv, 16);
		g_var[5].attrs = 7;
		memcpy(g_var[5].data, "C02705101J9JG36FB", 17);
		g_var[5].size = 17;
		g_var[6].used = 1;
		snprintf(g_var[6].name, sizeof g_var[6].name, "ROM");
		memcpy(g_var[6].guid, apple_nv, 16);
		g_var[6].attrs = 7;
		g_var[6].size = 6;
		g_var[6].data[0] = 0x00; g_var[6].data[1] = 0x16;
		g_var[6].data[2] = 0xcb; g_var[6].data[3] = 0xf8;
		g_var[6].data[4] = 0x6f; g_var[6].data[5] = 0x86;
		g_var[7].used = 1;
		snprintf(g_var[7].name, sizeof g_var[7].name, "csr-active-config");
		memcpy(g_var[7].guid, apple_nv, 16);
		g_var[7].attrs = 7;
		g_var[7].size = 4;
		g_var[7].data[0] = 0x67; /* allow unsigned kexts / disabled SIP-ish */
		g_var[8].used = 1;
		snprintf(g_var[8].name, sizeof g_var[8].name, "boot-args");
		memcpy(g_var[8].guid, apple_nv, 16);
		g_var[8].attrs = 7;
		{
			const char *ba = "-v keepsyms=1 debug=0x144 -no_compat_check cpus=1 serial=3";
			g_var[8].size = (uint32_t)strlen(ba) + 1;
			memcpy(g_var[8].data, ba, g_var[8].size);
		}
	}
	g_h[0].used = 1;
	g_h[1].used = 1;
	g_h[2].used = 1;
	g_h[3].used = 1;
	g_h[4].used = 1;
	snprintf(g_h[1].host_path, sizeof g_h[1].host_path, "%s",
	         f86_sys_root() ? f86_sys_root() : ".");
	g_h[1].is_dir = 1;
	g_h[1].proto_gpa = g_fs_proto;
	g_h[0].image_base = f86_sys_image_base();
	g_h[0].image_size = f86_sys_image_size();
	g_h[0].entry = 0;

	uint8_t *li = f86_ram() + g_li_proto;
	memset(li, 0, 0x80);
	uint32_t lirev = 0x1000;
	uint64_t parent = 0, st = g_st_table, dev = g_vol_handle, dp = g_file_dp;
	uint64_t ibase = f86_sys_image_base(), isize = f86_sys_image_size();
	memcpy(li + 0, &lirev, 4);
	memcpy(li + 8, &parent, 8);
	memcpy(li + 16, &st, 8);
	memcpy(li + 24, &dev, 8);
	memcpy(li + 32, &dp, 8);
	memcpy(li + 64, &ibase, 8);
	memcpy(li + 72, &isize, 8);

	/* GOP 1024x768 BGRA framebuffer in the identity-mapped alloc pool. */
	{
		uint64_t fbsz = (uint64_t)GOP_W * GOP_H * 4;
		/* Park the framebuffer in low conventional RAM so XNU PHYSMAP_PTOV
		   covers it (pool allocations sit at 0x6fxxxxxx). */
		g_gop_fb = 0x00400000ull;
		if (g_gop_fb + fbsz < f86_ram_size())
			memset(f86_ram() + g_gop_fb, 0, (size_t)fbsz);
		else
			g_gop_fb = f86_uefi_alloc((fbsz + 0xfff) / 0x1000);
		uint64_t *gp = (uint64_t *)(f86_ram() + g_gop);
		memset(gp, 0, 64);
		gp[0] = g_stub_base + (uint64_t)PR_GopQuery * STUB_SIZE;
		gp[1] = g_stub_base + (uint64_t)PR_GopSet * STUB_SIZE;
		gp[2] = g_stub_base + (uint64_t)PR_GopBlt * STUB_SIZE;
		gp[3] = g_gop_mode;
		uint8_t *mi = f86_ram() + g_gop_info;
		memset(mi, 0, 64);
		uint32_t w = GOP_W, h = GOP_H, fmt = 1, ver = 0;
		memcpy(mi + 0, &ver, 4);
		memcpy(mi + 4, &w, 4);
		memcpy(mi + 8, &h, 4);
		memcpy(mi + 12, &fmt, 4);
		memcpy(mi + 32, &w, 4);
		uint8_t *md = f86_ram() + g_gop_mode;
		memset(md, 0, 64);
		uint32_t maxm = 1, curm = 0;
		uint64_t infop = g_gop_info, infosz = 36;
		uint64_t fb = g_gop_fb;
		memcpy(md + 0, &maxm, 4);
		memcpy(md + 4, &curm, 4);
		memcpy(md + 8, &infop, 8);
		memcpy(md + 16, &infosz, 8);
		memcpy(md + 24, &fb, 8);
		memcpy(md + 32, &fbsz, 8);
		fprintf(stderr, "fast86: gop %ux%u fb=%lx\n", GOP_W, GOP_H,
		        (unsigned long)g_gop_fb);
	}

	install_proto(0, GUID_LOADED_IMAGE, g_li_proto);
	install_proto(0, GUID_DEVICE_PATH, g_file_dp);
	install_proto(0, GUID_LI_DP, g_file_dp);
	/* BlockIo on a separate disk handle so OpenHfsPlus does not bind
	   to the EFI SimpleFS volume. */
	{
		uint64_t nblk = f86_sys_part_blocks();
		if (!nblk)
			nblk = 0x20000;
		uint8_t *md = f86_ram() + g_blk_media;
		memset(md, 0, 64);
		uint32_t mid = 1, bsz = 512;
		uint64_t last = nblk ? nblk - 1 : 0;
		md[4] = 0;
		md[5] = 1;
		md[6] = 1; /* LogicalPartition */
		md[7] = 1; /* ReadOnly */
		memcpy(md + 0, &mid, 4);
		memcpy(md + 12, &bsz, 4);
		memcpy(md + 24, &last, 8);
		uint64_t *bp = (uint64_t *)(f86_ram() + g_blk_io);
		memset(bp, 0, 64);
		bp[0] = 0x00020001;
		bp[1] = g_blk_media;
		bp[2] = g_stub_base + (uint64_t)PR_BlkReset * STUB_SIZE;
		bp[3] = g_stub_base + (uint64_t)PR_BlkRead * STUB_SIZE;
		bp[4] = g_stub_base + (uint64_t)PR_BlkWrite * STUB_SIZE;
		bp[5] = g_stub_base + (uint64_t)PR_BlkFlush * STUB_SIZE;
		if (f86_sys_disk_blocks())
			install_proto(2, GUID_BLOCK_IO, g_blk_io);
	}
	{
		uint64_t *hp = (uint64_t *)(f86_ram() + g_conctl);
		memset(hp, 0, 64);
		hp[0] = g_stub_base + (uint64_t)PR_ConCtlGet * STUB_SIZE;
		hp[1] = g_stub_base + (uint64_t)PR_ConCtlSet * STUB_SIZE;
		hp[2] = g_stub_base + (uint64_t)PR_ConCtlLock * STUB_SIZE;
	}
	install_proto(1, GUID_SIMPLE_FS, g_fs_proto);
	install_proto(1, GUID_DEVICE_PATH, g_vol_dp);
	if (f86_sys_disk_blocks())
		install_proto(2, GUID_DEVICE_PATH, g_vol_dp);
	/* A second SimpleFS volume over an extracted macOS boot tree, so
	   OpenCore's bless scan finds System/Library/CoreServices/boot.efi. */
	{
		const char *mroot = f86_sys_mac_root();
		if (mroot && mroot[0]) {
			write_vendor_dp(g_mac_vol_dp);
			uint8_t *mdp = f86_gpa_hva(g_mac_vol_dp);
			if (mdp)
				mdp[39] = 0x02; /* distinct GPT partition signature GUID */
			int mi = alloc_hnd();
			if (mi >= 0) {
				snprintf(g_h[mi].host_path, sizeof g_h[mi].host_path,
				         "%s", mroot);
				g_h[mi].is_dir = 1;
				g_h[mi].fd = -1;
				g_h[mi].persistent = 1;
				uint64_t fs2 = make_sfs_proto();
				install_proto(mi, GUID_SIMPLE_FS, fs2);
				install_proto(mi, GUID_DEVICE_PATH, g_mac_vol_dp);
				fprintf(stderr, "fast86: mac root %s -> hnd %d fs=%lx\n",
				        mroot, mi, (unsigned long)fs2);
			}
		}
	}
	install_proto(3, GUID_GOP, g_gop);
	install_proto(3, GUID_TEXT_OUT, g_conout);
	install_proto(4, GUID_TEXT_IN, g_conin);
	{
		uint64_t *ap = (uint64_t *)(f86_ram() + g_acpi_proto);
		memset(ap, 0, 32);
		ap[0] = g_stub_base + (uint64_t)PR_AcpiInstall * STUB_SIZE;
		ap[1] = g_stub_base + (uint64_t)PR_AcpiUninstall * STUB_SIZE;
		/* Standard EFI_ACPI_TABLE_PROTOCOL_GUID, not 26baccb1. */
		static const uint8_t guid_acpi_std[16] = {
			0xdd,0x6b,0xe0,0xff, 0x07,0x61, 0xa6,0x46,
			0x7b,0xb2,0x5a,0x9c,0x7e,0xc5,0x27,0x5c
		};
		install_proto(1, guid_acpi_std, g_acpi_proto);
	}
	{
		uint64_t *dp = (uint64_t *)(f86_ram() + g_devprop);
		memset(dp, 0, 48);
		dp[0] = 0x10000;
		dp[1] = g_stub_base + (uint64_t)PR_DevPropGet * STUB_SIZE;
		dp[2] = g_stub_base + (uint64_t)PR_DevPropSet * STUB_SIZE;
		dp[3] = g_stub_base + (uint64_t)PR_DevPropDel * STUB_SIZE;
		dp[4] = g_stub_base + (uint64_t)PR_DevPropAll * STUB_SIZE;
		install_proto(1, GUID_APPLE_DEVPROP, g_devprop);
	}

	/* FirmwareVendor UTF-16 + configuration tables (SMBIOS, ACPI). */
	uint64_t vend = g_stub_base + 0x3900;
	uint64_t hob = g_stub_base + 0x3930;
	uint64_t cfg = g_stub_base + 0x3940;
	{
		const char *vs = "fast86";
		uint8_t *w = f86_ram() + vend;
		memset(w, 0, 32);
		for (int i = 0; vs[i]; i++)
			w[i * 2] = (uint8_t)vs[i];
	}
	{
		/* EFI_HOB_TYPE_END_OF_HOB_LIST */
		uint8_t *h = f86_ram() + hob;
		memset(h, 0, 16);
		h[0] = 0xff;
		h[1] = 0xff;
		h[2] = 8;
		h[3] = 0;
	}
	{
		/* SMBIOS  {EB9D2D31-2D88-11D3-9A16-0090273FC14D} */
		static const uint8_t smbios[16] = {
			0x31,0x2d,0x9d,0xeb, 0x88,0x2d, 0xd3,0x11,
			0x9a,0x16,0x00,0x90,0x27,0x3f,0xc1,0x4d
		};
		/* ACPI 2.0 {8868E871-E4F1-11D3-BC22-0080C73C8881} */
		static const uint8_t acpi2[16] = {
			0x71,0xe8,0x68,0x88, 0xf1,0xe4, 0xd3,0x11,
			0xbc,0x22,0x00,0x80,0xc7,0x3c,0x88,0x81
		};
		/* HOB list {7739F24C-93D7-11D4-9A3A-0090273FC14D} */
		static const uint8_t hobg[16] = {
			0x4c,0xf2,0x39,0x77, 0xd7,0x93, 0xd4,0x11,
			0x9a,0x3a,0x00,0x90,0x27,0x3f,0xc1,0x4d
		};
		/* DXE Services {05AD34BA-6F02-4214-952E-4DA0398E2BB9}: EDK2's
		   DxeServicesTableLib constructor asserts (DEBUG builds dead-loop)
		   when this table is missing. Every entry returns EFI_UNSUPPORTED. */
		static const uint8_t dxeg[16] = {
			0xba,0x34,0xad,0x05, 0x02,0x6f, 0x14,0x42,
			0x95,0x2e,0x4d,0xa0,0x39,0x8e,0x2b,0xb9
		};
		uint64_t dxe = g_stub_base + 0x3c00;
		{
			uint8_t *d = f86_ram() + dxe;
			memset(d, 0, 24 + 18 * 8);
			uint64_t dsig = 0x565245535f455844ull; /* DXE_SERV */
			uint32_t drev = 0x00010000, dhsz = 24 + 18 * 8;
			memcpy(d + 0, &dsig, 8);
			memcpy(d + 8, &drev, 4);
			memcpy(d + 12, &dhsz, 4);
			for (int i = 0; i < 18; i++) {
				uint64_t fp = g_stub_base + (uint64_t)PR_DxeStub * STUB_SIZE;
				memcpy(d + 24 + (size_t)i * 8, &fp, 8);
			}
		}
		uint8_t *ct = f86_ram() + cfg;
		memset(ct, 0, 96); /* four entries; InstallConfigurationTable grows elsewhere */
		uint64_t smbp = 0xF0000, acpip = 0xE0000;
		memcpy(ct + 0, smbios, 16);
		memcpy(ct + 16, &smbp, 8);
		memcpy(ct + 24, acpi2, 16);
		memcpy(ct + 40, &acpip, 8);
		memcpy(ct + 48, hobg, 16);
		memcpy(ct + 64, &hob, 8);
		memcpy(ct + 72, dxeg, 16);
		memcpy(ct + 88, &dxe, 8);
	}
	uint8_t *stb = f86_ram() + g_st_table;
	memset(stb, 0, 0x80);
	uint64_t sig = 0x5453595320494249ull;
	uint32_t rev = 0x0002001e, hsz = 72, zero = 0, fwrev = 0x00010000;
	uint64_t vendor = vend, hin = 2, cin = g_conin, hout = 1, cout = g_conout;
	uint64_t herr = 1, cerr = g_conout, rt = g_rt_table, boot = g_bs_table, ncfg = 4;
	memcpy(stb + 0, &sig, 8);
	memcpy(stb + 8, &rev, 4);
	memcpy(stb + 12, &hsz, 4);
	memcpy(stb + 16, &zero, 4);
	memcpy(stb + 20, &zero, 4);
	memcpy(stb + 24, &vendor, 8);
	memcpy(stb + 32, &fwrev, 4);
	memcpy(stb + 40, &hin, 8);
	memcpy(stb + 48, &cin, 8);
	memcpy(stb + 56, &hout, 8);
	memcpy(stb + 64, &cout, 8);
	memcpy(stb + 72, &herr, 8);
	memcpy(stb + 80, &cerr, 8);
	memcpy(stb + 88, &rt, 8);
	memcpy(stb + 96, &boot, 8);
	memcpy(stb + 104, &ncfg, 8);
	memcpy(stb + 112, &cfg, 8);
	if (out_st)
		*out_st = g_st_table;
	fprintf(stderr, "fast86: uefi st=%lx bs=%lx rt=%lx root=%s image=%lx\n",
	        (unsigned long)g_st_table, (unsigned long)g_bs_table,
	        (unsigned long)g_rt_table,
	        f86_sys_root() ? f86_sys_root() : "(none)",
	        (unsigned long)ibase);
	return 0;
}

static void bind_loaded_image(int ni, uint64_t parent)
{
	uint64_t li = f86_uefi_alloc(1);
	if (!li)
		return;
	memset(f86_gpa_hva(li), 0, 128);
	uint32_t lirev = 0x1000;
	uint64_t st = g_st_table, dev = g_vol_handle;
	uint64_t ibase = g_h[ni].image_base ? g_h[ni].image_base : f86_sys_image_base();
	uint64_t isize = g_h[ni].image_size ? g_h[ni].image_size : f86_sys_image_size();
	/* Per-image FilePath device path so the image can locate its own config. */
	uint64_t dp = g_file_dp;
	if (g_h[ni].dev_path[0]) {
		char efipath[256];
		snprintf(efipath, sizeof efipath, "%s", g_h[ni].dev_path);
		for (char *q = efipath; *q; q++)
			if (*q == '/')
				*q = '\\';
		g_h[ni].dev_dp = f86_uefi_alloc(1);
		if (g_h[ni].dev_dp)
			write_filepath_dp(g_h[ni].dev_dp, efipath);
		if (g_h[ni].dev_dp)
			dp = g_h[ni].dev_dp;
	}
	uint8_t *p = f86_gpa_hva(li);
	memcpy(p + 0, &lirev, 4);
	memcpy(p + 8, &parent, 8);
	memcpy(p + 16, &st, 8);
	memcpy(p + 24, &dev, 8);
	memcpy(p + 32, &dp, 8);
	memcpy(p + 64, &ibase, 8);
	memcpy(p + 72, &isize, 8);
	install_proto(ni, GUID_LOADED_IMAGE, li);
	install_proto(ni, GUID_DEVICE_PATH, dp);
	install_proto(ni, GUID_LI_DP, dp);
}

static uint64_t proto_for_guid(uint64_t handle, uint64_t guid_gpa)
{
	int hi = hnd_idx(handle);
	uint8_t *g = f86_gpa_hva(guid_gpa);
	if (hi >= 0 && g) {
		for (int i = 0; i < g_h[hi].nproto; i++)
			if (memcmp(g_h[hi].proto[i].guid, g, 16) == 0)
				return g_h[hi].proto[i].iface;
	}
	/* built-ins on the firmware handles */
	if (guid_at(guid_gpa, GUID_LOADED_IMAGE) && handle == g_img_handle)
		return g_li_proto;
	if (guid_at(guid_gpa, GUID_SIMPLE_FS) && handle == g_vol_handle)
		return g_fs_proto;
	if (guid_at(guid_gpa, GUID_BLOCK_IO) && handle == g_disk_handle)
		return g_blk_io;
	if (guid_at(guid_gpa, GUID_CONSOLE_CTL))
		return g_conctl;
	/* 26baccb1 is also what boot.efi LocateProtocol's for EB.MM;
	   returning a short ACPI vtable makes it call [iface+0x38] = NULL.
	   Offer the standard ACPI table GUID instead. */
	if (guid_at(guid_gpa, GUID_APPLE_DEVPROP))
		return g_devprop;
	if (guid_at(guid_gpa, GUID_DEVICE_PATH) && handle == g_disk_handle)
		return g_vol_dp;
	if (guid_at(guid_gpa, GUID_DEVICE_PATH) && handle == g_vol_handle)
		return g_vol_dp;
	if (guid_at(guid_gpa, GUID_DEVICE_PATH) && handle == g_img_handle)
		return g_file_dp;
	if (guid_at(guid_gpa, GUID_LI_DP) && handle == g_img_handle)
		return g_file_dp;
	if (guid_at(guid_gpa, GUID_GOP) &&
	    (handle == g_conout_handle || handle == g_vol_handle))
		return g_gop;
	if (guid_at(guid_gpa, GUID_TEXT_OUT) && handle == g_conout_handle)
		return g_conout;
	if (guid_at(guid_gpa, GUID_TEXT_IN) && handle == g_conin_handle)
		return g_conin;
	return 0;
}

static int file_open(F86CPU *c, uint64_t this_gpa, uint64_t out_gpa,
                     uint64_t name_gpa, uint64_t mode)
{
	(void)mode;
	int pi = find_hnd_by_proto(this_gpa);
	if (pi < 0)
		pi = 1;
	uint16_t *wname = f86_gpa_hva(name_gpa);
	char rel[256];
	utf16_to_utf8(wname, rel, sizeof rel);
	char path[512];
	if (!rel[0] || strcmp(rel, ".") == 0)
		snprintf(path, sizeof path, "%s", g_h[pi].host_path);
	else if (strcmp(rel, "..") == 0) {
		snprintf(path, sizeof path, "%s", g_h[pi].host_path);
		char *sl = strrchr(path, '/');
		if (sl && sl != path)
			*sl = 0;
	} else
		host_join(path, sizeof path, g_h[pi].host_path, rel);
	struct stat st;
	if (stat(path, &st) != 0) {
		fprintf(stderr, "uefi open miss this=%lx name@%lx '%s' -> %s\n",
		        (unsigned long)this_gpa, (unsigned long)name_gpa, rel, path);
		c->r[R_RAX] = EFI_NOT_FOUND;
		return 0;
	}
	{
		/* Guest paths must stay inside the volume's host directory:
		   "a/../../etc/passwd" used to escape --root / --mac-root. */
		char real[PATH_MAX], rootreal[PATH_MAX];
		int vi = pi;
		while (vi >= 0 && !g_h[vi].persistent && vi != 1 && vi != 5 && vi > 5)
			vi = -1; /* non-volume handles still carry a host_path below a volume */
		const char *root = f86_sys_root() ? f86_sys_root() : ".";
		const char *mroot = f86_sys_mac_root();
		if (realpath(path, real)) {
			int inside = 0;
			const char *roots[2] = { root, mroot };
			for (int ri = 0; ri < 2; ri++) {
				if (!roots[ri] || !roots[ri][0] || !realpath(roots[ri], rootreal))
					continue;
				size_t rl = strlen(rootreal);
				if (strncmp(real, rootreal, rl) == 0 && (real[rl] == '/' || real[rl] == 0))
					inside = 1;
			}
			if (!inside) {
				fprintf(stderr, "uefi open DENIED (outside volume): '%s' -> %s\n", rel, real);
				c->r[R_RAX] = EFI_NOT_FOUND;
				return 0;
			}
		}
		(void)vi;
	}
	int ni = alloc_hnd();
	if (ni < 0) {
		c->r[R_RAX] = EFI_UNSUPPORTED;
		return 0;
	}
	snprintf(g_h[ni].host_path, sizeof g_h[ni].host_path, "%s", path);
	g_h[ni].is_dir = S_ISDIR(st.st_mode);
	g_h[ni].size = (uint64_t)st.st_size;
	g_h[ni].pos = 0;
	g_h[ni].ndent = 0;
	g_h[ni].ident = 0;
	g_h[ni].fd = g_h[ni].is_dir ? -1 : open(path, O_RDONLY);
	if (g_h[ni].is_dir) {
		DIR *d = opendir(path);
		if (d) {
			struct dirent *de;
			while ((de = readdir(d)) && g_h[ni].ndent < 64) {
				if (de->d_name[0] == '.' &&
				    (de->d_name[1] == 0 ||
				     (de->d_name[1] == '.' && de->d_name[2] == 0)))
					continue;
				snprintf(g_h[ni].dents[g_h[ni].ndent], 256, "%s", de->d_name);
				g_h[ni].ndent++;
			}
			closedir(d);
		}
	}
	uint64_t proto = make_file_proto(ni);
	uint64_t *out = f86_gpa_hva(out_gpa);
	if (out)
		*out = proto;
	fprintf(stderr, "uefi open %s -> hnd %d proto %lx dir=%d size=%lu\n",
	        path, ni, (unsigned long)proto, g_h[ni].is_dir,
	        (unsigned long)g_h[ni].size);
	c->r[R_RAX] = EFI_SUCCESS;
	return 0;
}

int f86_uefi_dispatch(F86CPU *c, uint32_t id)
{
	uint64_t a0 = c->r[R_RCX];
	uint64_t a1 = c->r[R_RDX];
	uint64_t a2 = c->r[R_R8];
	uint64_t a3 = c->r[R_R9];
	if (id != PR_ConOutput && id != BS_Stall && id != BS_WaitForEvent &&
	    id != PR_GopBlt)
		fprintf(stderr, "uefi call id=%u rcx=%lx rdx=%lx r8=%lx r9=%lx rip=%lx\n",
		        id, (unsigned long)a0, (unsigned long)a1,
		        (unsigned long)a2, (unsigned long)a3,
		        (unsigned long)c->rip);
	/* MS x64 5th arg is at rsp+0x28 after the shadow home... guest rsp
	   points at the return address. 5th is [rsp+0x28]. */
	uint64_t a4 = 0, a5 = 0, a6 = 0, a7 = 0, a8 = 0, a9 = 0;
	if (c->r[R_RSP] + 0x58 < f86_ram_size()) {
		memcpy(&a4, f86_ram() + c->r[R_RSP] + 0x28, 8);
		memcpy(&a5, f86_ram() + c->r[R_RSP] + 0x30, 8);
		memcpy(&a6, f86_ram() + c->r[R_RSP] + 0x38, 8);
		memcpy(&a7, f86_ram() + c->r[R_RSP] + 0x40, 8);
		memcpy(&a8, f86_ram() + c->r[R_RSP] + 0x48, 8);
		memcpy(&a9, f86_ram() + c->r[R_RSP] + 0x50, 8);
	}

	switch (id) {
	case BS_RaiseTPL:
		c->r[R_RAX] = a0 ? a0 : 4;
		return 0;
	case BS_RestoreTPL:
	case BS_FreePages:
	case BS_FreePool:
	case BS_SetWatchdog:
	case BS_CloseProtocol:
	case BS_CreateEvent:
	case BS_CreateEventEx:
	case BS_CloseEvent:
	case BS_SetTimer:
	case BS_SignalEvent:
	case BS_CheckEvent:
	case BS_GetNextMonotonic: {
		if (id == BS_CreateEvent || id == BS_CreateEventEx) {
			/* CreateEvent(Type,TPL,NotifyFn,NotifyCtx,*Event): Event is arg5
			   (a4). CreateEventEx adds EventGroup as arg5, Event is arg6 (a5).
			   Writing to a3/a4 clobbered NotifyContext/EventGroup, leaving the
			   real *Event unset, so the picker's timer event stayed NULL and
			   its main loop spun forever. */
			uint64_t *out = f86_gpa_hva(id == BS_CreateEventEx ? a5 : a4);
			if (out)
				*out = 0x80; /* dummy event handle */
		}
		if (id == BS_GetNextMonotonic) {
			static uint64_t mono;
			uint64_t *out = f86_gpa_hva(a0);
			if (out)
				*out = ++mono;
		}
		c->r[R_RAX] = EFI_SUCCESS;
		return 0;
	}
	case BS_AllocatePages: {
		/* Type, MemoryType, Pages, *Memory */
		uint32_t typ = (uint32_t)a0;
		uint32_t memtype = (uint32_t)a1;
		uint64_t pages = a2;
		uint64_t *out = f86_gpa_hva(a3);
		uint64_t want = out ? *out : 0;
		if (pages == 0 || pages > (512ull << 10)) {
			fprintf(stderr, "uefi AllocatePages reject type=%u mem=%u pages=%lx want=%lx\n",
			        typ, memtype, (unsigned long)pages, (unsigned long)want);
			c->r[R_RAX] = 0x8000000000000009ull; /* OUT_OF_RESOURCES */
			return 0;
		}
		uint64_t p = 0;
		if (typ == 2) {
			/* AllocateAddress: honour the exact address or fail; the old
			   code silently handed back a different range with SUCCESS. */
			if (out && want >= 0x200000 && want + pages * 4096ull <= 0x70000000ull)
				p = want;
			else {
				fprintf(stderr, "uefi AllocatePages AllocateAddress want=%lx pages=%lu -> NOT_FOUND\n",
				        (unsigned long)want, (unsigned long)pages);
				c->r[R_RAX] = EFI_NOT_FOUND;
				return 0;
			}
		} else
			p = f86_uefi_alloc(pages);
		fprintf(stderr, "uefi AllocatePages type=%u mem=%u pages=%lu want=%lx -> %lx\n",
		        typ, memtype, (unsigned long)pages, (unsigned long)want,
		        (unsigned long)p);
		if (!p) {
			c->r[R_RAX] = EFI_UNSUPPORTED;
			return 0;
		}
		note_pages(p, pages, memtype);
		if (out)
			*out = p;
		c->r[R_RAX] = EFI_SUCCESS;
		return 0;
	}
	case BS_AllocatePool: {
		uint64_t sz = (a1 + 0xfff) / 0x1000;
		if (!sz)
			sz = 1;
		uint64_t p = f86_uefi_alloc(sz);
		uint64_t *out = f86_gpa_hva(a2);
		if (!p) {
			c->r[R_RAX] = EFI_UNSUPPORTED;
			return 0;
		}
		if (out)
			*out = p;
		c->r[R_RAX] = EFI_SUCCESS;
		return 0;
	}
	case BS_GetMemoryMap: {
		/* DescriptorSize is UINTN (8 on x64). Writing 4 left 0xAA in the
		   high half and boot.efi walked the map with stride 0xaaaaaaaa00000028. */
		enum { DSZ = 40, MAXD = 40 };
		typedef struct {
			uint32_t type, pad;
			uint64_t phys, virt, pages, attr;
		} MemDesc;
		MemDesc d[MAXD];
		int nd = 0;
		int idx[MAX_AP];
		int nap = g_nap;
		for (int i = 0; i < nap; i++)
			idx[i] = i;
		for (int i = 0; i < nap; i++)
			for (int j = i + 1; j < nap; j++)
				if (g_ap[idx[j]].phys < g_ap[idx[i]].phys) {
					int t = idx[i];
					idx[i] = idx[j];
					idx[j] = t;
				}
		#define ADD(ty, ph, pg, at) do { \
			if ((pg) && nd < MAXD) { \
				if (nd && d[nd-1].type == (uint32_t)(ty) && \
				    d[nd-1].attr == (uint64_t)(at) && \
				    d[nd-1].phys + d[nd-1].pages * 4096ull == (uint64_t)(ph)) \
					d[nd-1].pages += (uint64_t)(pg); \
				else { \
					d[nd].type = (uint32_t)(ty); d[nd].pad = 0; \
					d[nd].phys = (uint64_t)(ph); d[nd].virt = 0; \
					d[nd].pages = (uint64_t)(pg); d[nd].attr = (uint64_t)(at); \
					nd++; \
				} \
			} \
		} while (0)
		ADD(3, 0x00001000ull, (0x00100000ull - 0x1000ull) / 4096, 0xf);
		uint64_t cur = 0x00100000ull;
		const uint64_t conv_end = 0x60000000ull;
		for (int i = 0; i < nap; i++) {
			uint64_t p = g_ap[idx[i]].phys;
			uint64_t e = p + g_ap[idx[i]].pages * 4096ull;
			if (e <= cur || p >= conv_end)
				continue;
			if (p < cur)
				p = cur;
			if (e > conv_end)
				e = conv_end;
			if (p > cur)
				ADD(7, cur, (p - cur) / 4096, 0xf);
			ADD(g_ap[idx[i]].type, p, (e - p) / 4096, 0xf);
			if (e > cur)
				cur = e;
		}
		if (cur < conv_end)
			ADD(7, cur, (conv_end - cur) / 4096, 0xf);
		/* Include the UEFI pool so the GOP FB and boot_args are in physmap. */
		ADD(7, 0x60000000ull, (0x70000000ull - 0x60000000ull) / 4096, 0xf);
		ADD(0, 0x70000000ull, (0x80000000ull - 0x70000000ull) / 4096, 0);
		/* Only real RAM above 2 GiB. Advertising a fake 2-4 GiB range made
		   XNU hand out page-table pages at ~0xffbff000, outside the
		   emulated RAM, so PTE reads/writes vanished (PTE_LOCK spin). */
		{
			/* RAM above 2 GiB, stopping below the MMIO windows (ECAM at
			   0xf0000000, APICs/HPET above it) that f86_sys_init never
			   backs with memory. */
			uint64_t top = f86_ram_size();
			if (top > 0xf0000000ull)
				top = 0xf0000000ull;
			if (top > 0x80000000ull)
				ADD(7, 0x80000000ull, (top - 0x80000000ull) / 4096, 0xf);
		}
		#undef ADD
		uint64_t *szp = f86_gpa_hva(a0);
		uint64_t *dsize = f86_gpa_hva(a3); /* UINTN */
		uint32_t *dver = f86_gpa_hva(a4);
		uint64_t *key = f86_gpa_hva(a2);
		if (dsize)
			*dsize = DSZ;
		if (dver)
			*dver = 1;
		if (key)
			*key = 1;
		uint64_t need = (uint64_t)DSZ * (uint64_t)nd;
		if (!a1 || (szp && *szp < need)) {
			if (szp)
				*szp = need;
			c->r[R_RAX] = EFI_BAD_BUFFER;
			return 0;
		}
		if (szp)
			*szp = need;
		uint8_t *map = gpa_range(a1, need);
		if (map)
			memcpy(map, d, (size_t)need);
		c->r[R_RAX] = EFI_SUCCESS;
		return 0;
	}
	case BS_Stall:
		if (a0 > 10000)
			usleep((useconds_t)(a0 > 200000 ? 200000 : a0));
		c->r[R_RAX] = EFI_SUCCESS;
		return 0;
	case BS_HandleProtocol:
	case BS_OpenProtocol: {
		/* HandleProtocol(Handle, Guid, Interface)
		   OpenProtocol(Handle, Guid, Interface, Agent, Controller, Attr)
		   Interface is the 3rd argument (r8) in both. */
		uint64_t handle = a0;
		uint64_t guid = a1;
		uint64_t outp = a2;
		uint64_t iface = proto_for_guid(handle, guid);
		uint64_t *out = f86_gpa_hva(outp);
		if (!iface) {
			fprintf(stderr, "uefi handle %lx guid@%lx ",
			        (unsigned long)handle, (unsigned long)guid);
			log_guid("", guid);
			fprintf(stderr, " -> miss\n");
			c->r[R_RAX] = EFI_NOT_FOUND;
			return 0;
		}
		if (out)
			*out = iface;
		if (getenv("F86_UEFI")) {
			fprintf(stderr, "uefi handle %lx guid@%lx ",
			        (unsigned long)handle, (unsigned long)guid);
			log_guid("", guid);
			fprintf(stderr, " -> iface=%lx\n", (unsigned long)iface);
		}
		c->r[R_RAX] = EFI_SUCCESS;
		return 0;
	}
	case BS_LocateProtocol: {
		uint64_t iface = proto_for_guid(g_vol_handle, a0);
		if (!iface)
			iface = proto_for_guid(g_img_handle, a0);
		if (!iface) {
			uint8_t *g = f86_gpa_hva(a0);
			if (g) {
				for (int i = 0; i < MAX_HND && !iface; i++) {
					if (!g_h[i].used)
						continue;
					for (int j = 0; j < g_h[i].nproto; j++)
						if (memcmp(g_h[i].proto[j].guid, g, 16) == 0) {
							iface = g_h[i].proto[j].iface;
							break;
						}
				}
			}
		}
		uint64_t *out = f86_gpa_hva(a2);
		if (!iface) {
			log_guid("uefi LocateProtocol miss", a0);
			fprintf(stderr, "\n");
			c->r[R_RAX] = EFI_NOT_FOUND;
			return 0;
		}
		if (out)
			*out = iface;
		c->r[R_RAX] = EFI_SUCCESS;
		return 0;
	}
	case BS_InstallMultiple:
	case BS_InstallProtocol: {
		/* InstallProtocolInterface(Handle*, Guid, Type, Interface)
		   InstallMultipleProtocolInterfaces(Handle*, Guid, Interface, ..., NULL) */
		uint64_t guid_gpa = a1;
		uint64_t iface = (id == BS_InstallMultiple) ? a2 : a3;
		fprintf(stderr, "uefi Install id=%u handlep=%lx guid@%lx iface=%lx\n",
		        id, (unsigned long)a0, (unsigned long)guid_gpa, (unsigned long)iface);
		uint64_t *hp = f86_gpa_hva(a0);
		uint64_t h = hp ? *hp : 0;
		int hi = hnd_idx(h);
		if (hi < 0) {
			hi = alloc_hnd();
			if (hi < 0) {
				c->r[R_RAX] = EFI_UNSUPPORTED;
				return 0;
			}
			if (hp)
				*hp = hnd_val(hi);
		}
		uint8_t *g = f86_gpa_hva(guid_gpa);
		if (g)
			install_proto(hi, g, iface);
		if (id == BS_InstallMultiple) {
			/* further (Guid, Interface) pairs up to the NULL terminator */
			uint64_t more[6] = { a3, a4, a5, a6, a7, a8 };
			for (int k = 0; k < 3 && more[k * 2]; k++) {
				uint8_t *g2 = f86_gpa_hva(more[k * 2]);
				if (g2)
					install_proto(hi, g2, more[k * 2 + 1]);
			}
		}
		c->r[R_RAX] = EFI_SUCCESS;
		return 0;
	}
	case BS_InstallConfigTable: {
		/* InstallConfigurationTable(Guid, Table): replace or append an
		   entry in the EFI system table. OpenCore installs the SMBIOS and
		   ACPI tables it generates here; returning UNSUPPORTED leaves
		   macOS with the firmware's table and no platform UUID, and the
		   kernel then blocks forever in IOBSDGetPlatformUUID. The initial
		   array at g_stub_base+0x3940 holds four entries and is flanked by
		   other firmware data, so growth moves it to a fresh page. */
		static uint64_t cfg_tab, cfg_cap;
		uint8_t *g = gpa_range(a0, 16);
		uint64_t n = 0, ct = 0;
		if (!g) {
			c->r[R_RAX] = EFI_INVALID_PARAM;
			return 0;
		}
		memcpy(&n, f86_ram() + g_st_table + 104, 8);
		memcpy(&ct, f86_ram() + g_st_table + 112, 8);
		if (ct != cfg_tab) {
			cfg_tab = ct;
			cfg_cap = 4;
		}
		uint8_t *tab = gpa_range(ct, cfg_cap * 24);
		if (!tab) {
			c->r[R_RAX] = EFI_INVALID_PARAM;
			return 0;
		}
		for (uint64_t i = 0; i < n; i++) {
			if (memcmp(tab + i * 24, g, 16) == 0) {
				memcpy(tab + i * 24 + 16, &a1, 8);
				c->r[R_RAX] = EFI_SUCCESS;
				return 0;
			}
		}
		if (n >= cfg_cap) {
			uint64_t np = n < 4096 / 24 ? f86_uefi_alloc(1) : 0;
			uint8_t *nt = np ? gpa_range(np, 4096) : NULL;
			if (!nt) {
				c->r[R_RAX] = EFI_OUT_OF_RESOURCES;
				return 0;
			}
			memcpy(nt, tab, (size_t)n * 24);
			ct = np;
			cfg_tab = np;
			cfg_cap = 4096 / 24;
			tab = nt;
			memcpy(f86_ram() + g_st_table + 112, &ct, 8);
		}
		memcpy(tab + n * 24, g, 16);
		memcpy(tab + n * 24 + 16, &a1, 8);
		n++;
		memcpy(f86_ram() + g_st_table + 104, &n, 8);
		fprintf(stderr, "uefi config table guid@%lx -> %lx (n=%lu)\n",
		        (unsigned long)a0, (unsigned long)a1, (unsigned long)n);
		c->r[R_RAX] = EFI_SUCCESS;
		return 0;
	}
	case BS_LocateHandle:
	case BS_LocateHandleBuffer: {
		/* SearchType, Protocol, SearchKey, *BufSize/NoHandles, Buffer/**Buffer */
		uint32_t kind = (uint32_t)a0;
		uint64_t found[8];
		int nf = 0;
		if (kind == 2 /* ByProtocol */ && a1) {
			if (proto_for_guid(g_vol_handle, a1))
				found[nf++] = g_vol_handle;
			if (proto_for_guid(g_img_handle, a1))
				found[nf++] = g_img_handle;
			uint8_t *g = f86_gpa_hva(a1);
			if (g) {
				for (int i = 0; i < MAX_HND && nf < 8; i++) {
					if (!g_h[i].used)
						continue;
					for (int j = 0; j < g_h[i].nproto; j++)
						if (memcmp(g_h[i].proto[j].guid, g, 16) == 0) {
							uint64_t hv = hnd_val(i);
							int dup = 0;
							for (int k = 0; k < nf; k++)
								if (found[k] == hv)
									dup = 1;
							if (!dup)
								found[nf++] = hv;
							break;
						}
				}
			}
		}
		if (getenv("F86_UEFI") || 1)
			fprintf(stderr, "uefi LocateHandle kind=%u proto@%lx n=%d\n",
			        kind, (unsigned long)a1, nf);
		if (!nf) {
			c->r[R_RAX] = EFI_NOT_FOUND;
			return 0;
		}
		if (id == BS_LocateHandleBuffer) {
			uint64_t *nh = f86_gpa_hva(a3);
			uint64_t *bp = f86_gpa_hva(a4);
			uint64_t buf = f86_uefi_alloc(1);
			if (nh)
				*nh = (uint64_t)nf;
			if (bp)
				*bp = buf;
			if (buf)
				memcpy(f86_gpa_hva(buf), found, (size_t)nf * 8);
			c->r[R_RAX] = EFI_SUCCESS;
			return 0;
		}
		uint64_t *szp = f86_gpa_hva(a3);
		uint64_t need = (uint64_t)nf * 8;
		if (szp && *szp < need) {
			*szp = need;
			c->r[R_RAX] = 0x8000000000000005ull;
			return 0;
		}
		if (szp)
			*szp = need;
		void *buf = f86_gpa_hva(a4);
		if (buf)
			memcpy(buf, found, (size_t)need);
		c->r[R_RAX] = EFI_SUCCESS;
		return 0;
	}
	case BS_LoadImage: {
		/* BootPolicy, Parent, DevicePath, SourceBuffer, SourceSize, *ImageHandle */
		uint64_t src = a3, sz = a4, out_h = a5;
		if (!src || !sz) {
			/* No buffer — try the usual OpenCore path. */
			const char *root = f86_sys_root();
			char path[512];
			snprintf(path, sizeof path, "%s/EFI/OC/OpenCore.efi",
			         root ? root : ".");
			uint64_t entry = 0;
			if (f86_sys_load_efi(path, &entry) != 0) {
				c->r[R_RAX] = EFI_NOT_FOUND;
				return 0;
			}
			int ni = alloc_hnd();
			if (ni < 0) {
				c->r[R_RAX] = EFI_UNSUPPORTED;
				return 0;
			}
			g_h[ni].entry = entry;
			g_h[ni].image_base = f86_sys_image_base();
			g_h[ni].image_size = f86_sys_image_size();
			if (a2)
				device_path_extract(a2, g_h[ni].dev_path, sizeof g_h[ni].dev_path);
			bind_loaded_image(ni, a1);
			uint64_t *oh = f86_gpa_hva(out_h);
			if (oh)
				*oh = hnd_val(ni);
			c->r[R_RAX] = EFI_SUCCESS;
			return 0;
		}
		/* write buffer to a temp file and reuse the PE loader */
		char tmp[] = "/tmp/f86efiXXXXXX";
		int fd = mkstemp(tmp);
		if (fd < 0) {
			c->r[R_RAX] = EFI_UNSUPPORTED;
			return 0;
		}
		void *buf = f86_gpa_hva(src);
		if (!buf || write(fd, buf, (size_t)sz) != (ssize_t)sz) {
			close(fd);
			unlink(tmp);
			c->r[R_RAX] = EFI_UNSUPPORTED;
			return 0;
		}
		close(fd);
		uint64_t entry = 0;
		if (f86_sys_load_efi(tmp, &entry) != 0) {
			unlink(tmp);
			c->r[R_RAX] = EFI_UNSUPPORTED;
			return 0;
		}
		unlink(tmp);
		int ni = alloc_hnd();
		if (ni < 0) {
			c->r[R_RAX] = EFI_UNSUPPORTED;
			return 0;
		}
		g_h[ni].entry = entry;
		g_h[ni].image_base = f86_sys_image_base();
		g_h[ni].image_size = f86_sys_image_size();
		if (a2)
			device_path_extract(a2, g_h[ni].dev_path, sizeof g_h[ni].dev_path);
		bind_loaded_image(ni, a1);
		uint64_t *oh = f86_gpa_hva(out_h);
		if (oh)
			*oh = hnd_val(ni);
		c->r[R_RAX] = EFI_SUCCESS;
		return 0;
	}
	case BS_StartImage: {
		int hi = hnd_idx(a0);
		if (hi < 0 || !g_h[hi].entry) {
			c->r[R_RAX] = EFI_INVALID;
			return 0;
		}
		/* Re-enter the new image. Save return so Exit/ret-0 can come back. */
		g_h[hi].pos = c->rip; /* reuse pos as saved rip after StartImage hlt */
		c->r[R_RCX] = a0;
		c->r[R_RDX] = g_st_table;
		c->rip = g_h[hi].entry;
		fprintf(stderr, "uefi StartImage hnd=%lx entry=%lx\n",
		        (unsigned long)a0, (unsigned long)g_h[hi].entry);
		c->r[R_RAX] = EFI_SUCCESS;
		return 2; /* signal: rip already set */
	}
	case BS_Exit:
		c->r[R_RAX] = a1;
		c->exited = 1;
		c->exit_code = 0;
		return 1;
	case BS_ExitBootServices:
		fprintf(stderr, "fast86: ExitBootServices\n");
		extern void f86_sys_exited_bs(void);
		f86_sys_exited_bs();
		{
			uint64_t zero = 0;
			void *st = f86_gpa_hva(g_st_table);
			if (st)
				memcpy((uint8_t *)st + 96, &zero, 8);
		}
		c->r[R_RAX] = EFI_SUCCESS;
		return 0;
	case BS_CopyMem: {
		void *d = gpa_range(a0, a2);
		void *s = gpa_range(a1, a2);
		if (d && s && a2)
			memmove(d, s, (size_t)a2);
		c->r[R_RAX] = EFI_SUCCESS;
		return 0;
	}
	case BS_SetMem: {
		/* Buffer, Size, Value */
		void *d = gpa_range(a0, a1);
		if (d && a1)
			memset(d, (int)(uint8_t)a2, (size_t)a1);
		c->r[R_RAX] = EFI_SUCCESS;
		return 0;
	}
	case BS_CalculateCrc32: {
		uint32_t *out = gpa_range(a2, 4);
		void *buf = gpa_range(a0, a1);
		if (out && buf)
			*out = efi_crc32(buf, (size_t)a1);
		else if (out)
			*out = 0;
		c->r[R_RAX] = (out && buf) ? EFI_SUCCESS : EFI_INVALID_PARAM;
		return 0;
	}
	case PR_ConReset:
		c->r[R_RAX] = EFI_SUCCESS;
		return 0;
	case PR_ConOutput: {
		uint16_t *s = f86_gpa_hva(a1);
		if (s) {
			for (int i = 0; i < 2048 && s[i]; i++) {
				unsigned char ch = s[i] < 128 ? (unsigned char)s[i] : '?';
				fputc(ch, stderr);
			}
			fflush(stderr);
		}
		c->r[R_RAX] = EFI_SUCCESS;
		return 0;
	}
	case PR_OpenVolume: {
		int hi = find_hnd_by_sfs(a0);
		if (hi < 0)
			hi = 1;
		uint64_t proto = make_file_proto(hi);
		g_h[hi].ident = 0;
		g_h[hi].ndent = 0;
		if (g_h[hi].host_path[0]) {
			DIR *d = opendir(g_h[hi].host_path);
			if (d) {
				struct dirent *de;
				while ((de = readdir(d)) && g_h[hi].ndent < 64) {
					if (de->d_name[0] == '.' &&
					    (de->d_name[1] == 0 ||
					     (de->d_name[1] == '.' && de->d_name[2] == 0)))
						continue;
					snprintf(g_h[hi].dents[g_h[hi].ndent], 256, "%s", de->d_name);
					g_h[hi].ndent++;
				}
				closedir(d);
			}
		}
		uint64_t *out = f86_gpa_hva(a1);
		if (out)
			*out = proto;
		fprintf(stderr, "uefi OpenVolume this=%lx root=%s proto=%lx ndent=%d\n",
		        (unsigned long)a0, g_h[hi].host_path, (unsigned long)proto,
		        g_h[hi].ndent);
		c->r[R_RAX] = proto ? EFI_SUCCESS : EFI_UNSUPPORTED;
		return 0;
	}
	case PR_FileOpen:
		return file_open(c, a0, a1, a2, a3);
	case PR_FileClose: {
		int hi = find_hnd_by_proto(a0);
		if (hi >= 2 && !g_h[hi].persistent) {
			if (g_h[hi].fd >= 0)
				close(g_h[hi].fd);
			g_h[hi].used = 0;
		}
		c->r[R_RAX] = EFI_SUCCESS;
		return 0;
	}
	case PR_FileRead: {
		int hi = find_hnd_by_proto(a0);
		uint64_t *szp = f86_gpa_hva(a1);
		void *buf = f86_gpa_hva(a2);
		if (hi < 0 || !szp || !buf) {
			c->r[R_RAX] = EFI_UNSUPPORTED;
			return 0;
		}
		if (g_h[hi].is_dir) {
			if (g_h[hi].ident >= g_h[hi].ndent) {
				*szp = 0;
				c->r[R_RAX] = EFI_SUCCESS;
				return 0;
			}
			const char *nm = g_h[hi].dents[g_h[hi].ident++];
			size_t nlen = strlen(nm);
			uint64_t need = 80 + (nlen + 1) * 2;
			if (*szp < need) {
				*szp = need;
				g_h[hi].ident--;
				c->r[R_RAX] = EFI_BAD_BUFFER;
				return 0;
			}
			char full[512];
			host_join(full, sizeof full, g_h[hi].host_path, nm);
			struct stat st;
			memset(&st, 0, sizeof st);
			stat(full, &st);
			memset(buf, 0, (size_t)need);
			uint64_t sz = (uint64_t)st.st_size;
			uint64_t attr = S_ISDIR(st.st_mode) ? 0x10ull : 0x1ull;
			uint8_t *info = buf;
			memcpy(info + 0, &need, 8);
			memcpy(info + 8, &sz, 8);
			memcpy(info + 16, &sz, 8);
			memcpy(info + 72, &attr, 8);
			for (size_t i = 0; i <= nlen; i++) {
				info[80 + i * 2] = (uint8_t)nm[i];
				info[81 + i * 2] = 0;
			}
			*szp = need;
			c->r[R_RAX] = EFI_SUCCESS;
			return 0;
		}
		if (g_h[hi].fd < 0) {
			c->r[R_RAX] = EFI_UNSUPPORTED;
			return 0;
		}
		if (!gpa_range(a2, *szp)) {
			c->r[R_RAX] = EFI_INVALID_PARAM;
			return 0;
		}
		ssize_t n = read(g_h[hi].fd, buf, (size_t)*szp);
		if (n < 0)
			n = 0;
		*szp = (uint64_t)n;
		g_h[hi].pos += (uint64_t)n;
		c->r[R_RAX] = EFI_SUCCESS;
		return 0;
	}
	case PR_FileSetPos: {
		int hi = find_hnd_by_proto(a0);
		if (hi >= 0 && g_h[hi].is_dir) {
			if (a1 == 0)
				g_h[hi].ident = 0;
			c->r[R_RAX] = EFI_SUCCESS;
			return 0;
		}
		if (hi >= 0 && g_h[hi].fd >= 0) {
			off_t o = (a1 == ~0ull) ? (off_t)g_h[hi].size : (off_t)a1;
			lseek(g_h[hi].fd, o, SEEK_SET);
			g_h[hi].pos = (uint64_t)o;
		}
		c->r[R_RAX] = EFI_SUCCESS;
		return 0;
	}
	case PR_FileGetPos: {
		int hi = find_hnd_by_proto(a0);
		uint64_t *out = f86_gpa_hva(a1);
		if (out && hi >= 0)
			*out = g_h[hi].pos;
		c->r[R_RAX] = EFI_SUCCESS;
		return 0;
	}
	case PR_FileGetInfo: {
		int hi = find_hnd_by_proto(a0);
		uint64_t *szp = f86_gpa_hva(a2);
		uint8_t *info = f86_gpa_hva(a3);
		if (guid_at(a1, GUID_FILE_SYS_INFO)) {
			uint64_t need = 8 + 1 + 7 + 8 + 8 + 4 + 2; /* ~38, pad to 40 */
			need = 40;
			if (szp && *szp < need) {
				*szp = need;
				c->r[R_RAX] = EFI_BAD_BUFFER;
				return 0;
			}
			if (szp)
				*szp = need;
			if (info) {
				memset(info, 0, (size_t)need);
				memcpy(info + 0, &need, 8);
				info[8] = 1; /* ReadOnly */
				uint64_t vol = 1ull << 30, freeb = 1ull << 29;
				uint32_t blk = 512;
				memcpy(info + 16, &vol, 8);
				memcpy(info + 24, &freeb, 8);
				memcpy(info + 32, &blk, 4);
			}
			c->r[R_RAX] = EFI_SUCCESS;
			return 0;
		}
		/* Any other GetInfo GUID (Apple APFS volume/container and bless
		   metadata) is unsupported, not generic file info. Returning success
		   here made OpenCore read EFI_FILE_INFO bytes as APPLE_APFS_VOLUME_INFO
		   and take the APFS boot path, so it never probed the predefined
		   System/Library/CoreServices/boot.efi paths. */
		if (!guid_at(a1, GUID_FILE_INFO)) {
			c->r[R_RAX] = EFI_UNSUPPORTED;
			return 0;
		}
		const char *bn = (hi >= 0) ? g_h[hi].host_path : "";
		const char *slash = strrchr(bn, '/');
		if (slash)
			bn = slash + 1;
		size_t nlen = strlen(bn);
		/* EFI_FILE_INFO: Size, FileSize, PhysicalSize, 3*EFI_TIME, Attribute, FileName */
		uint64_t need = 80 + (nlen + 1) * 2;
		if (szp && *szp < need) {
			*szp = need;
			c->r[R_RAX] = EFI_BAD_BUFFER;
			return 0;
		}
		if (szp)
			*szp = need;
		if (info && hi >= 0) {
			memset(info, 0, (size_t)need);
			uint64_t sz = g_h[hi].size;
			uint64_t attr = g_h[hi].is_dir ? 0x10ull : 0x1ull;
			memcpy(info + 0, &need, 8);
			memcpy(info + 8, &sz, 8);
			memcpy(info + 16, &sz, 8);
			memcpy(info + 72, &attr, 8);
			for (size_t i = 0; i <= nlen; i++) {
				info[80 + i * 2] = (uint8_t)bn[i];
				info[81 + i * 2] = 0;
			}
		}
		c->r[R_RAX] = EFI_SUCCESS;
		return 0;
	}
	case PR_FileDelete:
	case PR_FileWrite:
	case PR_FileSetInfo:
	case PR_FileFlush:
		c->r[R_RAX] = EFI_UNSUPPORTED;
		return 0;
	case BS_WaitForEvent: {
		uint64_t *idx = f86_gpa_hva(a2);
		if (idx)
			*idx = 0;
		usleep(2000); /* 2 ms so the picker does not spin the host */
		{
			static int waits;
			if (++waits == 80 && g_gop_fb) {
				FILE *f = fopen("/tmp/f86-gop.ppm", "w");
				if (f) {
					fprintf(f, "P6\n%d %d\n255\n", GOP_W, GOP_H);
					uint32_t *px = (uint32_t *)(f86_ram() + g_gop_fb);
					for (int i = 0; i < GOP_W * GOP_H; i++) {
						unsigned p = px[i];
						fputc(p & 0xff, f);
						fputc((p >> 8) & 0xff, f);
						fputc((p >> 16) & 0xff, f);
					}
					fclose(f);
					fprintf(stderr, "uefi gop dumped after wait=%d fb=%lx\n",
					        waits, (unsigned long)g_gop_fb);
				}
			}
		}
		c->r[R_RAX] = EFI_SUCCESS;
		return 0;
	}
	case BS_LocateDevicePath: {
		/* Protocol, **DevicePath, *Device. Map the leading volume node to the
		   matching handle and advance *DevicePath past it, so OpenCore's
		   predefined-path scan opens System/Library/CoreServices/boot.efi on
		   the right SimpleFS volume instead of always hitting the ESP. */
		uint64_t *dpp = f86_gpa_hva(a1);
		uint64_t *dev = f86_gpa_hva(a2);
		uint64_t handle = g_vol_handle;
		if (dpp && *dpp) {
			uint8_t *dp = f86_gpa_hva(*dpp);
			if (dp && dp[0] == 4 && dp[1] == 1) {
				uint16_t nlen = (uint16_t)(dp[2] | (dp[3] << 8));
				if (nlen < 512) {
					for (int i = 0; i < MAX_HND; i++) {
						if (!g_h[i].used)
							continue;
						for (int j = 0; j < g_h[i].nproto; j++) {
							if (memcmp(g_h[i].proto[j].guid, GUID_DEVICE_PATH, 16))
								continue;
							uint8_t *v = f86_gpa_hva(g_h[i].proto[j].iface);
							if (v && memcmp(v, dp, nlen) == 0) {
								handle = hnd_val(i);
								*dpp = *dpp + nlen;
								break;
							}
						}
					}
				}
			}
		}
		if (dev)
			*dev = handle;
		c->r[R_RAX] = EFI_SUCCESS;
		return 0;
	}
	case BS_RegisterProtocolNotify: {
		/* (Protocol, Event, *Registration). Nothing is ever hot-plugged,
		   so hand back a registration key and never signal the event.
		   OpenCore's AppleEvent install (SimplePointer notify) needs
		   EFI_SUCCESS here or it bails with a halting DEBUG_ERROR. */
		static uint64_t regkey = 0x9000;
		uint64_t *out = f86_gpa_hva(a2);
		if (out)
			*out = regkey++;
		c->r[R_RAX] = EFI_SUCCESS;
		return 0;
	}
	case PR_DxeStub:
		c->r[R_RAX] = EFI_UNSUPPORTED;
		return 0;
	case BS_UninstallProtocol:
	case BS_UninstallMultiple:
	case BS_ReinstallProtocol: {
		/* UninstallProtocolInterface(Handle, Guid, Interface)
		   UninstallMultipleProtocolInterfaces(Handle, Guid, Iface, ..., NULL)
		   ReinstallProtocolInterface(Handle, Guid, Old, New)
		   EDK2's EfiNamedEventSignal (used by OpenCore's OSInfo protocol
		   right before boot.efi runs) installs a NULL interface on a fresh
		   handle and uninstalls it again; DEBUG builds assert on failure. */
		int hi = hnd_idx(a0);
		uint64_t pairs[8] = { a1, a2, a3, a4, a5, a6, a7, a8 };
		int npairs = (id == BS_UninstallMultiple) ? 4 : 1;
		int removed = 0;
		for (int k = 0; k < npairs && hi >= 0; k++) {
			uint64_t gg = pairs[k * 2];
			if (!gg)
				break;
			uint8_t *g = f86_gpa_hva(gg);
			if (!g)
				break;
			for (int j = 0; j < g_h[hi].nproto; j++) {
				if (memcmp(g_h[hi].proto[j].guid, g, 16) != 0)
					continue;
				if (id == BS_ReinstallProtocol) {
					g_h[hi].proto[j].iface = a3;
				} else {
					memmove(&g_h[hi].proto[j], &g_h[hi].proto[j + 1],
					        (size_t)(g_h[hi].nproto - j - 1) * sizeof(Proto));
					g_h[hi].nproto--;
				}
				removed++;
				break;
			}
		}
		if (hi >= 5 && g_h[hi].nproto == 0 && g_h[hi].fd < 0 &&
		    !g_h[hi].host_path[0] && !g_h[hi].image_base && !g_h[hi].persistent)
			g_h[hi].used = 0; /* handle dies with its last protocol */
		fprintf(stderr, "uefi %s hnd=%lx removed=%d\n",
		        id == BS_ReinstallProtocol ? "Reinstall" : "Uninstall",
		        (unsigned long)a0, removed);
		c->r[R_RAX] = removed ? EFI_SUCCESS : EFI_NOT_FOUND;
		return 0;
	}
	case BS_ConnectController:
		/* Do not bind OpenHfsPlus onto the fake BlockIo (zeros are not HFS). */
		c->r[R_RAX] = EFI_NOT_FOUND;
		return 0;
	case BS_DisconnectController:
		c->r[R_RAX] = EFI_SUCCESS;
		return 0;
	case PR_ConInReset:
		c->r[R_RAX] = EFI_SUCCESS;
		return 0;
	case PR_ConInRead:
		c->r[R_RAX] = EFI_NOT_READY;
		return 0;
	case RT_GetTime: {
		uint8_t *t = f86_gpa_hva(a0);
		if (t) {
			time_t now = time(NULL);
			struct tm tm;
			gmtime_r(&now, &tm);
			uint16_t year = (uint16_t)(tm.tm_year + 1900);
			memset(t, 0, 16);
			memcpy(t + 0, &year, 2);
			t[2] = (uint8_t)(tm.tm_mon + 1);
			t[3] = (uint8_t)tm.tm_mday;
			t[4] = (uint8_t)tm.tm_hour;
			t[5] = (uint8_t)tm.tm_min;
			t[6] = (uint8_t)tm.tm_sec;
		}
		c->r[R_RAX] = EFI_SUCCESS;
		return 0;
	}
	case RT_SetTime:
	case RT_GetWakeup:
	case RT_SetWakeup:
	case RT_SetVAMap:
	case RT_ConvertPtr:
	case RT_GetNextMono:
	case RT_UpdateCapsule:
	case RT_QueryCapsule:
	case RT_QueryVariable:
		c->r[R_RAX] = EFI_UNSUPPORTED;
		return 0;
	case RT_GetVariable: {
		char name[128];
		uint16_t *w = f86_gpa_hva(a0);
		utf16_to_utf8(w, name, sizeof name);
		fprintf(stderr, "uefi GetVariable '%s'\n", name);
		uint8_t *guid = f86_gpa_hva(a1);
		uint64_t *szp = f86_gpa_hva(a3);
		void *dst = f86_gpa_hva(a4);
		int hit = -1;
		for (int i = 0; i < 64; i++) {
			if (!g_var[i].used)
				continue;
			if (strcmp(g_var[i].name, name) != 0)
				continue;
			if (guid && memcmp(g_var[i].guid, guid, 16) == 0) {
				hit = i;
				break;
			}
			if (hit < 0)
				hit = i; /* name-only fallback */
		}
		if (hit < 0) {
			c->r[R_RAX] = EFI_NOT_FOUND;
			return 0;
		}
		if (a2) {
			uint32_t *ap = f86_gpa_hva(a2);
			if (ap)
				*ap = g_var[hit].attrs;
		}
		if (szp && *szp < g_var[hit].size) {
			*szp = g_var[hit].size;
			c->r[R_RAX] = EFI_BAD_BUFFER;
			return 0;
		}
		if (szp)
			*szp = g_var[hit].size;
		if (dst)
			memcpy(dst, g_var[hit].data, g_var[hit].size);
		c->r[R_RAX] = EFI_SUCCESS;
		return 0;
	}
	case RT_SetVariable: {
		char name[128];
		uint16_t *w = f86_gpa_hva(a0);
		utf16_to_utf8(w, name, sizeof name);
		uint8_t *guid = f86_gpa_hva(a1);
		uint32_t attrs = (uint32_t)a2;
		uint64_t sz = a3;
		void *src = f86_gpa_hva(a4);
		if (!name[0] || !guid) {
			c->r[R_RAX] = EFI_INVALID;
			return 0;
		}
		if (sz == 0) {
			for (int i = 0; i < 64; i++) {
				if (g_var[i].used && strcmp(g_var[i].name, name) == 0 &&
				    memcmp(g_var[i].guid, guid, 16) == 0)
					g_var[i].used = 0;
			}
			c->r[R_RAX] = EFI_SUCCESS;
			return 0;
		}
		if (sz > sizeof g_var[0].data) {
			c->r[R_RAX] = EFI_UNSUPPORTED;
			return 0;
		}
		int slot = -1;
		for (int i = 0; i < 64; i++) {
			if (g_var[i].used && strcmp(g_var[i].name, name) == 0 &&
			    memcmp(g_var[i].guid, guid, 16) == 0) {
				slot = i;
				break;
			}
			if (!g_var[i].used && slot < 0)
				slot = i;
		}
		if (slot < 0) {
			c->r[R_RAX] = EFI_UNSUPPORTED;
			return 0;
		}
		g_var[slot].used = 1;
		snprintf(g_var[slot].name, sizeof g_var[slot].name, "%s", name);
		memcpy(g_var[slot].guid, guid, 16);
		g_var[slot].attrs = attrs;
		g_var[slot].size = (uint32_t)sz;
		if (src && sz)
			memcpy(g_var[slot].data, src, (size_t)sz);
		fprintf(stderr, "uefi SetVariable '%s' size=%lu\n", name, (unsigned long)sz);
		c->r[R_RAX] = EFI_SUCCESS;
		return 0;
	}
	case RT_GetNextVariable:
		c->r[R_RAX] = EFI_NOT_FOUND;
		return 0;
	case RT_ResetSystem:
		fprintf(stderr, "fast86: ResetSystem\n");
		c->exited = 1;
		c->exit_code = 0;
		return 1;
	case PR_GopQuery: {
		uint64_t *szp = f86_gpa_hva(a2);
		uint64_t *infp = f86_gpa_hva(a3);
		if (a1 != 0) {
			c->r[R_RAX] = EFI_UNSUPPORTED;
			return 0;
		}
		if (szp)
			*szp = 36;
		if (infp)
			*infp = g_gop_info;
		c->r[R_RAX] = EFI_SUCCESS;
		return 0;
	}
	case PR_BlkReset:
	case PR_BlkFlush:
		c->r[R_RAX] = EFI_SUCCESS;
		return 0;
	case PR_BlkRead: {
		/* This, MediaId, LBA, BufferSize, Buffer */
		void *buf = f86_gpa_hva(a4);
		uint64_t lba = a2 + f86_sys_part_lba();
		if (!buf) {
			c->r[R_RAX] = EFI_INVALID;
			return 0;
		}
		if (f86_sys_disk_read(lba, (uint32_t)a3, buf) != 0)
			memset(buf, 0, (size_t)a3);
		c->r[R_RAX] = EFI_SUCCESS;
		return 0;
	}
	case PR_BlkWrite:
		c->r[R_RAX] = EFI_UNSUPPORTED;
		return 0;
	case PR_ConCtlGet: {
		uint32_t *mode = f86_gpa_hva(a1);
		if (mode)
			*mode = 1; /* EfiConsoleControlScreenGraphics */
		if (a2) {
			uint8_t *gop = f86_gpa_hva(a2);
			if (gop)
				*gop = 1;
		}
		if (a3) {
			uint8_t *lk = f86_gpa_hva(a3);
			if (lk)
				*lk = 0;
		}
		c->r[R_RAX] = EFI_SUCCESS;
		return 0;
	}
	case PR_ConCtlSet:
	case PR_ConCtlLock:
		c->r[R_RAX] = EFI_SUCCESS;
		return 0;
	case PR_AcpiInstall: {
		uint64_t *key = f86_gpa_hva(a3);
		if (key)
			*key = a1 ? a1 : 1;
		fprintf(stderr, "uefi AcpiInstall buf=%lx sz=%lx\n",
		        (unsigned long)a1, (unsigned long)a2);
		c->r[R_RAX] = EFI_SUCCESS;
		return 0;
	}
	case PR_AcpiUninstall:
		c->r[R_RAX] = EFI_SUCCESS;
		return 0;
	case PR_DevPropGet:
	case PR_DevPropSet:
	case PR_DevPropDel:
	case PR_DevPropAll:
		c->r[R_RAX] = EFI_NOT_FOUND;
		return 0;
	case PR_GopSet:
		c->r[R_RAX] = (a1 == 0) ? EFI_SUCCESS : EFI_UNSUPPORTED;
		return 0;
	case PR_GopBlt: {
		/* This, BltBuffer, Op, SrcX, SrcY, DstX, DstY, W, H, Delta */
		uint32_t op = (uint32_t)a2;
		uint32_t sx = (uint32_t)a3, sy = (uint32_t)a4;
		uint32_t dx = (uint32_t)a5, dy = (uint32_t)a6;
		uint32_t w = (uint32_t)a7, h = (uint32_t)a8;
		uint32_t delta = (uint32_t)a9;
		uint8_t *fb = (g_gop_fb && g_gop_fb + (uint64_t)GOP_W * GOP_H * 4 <= f86_ram_size())
		              ? f86_ram() + g_gop_fb : NULL;
		uint32_t *buf = f86_gpa_hva(a1);
		if (!fb || !w || !h || dx >= GOP_W || dy >= GOP_H) {
			c->r[R_RAX] = EFI_INVALID;
			return 0;
		}
		if (dx + w > GOP_W)
			w = GOP_W - dx;
		if (dy + h > GOP_H)
			h = GOP_H - dy;
		uint32_t stride = delta ? delta / 4 : w;
		for (uint32_t y = 0; y < h; y++) {
			uint32_t *dst = (uint32_t *)(fb + ((dy + y) * GOP_W + dx) * 4);
			if (op == 0 && buf) { /* VideoFill */
				uint32_t pix = buf[0];
				for (uint32_t x = 0; x < w; x++)
					dst[x] = pix;
			} else if (op == 2 && buf) { /* BufferToVideo */
				uint32_t *src = buf + (sy + y) * stride + sx;
				memcpy(dst, src, w * 4);
			} else if (op == 1 && buf) { /* VideoToBuffer */
				uint32_t *src = (uint32_t *)(fb + ((sy + y) * GOP_W + sx) * 4);
				uint32_t *d = buf + (dy + y) * stride + dx;
				memcpy(d, src, w * 4);
			} else if (op == 3) { /* VideoToVideo */
				uint32_t *src = (uint32_t *)(fb + ((sy + y) * GOP_W + sx) * 4);
				memmove(dst, src, w * 4);
			}
		}
		c->r[R_RAX] = EFI_SUCCESS;
		{
			static int blts;
			if (++blts == 50 || (blts % 500) == 0) {
				FILE *f = fopen("/tmp/f86-gop.ppm", "w");
				if (f && g_gop_fb) {
					fprintf(f, "P6\n%d %d\n255\n", GOP_W, GOP_H);
					uint32_t *px = (uint32_t *)(f86_ram() + g_gop_fb);
					for (int i = 0; i < GOP_W * GOP_H; i++) {
						unsigned p = px[i];
						fputc(p & 0xff, f);
						fputc((p >> 8) & 0xff, f);
						fputc((p >> 16) & 0xff, f);
					}
					fclose(f);
					fprintf(stderr, "uefi gop dumped /tmp/f86-gop.ppm (blt=%d)\n", blts);
				} else if (f)
					fclose(f);
			}
		}
		return 0;
	}
	default:
		if (getenv("F86_UEFI"))
			fprintf(stderr, "uefi bs[%u] rcx=%lx rdx=%lx r8=%lx r9=%lx\n",
			        id, (unsigned long)a0, (unsigned long)a1,
			        (unsigned long)a2, (unsigned long)a3);
		c->r[R_RAX] = EFI_UNSUPPORTED;
		return 0;
	}
}
