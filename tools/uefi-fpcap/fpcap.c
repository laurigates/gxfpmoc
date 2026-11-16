// SPDX-License-Identifier: GPL-2.0-only
//
// fpcap - UEFI pre-boot fingerprint-key capture for the Huawei MateBook X Pro 2020.
//
// During BIOS pre-boot auth (PBA) the EC runs GET_BIOS_KEY and bus-masters the
// 32-byte TLS-PSK ("Client_identity") into the host EMI window. The OS clears it
// before Linux runs, so it can only be caught from the pre-boot environment.
//
// This app scans the three staged regions (addresses read from this unit's ACPI
// HWNS block) for a 32-byte window whose SHA-256 equals the sensor's reported PMK
// hash, prints the key on screen if found, and dumps the raw regions to the ESP.
//
// Addresses are specific to this unit; re-read HWNS (\_SB.SPBA _CRS pointers) if
// they differ. Build with gnu-efi (see Makefile). Non-destructive: read-only.

#include <efi.h>
#include <efilib.h>

// ACPI HWNS pointers (live values on this unit).
#define BNKY_ADDR 0x6EEE0000ULL   // EMI data/mailbox region
#define BNKY_LEN  0x1000
#define FPKY_ADDR 0x6EEE1000ULL   // _DSM fn1 (SGX-sealed) region
#define FPKY_LEN  0x800
#define FPDA_ADDR 0x40200000ULL   // sensor eSPI bus-master window
#define FPDA_LEN  0x8000

// Target: SHA-256 of the plaintext PMK, as returned by sensor cmd 0xE4.
static const UINT8 TARGET[32] = {
    0xef,0x39,0x65,0x4f,0xcf,0x61,0xc8,0x7f,0xb9,0xbf,0x01,0x66,0x36,0x0d,0x34,0xc6,
    0x0b,0x5f,0x6d,0x54,0xce,0xeb,0x7e,0x8f,0x70,0x43,0x58,0xf2,0x08,0x7b,0xc8,0x5c,
};

// --- minimal SHA-256 ---------------------------------------------------------
typedef struct { UINT32 h[8]; UINT64 len; UINT8 buf[64]; UINT32 n; } sha256;
static UINT32 ror(UINT32 x, int c){ return (x>>c)|(x<<(32-c)); }
static const UINT32 K[64] = {
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
static void sha_blk(sha256 *s, const UINT8 *p){
    UINT32 w[64], a,b,c,d,e,f,g,h,t1,t2; int i;
    for(i=0;i<16;i++) w[i]=(p[i*4]<<24)|(p[i*4+1]<<16)|(p[i*4+2]<<8)|p[i*4+3];
    for(;i<64;i++){ UINT32 s0=ror(w[i-15],7)^ror(w[i-15],18)^(w[i-15]>>3);
        UINT32 s1=ror(w[i-2],17)^ror(w[i-2],19)^(w[i-2]>>10); w[i]=w[i-16]+s0+w[i-7]+s1; }
    a=s->h[0];b=s->h[1];c=s->h[2];d=s->h[3];e=s->h[4];f=s->h[5];g=s->h[6];h=s->h[7];
    for(i=0;i<64;i++){ UINT32 S1=ror(e,6)^ror(e,11)^ror(e,25); UINT32 ch=(e&f)^((~e)&g);
        t1=h+S1+ch+K[i]+w[i]; UINT32 S0=ror(a,2)^ror(a,13)^ror(a,22); UINT32 mj=(a&b)^(a&c)^(b&c);
        t2=S0+mj; h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2; }
    s->h[0]+=a;s->h[1]+=b;s->h[2]+=c;s->h[3]+=d;s->h[4]+=e;s->h[5]+=f;s->h[6]+=g;s->h[7]+=h;
}
static void sha_init(sha256 *s){ s->h[0]=0x6a09e667;s->h[1]=0xbb67ae85;s->h[2]=0x3c6ef372;
    s->h[3]=0xa54ff53a;s->h[4]=0x510e527f;s->h[5]=0x9b05688c;s->h[6]=0x1f83d9ab;s->h[7]=0x5be0cd19;
    s->len=0;s->n=0; }
static void sha_upd(sha256 *s,const UINT8 *p,UINTN n){ s->len+=n;
    while(n){ UINT32 k=64-s->n; if(k>n)k=n; UINT32 i; for(i=0;i<k;i++)s->buf[s->n+i]=p[i];
        s->n+=k;p+=k;n-=k; if(s->n==64){ sha_blk(s,s->buf); s->n=0; } } }
static void sha_fin(sha256 *s,UINT8 out[32]){ UINT64 bits=s->len*8; UINT8 pad=0x80;
    sha_upd(s,&pad,1); UINT8 z=0; while(s->n!=56) sha_upd(s,&z,1);
    UINT8 L[8]; int i; for(i=0;i<8;i++)L[i]=(bits>>(56-i*8))&0xff; sha_upd(s,L,8);
    for(i=0;i<8;i++){ out[i*4]=s->h[i]>>24;out[i*4+1]=s->h[i]>>16;out[i*4+2]=s->h[i]>>8;out[i*4+3]=s->h[i]; } }
static void sha256_once(const UINT8 *p, UINTN n, UINT8 out[32]){ sha256 s; sha_init(&s); sha_upd(&s,p,n); sha_fin(&s,out); }

static int eq32(const UINT8 *a,const UINT8 *b){ int i; for(i=0;i<32;i++) if(a[i]!=b[i]) return 0; return 1; }

// Scan a region for a 32-byte window hashing to TARGET; print + return 1 on hit.
static int scan(const CHAR16 *name, UINT64 addr, UINTN len){
    volatile UINT8 *base = (UINT8 *)(UINTN)addr;
    UINT8 w[32], h[32]; UINTN i,j; int found=0;
    for(i=0;i+32<=len;i++){
        for(j=0;j<32;j++) w[j]=base[i+j];
        sha256_once(w,32,h);
        if(eq32(h,TARGET)){
            Print(L"  *** PMK FOUND in %s at +0x%x ***\n  KEY=", name, i);
            for(j=0;j<32;j++) Print(L"%02x", w[j]);
            Print(L"\n");
            found=1;
        }
    }
    if(!found) Print(L"  %s: no PMK (scanned 0x%x bytes)\n", name, len);
    return found;
}

// Best-effort raw dump of a region to a file on the ESP.
static void dump(EFI_FILE_HANDLE root, const CHAR16 *fname, UINT64 addr, UINTN len){
    EFI_FILE_HANDLE f=NULL;
    EFI_STATUS st = uefi_call_wrapper(root->Open, 5, root, &f, (CHAR16*)fname,
        EFI_FILE_MODE_READ|EFI_FILE_MODE_WRITE|EFI_FILE_MODE_CREATE, 0);
    if(EFI_ERROR(st)||!f){ Print(L"  (dump %s: open failed)\n", fname); return; }
    UINTN n=len; uefi_call_wrapper(f->Write, 3, f, &n, (void*)(UINTN)addr);
    uefi_call_wrapper(f->Close, 1, f);
    Print(L"  wrote %s (0x%x bytes)\n", fname, n);
}

EFI_STATUS efi_main(EFI_HANDLE Image, EFI_SYSTEM_TABLE *ST){
    InitializeLib(Image, ST);
    Print(L"fpcap: MateBook X Pro 2020 pre-boot FP key capture\n");
    Print(L"Looking for SHA-256(PMK) = ef39654f...87bc85c\n\n");

    int hit=0;
    hit |= scan(L"BNKY", BNKY_ADDR, BNKY_LEN);
    hit |= scan(L"FPKY", FPKY_ADDR, FPKY_LEN);
    hit |= scan(L"FPDA", FPDA_ADDR, FPDA_LEN);

    // Dump raw regions to the ESP the app was launched from (best effort).
    EFI_LOADED_IMAGE *li=NULL;
    EFI_GUID liG=LOADED_IMAGE_PROTOCOL;
    if(!EFI_ERROR(uefi_call_wrapper(ST->BootServices->HandleProtocol,3,Image,&liG,(void**)&li)) && li){
        EFI_FILE_IO_INTERFACE *fs=NULL; EFI_GUID fsG=SIMPLE_FILE_SYSTEM_PROTOCOL;
        if(!EFI_ERROR(uefi_call_wrapper(ST->BootServices->HandleProtocol,3,li->DeviceHandle,&fsG,(void**)&fs)) && fs){
            EFI_FILE_HANDLE root=NULL;
            if(!EFI_ERROR(uefi_call_wrapper(fs->OpenVolume,2,fs,&root)) && root){
                dump(root,L"fpcap-bnky.bin",BNKY_ADDR,BNKY_LEN);
                dump(root,L"fpcap-fpky.bin",FPKY_ADDR,FPKY_LEN);
                dump(root,L"fpcap-fpda.bin",FPDA_ADDR,FPDA_LEN);
            }
        }
    }

    if(hit) Print(L"\nSUCCESS: key printed above. Photograph the KEY= line.\n");
    else    Print(L"\nNo key this run. If you just did a BIOS fingerprint auth,\n"
                  L"the window may have been cleared; see notes. Dumps saved for offline scan.\n");
    Print(L"\nPress any key to continue boot...\n");
    uefi_call_wrapper(ST->ConIn->Reset,2,ST->ConIn,FALSE);
    EFI_INPUT_KEY key; UINTN idx;
    uefi_call_wrapper(ST->BootServices->WaitForEvent,3,1,&ST->ConIn->WaitForKey,&idx);
    uefi_call_wrapper(ST->ConIn->ReadKeyStroke,2,ST->ConIn,&key);
    return EFI_SUCCESS;
}
