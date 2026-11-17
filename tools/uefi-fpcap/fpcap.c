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

// --- logging: mirror every diagnostic line to screen AND \fpcap.log ----------
static EFI_FILE_HANDLE g_log = NULL;
static void dlog(const CHAR16 *fmt, ...){
    CHAR16 buf[512]; __builtin_va_list ap; __builtin_va_start(ap, fmt);
    VSPrint(buf, sizeof(buf), (CHAR16*)fmt, ap); __builtin_va_end(ap);
    Print(L"%s", buf);
    if(g_log){
        CHAR8 a[512]; UINTN i=0;
        while(buf[i] && i<511){ a[i] = (buf[i] < 128) ? (CHAR8)buf[i] : '?'; i++; }
        UINTN n=i;
        uefi_call_wrapper(g_log->Write, 3, g_log, &n, a);
        uefi_call_wrapper(g_log->Flush, 1, g_log);
    }
}

// --- live change monitor -----------------------------------------------------
static UINT8 prev_bnky[BNKY_LEN], prev_fpky[FPKY_LEN], prev_fpda[FPDA_LEN];
static int   have_prev = 0;

static UINTN nonzero(const volatile UINT8 *p, UINTN n){ UINTN i,c=0; for(i=0;i<n;i++) if(p[i]) c++; return c; }

// Compare a region to its previous snapshot; on change print offset + 16 bytes
// and the count. Returns 1 if changed. Updates the snapshot and a change counter.
static int watch(const CHAR16 *name, UINT64 addr, UINTN len, UINT8 *prev, UINTN *chg){
    volatile UINT8 *p = (UINT8 *)(UINTN)addr;
    UINTN i, first = (UINTN)-1;
    if(have_prev){
        for(i=0;i<len;i++){ if(p[i]!=prev[i]){ first=i; break; } }
    }
    for(i=0;i<len;i++) prev[i]=p[i];        // refresh snapshot
    if(first==(UINTN)-1) return 0;
    (*chg)++;
    dlog(L"[CHANGE %s] +0x%x nz=%d bytes: %02x %02x %02x %02x %02x %02x %02x %02x\n",
         name, first, nonzero(p,len),
         p[first], (first+1<len)?p[first+1]:0, (first+2<len)?p[first+2]:0, (first+3<len)?p[first+3]:0,
         (first+4<len)?p[first+4]:0, (first+5<len)?p[first+5]:0, (first+6<len)?p[first+6]:0, (first+7<len)?p[first+7]:0);
    return 1;
}

// Scan a region for a 32-byte window hashing to TARGET; print + return 1 on hit.
// Silent on miss (for loop mode). Also reports a [0x20][32] len-prefixed record once.
static int scan(const CHAR16 *name, UINT64 addr, UINTN len){
    volatile UINT8 *base = (UINT8 *)(UINTN)addr;
    UINT8 w[32], h[32]; UINTN i,j; int found=0;
    for(i=0;i+32<=len;i++){
        for(j=0;j<32;j++) w[j]=base[i+j];
        sha256_once(w,32,h);
        if(eq32(h,TARGET)){
            dlog(L"\n  *** PMK FOUND in %s at +0x%x ***\n", name, i);
            dlog(L"  KEY=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
                 L"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
                 w[0],w[1],w[2],w[3],w[4],w[5],w[6],w[7],w[8],w[9],w[10],w[11],w[12],w[13],w[14],w[15],
                 w[16],w[17],w[18],w[19],w[20],w[21],w[22],w[23],w[24],w[25],w[26],w[27],w[28],w[29],w[30],w[31]);
            found=1;
        }
    }
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

// Open the ESP root the app was launched from (best effort).
static EFI_FILE_HANDLE esp_root(EFI_HANDLE Image, EFI_SYSTEM_TABLE *ST){
    EFI_LOADED_IMAGE *li=NULL; EFI_GUID liG=LOADED_IMAGE_PROTOCOL;
    if(EFI_ERROR(uefi_call_wrapper(ST->BootServices->HandleProtocol,3,Image,&liG,(void**)&li))||!li) return NULL;
    EFI_FILE_IO_INTERFACE *fs=NULL; EFI_GUID fsG=SIMPLE_FILE_SYSTEM_PROTOCOL;
    if(EFI_ERROR(uefi_call_wrapper(ST->BootServices->HandleProtocol,3,li->DeviceHandle,&fsG,(void**)&fs))||!fs) return NULL;
    EFI_FILE_HANDLE root=NULL;
    if(EFI_ERROR(uefi_call_wrapper(fs->OpenVolume,2,fs,&root))||!root) return NULL;
    return root;
}

EFI_STATUS efi_main(EFI_HANDLE Image, EFI_SYSTEM_TABLE *ST){
    InitializeLib(Image, ST);
    Print(L"fpcap: MateBook X Pro 2020 pre-boot FP key capture\n");
    Print(L"Target SHA-256(PMK) = ef39654f...87bc85c\n");
    Print(L"Watching BNKY/FPKY/FPDA continuously. Touch the fingerprint/power\n");
    Print(L"button now. Press ESC to stop and continue boot.\n\n");

    EFI_FILE_HANDLE root = esp_root(Image, ST);
    if(root) uefi_call_wrapper(root->Open, 5, root, &g_log, L"fpcap.log",
        EFI_FILE_MODE_READ|EFI_FILE_MODE_WRITE|EFI_FILE_MODE_CREATE, 0);
    uefi_call_wrapper(ST->ConIn->Reset,2,ST->ConIn,FALSE);

    dlog(L"nz = non-zero bytes now: BNKY %d/%d  FPKY %d/%d  FPDA %d/%d\n\n",
          nonzero((UINT8*)(UINTN)BNKY_ADDR,BNKY_LEN), BNKY_LEN,
          nonzero((UINT8*)(UINTN)FPKY_ADDR,FPKY_LEN), FPKY_LEN,
          nonzero((UINT8*)(UINTN)FPDA_ADDR,FPDA_LEN), FPDA_LEN);

    int found=0; UINTN iter=0;
    UINTN cB=0,cK=0,cD=0;   // per-region change counters
    for(;;){
        // Non-blocking ESC check.
        EFI_INPUT_KEY key;
        EFI_STATUS ks = uefi_call_wrapper(ST->ConIn->ReadKeyStroke,2,ST->ConIn,&key);
        if(ks==EFI_SUCCESS && key.ScanCode==SCAN_ESC) break;

        // Live change monitor: shows when the EC writes to any region.
        watch(L"BNKY", BNKY_ADDR, BNKY_LEN, prev_bnky, &cB);
        watch(L"FPKY", FPKY_ADDR, FPKY_LEN, prev_fpky, &cK);
        watch(L"FPDA", FPDA_ADDR, FPDA_LEN, prev_fpda, &cD);
        have_prev = 1;

        // Key check (the actual goal).
        int hit=0;
        hit |= scan(L"BNKY", BNKY_ADDR, BNKY_LEN);
        hit |= scan(L"FPKY", FPKY_ADDR, FPKY_LEN);
        hit |= scan(L"FPDA", FPDA_ADDR, FPDA_LEN);
        if(hit && !found){
            found=1;
            if(root){
                dump(root,L"fpcap-bnky.bin",BNKY_ADDR,BNKY_LEN);
                dump(root,L"fpcap-fpky.bin",FPKY_ADDR,FPKY_LEN);
                dump(root,L"fpcap-fpda.bin",FPDA_ADDR,FPDA_LEN);
            }
            dlog(L"\nSUCCESS: key logged to fpcap.log. Still watching; ESC to boot.\n");
        }

        if((iter % 20)==0)                       // status line every ~2 s
            dlog(L"  [iter %d] changes: BNKY=%d FPKY=%d FPDA=%d  (touch sensor now)\n",
                  iter, cB, cK, cD);
        iter++;
        if(iter > 3000) break;                   // ~5 min safety cap if ESC never arrives
        uefi_call_wrapper(ST->BootServices->Stall, 1, 100000); // 100 ms
    }

    // Final dump regardless, for offline scanning.
    if(root){
        dump(root,L"fpcap-bnky-final.bin",BNKY_ADDR,BNKY_LEN);
        dump(root,L"fpcap-fpky-final.bin",FPKY_ADDR,FPKY_LEN);
        dump(root,L"fpcap-fpda-final.bin",FPDA_ADDR,FPDA_LEN);
    }
    dlog(L"\n%s. iters=%d changes BNKY=%d FPKY=%d FPDA=%d. Continuing boot.\n",
         found ? L"Key was found" : L"No key this run", iter, cB, cK, cD);
    if(g_log) uefi_call_wrapper(g_log->Close, 1, g_log);
    return EFI_SUCCESS;
}
