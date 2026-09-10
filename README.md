# palimpsest

Fileless x86-64 ELF execution without `execve`, filesystem objects, or kernel
keys, with the payload mapped at the loader's own kernel-chosen PIE base.

## What it does

Runs an ELF entirely from memory and then hands the process over to it. The
payload ends up at the canonical `0x55…` address the kernel originally gave
the loader, not at a hand-picked low address, a memfd, a tmpfs inode, or a
borrowed vdso region, which is what every earlier technique settles for.

The payload is never represented by a new kernel object: no inode, no memfd,
no key. The handoff is a jump, not an exec, so exec-specific telemetry
(`sched_process_exec`, exec audit records) is not generated for it.

## The technique

1. The loader records the PIE base the kernel gave it.
2. It copies its own segments to a scratch `mmap`, rewrites its
   `R_X86_64_RELATIVE` relocations for the new base, and jumps to the copy,
   vacating the canonical `0x55…` slot.
3. It unmaps everything except the stack, vdso, vvar, the brk heap, and the
   anonymous TLS cluster.
4. The payload's `PT_LOAD`s are mapped with `MAP_FIXED` at the loader's
   original base; a fresh copy of ld.so is mapped at a kernel-picked `0x7f…`
   address; a full initial stack (`argc/argv/envp/auxv`) is built.
5. A trampoline page unmaps the scratch region, resets `FS`/`GS`, zeroes the
   general registers (kernel-equivalent execve state), switches `rsp`, and
   jumps into ld.so's entry point. On glibc 2.44, ld.so's `_start` passes the
   initial stack pointer to `_dl_start` in `rdi` (`elf/rtld.c`); older glibc
   passed the ELF header in `rdx`, the trampoline sets both.

## Requirements

- x86-64 Linux
- glibc 2.44 (entry convention verified against this version)
- gcc, make

## Build

```sh
make            # builds palimpsest
make payloads   # builds the test binaries (dynamic, static, static-pie)
```

## Usage

```sh
./palimpsest file  <elf>  [spoof_name]    # load from a file
./palimpsest stdin [spoof_name]           # load from stdin
./palimpsest http  <url>  [spoof_name]    # load over HTTP

cat payload.bin | ./palimpsest stdin sshd
./palimpsest file ./payload sshd
```

`[spoof_name]` becomes `argv[0]`, `comm`, and the visible cmdline (default
`python3`). The loader unlinks itself before the handoff; use `-k` to keep it
on disk. With `CAP_SYS_RESOURCE`, `PR_SET_MM_EXE_FILE` is attempted so
`/proc/pid/exe` points at a memfd instead of the deleted loader.

## Supported payloads

| Type | Status |
|------|--------|
| Dynamic PIE | supported (TLS, threads verified) |
| Static non-PIE | supported |
| Static PIE | rejected with exit code 2 (image collides with the inherited brk arena) |

Test matrix: 10/10 runs per supported type, file/stdin/http delivery.

## Disclaimer

Security research PoC. Run it only on systems you own or are authorized to
test. The idea of userland exec is not new, see grugq's ul_exec, fireelf,
ulexecve, Dntry. The contribution here is the address-space recycling handoff
and the documentation of what survives it.

Article: [https://klydz.net/post.php?slug=how-to-apt-ep-5-reusing-the-loaders-pie-base-for-userland-exec]
