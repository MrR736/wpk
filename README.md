# WPK

WPK is a small archive format and C library for packing files, with optional
per-file AES-256-GCM encryption. It ships with:

- **libwpk** – a static C library (create, read and extract archives, from disk or memory)
- **wpkc** – a command-line tool (`list`, `compress`, `extract`, `convert`)
- **webinitg** – a build helper that packs a web app into an encrypted `.wpk` and generates Java/C code to decrypt it

## Features

- Deflate compression via bundled [miniz](src/miniz/readme.md) (levels 1–10)
- Optional encryption: PBKDF2-HMAC-SHA256 key derivation, AES-256-GCM per entry
- 16-byte archive UUID (v4), with optional UUID verification on extraction
- Unix timestamps stored per entry
- Memory-based APIs: open, extract and convert archives without touching disk
- ZIP interop: convert WPK to ZIP and ZIP to WPK
- Extraction refuses to overwrite existing files and is tested against path traversal
- C11 library, C++-friendly headers, builds on Linux, Windows and Android

## Repository layout

```
include/wpk/      public headers (wpk.h is the umbrella header)
src/              library sources (+ bundled miniz)
cli/wpkc.cpp      command-line tool
webinitg/         web-app packer and Java/C code generator (bundles cJSON)
test/wpktest.c    test suite
```

## Building

### Requirements

- CMake 3.16+
- A C11 and C++17 compiler
- Mbed TLS (crypto, with the PSA API)
- libuuid (Linux/macOS; Windows uses `ole32`)
- OpenSSL (only for `webinitg`)

On Debian/Ubuntu:

```sh
sudo apt install build-essential cmake libmbedtls-dev uuid-dev libssl-dev
```

### Desktop

```sh
cmake -S . -B build
cmake --build build
```

This produces `libwpk.a`, `wpkc` and `webinitg`.

CMake options:

| Option           | Default | Description                          |
|------------------|---------|--------------------------------------|
| `LIBWPK_CLI`     | `ON`    | Build `wpkc` and `webinitg`          |
| `LIBWPK_TESTS`   | `OFF`   | Build the `wpktest` test executable  |

Run the tests:

```sh
cmake -S . -B build -DLIBWPK_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

## Command-line tool: `wpkc`

```
wpkc list     <archive.wpk> [-p password]
wpkc compress <archive.wpk> <file|dir>... [-l level] [-p password] [-i iterations] [-f]
wpkc extract  <archive.wpk> [file...] [-o outdir] [-p password]
wpkc convert  <in.zip> <out.wpk> [-p password] [-f]
```

Short forms: `l`, `c`, `x`.

| Option          | Applies to          | Description                                                        |
|-----------------|---------------------|--------------------------------------------------------------------|
| `-p <password>` | all                 | Encrypt or decrypt. Falls back to `WPKC_PASSWORD`; if an encrypted archive needs one and none is given, you are prompted on the terminal |
| `-l <1-10>`     | compress            | Compression level (default 6)                                      |
| `-i <count>`    | compress (with `-p`)| PBKDF2 iterations, 100000 or more (default 600000)                 |
| `-f`            | compress, convert   | Overwrite an existing output file                                  |
| `-o <dir>`      | extract             | Output directory (default `.`)                                     |

Examples:

```sh
# Pack a directory (its contents are stored at the archive root)
wpkc compress site.wpk ./dist

# Encrypted archive
wpkc compress secret.wpk ./dist -p "correct horse battery staple"

# List, then extract everything or a single file
wpkc list secret.wpk -p "correct horse battery staple"
wpkc x secret.wpk -o out -p "correct horse battery staple"
wpkc x site.wpk index.html -o out

# Convert a ZIP
wpkc convert backup.zip backup.wpk
```

Notes:

- Extraction never overwrites existing files.
- `convert` drops directory entries and rejects encrypted ZIP entries.
- Exit status: `0` success, `1` failure, `2` bad usage.

## Library usage

Include the umbrella header and link against `wpk`:

```c
#include <wpk/wpk.h>
```

Most functions return `1` on success and `0` on failure.

### Create an archive

```c
WPK_COMPRESS_OPTIONS opt = {
    .level = WPK_DEFAULT_COMPRESSION,
    .password = "secret",        /* NULL = no encryption */
    .pbkdf2_iterations = 0,      /* 0 = default (600000) */
};
wpk_uuid_t uuid;

if (!wpk_compress_dir("app.wpk", "./dist", &opt, uuid)) { /* error */ }
```

Also available: `wpk_compress_file`, `wpk_compress_files`, `wpk_compress_files_ex`
(custom archive paths) and `wpk_compress_mem` (files already in memory).

### Extract

```c
/* Everything */
wpk_extract_password("app.wpk", "out", "secret");   /* password may be NULL */

/* One entry by index, verifying the archive UUID */
wpk_extract_file_password_uuid("app.wpk", 0, "out", uuid, "secret");

/* From a memory buffer */
wpk_extract_buffer_password(buf, buf_size, "out", "secret");
```

Variants exist for each combination of plain/password, with/without UUID check,
and file/buffer input (see `wpk_extract.h`).

### Read without extracting

```c
wpk_reader_t *r;
if (wpk_reader_open_password("app.wpk", "secret", &r)) {
    uint32_t n = wpk_reader_get_file_count(r);
    char path[WPK_ZIP_MAX_ARCHIVE_FILENAME_SIZE];
    for (uint32_t i = 0; i < n; ++i) {
        wpk_reader_get_file_path(r, i, path, sizeof path);
        puts(path);
    }
    wpk_reader_close(r);
}
```

`wpk_reader_open_mem` / `wpk_reader_open_password_mem` open from memory,
`wpk_reader_get_entry_info` returns sizes and timestamp, and
`wpk_reader_init_file` / `wpk_reader_init_mem` open an unencrypted WPK as a miniz ZIP reader.

### Convert

```c
wpk_convert_to_zip("app.wpk", "app.zip", "secret");
zip_convert_to_wpk("app.zip", "app.wpk", NULL);
```

### UUIDs

`wpk_uuid_generate`, `wpk_uuid_parse`, `wpk_uuid_to_string` and `wpk_uuid_equal`
are in `wpk_uuid.h`; `example/wpk_uuid.c` shows them in use.

## `webinitg`

`webinitg` builds a web app into a WPK and emits helper code for an app that
needs to open it:

```
webinitg -c webinit.json [-o output.wpk]
```

Steps, in order:

1. Run `CommandsBefore` (for example `npm install`, a build script)
2. Create `BuildDir` and copy `Assets` into it (glob patterns such as `*.png` work)
3. Delete `Removes` from `BuildDir`
4. Run `CommandsAfter` inside `BuildDir`
5. If `Encryption` is true, use `Password`, or generate a random 32-character hex password
6. Pack `BuildDir` into `<Name>.wpk` (or the `-o` path)
7. Print the archive UUID and password, and write `WebInitCrypto.java` and
   `WebInitCrypto.c` to the current directory. They embed the password and UUID
   in an AES-GCM-encrypted payload for use from an Android app.

Config fields (see [`webinitg/examples/webinit.json`](webinitg/examples/webinit.json)):

| Field            | Description                                            |
|------------------|--------------------------------------------------------|
| `Name`           | Output archive name (`<Name>.wpk`)                     |
| `App`            | Application identifier (e.g. `com.example`)            |
| `BuildDir`       | Staging directory                                      |
| `CommandsBefore` | Shell commands run before copying assets (or `null`)   |
| `CommandsAfter`  | Shell commands run inside `BuildDir` (or `null`)       |
| `Assets`         | Files, directories and globs to copy into `BuildDir`   |
| `Removes`        | Paths to delete from `BuildDir` after copying          |
| `Password`       | Fixed password, or `null` to generate one              |
| `Encryption`     | `true` to encrypt                                      |

`webinitg` is POSIX-only (it uses `glob.h`, `unistd.h` and `sys/wait.h`).

Obfuscating the key inside a shipped app raises the effort needed to extract it
but does not make it secret from someone with access to the app.

## File format

All integers are little-endian. Version 1, magic `WPK100`.

**Header (64 bytes)**

| Offset | Size | Field                    |
|-------:|-----:|--------------------------|
| 0      | 6    | Magic `WPK100`           |
| 6      | 16   | Archive UUID             |
| 22     | 4    | Format version (1)       |
| 26     | 4    | File count               |
| 30     | 8    | File table offset        |
| 38     | 16   | PBKDF2 salt              |
| 54     | 4    | PBKDF2 iterations        |
| 58     | 4    | Flags (`1` = encrypted)  |
| 62     | 2    | Reserved                 |

**Payloads** follow the header, one per file (deflated, then encrypted if the
archive is encrypted).

**File table** at `table_offset`: one record per file, 64 fixed bytes followed
by the path.

| Size | Field                                  |
|-----:|----------------------------------------|
| 2    | Path length                            |
| 2    | Entry flags                            |
| 8    | Original size                          |
| 8    | Compressed size                        |
| 8    | Data offset                            |
| 12   | AES-GCM nonce                          |
| 16   | AES-GCM tag                            |
| 8    | Timestamp (UTC Unix time)              |
| n    | Path (UTF-8, `/` separators)           |

**Encryption:** the key is `PBKDF2-HMAC-SHA256(password, salt, iterations)`
(32 bytes). Each entry is encrypted with AES-256-GCM using its own nonce, and
its compressed size, data offset, path length and path are authenticated as
additional data, so moving or renaming entries is detected.

Limits: 100,000 files per archive, 4096-byte paths.

## Third-party Dependencies

- [miniz](https://github.com/richgel999/miniz) — Compression.
- [Mbed TLS](https://github.com/Mbed-TLS/mbedtls) — PBKDF2 key derivation and AES-GCM encryption.
- [cJSON](https://github.com/davegamble/cjson) — JSON parsing in `webinitg`.
- [OpenSSL](https://github.com/openssl/openssl) — Used exclusively by `webinitg`.

## License

This library is licensed under the [GNU General Public License v3](https://www.gnu.org/licenses/gpl-3.0.en.html).
You are free to use, modify, and redistribute it under the terms of the GPLv3.
