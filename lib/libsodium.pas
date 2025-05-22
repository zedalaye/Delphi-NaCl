unit libsodium;

{$ALIGN 1}

{.$define SODIUM_LIBRARY_MINIMAL}

interface

const
  SODIUM_LIB = 'libsodium.dll';

  LIBSODIUM_VERSION_STRING = '1.0.20';

  LIBSODIUM_LIBRARY_VERSION_MAJOR = 26;
  LIBSODIUM_LIBRARY_VERSION_MINOR = 2;

(* sodium/export.h *)

const
{$if defined(CPU32BITS)}
  SODIUM_SIZE_MAX = High(NativeUInt);
{$else}
  SODIUM_SIZE_MAX = High(UInt64);
{$endif}

(* sodium/core.h *)
function sodium_init: Integer; cdecl; external SODIUM_LIB;

type
  TSodiumMisuseHandler = procedure; cdecl;

function sodium_set_misuse_handler(handler: TSodiumMisuseHandler): Integer; cdecl; external SODIUM_LIB;

procedure sodium_misuse; cdecl; external SODIUM_LIB;

(* sodium/version.h *)
function sodium_version_string: PAnsiChar; cdecl; external SODIUM_LIB;
function sodium_library_version_major: Integer; cdecl; external SODIUM_LIB;
function sodium_library_version_minor: Integer; cdecl; external SODIUM_LIB;
function sodium_library_minimal: Integer; cdecl; external SODIUM_LIB;

(* sodium/utils.h *)
procedure sodium_memzero(const pnt: Pointer; const len: NativeUInt); cdecl; external SODIUM_LIB;
procedure sodium_stackzero(const len: NativeUInt); cdecl; external SODIUM_LIB;

(*
 * WARNING: sodium_memcmp() must be used to verify if two secret keys
 * are equal, in constant time.
 * It returns 0 if the keys are equal, and -1 if they differ.
 * This function is not designed for lexicographical comparisons.
 *)
function sodium_memcmp(const b1_, b2_: Pointer; len: NativeUInt): Integer; cdecl; external SODIUM_LIB;

(*
 * sodium_compare() returns -1 if b1_ < b2_, 1 if b1_ > b2_ and 0 if b1_ == b2_
 * It is suitable for lexicographical comparisons, or to compare nonces
 * and counters stored in little-endian format.
 * However, it is slower than sodium_memcmp().
 *)
function sodium_compare(const b1_, b2_: PByte; len: NativeUInt): Integer; cdecl; external SODIUM_LIB;

function sodium_is_zero(const n: PByte; const len: NativeUInt): Integer; cdecl; external SODIUM_LIB;

procedure sodium_increment(n: PByte; const len: NativeUInt); cdecl; external SODIUM_LIB;

procedure sodium_add(a: PByte; const b: PByte; const len: NativeUInt); cdecl; external SODIUM_LIB;

procedure sodium_sub(a: PByte; const b: PByte; const len: NativeUInt); cdecl; external SODIUM_LIB;

function sodium_bin2hex(hex: PAnsiChar; const hex_maxlen: NativeUInt;
                        const bin: PByte; const bin_len: NativeUInt): PAnsiChar; cdecl; external SODIUM_LIB;

function sodium_hex2bin(bin: PByte; const bin_maxlen: NativeUInt;
                        const hex: PAnsiChar; const hex_len: NativeUInt;
                        const ignore: PAnsiChar; var bin_len: NativeUInt;
                        var hex_end: PAnsiChar): Integer; cdecl; external SODIUM_LIB;

const
  SODIUM_BASE64_VARIANT_ORIGINAL            = 1;
  SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING = 3;
  SODIUM_BASE64_VARIANT_URLSAFE             = 5;
  SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING  = 7;

(*
 * Computes the required length to encode BIN_LEN bytes as a base64 string
 * using the given variant. The computed length includes a trailing \0.
 *)
function _SODIUM_BASE64_ENCODED_LEN(BIN_LEN: NativeUInt; VARIANT: Byte): UInt64; inline;

function sodium_base64_encoded_len(const bin_len: NativeUInt; const variant: Integer): NativeUInt; cdecl; external SODIUM_LIB;

function sodium_bin2base64(b64: PAnsiChar; const b64_maxlen: NativeUInt;
                           const bin: PByte; const bin_len: NativeUInt;
                           const variant: Integer): PAnsiChar; cdecl; external SODIUM_LIB;

function sodium_base642bin(bin: PByte; const bin_maxlen: NativeUInt;
                           const b64: PAnsiChar; const b64_len: NativeUInt;
                           const ignore: PAnsiChar; var bin_len: NativeUInt;
                           var b64end: PAnsiChar; const variant: Integer): Integer; cdecl; external SODIUM_LIB;

function sodium_mlock(addr: Pointer; const len: NativeUInt): Integer; cdecl; external SODIUM_LIB;

function sodium_munlock(addr: Pointer; const len: NativeUInt): Integer; cdecl; external SODIUM_LIB;

(* WARNING: sodium_malloc() and sodium_allocarray() are not general-purpose
 * allocation functions.
 *
 * They return a pointer to a region filled with 0xd0 bytes, immediately
 * followed by a guard page.
 * As a result, accessing a single byte after the requested allocation size
 * will intentionally trigger a segmentation fault.
 *
 * A canary and an additional guard page placed before the beginning of the
 * region may also kill the process if a buffer underflow is detected.
 *
 * The memory layout is:
 * [unprotected region size (read only)][guard page (no access)][unprotected pages (read/write)][guard page (no access)]
 * With the layout of the unprotected pages being:
 * [optional padding][16-bytes canary][user region]
 *
 * However:
 * - These functions are significantly slower than standard functions
 * - Each allocation requires 3 or 4 additional pages
 * - The returned address will not be aligned if the allocation size is not
 *   a multiple of the required alignment. For this reason, these functions
 *   are designed to store data, such as secret keys and messages.
 *
 * sodium_malloc() can be used to allocate any libsodium data structure.
 *
 * The crypto_generichash_state structure is packed and its length is
 * either 357 or 361 bytes. For this reason, when using sodium_malloc() to
 * allocate a crypto_generichash_state structure, padding must be added in
 * order to ensure proper alignment. crypto_generichash_statebytes()
 * returns the rounded up structure size, and should be preferred to sizeof():
 * state = sodium_malloc(crypto_generichash_statebytes());
 *)

function sodium_malloc(const size: NativeUInt): Pointer; cdecl; external SODIUM_LIB;

function sodium_allocarray(count: NativeUInt; size: NativeUInt): Pointer; cdecl; external SODIUM_LIB;

procedure sodium_free(ptr: Pointer); cdecl; external SODIUM_LIB;

function sodium_mprotect_noaccess(ptr: Pointer): Integer; cdecl; external SODIUM_LIB;

function sodium_mprotect_readonly(ptr: Pointer): Integer; cdecl; external SODIUM_LIB;

function sodium_mprotect_readwrite(ptr: Pointer): Integer; cdecl; external SODIUM_LIB;

function sodium_pad(var padded_buflen_p: NativeUInt; buf: PByte;
                    unpadded_buflen, blocksize, max_buflen: NativeUInt): Integer; cdecl; external SODIUM_LIB;

function sodium_unpad(var unpadded_buflen_p: NativeUInt; const buf: PByte;
                      padded_buflen, blocksize: NativeUInt): Integer; cdecl; external SODIUM_LIB;

(* sodium/randombytes.h *)

type
  TRandomBytesImplementationName = function: PAnsiChar; cdecl;
  TRandomBytesRandom             = function: Cardinal; cdecl;
  TRandomBytesStir               = procedure; cdecl;
  TRandomBytesUniform            = function(const UpperBound: Cardinal): Cardinal; cdecl;
  TRandomBytesBuf                = procedure(buf: Pointer; const size: NativeUInt); cdecl;
  TRandomBytesClose              = function: Integer; cdecl;

  PRandomBytesImplementation = ^TRandomBytesImplementation;
  TRandomBytesImplementation = record
    implementation_name: TRandomBytesImplementationName; (* required *)
    random: TRandomBytesRandom;                          (* required *)
    stir: TRandomBytesStir;                              (* optional *)
    uniform: TRandomBytesUniform;                        (* optional, a default implementation will be used if NULL *)
    buf: TRandomBytesBuf;                                (* required *)
    close: TRandomBytesClose;                            (* optional *)
  end;

function RANDOMBYTES_BYTES_MAX: UInt64; inline;

const
  _RANDOMBYTES_SEEDBYTES = 32;

function randombytes_seedbytes: NativeUInt; cdecl; external SODIUM_LIB;

procedure randombytes_buf(buf: Pointer; const size: NativeUInt); cdecl; external SODIUM_LIB;

type
  TRandomBytesSeed = array[0.._RANDOMBYTES_SEEDBYTES -1] of Byte;

procedure randombytes_buf_deterministic(buf: Pointer; const size: NativeUInt;
                                        const seed: TRandomBytesSeed); cdecl; external SODIUM_LIB;

function randombytes_random: Cardinal; cdecl; external SODIUM_LIB;

function randombytes_uniform(const upper_bound: Cardinal): Cardinal; cdecl; external SODIUM_LIB;

procedure randombytes_stir; cdecl; external SODIUM_LIB;

function randombytes_close: Integer; cdecl; external SODIUM_LIB;

function randombytes_set_implementation(const impl: PRandomBytesImplementation): Integer; cdecl; external SODIUM_LIB;

function randombytes_implementation_name: PAnsiChar; cdecl; external SODIUM_LIB;

(* -- NaCl compatibility interface -- *)

procedure randombytes(buf: PByte; const buf_len: UInt64); cdecl; external SODIUM_LIB;

(* sodium/randombytes_internal_random.h *)

type
  PRandomBytesInternalImplementation = ^TRandomBytesInternalImplementation;
  TRandomBytesInternalImplementation = TRandomBytesImplementation;

  (* Backwards compatibility with libsodium < 1.0.18 *)
  PRandomBytesSalsa20Implementation = ^TRandomBytesSalsa20Implementation;
  TRandomBytesSalsa20Implementation = TRandomBytesInternalImplementation;

(* sodium/randombytes_sysrandom.h *)

type
  PRandomBytesSysrandomImplementation = ^TRandomBytesSysrandomImplementation;
  TRandomBytesSysrandomImplementation = TRandomBytesImplementation;

(* sodium/runtime.h *)

function sodium_runtime_has_neon: Integer; cdecl; external SODIUM_LIB;

function sodium_runtime_has_armcrypto: Integer; cdecl; external SODIUM_LIB;

function sodium_runtime_has_sse2: Integer; cdecl; external SODIUM_LIB;

function sodium_runtime_has_sse3: Integer; cdecl; external SODIUM_LIB;

function sodium_runtime_has_ssse3: Integer; cdecl; external SODIUM_LIB;

function sodium_runtime_has_sse41: Integer; cdecl; external SODIUM_LIB;

function sodium_runtime_has_avx: Integer; cdecl; external SODIUM_LIB;

function sodium_runtime_has_avx2: Integer; cdecl; external SODIUM_LIB;

function sodium_runtime_has_avx512f: Integer; cdecl; external SODIUM_LIB;

function sodium_runtime_has_pclmul: Integer; cdecl; external SODIUM_LIB;

function sodium_runtime_has_aesni: Integer; cdecl; external SODIUM_LIB;

function sodium_runtime_has_rdrand: Integer; cdecl; external SODIUM_LIB;

(* sodium/crypto_aead_aegis128l.h *)

const
  _CRYPTO_AEAD_AEGIS128L_KEYBYTES = 16;
function crypto_aead_aegis128l_keybytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_AEAD_AEGIS128L_NSECBYTES = 0;
function crypto_aead_aegis128l_nsecbytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_AEAD_AEGIS128L_NPUBBYTES = 16;
function crypto_aead_aegis128l_npubbytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_AEAD_AEGIS128L_ABYTES = 32;
function crypto_aead_aegis128l_abytes: NativeUInt; cdecl; external SODIUM_LIB;

function _CRYPTO_AEAD_AEGIS128L_MESSAGEBYTES_MAX: UInt64; inline;
function crypto_aead_aegis128l_messagebytes_max: NativeUInt; cdecl; external SODIUM_LIB;

function crypto_aead_aegis128l_encrypt(c: PByte;
                                       var clen_p: UInt64;
                                       const m: PByte;
                                       mlen: UInt64;
                                       const ad: PByte;
                                       adlen: UInt64;
                                       const nsec: PByte;
                                       const npub: PByte;
                                       const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_aead_aegis128l_decrypt(m: PByte;
                                       var mlen_p: UInt64;
                                       nsec: PByte;
                                       const c: PByte;
                                       clen: UInt64;
                                       const ad: PByte;
                                       adlen: UInt64;
                                       const npub: PByte;
                                       const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_aead_aegis128l_encrypt_detached(c: PByte;
                                                mac: PByte;
                                                var maclen_p: UInt64;
                                                const m: PByte;
                                                mlen: UInt64;
                                                const ad: PByte;
                                                adlen: UInt64;
                                                const nsec: PByte;
                                                const npub: PByte;
                                                const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_aead_aegis128l_decrypt_detached(m: PByte;
                                                nsec: PByte;
                                                const c: PByte;
                                                clen: UInt64;
                                                const mac: PByte;
                                                const ad: PByte;
                                                adlen: UInt64;
                                                const npub: PByte;
                                                const k: PByte): Integer; cdecl; external SODIUM_LIB;

type
  TCryptoAeadAegis128lKey = array[0.._CRYPTO_AEAD_AEGIS128L_KEYBYTES -1] of Byte;

procedure crypto_aead_aegis128l_keygen(var k: TCryptoAeadAegis128lKey); cdecl; external SODIUM_LIB;

type
  TCryptoAeadAegis128lPubBytes = array[0.._CRYPTO_AEAD_AEGIS128L_NPUBBYTES -1] of Byte;

(* sodium/crypto_aead_aegis256.h *)

const
  _CRYPTO_AEAD_AEGIS256_KEYBYTES = 32;
function crypto_aead_aegis256_keybytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_AEAD_AEGIS256_NSECBYTES = 0;
function crypto_aead_aegis256_nsecbytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_AEAD_AEGIS256_NPUBBYTES = 32;
function crypto_aead_aegis256_npubbytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_AEAD_AEGIS256_ABYTES = 32;
function crypto_aead_aegis256_abytes: NativeUInt; cdecl; external SODIUM_LIB;

function _CRYPTO_AEAD_AEGIS256_MESSAGEBYTES_MAX: UInt64; inline;
function crypto_aead_aegis256_messagebytes_max: NativeUInt; cdecl; external SODIUM_LIB;

function crypto_aead_aegis256_encrypt(c: PByte;
                                      var clen_p: UInt64;
                                      const m: PByte;
                                      mlen: UInt64;
                                      const ad: PByte;
                                      adlen: UInt64;
                                      const nsec: PByte;
                                      const npub: PByte;
                                      const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_aead_aegis256_decrypt(m: PByte;
                                      var mlen_p: UInt64;
                                      nsec: PByte;
                                      const c: PByte;
                                      clen: UInt64;
                                      const ad: PByte;
                                      adlen: UInt64;
                                      const npub: PByte;
                                      const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_aead_aegis256_encrypt_detached(c: PByte;
                                               mac: PByte;
                                               var maclen_p: UInt64;
                                               const m: PByte;
                                               mlen: UInt64;
                                               const ad: PByte;
                                               adlen: UInt64;
                                               const nsec: PByte;
                                               const npub: PByte;
                                               const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_aead_aegis256_decrypt_detached(m: PByte;
                                               nsec: PByte;
                                               const c: PByte;
                                               clen: UInt64;
                                               const mac: PByte;
                                               const ad: PByte;
                                               adlen: UInt64;
                                               const npub: PByte;
                                               const k: PByte): Integer; cdecl; external SODIUM_LIB;

type
  TCryptoAeadAegis256Key = array[0.._CRYPTO_AEAD_AEGIS256_KEYBYTES -1] of Byte;

procedure crypto_aead_aegis256_keygen(var k: TCryptoAeadAegis256Key); cdecl; external SODIUM_LIB;

type
  TCryptoAeadAegis256PubBytes = array[0.._CRYPTO_AEAD_AEGIS256_NPUBBYTES -1] of Byte;

(* sodium/crypto_aead_aes256gcm.h *)

(*
 * WARNING: Despite being the most popular AEAD construction due to its
 * use in TLS, safely using AES-GCM in a different context is tricky.
 *
 * No more than ~ 350 GB of input data should be encrypted with a given key.
 * This is for ~ 16 KB messages -- Actual figures vary according to
 * message sizes.
 *
 * In addition, nonces are short and repeated nonces would totally destroy
 * the security of this scheme.
 *
 * Nonces should thus come from atomic counters, which can be difficult to
 * set up in a distributed environment.
 *
 * Unless you absolutely need AES-GCM, use crypto_aead_xchacha20poly1305_ietf_*()
 * instead. It doesn't have any of these limitations.
 * Or, if you don't need to authenticate additional data, just stick to
 * crypto_secretbox().
 *)

function crypto_aead_aes256gcm_is_available: Integer; cdecl; external SODIUM_LIB;

const
  _CRYPTO_AEAD_AES256GCM_KEYBYTES = 32;
function crypto_aead_aes256gcm_keybytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_AEAD_AES256GCM_NSECBYTES = 0;
function crypto_aead_aes256gcm_nsecbytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_AEAD_AES256GCM_NPUBBYTES = 12;
function crypto_aead_aes256gcm_npubbytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_AEAD_AES256GCM_ABYTES    = 16;
function crypto_aead_aes256gcm_abytes: NativeUInt; cdecl; external SODIUM_LIB;

function _CRYPTO_AEAD_AES256GCM_MESSAGEBYTES_MAX: UINT64; inline;
function crypto_aead_aes256gcm_messagebytes_max: NativeUInt; cdecl; external SODIUM_LIB;

type
  PCryptoAeadAES256GCMState = ^TCryptoAeadAES256GCMState;
  {$ALIGN 16}
  TCryptoAeadAES256GCMState = record
    opaque: array[0..512 -1] of Byte;
  end;
  {$ALIGN 1}

function crypto_aead_aes256gcm_statebytes: NativeUInt; cdecl; external SODIUM_LIB;

function crypto_aead_aes256gcm_encrypt(c: PByte;
                                       var clen_p: UInt64;
                                       const m: PByte;
                                       mlen: UInt64;
                                       const ad: PByte;
                                       adlen: UInt64;
                                       const nsec: PByte;
                                       const npub: PByte;
                                       const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_aead_aes256gcm_decrypt(m: PByte;
                                       var mlen_p: UInt64;
                                       nsec: PByte;
                                       const c: PByte;
                                       clen: UInt64;
                                       const ad: PByte;
                                       adlen: UInt64;
                                       const npub: PByte;
                                       const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_aead_aes256gcm_encrypt_detached(c: PByte;
                                                mac: PByte;
                                                var maclen_p: UInt64;
                                                const m: PByte;
                                                mlen: UInt64;
                                                const ad: PByte;
                                                adlen: UInt64;
                                                const nsec: PByte;
                                                const npub: PByte;
                                                const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_aead_aes256gcm_decrypt_detached(m: PByte;
                                                nsec: PByte;
                                                const c: PByte;
                                                clen: UInt64;
                                                const mac: PByte;
                                                const ad: PByte;
                                                adlen: UInt64;
                                                const npub: PByte;
                                                const k: PByte): Integer; cdecl; external SODIUM_LIB;

(* -- Precomputation interface -- *)

function crypto_aead_aes256gcm_beforenm(ctx: PCryptoAeadAES256GCMState;
                                        const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_aead_aes256gcm_encrypt_afternm(c: PByte;
                                               var clen_p: UInt64;
                                               const m: PByte;
                                               mlen: UInt64;
                                               const ad: PByte;
                                               adlen: UInt64;
                                               const nsec: PByte;
                                               const npub: PByte;
                                               const ctx: PCryptoAeadAES256GCMState): Integer; cdecl; external SODIUM_LIB;

function crypto_aead_aes256gcm_decrypt_afternm(m: PByte;
                                               var mlen_p: UInt64;
                                               nsec: PByte;
                                               const c: PByte;
                                               clen: UInt64;
                                               const ad: PByte;
                                               adlen: UInt64;
                                               const npub: PByte;
                                               const ctx: PCryptoAeadAES256GCMState): Integer; cdecl; external SODIUM_LIB;

function crypto_aead_aes256gcm_encrypt_detached_afternm(c: PByte;
                                                        mac: PByte;
                                                        var maclen_p: UInt64;
                                                        const m: PByte;
                                                        mlen: UInt64;
                                                        const ad: PByte;
                                                        adlen: UInt64;
                                                        const nsec: PByte;
                                                        const npub: PByte;
                                                        const ctx: PCryptoAeadAES256GCMState): Integer; cdecl; external SODIUM_LIB;

function crypto_aead_aes256gcm_decrypt_detached_afternm(m: PByte;
                                                        nsec: PByte;
                                                        const c: PByte;
                                                        clen: UInt64;
                                                        const mac: PByte;
                                                        const ad: PByte;
                                                        adlen: UInt64;
                                                        const npub: PByte;
                                                        const ctx: PCryptoAeadAES256GCMState): Integer; cdecl; external SODIUM_LIB;

type
  TCryptoAeadAES256GCMKey = array[0.._CRYPTO_AEAD_AES256GCM_KEYBYTES -1] of Byte;

procedure crypto_aead_aes256gcm_keygen(var k: TCryptoAeadAES256GCMKey); cdecl; external SODIUM_LIB;

type
  TCryptoAeadAES256GCMPubBytes = array[0.._CRYPTO_AEAD_AES256GCM_NPUBBYTES -1] of Byte;

(* sodium/crypto_aead_chacha20poly1305.h *)

(* -- IETF ChaCha20-Poly1305 construction with a 96-bit nonce and a 32-bit internal counter -- *)

const
  _CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES = 32;
function crypto_aead_chacha20poly1305_ietf_keybytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_AEAD_CHACHA20POLY1305_IETF_NSECBYTES = 0;
function crypto_aead_chacha20poly1305_ietf_nsecbytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES = 12;
function crypto_aead_chacha20poly1305_ietf_npubbytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES = 16;
function crypto_aead_chacha20poly1305_ietf_abytes: NativeUInt; cdecl; external SODIUM_LIB;

function _CRYPTO_AEAD_CHACHA20POLY1305_IETF_MESSAGEBYTES_MAX: UInt64; inline;
function crypto_aead_chacha20poly1305_ietf_messagebytes_max: NativeUInt; cdecl; external SODIUM_LIB;


function crypto_aead_chacha20poly1305_ietf_encrypt(c: PByte;
                                                   var clen_p: UInt64;
                                                   const m: PByte;
                                                   mlen: UInt64;
                                                   const ad: PByte;
                                                   adlen: UInt64;
                                                   const nsec: PByte;
                                                   const npub: PByte;
                                                   const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_aead_chacha20poly1305_ietf_decrypt(m: PByte;
                                                   var mlen_p: UInt64;
                                                   nsec: PByte;
                                                   const c: PByte;
                                                   clen: UInt64;
                                                   const ad: PByte;
                                                   adlen: UInt64;
                                                   const npub: PByte;
                                                   const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_aead_chacha20poly1305_ietf_encrypt_detached(c: PByte;
                                                            mac: PByte;
                                                            var maclen_p: UInt64;
                                                            const m: PByte;
                                                            mlen: UInt64;
                                                            const ad: PByte;
                                                            adlen: UInt64;
                                                            const nsec: PByte;
                                                            const npub: PByte;
                                                            const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_aead_chacha20poly1305_ietf_decrypt_detached(m: PByte;
                                                            nsec: PByte;
                                                            const c: PByte;
                                                            clen: UInt64;
                                                            const mac: PByte;
                                                            const ad: PByte;
                                                            adlen: UInt64;
                                                            const npub: PByte;
                                                            const k: PByte): Integer; cdecl; external SODIUM_LIB;

type
  TCryptoAeadChacha20poly1305IetfKey = array[0.._CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES -1] of Byte;

procedure crypto_aead_chacha20poly1305_ietf_keygen(var k: TCryptoAeadChacha20poly1305IetfKey); cdecl; external SODIUM_LIB;

type
  TCryptoAeadChacha20poly1305IetfPubBytes = array[0.._CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES -1] of Byte;

(* -- Original ChaCha20-Poly1305 construction with a 64-bit nonce and a 64-bit internal counter -- *)

const
  _CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES = 32;
function crypto_aead_chacha20poly1305_keybytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_AEAD_CHACHA20POLY1305_NSECBYTES = 0;
function crypto_aead_chacha20poly1305_nsecbytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES = 8;
function crypto_aead_chacha20poly1305_npubbytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_AEAD_CHACHA20POLY1305_ABYTES = 16;
function crypto_aead_chacha20poly1305_abytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_AEAD_CHACHA20POLY1305_MESSAGEBYTES_MAX =
    SODIUM_SIZE_MAX - _CRYPTO_AEAD_CHACHA20POLY1305_ABYTES;
function crypto_aead_chacha20poly1305_messagebytes_max: NativeUInt; cdecl; external SODIUM_LIB;

function crypto_aead_chacha20poly1305_encrypt(c: PByte;
                                              var clen_p: UInt64;
                                              const m: PByte;
                                              mlen: UInt64;
                                              const ad: PByte;
                                              adlen: UInt64;
                                              const nsec: PByte;
                                              const npub: PByte;
                                              const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_aead_chacha20poly1305_decrypt(m: PByte;
                                              var mlen_p: UInt64;
                                              nsec: PByte;
                                              const c: PByte;
                                              clen: UInt64;
                                              const ad: PByte;
                                              adlen: UInt64;
                                              const npub: PByte;
                                              const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_aead_chacha20poly1305_encrypt_detached(c: PByte;
                                                       mac: PByte;
                                                       var maclen_p: UInt64;
                                                       const m: PByte;
                                                       mlen: UInt64;
                                                       const ad: PByte;
                                                       adlen: UInt64;
                                                       const nsec: PByte;
                                                       const npub: PByte;
                                                       const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_aead_chacha20poly1305_decrypt_detached(m: PByte;
                                                       nsec: PByte;
                                                       const c: PByte;
                                                       clen: UInt64;
                                                       const mac: PByte;
                                                       const ad: PByte;
                                                       adlen: UInt64;
                                                       const npub: PByte;
                                                       const k: PByte): Integer; cdecl; external SODIUM_LIB;

type
  TCryptoAeadChacha20poly1305Key = array[0.._CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES -1] of Byte;

procedure crypto_aead_chacha20poly1305_keygen(var k: TCryptoAeadChacha20poly1305Key); cdecl; external SODIUM_LIB;

type
  TCryptoAeadChacha20poly1305PubBytes = array[0.._CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES -1] of Byte;

(* Aliases (Ignored: Pascal is not case sensitive) *)

//const
//  _CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES         = _CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES;
//  _CRYPTO_AEAD_CHACHA20POLY1305_IETF_NSECBYTES        = _CRYPTO_AEAD_CHACHA20POLY1305_IETF_NSECBYTES;
//  _CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES        = _CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES;
//  _CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES           = _CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES;
//  _CRYPTO_AEAD_CHACHA20POLY1305_IETF_MESSAGEBYTES_MAX = _CRYPTO_AEAD_CHACHA20POLY1305_IETF_MESSAGEBYTES_MAX;

(* sodium/crypto_aead_xchacha20poly1305.h *)

const
  _CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES = 32;
function crypto_aead_xchacha20poly1305_ietf_keybytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NSECBYTES = 0;
function crypto_aead_xchacha20poly1305_ietf_nsecbytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES = 24;
function crypto_aead_xchacha20poly1305_ietf_npubbytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES = 16;
function crypto_aead_xchacha20poly1305_ietf_abytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_AEAD_XCHACHA20POLY1305_IETF_MESSAGEBYTES_MAX =
    SODIUM_SIZE_MAX - _CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES;
function crypto_aead_xchacha20poly1305_ietf_messagebytes_max: NativeUInt; cdecl; external SODIUM_LIB;

function crypto_aead_xchacha20poly1305_ietf_encrypt(c: PByte;
                                                    var clen_p: UInt64;
                                                    const m: PByte;
                                                    mlen: UInt64;
                                                    const ad: PByte;
                                                    adlen: UInt64;
                                                    const nsec: PByte;
                                                    const npub: PByte;
                                                    const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_aead_xchacha20poly1305_ietf_decrypt(m: PByte;
                                                    var mlen_p: UInt64;
                                                    nsec: PByte;
                                                    const c: PByte;
                                                    clen: UInt64;
                                                    const ad: PByte;
                                                    adlen: UInt64;
                                                    const npub: PByte;
                                                    const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_aead_xchacha20poly1305_ietf_encrypt_detached(c: PByte;
                                                             mac: PByte;
                                                             var maclen_p: UInt64;
                                                             const m: PByte;
                                                             mlen: UInt64;
                                                             const ad: PByte;
                                                             adlen: UInt64;
                                                             const nsec: PByte;
                                                             const npub: PByte;
                                                             const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_aead_xchacha20poly1305_ietf_decrypt_detached(m: PByte;
                                                             nsec: PByte;
                                                             const c: PByte;
                                                             clen: UInt64;
                                                             const mac: PByte;
                                                             const ad: PByte;
                                                             adlen: UInt64;
                                                             const npub: PByte;
                                                             const k: PByte): Integer; cdecl; external SODIUM_LIB;

type
  TCryptoAeadXChacha20poly1305IetfKey = array[0.._CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES -1] of Byte;

procedure crypto_aead_xchacha20poly1305_ietf_keygen(var k: TCryptoAeadXChacha20poly1305IetfKey); cdecl; external SODIUM_LIB;

type
  TCryptoAeadXChacha20poly1305IetfPubBytes = array[0.._CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES -1] of Byte;

(* Aliases (Ignored: Pascal is not case sensitive) *)

//const
//  _CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES         = _CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES;
//  _CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NSECBYTES        = _CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NSECBYTES;
//  _CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES        = _CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
//  _CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES           = _CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES;
//  _CRYPTO_AEAD_XCHACHA20POLY1305_IETF_MESSAGEBYTES_MAX = _CRYPTO_AEAD_XCHACHA20POLY1305_IETF_MESSAGEBYTES_MAX;

(* sodium/crypto_hash_sha256.h *)

(*
 * WARNING: Unless you absolutely need to use SHA256 for interoperability,
 * purposes, you might want to consider crypto_generichash() instead.
 * Unlike SHA256, crypto_generichash() is not vulnerable to length
 * extension attacks.
 *)

type
  TCryptoHashSha256State = record
    state: array[0..8-1] of Cardinal;
    count: UInt64;
    buf: array[0..64-1] of Byte;
  end;

function crypto_hash_sha256_statebytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_HASH_SHA256_BYTES = 32;
function crypto_hash_sha256_bytes: NativeUInt; cdecl; external SODIUM_LIB;

function crypto_hash_sha256(&out: PByte; const &in: PByte;
                            inlen: UInt64): Integer; cdecl; external SODIUM_LIB;

function crypto_hash_sha256_init(var state: TCryptoHashSha256State): Integer; cdecl; external SODIUM_LIB;

function crypto_hash_sha256_update(var state: TCryptoHashSha256State;
                                   const &in: PByte;
                                   inlen: UInt64): Integer; cdecl; external SODIUM_LIB;

function crypto_hash_sha256_final(var state: TCryptoHashSha256State;
                                  &out: PByte): Integer; cdecl; external SODIUM_LIB;

type
  TCryptoHashSha256Hash = array[0.._CRYPTO_HASH_SHA256_BYTES -1] of Byte;

(* sodium/crypto_hash_sha512.h *)

(*
 * WARNING: Unless you absolutely need to use SHA256 for interoperability,
 * purposes, you might want to consider crypto_generichash() instead.
 * Unlike SHA512, crypto_generichash() is not vulnerable to length
 * extension attacks.
 *)

type
  TCryptoHashSha512State = record
    state: array[0..8-1] of UInt64;
    count: array[0..2-1] of UInt64;
    buf: array[0..128-1] of Byte;
  end;

function crypto_hash_sha512_statebytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_HASH_SHA512_BYTES = 64;
function crypto_hash_sha512_bytes: NativeUInt; cdecl; external SODIUM_LIB;

function crypto_hash_sha512(&out: PByte; const &in: PByte;
                            inlen: UInt64): Integer; cdecl; external SODIUM_LIB;

function crypto_hash_sha512_init(var state: TCryptoHashSha512State): Integer; cdecl; external SODIUM_LIB;

function crypto_hash_sha512_update(var state: TCryptoHashSha512State;
                                   const &in: PByte;
                                   inlen: UInt64): Integer; cdecl; external SODIUM_LIB;

function crypto_hash_sha512_final(var state: TCryptoHashSha512State;
                                  &out: PByte): Integer; cdecl; external SODIUM_LIB;

type
  TCryptoHashSha512Hash = array[0.._CRYPTO_HASH_SHA512_BYTES -1] of Byte;

(* sodium/crypto_hash.h *)

const
  _CRYPTO_HASH_BYTES = _CRYPTO_HASH_SHA512_BYTES;
function crypto_hash_bytes: NativeUInt; cdecl; external SODIUM_LIB;

function crypto_hash(&out: PByte; const &in: PByte;
                     inlen: UInt64): Integer; cdecl; external SODIUM_LIB;

const
  _CRYPTO_HASH_PRIMITIVE = 'sha512';
function crypto_hash_primitive: PAnsiChar; cdecl; external SODIUM_LIB;

type
  TCryptoHashHash = array[0.._CRYPTO_HASH_BYTES -1] of Byte;

(* sodium/crypto_generichash_blake2b.h *)

type
  TCryptoGenericHashBlake2bState = record
    opaque: array[0..384-1] of Byte;
  end;

const
  _CRYPTO_GENERICHASH_BLAKE2B_BYTES_MIN = 16;
function crypto_generichash_blake2b_bytes_min: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_GENERICHASH_BLAKE2B_BYTES_MAX = 64;
function crypto_generichash_blake2b_bytes_max: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_GENERICHASH_BLAKE2B_BYTES = 32;
function crypto_generichash_blake2b_bytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES_MIN = 16;
function crypto_generichash_blake2b_keybytes_min: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES_MAX = 64;
function crypto_generichash_blake2b_keybytes_max: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES = 32;
function crypto_generichash_blake2b_keybytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_GENERICHASH_BLAKE2B_SALTBYTES = 16;
function crypto_generichash_blake2b_saltbytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_GENERICHASH_BLAKE2B_PERSONALBYTES = 16;
function crypto_generichash_blake2b_personalbytes: NativeUInt; cdecl; external SODIUM_LIB;

function crypto_generichash_blake2b_statebytes: NativeUInt; cdecl; external SODIUM_LIB;

function crypto_generichash_blake2b(&out: PByte; outlen: NativeUInt;
                                    const &in: PByte;
                                    inlen: UInt64;
                                    const key: PByte; keylen: NativeUInt): Integer; cdecl; external SODIUM_LIB;

function crypto_generichash_blake2b_salt_personal(&out: PByte; outlen: NativeUInt;
                                                  const &in: PByte;
                                                  inlen: UInt64;
                                                  const key: PByte;
                                                  keylen: NativeUInt;
                                                  const salt: PByte;
                                                  const personal: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_generichash_blake2b_init(var state: TCryptoGenericHashBlake2bState;
                                         const key: PByte;
                                         const keylen: NativeUInt; const outlen: NativeUInt): Integer; cdecl; external SODIUM_LIB;

function crypto_generichash_blake2b_init_salt_personal(var state: TCryptoGenericHashBlake2bState;
                                                       const key: PByte;
                                                       const keylen: NativeUInt; const outlen: NativeUInt;
                                                       const salt: PByte;
                                                       const personal: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_generichash_blake2b_update(var state: TCryptoGenericHashBlake2bState;
                                           const &in: PByte;
                                           inlen: UInt64): Integer; cdecl; external SODIUM_LIB;

function crypto_generichash_blake2b_final(var state: TCryptoGenericHashBlake2bState;
                                          &out: PByte;
                                          const outlen: NativeUInt): Integer; cdecl; external SODIUM_LIB;

type
  TCryptoGenericHashBlake2bKey = array[0.._CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES -1] of Byte;

procedure crypto_generichash_blake2b_keygen(var k: TCryptoGenericHashBlake2bKey); cdecl; external SODIUM_LIB;

type
  TCryptoGenericHashBlake2bHash = array[0.._CRYPTO_GENERICHASH_BLAKE2B_BYTES -1] of Byte;

(* sodium/crypto_generichash.h *)

const
  _CRYPTO_GENERICHASH_BYTES_MIN = _CRYPTO_GENERICHASH_BLAKE2B_BYTES_MIN;
function crypto_generichash_bytes_min: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_GENERICHASH_BYTES_MAX = _CRYPTO_GENERICHASH_BLAKE2B_BYTES_MAX;
function crypto_generichash_bytes_max: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_GENERICHASH_BYTES = _CRYPTO_GENERICHASH_BLAKE2B_BYTES;
function crypto_generichash_bytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_GENERICHASH_KEYBYTES_MIN = _CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES_MIN;
function crypto_generichash_keybytes_min: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_GENERICHASH_KEYBYTES_MAX = _CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES_MAX;
function crypto_generichash_keybytes_max: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_GENERICHASH_KEYBYTES = _CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES;
function crypto_generichash_keybytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_GENERICHASH_PRIMITIVE = 'blake2b';
function crypto_generichash_primitive: PAnsiChar; cdecl; external SODIUM_LIB;

(*
 * Important when writing bindings for other programming languages:
 * the state address should be 64-bytes aligned.
 *)
type
  TCryptoGenericHashState = TCryptoGenericHashBlake2bState;

function crypto_generichash_statebytes: NativeUint; cdecl; external SODIUM_LIB;

function crypto_generichash(&out: PByte; outlen: NativeUInt;
                            const &in: PByte; inlen: UInt64;
                            const key: PByte; keylen: NativeUInt): Integer; cdecl; external SODIUM_LIB;

function crypto_generichash_init(var state: TCryptoGenericHashState;
                                 const key: PByte;
                                 const keylen: NativeUInt; const outlen: NativeUInt): Integer; cdecl; external SODIUM_LIB;

function crypto_generichash_update(var state: TCryptoGenericHashState;
                                   const &in: PByte;
                                   inlen: UInt64): Integer; cdecl; external SODIUM_LIB;

function crypto_generichash_final(var state: TCryptoGenericHashState;
                                  &out: PByte; const outlen: NativeUInt): Integer; cdecl; external SODIUM_LIB;

type
  TCryptoGenericHashKey = array[0.._CRYPTO_GENERICHASH_KEYBYTES -1] of Byte;

procedure crypto_generichash_keygen(var k: TCryptoGenericHashKey); cdecl; external SODIUM_LIB;

type
  TCryptoGenericHashHash = array[0.._CRYPTO_GENERICHASH_BYTES -1] of Byte;

(* sodium/crypto_auth_hmacsha512.h *)

const
  _CRYPTO_AUTH_HMACSHA512_BYTES = 64;
function crypto_auth_hmacsha512_bytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_AUTH_HMACSHA512_KEYBYTES = 32;
function crypto_auth_hmacsha512_keybytes: NativeUInt; cdecl; external SODIUM_LIB;

function crypto_auth_hmacsha512(&out: PByte;
                                const &in: PByte;
                                inlen: UInt64;
                                const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_auth_hmacsha512_verify(const h: PByte;
                                       const &in: PByte;
                                       inlen: UInt64;
                                       const k: PByte): Integer; cdecl; external SODIUM_LIB;

(* ------------------------------------------------------------------------- *)

type
  TCryptoAuthHmacSha512State = record
    ictx: TCryptoHashSha512State;
    octx: TCryptoHashSha512State;
  end;

function crypto_auth_hmacsha512_statebytes: NativeUInt; cdecl; external SODIUM_LIB;

function crypto_auth_hmacsha512_init(var State: TCryptoAuthHmacSha512State;
                                     const key: PByte;
                                     keylen: NativeUInt): Integer; cdecl; external SODIUM_LIB;

function crypto_auth_hmacsha512_update(var State: TCryptoAuthHmacSha512State;
                                       const &in: PByte;
                                       inlen: UInt64): Integer; cdecl; external SODIUM_LIB;

function crypto_auth_hmacsha512_final(var State: TCryptoAuthHmacSha512State;
                                      &out: PByte): Integer; cdecl; external SODIUM_LIB;

type
  TCryptoAuthHmacSha512Key = array[0.._CRYPTO_AUTH_HMACSHA512_KEYBYTES -1] of Byte;

procedure crypto_auth_hmacsha512_keygen(var k: TCryptoAuthHmacSha512Key); cdecl; external SODIUM_LIB;

type
  TCryptoAuthHmacSha512Hash = array[0.._CRYPTO_AUTH_HMACSHA512_BYTES -1] of Byte;

(* sodium/#ifndef crypto_auth_hmacsha256.h *)

const
  _CRYPTO_AUTH_HMACSHA256_BYTES = 32;
function crypto_auth_hmacsha256_bytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_AUTH_HMACSHA256_KEYBYTES = 32;
function crypto_auth_hmacsha256_keybytes: NativeUInt; cdecl; external SODIUM_LIB;

function crypto_auth_hmacsha256(&out: PByte;
                                const &in: PByte;
                                inlen: UInt64;
                                const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_auth_hmacsha256_verify(const h: PByte;
                                       const &in: PByte;
                                       inlen: UInt64;
                                       const k: PByte): Integer; cdecl; external SODIUM_LIB;

(* ------------------------------------------------------------------------- *)

type
  TCryptoAuthHmacSha256State = record
    ictx: TCryptoHashSha256State;
    octx: TCryptoHashSha256State;
  end;

function crypto_auth_hmacsha256_statebytes: NativeUInt; cdecl; external SODIUM_LIB;

function crypto_auth_hmacsha256_init(var state: TCryptoAuthHmacSha256State;
                                     const key: PByte;
                                     keylen: NativeUInt): Integer; cdecl; external SODIUM_LIB;

function crypto_auth_hmacsha256_update(var state: TCryptoAuthHmacSha256State;
                                       const &in: PByte;
                                       inlen: UInt64): Integer; cdecl; external SODIUM_LIB;

function crypto_auth_hmacsha256_final(var state: TCryptoAuthHmacSha256State;
                                      &out: PByte): Integer; cdecl; external SODIUM_LIB;

type
  TCryptoAuthHmacSha256Key = array[0.._CRYPTO_AUTH_HMACSHA256_KEYBYTES -1] of Byte;

procedure crypto_auth_hmacsha256_keygen(var k: TCryptoAuthHmacSha256Key); cdecl; external SODIUM_LIB;

type
  TCryptoAuthHmacSha256Hash = array[0.._CRYPTO_AUTH_HMACSHA256_BYTES -1] of Byte;

(* sodium/crypto_auth_hmacsha512256.h *)

const
  _CRYPTO_AUTH_HMACSHA512256_BYTES = 32;
function crypto_auth_hmacsha512256_bytes: NativeUInt; cdecl; external SODIUM_LIB;

const
 _CRYPTO_AUTH_HMACSHA512256_KEYBYTES = 32;
function crypto_auth_hmacsha512256_keybytes: NativeUInt; cdecl; external SODIUM_LIB;

function crypto_auth_hmacsha512256(&out: PByte;
                                   const &in: PByte;
                                   inlen: UInt64;
                                   const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_auth_hmacsha512256_verify(const h: PByte;
                                          const &in: PByte;
                                          inlen: UInt64;
                                          const k: PByte): Integer; cdecl; external SODIUM_LIB;

(* ------------------------------------------------------------------------- *)

type
 TCryptoAuthHmacSha512256State = TCryptoAuthHmacSha512State;

function crypto_auth_hmacsha512256_statebytes: NativeUInt; cdecl; external SODIUM_LIB;

function crypto_auth_hmacsha512256_init(var state: TCryptoAuthHmacSha512256State;
                                        const key: PByte;
                                        keylen: NativeUInt): Integer; cdecl; external SODIUM_LIB;

function crypto_auth_hmacsha512256_update(var state: TCryptoAuthHmacSha512256State;
                                          const &in: PByte;
                                          inlen: UInt64): Integer; cdecl; external SODIUM_LIB;

function crypto_auth_hmacsha512256_final(var state: TCryptoAuthHmacSha512256State;
                                         &out: PByte): Integer; cdecl; external SODIUM_LIB;

type
  TCryptoAuthHmacSha512256Key = array[0.._CRYPTO_AUTH_HMACSHA512256_KEYBYTES -1] of Byte;

procedure crypto_auth_hmacsha512256_keygen(var k: TCryptoAuthHmacSha512256Key); cdecl; external SODIUM_LIB;

type
  TCryptoAuthHmacSha512256Hash = array[0.._CRYPTO_AUTH_HMACSHA512256_BYTES -1] of Byte;

(* sodium/crypto_auth.h *)

const
  _CRYPTO_AUTH_BYTES = _CRYPTO_AUTH_HMACSHA512256_BYTES;
function crypto_auth_bytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_AUTH_KEYBYTES = _CRYPTO_AUTH_HMACSHA512256_KEYBYTES;
function crypto_auth_keybytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_AUTH_PRIMITIVE = 'hmacsha512256';
function crypto_auth_primitive: PAnsiChar; cdecl; external SODIUM_LIB;

function crypto_auth(&out: PByte; const &in: PByte;
                     inlen: UInt64; const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_auth_verify(const h: PByte; const &in: PByte;
                            inlen: UInt64; const k: PByte): Integer; cdecl; external SODIUM_LIB;

type
  TCryptoAuthKey = array[0.._crypto_auth_KEYBYTES -1] of Byte;

procedure crypto_auth_keygen(var k: TCryptoAuthKey); cdecl; external SODIUM_LIB;

type
  TCryptoAuthHash = array[0.._crypto_auth_BYTES -1] of Byte;

(* sodium/crypto_core_ed25519.h *)

const
  _CRYPTO_CORE_ED25519_BYTES = 32;
function crypto_core_ed25519_bytes: NativeUInt; cdecl; external SODIUM_LIB;

type
  TCryptoCoreEd25519 = array[0.._CRYPTO_CORE_ED25519_BYTES -1] of Byte;

const
  _CRYPTO_CORE_ED25519_UNIFORMBYTES = 32;
function crypto_core_ed25519_uniformbytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_CORE_ED25519_HASHBYTES = 64;
function crypto_core_ed25519_hashbytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_CORE_ED25519_SCALARBYTES = 32;
function crypto_core_ed25519_scalarbytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_CORE_ED25519_NONREDUCEDSCALARBYTES = 64;
function crypto_core_ed25519_nonreducedscalarbytes: NativeUInt; cdecl; external SODIUM_LIB;

//const
//  _CRYPTO_CORE_ED25519_H2CSHA256 = 1;
//  _CRYPTO_CORE_ED25519_H2CSHA512 = 2;

function crypto_core_ed25519_is_valid_point(const p: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_core_ed25519_add(r: PByte;
                                 const p: PByte; const q: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_core_ed25519_sub(r: PByte;
                                 const p: PByte; const q: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_core_ed25519_from_uniform(p: PByte; const r: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_core_ed25519_from_hash(p: PByte; const h: PByte): Integer; cdecl; external SODIUM_LIB;

//function crypto_core_ed25519_from_string(p: TCryptoCoreEd25519;
//                                         const ctx: PAnsiChar; const msg: PByte;
//                                         msg_len: NativeUInt; hash_alg: Integer): Integer; cdecl; external SODIUM_LIB;
//
//function crypto_core_ed25519_from_string_ro(p: TCryptoCoreEd25519;
//                                            const ctx: PAnsiChar; const msg: PByte;
//                                            msg_len: NativeUInt; hash_alg: Integer): Integer; cdecl; external SODIUM_LIB;

procedure crypto_core_ed25519_random(p: PByte); cdecl; external SODIUM_LIB;

procedure crypto_core_ed25519_scalar_random(r: PByte); cdecl; external SODIUM_LIB;

function crypto_core_ed25519_scalar_invert(recip: PByte; const s: PByte): Integer; cdecl; external SODIUM_LIB;

procedure crypto_core_ed25519_scalar_negate(nep: PByte; const s: PByte); cdecl; external SODIUM_LIB;

procedure crypto_core_ed25519_scalar_complement(comp: PByte; const s: PByte); cdecl; external SODIUM_LIB;

procedure crypto_core_ed25519_scalar_add(z: PByte; const x: PByte;
                                         const y: PByte); cdecl; external SODIUM_LIB;

procedure crypto_core_ed25519_scalar_sub(z: PByte; const x: PByte;
                                         const y: PByte); cdecl; external SODIUM_LIB;

procedure crypto_core_ed25519_scalar_mul(z: PByte; const x: PByte;
                                         const y: PByte); cdecl; external SODIUM_LIB;

(*
 * The interval `s` is sampled from should be at least 317 bits to ensure almost
 * uniformity of `r` over `L`.
 *)
procedure crypto_core_ed25519_scalar_reduce(r: PByte; const s: PByte); cdecl; external SODIUM_LIB;

//function crypto_core_ed25519_scalar_is_canonical(const s: PByte): Integer; cdecl; external SODIUM_LIB;

(* sodium/crypto_core_hchacha20.h *)

const
  _CRYPTO_CORE_HCHACHA20_OUTPUTBYTES = 32;
function crypto_core_hchacha20_outputbytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_CORE_HCHACHA20_INPUTBYTES = 16;
function crypto_core_hchacha20_inputbytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_CORE_HCHACHA20_KEYBYTES = 32;
function crypto_core_hchacha20_keybytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_CORE_HCHACHA20_CONSTBYTES = 16;
function crypto_core_hchacha20_constbytes: NativeUInt; cdecl; external SODIUM_LIB;

function crypto_core_hchacha20(&out: PByte; const &in: PByte;
                               const k: PByte; const c: PByte): Integer; cdecl; external SODIUM_LIB;

(* sodium/crypto_core_hsalsa20.h *)

const
  _CRYPTO_CORE_HSALSA20_OUTPUTBYTES = 32;
function crypto_core_hsalsa20_outputbytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_CORE_HSALSA20_INPUTBYTES = 16;
function crypto_core_hsalsa20_inputbytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_CORE_HSALSA20_KEYBYTES = 32;
function crypto_core_hsalsa20_keybytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_CORE_HSALSA20_CONSTBYTES = 16;
function crypto_core_hsalsa20_constbytes: NativeUInt; cdecl; external SODIUM_LIB;

function crypto_core_hsalsa20(&out: PByte; const &in: PByte;
                              const k: PByte; const c: PByte): Integer; cdecl; external SODIUM_LIB;

(* sodium/crypto_core_ristretto255.h *)

const
  _CRYPTO_CORE_RISTRETTO255_BYTES = 32;
function crypto_core_ristretto255_bytes: NativeUInt; cdecl; external SODIUM_LIB;

type
  TCryptoCoreRistretto255 = array[0.._CRYPTO_CORE_RISTRETTO255_BYTES -1] of Byte;

const
  _CRYPTO_CORE_RISTRETTO255_HASHBYTES = 64;
function crypto_core_ristretto255_hashbytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_CORE_RISTRETTO255_SCALARBYTES = 32;
function crypto_core_ristretto255_scalarbytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_CORE_RISTRETTO255_NONREDUCEDSCALARBYTES = 64;
function crypto_core_ristretto255_nonreducedscalarbytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_CORE_RISTRETTO255_H2CSHA256 = 1;
  _CRYPTO_CORE_RISTRETTO255_H2CSHA512 = 2;

function crypto_core_ristretto255_is_valid_point(const p: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_core_ristretto255_add(r: PByte;
                                      const p: PByte; const q: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_core_ristretto255_sub(r: PByte;
                                      const p: PByte; const q: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_core_ristretto255_from_hash(p: PByte;
                                            const r: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_core_ristretto255_from_string(p: TCryptoCoreRistretto255;
                                              const ctx: PAnsiChar;
                                              const msg: PByte;
                                              msg_len: NativeUInt; hash_alg: Integer): Integer; cdecl; external SODIUM_LIB;

function crypto_core_ristretto255_from_string_ro(p: TCryptoCoreRistretto255;
                                                 const ctx: PAnsiChar;
                                                 const msg: PByte;
                                                 msg_len: NativeUInt; hash_alg: Integer): Integer; cdecl; external SODIUM_LIB;

procedure crypto_core_ristretto255_random(p: PByte); cdecl; external SODIUM_LIB;

procedure crypto_core_ristretto255_scalar_random(r: PByte); cdecl; external SODIUM_LIB;

function crypto_core_ristretto255_scalar_invert(recip: PByte;
                                                const s: PByte): Integer; cdecl; external SODIUM_LIB;

procedure crypto_core_ristretto255_scalar_negate(neg: PByte;
                                                 const s: PByte); cdecl; external SODIUM_LIB;

procedure crypto_core_ristretto255_scalar_complement(comp: PByte;
                                                     const s: PByte); cdecl; external SODIUM_LIB;

procedure crypto_core_ristretto255_scalar_add(z: PByte;
                                              const x: PByte;
                                              const y: PByte); cdecl; external SODIUM_LIB;

procedure crypto_core_ristretto255_scalar_sub(z: PByte;
                                              const x: PByte;
                                              const y: PByte); cdecl; external SODIUM_LIB;

procedure crypto_core_ristretto255_scalar_mul(z: PByte;
                                              const x: PByte;
                                              const y: PByte); cdecl; external SODIUM_LIB;

(*
 * The interval `s` is sampled from should be at least 317 bits to ensure almost
 * uniformity of `r` over `L`.
 *)
procedure crypto_core_ristretto255_scalar_reduce(r: PByte;
                                                 const s: PByte); cdecl; external SODIUM_LIB;

function crypto_core_ristretto255_scalar_is_canonical(const s: PByte): Integer; cdecl; external SODIUM_LIB;

(* sodium/crypto_core_salsa20.h *)

const
  _CRYPTO_CORE_SALSA20_OUTPUTBYTES = 64;
function crypto_core_salsa20_outputbytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_CORE_SALSA20_INPUTBYTES = 16;
function crypto_core_salsa20_inputbytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_CORE_SALSA20_KEYBYTES = 32;
function crypto_core_salsa20_keybytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_CORE_SALSA20_CONSTBYTES = 16;
function crypto_core_salsa20_constbytes: NativeUInt; cdecl; external SODIUM_LIB;

function crypto_core_salsa20(&out: PByte; const &in: PByte;
                             const k: PByte; const c: PByte): Integer; cdecl; external SODIUM_LIB;

(* sodium/crypto_core_salsa208.h *)

const
  _CRYPTO_CORE_SALSA208_OUTPUTBYTES = 64;
function crypto_core_salsa208_outputbyte: NativeUInt; cdecl; external SODIUM_LIB; deprecated;

const
  _CRYPTO_CORE_SALSA208_INPUTBYTES = 16;
function crypto_core_salsa208_inputbyte: NativeUInt; cdecl; external SODIUM_LIB; deprecated;

const
  _CRYPTO_CORE_SALSA208_KEYBYTES = 32;
function crypto_core_salsa208_keybyte: NativeUInt; cdecl; external SODIUM_LIB; deprecated;

const
  _CRYPTO_CORE_SALSA208_CONSTBYTES = 16;
function crypto_core_salsa208_constbyte: NativeUInt; cdecl; external SODIUM_LIB; deprecated;

function crypto_core_salsa208(&out: PByte; const &in: PByte;
                              const k: PByte; const c: PByte): Integer; cdecl; external SODIUM_LIB; deprecated;

(* sodium/crypto_core_salsa2012.h *)

const
  _CRYPTO_CORE_SALSA2012_OUTPUTBYTES = 64;
function crypto_core_salsa2012_outputbytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_CORE_SALSA2012_INPUTBYTES = 16;
function crypto_core_salsa2012_inputbytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_CORE_SALSA2012_KEYBYTES = 32;
function crypto_core_salsa2012_keybytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_CORE_SALSA2012_CONSTBYTES = 16;
function crypto_core_salsa2012_constbytes: NativeUInt; cdecl; external SODIUM_LIB;

function crypto_core_salsa2012(&out: PByte; const &in: PByte;
                               const k: PByte; const c: PByte): Integer; cdecl; external SODIUM_LIB;

(* sodium/crypto_stream_chacha20.h *)

(*
 *  WARNING: This is just a stream cipher. It is NOT authenticated encryption.
 *  While it provides some protection against eavesdropping, it does NOT
 *  provide any security against active attacks.
 *  Unless you know what you're doing, what you are looking for is probably
 *  the crypto_box functions.
 *)

const
  _CRYPTO_STREAM_CHACHA20_KEYBYTES = 32;
function crypto_stream_chacha20_keybytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_STREAM_CHACHA20_NONCEBYTES = 8;
function crypto_stream_chacha20_noncebytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_STREAM_CHACHA20_MESSAGEBYTES_MAX = SODIUM_SIZE_MAX;
function crypto_stream_chacha20_messagebytes_max: NativeUInt; cdecl; external SODIUM_LIB;

(* ChaCha20 with a 64-bit nonce and a 64-bit counter, as originally designed *)

function crypto_stream_chacha20(c: PByte; clen: UInt64;
                                const n: PByte; const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_stream_chacha20_xor(c: PByte; const m: PByte;
                                    mlen: UInt64; const n: PByte;
                                    const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_stream_chacha20_xor_ic(c: PByte; const m: PByte;
                                       mlen: UInt64;
                                       const n: PByte; ic: UInt64;
                                       const k: PByte): Integer; cdecl; external SODIUM_LIB;

type
  TCryptoStreamChacha20Key = array[0.._CRYPTO_STREAM_CHACHA20_KEYBYTES -1] of Byte;

procedure crypto_stream_chacha20_keygen(var k: TCryptoStreamChacha20Key); cdecl; external SODIUM_LIB;

(* ChaCha20 with a 96-bit nonce and a 32-bit counter (IETF) *)

const
  _CRYPTO_STREAM_CHACHA20_IETF_KEYBYTES = 32;
function crypto_stream_chacha20_ietf_keybytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_STREAM_CHACHA20_IETF_NONCEBYTES = 12;
function crypto_stream_chacha20_ietf_noncebytes: NativeUInt; cdecl; external SODIUM_LIB;

type
  TCryptoStreamChacha20IetfNonce = array[0.._crypto_stream_chacha20_ietf_NONCEBYTES -1] of Byte;

function _CRYPTO_STREAM_CHACHA20_IETF_MESSAGEBYTES_MAX: UInt64; inline;
function crypto_stream_chacha20_ietf_messagebytes_max: NativeUInt; cdecl; external SODIUM_LIB;

function crypto_stream_chacha20_ietf(c: PByte; clen: UInt64;
                                     const n: PByte; const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_stream_chacha20_ietf_xor(c: PByte; const m: PByte;
                                         mlen: UInt64; const n: PByte;
                                         const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_stream_chacha20_ietf_xor_ic(c: PByte; const m: PByte;
                                            mlen: UInt64;
                                            const n: PByte; ic: Cardinal;
                                            const k: PByte): Integer; cdecl; external SODIUM_LIB;

type
  TCryptoStreamChacha20IetfKey = array[0.._CRYPTO_STREAM_CHACHA20_IETF_KEYBYTES -1] of Byte;

procedure crypto_stream_chacha20_ietf_keygen(var k: TCryptoStreamChacha20IetfKey); cdecl; external SODIUM_LIB;

(* sodium/crypto_stream_salsa20.h *)

(*
 *  WARNING: This is just a stream cipher. It is NOT authenticated encryption.
 *  While it provides some protection against eavesdropping, it does NOT
 *  provide any security against active attacks.
 *  Unless you know what you're doing, what you are looking for is probably
 *  the crypto_box functions.
 *)

const
  _CRYPTO_STREAM_SALSA20_KEYBYTES = 32;
function crypto_stream_salsa20_keybytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_STREAM_SALSA20_NONCEBYTES = 8;
function crypto_stream_salsa20_noncebytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_STREAM_SALSA20_MESSAGEBYTES_MAX = SODIUM_SIZE_MAX;
function crypto_stream_salsa20_messagebytes_max: NativeUInt; cdecl; external SODIUM_LIB;

function crypto_stream_salsa20(c: PByte; clen: UInt64;
                               const n: PByte; const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_stream_salsa20_xor(c: PByte; const m: PByte;
                                   mlen: UInt64; const n: PByte;
                                   const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_stream_salsa20_xor_ic(c: PByte; const m: PByte;
                                      mlen: UInt64;
                                      const n: PByte; ic: UInt64;
                                      const k: PByte): Integer; cdecl; external SODIUM_LIB;

type
  TCryptoStreamSalsa20Key = array[0.._CRYPTO_STREAM_SALSA20_KEYBYTES -1] of Byte;

procedure crypto_stream_salsa20_keygen(var k: TCryptoStreamSalsa20Key); cdecl; external SODIUM_LIB;

(* sodium/crypto_stream_salsa208.h *)

(*
 *  WARNING: This is just a stream cipher. It is NOT authenticated encryption.
 *  While it provides some protection against eavesdropping, it does NOT
 *  provide any security against active attacks.
 *  Unless you know what you're doing, what you are looking for is probably
 *  the crypto_box functions.
 *)

const
  _CRYPTO_STREAM_SALSA208_KEYBYTES = 32;
function crypto_stream_salsa208_keybyte: NativeUInt; cdecl; external SODIUM_LIB; deprecated;

const
  _CRYPTO_STREAM_SALSA208_NONCEBYTES = 8;
function crypto_stream_salsa208_noncebyte: NativeUInt; cdecl; external SODIUM_LIB; deprecated;

const
  _CRYPTO_STREAM_SALSA208_MESSAGEBYTES_MAX = SODIUM_SIZE_MAX;
function crypto_stream_salsa208_messagebytes_max: NativeUInt; cdecl; external SODIUM_LIB; deprecated;

function crypto_stream_salsa208(c: PByte; clen: UInt64;
                                const n: PByte; const k: PByte): Integer; cdecl; external SODIUM_LIB; deprecated;

function crypto_stream_salsa208_xor(c: PByte; const m: PByte;
                                    mlen: UInt64; const n: PByte;
                                    const k: PByte): Integer; cdecl; external SODIUM_LIB; deprecated;

type
  TCryptoStreamSalsa208Key = array[0.._CRYPTO_STREAM_SALSA208_KEYBYTES -1] of Byte;

procedure crypto_stream_salsa208_keygen(var k: TCryptoStreamSalsa208Key); cdecl; external SODIUM_LIB; deprecated;

(* sodium/crypto_stream_salsa2012.h *)

(*
 *  WARNING: This is just a stream cipher. It is NOT authenticated encryption.
 *  While it provides some protection against eavesdropping, it does NOT
 *  provide any security against active attacks.
 *  Unless you know what you're doing, what you are looking for is probably
 *  the crypto_box functions.
 *)

const
  _CRYPTO_STREAM_SALSA2012_KEYBYTES = 32;
function crypto_stream_salsa2012_keybytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_STREAM_SALSA2012_NONCEBYTES = 8;
function crypto_stream_salsa2012_noncebytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_STREAM_SALSA2012_MESSAGEBYTES_MAX = SODIUM_SIZE_MAX;
function crypto_stream_salsa2012_messagebytes_max: NativeUInt; cdecl; external SODIUM_LIB;

function crypto_stream_salsa2012(c: PByte; clen: UInt64;
                                 const n: PByte; const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_stream_salsa2012_xor(c: PByte; const m: PByte;
                                     mlen: UInt64; const n: PByte;
                                     const k: PByte): Integer; cdecl; external SODIUM_LIB;

type
  TCryptoStreamSalsa2012Key = array[0.._CRYPTO_STREAM_SALSA2012_KEYBYTES -1] of Byte;

procedure crypto_stream_salsa2012_keygen(var k: TCryptoStreamSalsa2012Key); cdecl; external SODIUM_LIB;

(* sodium/crypto_stream_xchacha20.h *)

(*
 *  WARNING: This is just a stream cipher. It is NOT authenticated encryption.
 *  While it provides some protection against eavesdropping, it does NOT
 *  provide any security against active attacks.
 *  Unless you know what you're doing, what you are looking for is probably
 *  the crypto_box functions.
 *)

const
  _CRYPTO_STREAM_XCHACHA20_KEYBYTES = 32;
function crypto_stream_xchacha20_keybytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_STREAM_XCHACHA20_NONCEBYTES = 24;
function crypto_stream_xchacha20_noncebytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_STREAM_XCHACHA20_MESSAGEBYTES_MAX = SODIUM_SIZE_MAX;
function crypto_stream_xchacha20_messagebytes_max: NativeUInt; cdecl; external SODIUM_LIB;

function crypto_stream_xchacha20(c: PByte; clen: UInt64;
                                 const n: PByte; const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_stream_xchacha20_xor(c: PByte; const m: PByte;
                                     mlen: UInt64; const n: PByte;
                                     const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_stream_xchacha20_xor_ic(c: PByte; const m: PByte;
                                        mlen: UInt64;
                                        const n: PByte; ic: UInt64;
                                        const k: PByte): Integer; cdecl; external SODIUM_LIB;

type
  TCryptoStreamXChacha20Key = array[0.._CRYPTO_STREAM_XCHACHA20_KEYBYTES -1] of Byte;

procedure crypto_stream_xchacha20_keygen(var k: TCryptoStreamXChacha20Key); cdecl; external SODIUM_LIB;

(* sodium/crypto_stream_xsalsa20.h *)

(*
 *  WARNING: This is just a stream cipher. It is NOT authenticated encryption.
 *  While it provides some protection against eavesdropping, it does NOT
 *  provide any security against active attacks.
 *  Unless you know what you're doing, what you are looking for is probably
 *  the crypto_box functions.
 *)

const
  _CRYPTO_STREAM_XSALSA20_KEYBYTES = 32;
function crypto_stream_xsalsa20_keybytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_STREAM_XSALSA20_NONCEBYTES = 24;
function crypto_stream_xsalsa20_noncebytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_STREAM_XSALSA20_MESSAGEBYTES_MAX = SODIUM_SIZE_MAX;
function crypto_stream_xsalsa20_messagebytes_max: NativeUInt; cdecl; external SODIUM_LIB;

function crypto_stream_xsalsa20(c: PByte; clean: UInt64;
                                const n: PByte; const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_stream_xsalsa20_xor(c: PByte; const m: PByte;
                                    mlen: UInt64; const n: PByte;
                                    const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_stream_xsalsa20_xor_ic(c: PByte; const m: PByte;
                                       mlen: UInt64;
                                       const n: PByte; ic: UInt64;
                                       const k: PByte): Integer; cdecl; external SODIUM_LIB;

type
  TCryptoStreamXSalsa20Key = array[0.._CRYPTO_STREAM_XSALSA20_KEYBYTES -1] of Byte;

procedure crypto_stream_xsalsa20_keygen(var k: TCryptoStreamXSalsa20Key); cdecl; external SODIUM_LIB;

(* sodium/crypto_stream.h *)

(*
 *  WARNING: This is just a stream cipher. It is NOT authenticated encryption.
 *  While it provides some protection against eavesdropping, it does NOT
 *  provide any security against active attacks.
 *  Unless you know what you're doing, what you are looking for is probably
 *  the crypto_box functions.
 *)

const
  _crypto_stream_KEYBYTES = _crypto_stream_xsalsa20_KEYBYTES;
function crypto_stream_keybytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _crypto_stream_NONCEBYTES = _crypto_stream_xsalsa20_NONCEBYTES;
function crypto_stream_noncebytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_STREAM_MESSAGEBYTES_MAX = _CRYPTO_STREAM_XSALSA20_MESSAGEBYTES_MAX;
function crypto_stream_messagebytes_max: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_STREAM_PRIMITIVE = 'xsalsa20';
function crypto_stream_primitive: PAnsiChar; cdecl; external SODIUM_LIB;

function crypto_stream(c: PByte; clen: UInt64;
                       const n: PByte; const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_stream_xor(c: PByte; const m: PByte;
                           mlen: UInt64; const n: PByte;
                           const k: PByte): Integer; cdecl; external SODIUM_LIB;

type
  TCryptoStreamKey = array[0.._CRYPTO_STREAM_KEYBYTES -1] of Byte;

procedure crypto_stream_keygen(var k: TCryptoStreamKey); cdecl; external SODIUM_LIB;

(* sodium/crypto_box_curve25519xchacha20poly1305.h *)

const
  _CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_SEEDBYTES = 32;
function crypto_box_curve25519xchacha20poly1305_seedbytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_PUBLICKEYBYTES = 32;
function crypto_box_curve25519xchacha20poly1305_publickeybytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_SECRETKEYBYTES = 32;
function crypto_box_curve25519xchacha20poly1305_secretkeybytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_BEFORENMBYTES = 32;
function crypto_box_curve25519xchacha20poly1305_beforenmbytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_NONCEBYTES = 24;
function crypto_box_curve25519xchacha20poly1305_noncebytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_MACBYTES = 16;
function crypto_box_curve25519xchacha20poly1305_macbytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_MESSAGEBYTES_MAX =
    _CRYPTO_STREAM_XCHACHA20_MESSAGEBYTES_MAX -
    _CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_MACBYTES;
function crypto_box_curve25519xchacha20poly1305_messagebytes_max: NativeUInt; cdecl; external SODIUM_LIB;

function crypto_box_curve25519xchacha20poly1305_seed_keypair(pk: PByte;
                                                             sk: PByte;
                                                             const seed: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_box_curve25519xchacha20poly1305_keypair(pk: PByte;
                                                        sk: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_box_curve25519xchacha20poly1305_easy(c: PByte;
                                                     const m: PByte;
                                                     mlen: UInt64;
                                                     const n: PByte;
                                                     const pk: PByte;
                                                     const sk: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_box_curve25519xchacha20poly1305_open_easy(m: PByte;
                                                          const c: PByte;
                                                          clen: UInt64;
                                                          const n: PByte;
                                                          const pk: PByte;
                                                          const sk: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_box_curve25519xchacha20poly1305_detached(c: PByte;
                                                         mac: PByte;
                                                         const m: PByte;
                                                         mlen: UInt64;
                                                         const n: PByte;
                                                         const pk: PByte;
                                                         const sk: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_box_curve25519xchacha20poly1305_open_detached(m: PByte;
                                                              const c: PByte;
                                                              const mac: PByte;
                                                              clen: UInt64;
                                                              const n: PByte;
                                                              const pk: PByte;
                                                              const sk: PByte): Integer; cdecl; external SODIUM_LIB;

(* -- Precomputation interface -- *)

function crypto_box_curve25519xchacha20poly1305_beforenm(k: PByte;
                                                         const pk: PByte;
                                                         const sk: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_box_curve25519xchacha20poly1305_easy_afternm(c: PByte;
                                                             const m: PByte;
                                                             mlen: UInt64;
                                                             const n: PByte;
                                                             const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_box_curve25519xchacha20poly1305_open_easy_afternm(m: PByte;
                                                                  const c: PByte;
                                                                  clen: UInt64;
                                                                  const n: PByte;
                                                                  const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_box_curve25519xchacha20poly1305_detached_afternm(c: PByte;
                                                                 mac: PByte;
                                                                 const m: PByte;
                                                                 mlen: UInt64;
                                                                 const n: PByte;
                                                                 const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_box_curve25519xchacha20poly1305_open_detached_afternm(m: PByte;
                                                                      const c: PByte;
                                                                      const mac: PByte;
                                                                      clen: UInt64;
                                                                      const n: PByte;
                                                                      const k: PByte): Integer; cdecl; external SODIUM_LIB;

(* -- Ephemeral SK interface -- *)

const
  _CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_SEALBYTES =
    _CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_PUBLICKEYBYTES +
    _CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_MACBYTES;
function crypto_box_curve25519xchacha20poly1305_sealbytes: NativeUInt; cdecl; external SODIUM_LIB;

function crypto_box_curve25519xchacha20poly1305_seal(c: PByte;
                                                     const m: PByte;
                                                     mlen: UInt64;
                                                     const pk: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_box_curve25519xchacha20poly1305_seal_open(m: PByte;
                                                          const c: PByte;
                                                          clen: UInt64;
                                                          const pk: PByte;
                                                          const sk: PByte): Integer; cdecl; external SODIUM_LIB;

(* sodium/crypto_box_curve25519xsalsa20poly1305.h *)

const
  _CRYPTO_BOX_CURVE25519XSALSA20POLY1305_SEEDBYTES = 32;
function crypto_box_curve25519xsalsa20poly1305_seedbytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_BOX_CURVE25519XSALSA20POLY1305_PUBLICKEYBYTES = 32;
function crypto_box_curve25519xsalsa20poly1305_publickeybytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_BOX_CURVE25519XSALSA20POLY1305_SECRETKEYBYTES = 32;
function crypto_box_curve25519xsalsa20poly1305_secretkeybytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_BOX_CURVE25519XSALSA20POLY1305_BEFORENMBYTES = 32;
function crypto_box_curve25519xsalsa20poly1305_beforenmbytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_BOX_CURVE25519XSALSA20POLY1305_NONCEBYTES = 24;
function crypto_box_curve25519xsalsa20poly1305_noncebytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_BOX_CURVE25519XSALSA20POLY1305_MACBYTES = 16;
function crypto_box_curve25519xsalsa20poly1305_macbytes: NativeUInt; cdecl; external SODIUM_LIB;

(* Only for the libsodium API - The NaCl compatibility API would require BOXZEROBYTES extra bytes *)
const
  _CRYPTO_BOX_CURVE25519XSALSA20POLY1305_MESSAGEBYTES_MAX =
    _CRYPTO_STREAM_XSALSA20_MESSAGEBYTES_MAX - _CRYPTO_BOX_CURVE25519XSALSA20POLY1305_MACBYTES;
function crypto_box_curve25519xsalsa20poly1305_messagebytes_max: NativeUInt; cdecl; external SODIUM_LIB;

function crypto_box_curve25519xsalsa20poly1305_seed_keypair(pk: PByte;
                                                            sk: PByte;
                                                            const seed: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_box_curve25519xsalsa20poly1305_keypair(pk: PByte;
                                                       sk: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_box_curve25519xsalsa20poly1305_beforenm(k: PByte;
                                                        const pk: PByte;
                                                        const sk: PByte): Integer; cdecl; external SODIUM_LIB;

(* -- NaCl compatibility interface ; Requires padding -- *)

const
  _CRYPTO_BOX_CURVE25519XSALSA20POLY1305_BOXZEROBYTES = 16;
function crypto_box_curve25519xsalsa20poly1305_boxzerobytes: NativeUInt; cdecl; external SODIUM_LIB;


const
  _CRYPTO_BOX_CURVE25519XSALSA20POLY1305_ZEROBYTES =
    _CRYPTO_BOX_CURVE25519XSALSA20POLY1305_BOXZEROBYTES +
    _CRYPTO_BOX_CURVE25519XSALSA20POLY1305_MACBYTES;
function crypto_box_curve25519xsalsa20poly1305_zerobytes: NativeUInt; cdecl; external SODIUM_LIB; deprecated;

function crypto_box_curve25519xsalsa20poly1305(c: PByte;
                                               const m: PByte;
                                               mlen: UInt64;
                                               constn: PByte;
                                               const pk: PByte;
                                               const sk: PByte): Integer; cdecl; external SODIUM_LIB; deprecated;

function crypto_box_curve25519xsalsa20poly1305_open(m: PByte;
                                                    const c: PByte;
                                                    clen: UInt64;
                                                    const n: PByte;
                                                    const pk: PByte;
                                                    const sk: PByte): Integer; cdecl; external SODIUM_LIB; deprecated;

function crypto_box_curve25519xsalsa20poly1305_afternm(c: PByte;
                                                       const m: PByte;
                                                       mlen: UInt64;
                                                       const n: PByte;
                                                       const k: PByte): Integer; cdecl; external SODIUM_LIB; deprecated;

function crypto_box_curve25519xsalsa20poly1305_open_afternm(m: PByte;
                                                            const c: PByte;
                                                            clen: UInt64;
                                                            const n: PByte;
                                                            const k: PByte): Integer; cdecl; external SODIUM_LIB; deprecated;

(* sodium/crypto_box.h *)

(*
 * THREAD SAFETY: crypto_box_keypair() is thread-safe,
 * provided that sodium_init() was called before.
 *
 * Other functions are always thread-safe.
 *)

const
  _CRYPTO_BOX_SEEDBYTES = _CRYPTO_BOX_CURVE25519XSALSA20POLY1305_SEEDBYTES;
function  crypto_box_seedbytes: NativeUInt; cdecl; external SODIUM_LIB;

type
  TCryptoBoxSeed = array[0.._CRYPTO_BOX_SEEDBYTES -1] of Byte;

const
  _CRYPTO_BOX_PUBLICKEYBYTES = _CRYPTO_BOX_CURVE25519XSALSA20POLY1305_PUBLICKEYBYTES;
function  crypto_box_publickeybytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_BOX_SECRETKEYBYTES = _CRYPTO_BOX_CURVE25519XSALSA20POLY1305_SECRETKEYBYTES;
function  crypto_box_secretkeybytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_BOX_NONCEBYTES = _CRYPTO_BOX_CURVE25519XSALSA20POLY1305_NONCEBYTES;
function  crypto_box_noncebytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_BOX_MACBYTES = _CRYPTO_BOX_CURVE25519XSALSA20POLY1305_MACBYTES;
function  crypto_box_macbytes: NativeUInt; cdecl; external SODIUM_LIB;

type
  TCryptoBoxMac = array[0.._CRYPTO_BOX_MACBYTES -1] of Byte;

const
  _CRYPTO_BOX_MESSAGEBYTES_MAX = _CRYPTO_BOX_CURVE25519XSALSA20POLY1305_MESSAGEBYTES_MAX;
function  crypto_box_messagebytes_max: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_BOX_PRIMITIVE = 'curve25519xsalsa20poly1305';
function crypto_box_primitive: PAnsiChar; cdecl; external SODIUM_LIB;

type
  TCryptoBoxPublicKey = array[0.._CRYPTO_BOX_PUBLICKEYBYTES -1] of Byte;
  TCryptoBoxSecretKey = array[0.._CRYPTO_BOX_SECRETKEYBYTES -1] of Byte;

function crypto_box_seed_keypair(pk: PByte; sk: PByte;
                                 const seed: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_box_keypair(pk: PByte; sk: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_box_easy(c: PByte; const m: PByte;
                         mlen: UInt64; const n: PByte;
                         const pk: PByte; const sk: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_box_open_easy(m: PByte; const c: PByte;
                              clen: UInt64; const n: PByte;
                              const pk: PByte; const sk: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_box_detached(c: PByte; mac: PByte;
                             const m: PByte; mlen: UInt64;
                             const n: PByte; const pk: PByte;
                             const sk: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_box_open_detached(m: PByte; const c: PByte;
                                  const mac: PByte;
                                  clen: UInt64;
                                  const n: PByte;
                                  const pk: PByte;
                                  const sk: PByte): Integer; cdecl; external SODIUM_LIB;

type
  TCryptoBoxNonce = array[0.._CRYPTO_BOX_NONCEBYTES -1] of Byte;

(* -- Precomputation interface -- *)

const
  _CRYPTO_BOX_BEFORENMBYTES = _CRYPTO_BOX_CURVE25519XSALSA20POLY1305_BEFORENMBYTES;
function  crypto_box_beforenmbytes: NativeUInt; cdecl; external SODIUM_LIB;

function crypto_box_beforenm(k: PByte; const pk: PByte;
                             const sk: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_box_easy_afternm(c: PByte; const m: PByte;
                                 mlen: UInt64; const n: PByte;
                                 const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_box_open_easy_afternm(m: PByte; const c: PByte;
                                      clen: UInt64; const n: PByte;
                                      const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_box_detached_afternm(c: PByte; mac: PByte;
                                     const m: PByte; mlen: UInt64;
                                     const n: PByte; const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_box_open_detached_afternm(m: PByte; const c: PByte;
                                          const mac: PByte;
                                          clen: UInt64; const n: PByte;
                                          const k: PByte): Integer; cdecl; external SODIUM_LIB;

(* -- Ephemeral SK interface -- *)

const
  _CRYPTO_BOX_SEALBYTES = _CRYPTO_BOX_PUBLICKEYBYTES + _CRYPTO_BOX_MACBYTES;
function crypto_box_sealbytes: NativeUInt; cdecl; external SODIUM_LIB;

function crypto_box_seal(c: PByte; const m: PByte;
                         mlen: UInt64; const pk: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_box_seal_open(m: PByte; const c: PByte;
                              clen: UInt64;
                              const pk: PByte; const sk: PByte): Integer; cdecl; external SODIUM_LIB;

(* -- NaCl compatibility interface ; Requires padding -- *)

const
  _CRYPTO_BOX_ZEROBYTES = _CRYPTO_BOX_CURVE25519XSALSA20POLY1305_ZEROBYTES;
function crypto_box_zerobytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_BOX_BOXZEROBYTES = _CRYPTO_BOX_CURVE25519XSALSA20POLY1305_BOXZEROBYTES;
function crypto_box_boxzerobytes: NativeUInt; cdecl; external SODIUM_LIB;

function crypto_box(c: PByte; const m: PByte;
                    mlen: UInt64; const n: PByte;
                    const pk: PByte; const sk: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_box_open(m: PByte; const c: PByte;
                         clen: UInt64; const n: PByte;
                         const pk: PByte; const sk: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_box_afternm(c: PByte; const m: PByte;
                            mlen: UInt64; const n: PByte;
                            const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_box_open_afternm(m: PByte; const c: PByte;
                                 clen: UInt64; const n: PByte;
                                 const k: PByte): Integer; cdecl; external SODIUM_LIB;

(* sodium/crypto_kdf_blake2b.h *)

const
  _CRYPTO_KDF_BLAKE2B_BYTES_MIN = 16;
function crypto_kdf_blake2b_bytes_min: NativeUint; cdecl; external SODIUM_LIB;

const
  _CRYPTO_KDF_BLAKE2B_BYTES_MAX = 64;
function crypto_kdf_blake2b_bytes_max: NativeUint; cdecl; external SODIUM_LIB;

const
  _CRYPTO_KDF_BLAKE2B_CONTEXTBYTES = 8;
function crypto_kdf_blake2b_contextbytes: NativeUint; cdecl; external SODIUM_LIB;

type
  TCryptoKdfBlake2bContext = array[0.._CRYPTO_KDF_BLAKE2B_CONTEXTBYTES -1] of Byte;

const
  _CRYPTO_KDF_BLAKE2B_KEYBYTES = 32;
function crypto_kdf_blake2b_keybytes: NativeUint; cdecl; external SODIUM_LIB;

type
  TCryptoKdfBlake2bKey = array[0.._CRYPTO_KDF_BLAKE2B_KEYBYTES -1] of Byte;

function crypto_kdf_blake2b_derive_from_key(subkey: PByte; subkey_len: NativeUInt;
                                            subkey_id: UInt64;
                                            const ctx: TCryptoKdfBlake2bContext;
                                            const key: TCryptoKdfBlake2bKey): Integer; cdecl; external SODIUM_LIB;

(* sodium/crypto_kdf_hkdf_sha256.h *)

const
  _CRYPTO_KDF_HKDF_SHA256_KEYBYTES = _CRYPTO_AUTH_HMACSHA256_BYTES;
function crypto_kdf_hkdf_sha256_keybytes: NativeUInt; cdecl; external SODIUM_LIB;

type
  TCryptoKdfHkdfSha256Key = array[0.._CRYPTO_KDF_HKDF_SHA256_KEYBYTES -1] of Byte;

const
  _CRYPTO_KDF_HKDF_SHA256_BYTES_MIN = 0;
function crypto_kdf_hkdf_sha256_bytes_min: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_KDF_HKDF_SHA256_BYTES_MAX = $ff * _CRYPTO_AUTH_HMACSHA256_BYTES;
function crypto_kdf_hkdf_sha256_bytes_max: NativeUInt; cdecl; external SODIUM_LIB;

function crypto_kdf_hkdf_sha256_extract(var prk: TCryptoKdfHkdfSha256Key;
                                        const salt: PByte; salt_len: NativeUInt;
                                        const ikm: PByte; ikm_len: NativeUInt): Integer; cdecl; external SODIUM_LIB;

procedure crypto_kdf_hkdf_sha256_keygen(var prk: TCryptoKdfHkdfSha256Key); cdecl; external SODIUM_LIB;

function crypto_kdf_hkdf_sha256_expand(&out: PByte; out_len: NativeUInt;
                                       const ctx: PAnsiChar; ctx_len: NativeUInt;
                                       const prk: TCryptoKdfHkdfSha256Key): Integer; cdecl; external SODIUM_LIB;

(* ------------------------------------------------------------------------- *)

type
  TCryptoKdfHkdfSha256State = record
    st: TCryptoAuthHmacsha256State;
  end;

function crypto_kdf_hkdf_sha256_statebytes: NativeUInt; cdecl; external SODIUM_LIB;

function crypto_kdf_hkdf_sha256_extract_init(var state: TCryptoKdfHkdfSha256State;
                                             const salt: PByte; salt_len: NativeUInt): Integer; cdecl; external SODIUM_LIB;

function crypto_kdf_hkdf_sha256_extract_update(var state: TCryptoKdfHkdfSha256State;
                                               const ikm: PByte; ikm_len: NativeUInt): Integer; cdecl; external SODIUM_LIB;

function crypto_kdf_hkdf_sha256_extract_final(var state: TCryptoKdfHkdfSha256State;
                                              var prk: TCryptoKdfHkdfSha256Key): Integer; cdecl; external SODIUM_LIB;

(* sodium/crypto_kdf_hkdf_sha512.h *)

const
  _CRYPTO_KDF_HKDF_SHA512_KEYBYTES = _CRYPTO_AUTH_HMACSHA512_BYTES;
function crypto_kdf_hkdf_sha512_keybytes: NativeUInt; cdecl; external SODIUM_LIB;

type
  TCryptoKdfHkdfSha512Key = array[0.._CRYPTO_KDF_HKDF_SHA512_KEYBYTES -1] of Byte;

const
  _CRYPTO_KDF_HKDF_SHA512_BYTES_MIN = 0;
function crypto_kdf_hkdf_sha512_bytes_min: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_KDF_HKDF_SHA512_BYTES_MAX = $ff * _CRYPTO_AUTH_HMACSHA512_BYTES;
function crypto_kdf_hkdf_sha512_bytes_max: NativeUInt; cdecl; external SODIUM_LIB;

function crypto_kdf_hkdf_sha512_extract(var prk: TCryptoKdfHkdfSha512Key;
                                        const salt: PByte; salt_len: NativeUInt;
                                        const ikm: PByte; ikm_len: NativeUInt): Integer; cdecl; external SODIUM_LIB;

procedure crypto_kdf_hkdf_sha512_keygen(var prk: TCryptoKdfHkdfSha512Key); cdecl; external SODIUM_LIB;

function crypto_kdf_hkdf_sha512_expand(&out: PByte; out_len: NativeUInt;
                                       const ctx: PAnsiChar; ctx_len: NativeUInt;
                                       const prk: TCryptoKdfHkdfSha512Key): Integer; cdecl; external SODIUM_LIB;

(* ------------------------------------------------------------------------- *)

type
  TCryptoKdfHkdfSha512State = record
    st: TCryptoAuthHmacsha512State;
  end;

function crypto_kdf_hkdf_sha512_statebytes: NativeUInt; cdecl; external SODIUM_LIB;

function crypto_kdf_hkdf_sha512_extract_init(var state: TCryptoKdfHkdfSha512State;
                                             const salt: PByte; salt_len: NativeUInt): Integer; cdecl; external SODIUM_LIB;

function crypto_kdf_hkdf_sha512_extract_update(var state: TCryptoKdfHkdfSha512State;
                                               const ikm: PByte; ikm_len: NativeUint): Integer; cdecl; external SODIUM_LIB;

function crypto_kdf_hkdf_sha512_extract_final(var state: TCryptoKdfHkdfSha512State;
                                              var prk: TCryptoKdfHkdfSha512Key): Integer; cdecl; external SODIUM_LIB;

(* sodium/crypto_kdf.h *)

const
  _CRYPTO_KDF_BYTES_MIN = _CRYPTO_KDF_BLAKE2B_BYTES_MIN;
function crypto_kdf_bytes_min: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_KDF_BYTES_MAX = _CRYPTO_KDF_BLAKE2B_BYTES_MAX;
function crypto_kdf_bytes_max: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_KDF_CONTEXTBYTES = _CRYPTO_KDF_BLAKE2B_CONTEXTBYTES;
function crypto_kdf_contextbytes: NativeUInt; cdecl; external SODIUM_LIB;

type
  TCryptoKdfContext = array[0.._CRYPTO_KDF_CONTEXTBYTES-1] of AnsiChar;

const
  _CRYPTO_KDF_KEYBYTES = _CRYPTO_KDF_BLAKE2B_KEYBYTES;
function crypto_kdf_keybytes: NativeUInt; cdecl; external SODIUM_LIB;

type
  TCryptoKdfKey = array[0.._CRYPTO_KDF_KEYBYTES-1] of Byte;

const
  _CRYPTO_KDF_PRIMITIVE = 'blake2b';
function crypto_kdf_primitive: PAnsiChar; cdecl; external SODIUM_LIB;

function crypto_kdf_derive_from_key(subkey: PByte; subkey_len: NativeUInt;
                                    subkey_id: UInt64;
                                    const ctx: TCryptoKdfContext;
                                    const key: TCryptoKdfKey): Integer; cdecl; external SODIUM_LIB;

procedure crypto_kdf_keygen(var k: TCryptoKdfKey); cdecl; external SODIUM_LIB;

(* sodium/crypto_kx.h *)

const
  _CRYPTO_KX_PUBLICKEYBYTES = 32;
function crypto_kx_publickeybytes: NativeUInt; cdecl; external SODIUM_LIB;

type
  TCryptoKxPublicKey = array[0.._CRYPTO_KX_PUBLICKEYBYTES -1] of Byte;

const
  _CRYPTO_KX_SECRETKEYBYTES = 32;
function crypto_kx_secretkeybytes: NativeUInt; cdecl; external SODIUM_LIB;

type
  TCryptoKxSecretKey = array[0.._CRYPTO_KX_SECRETKEYBYTES -1] of Byte;

const
  _CRYPTO_KX_SEEDBYTES = 32;
function crypto_kx_seedbytes: NativeUInt; cdecl; external SODIUM_LIB;

type
  TCryptoKxSeed = array[0.._CRYPTO_KX_SEEDBYTES -1] of Byte;

const
  _CRYPTO_KX_SESSIONKEYBYTES = 32;
function crypto_kx_sessionkeybytes: NativeUInt; cdecl; external SODIUM_LIB;

type
  TCryptoKxSessionKey = array[0.._CRYPTO_KX_SESSIONKEYBYTES -1] of Byte;

const
  _CRYPTO_KX_PRIMITIVE = 'x25519blake2b';
function crypto_kx_primitive: PAnsiChar; cdecl; external SODIUM_LIB;

function crypto_kx_seed_keypair(var pk: TCryptoKxPublicKey;
                                var sk: TCryptoKxSecretKey;
                                const seed: TCryptoKxSeed): Integer; cdecl; external SODIUM_LIB;

function crypto_kx_keypair(var pk: TCryptoKxPublicKey;
                           var sk: TCryptoKxSecretKey): Integer; cdecl; external SODIUM_LIB;

function crypto_kx_client_session_keys(var rx: TCryptoKxSessionKey;
                                       var tx: TCryptoKxSessionKey;
                                       const client_pk: TCryptoKxPublicKey;
                                       const client_sk: TCryptoKxSecretKey;
                                       const server_pk: TCryptoKxPublicKey): Integer; cdecl; external SODIUM_LIB;

function crypto_kx_server_session_keys(var rx: TCryptoKxSessionKey;
                                       var tx: TCryptoKxSessionKey;
                                       const server_pk: TCryptoKxPublicKey;
                                       const server_sk: TCryptoKxSecretKey;
                                       const client_pk: TCryptoKxPublicKey): Integer; cdecl; external SODIUM_LIB;

(* sodium/crypto_onetimeauth_poly1305.h *)

type
  {$ALIGN 16}
  TCyptoOnetimeAuthPoly1305State = record
    opaque: array[0..256 -1] of Byte;
  end;
  {$ALIGN 1}

function crypto_onetimeauth_poly1305_statebytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _crypto_onetimeauth_poly1305_BYTES = 16;
function crypto_onetimeauth_poly1305_bytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _crypto_onetimeauth_poly1305_KEYBYTES = 32;
function crypto_onetimeauth_poly1305_keybytes: NativeUInt; cdecl; external SODIUM_LIB;

function crypto_onetimeauth_poly1305(&out: PByte;
                                     const &in: PByte;
                                     inlen: UInt64;
                                     const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_onetimeauth_poly1305_verify(const h: PByte;
                                            const &in: PByte;
                                            inlen: UInt64;
                                            const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_onetimeauth_poly1305_init(var state: TCyptoOnetimeAuthPoly1305State;
                                          const key: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_onetimeauth_poly1305_update(var state: TCyptoOnetimeAuthPoly1305State;
                                            const &in: PByte;
                                            inlen: UInt64): Integer; cdecl; external SODIUM_LIB;

function crypto_onetimeauth_poly1305_final(var state: TCyptoOnetimeAuthPoly1305State;
                                           &out: PByte): Integer; cdecl; external SODIUM_LIB;

type
  TCryptoOnetimeAuthPoly1305Key = array[0.._CRYPTO_ONETIMEAUTH_POLY1305_KEYBYTES -1] of Byte;

procedure crypto_onetimeauth_poly1305_keygen(var k: TCryptoOnetimeAuthPoly1305Key); cdecl; external SODIUM_LIB;

(* sodium/crypto_onetimeauth.h *)

type
  TCryptoOnetimeAuthState = TCyptoOnetimeAuthPoly1305State;

function crypto_onetimeauth_statebytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _crypto_onetimeauth_BYTES = _crypto_onetimeauth_poly1305_BYTES;
function crypto_onetimeauth_bytes: NativeUInt; cdecl; external SODIUM_LIB;

type
  TCryptoOnetimeAuthTag = array[0.._crypto_onetimeauth_BYTES -1] of Byte;

const
  _crypto_onetimeauth_KEYBYTES = _crypto_onetimeauth_poly1305_KEYBYTES;
function crypto_onetimeauth_keybytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _crypto_onetimeauth_PRIMITIVE = 'poly1305';
function crypto_onetimeauth_primitive: PAnsiChar; cdecl; external SODIUM_LIB;

function crypto_onetimeauth(&out: PByte; const &in: PByte;
                            inlen: UInt64; const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_onetimeauth_verify(const h: PByte; const &in: PByte;
                                   inlen: UInt64; const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_onetimeauth_init(var state: TCryptoOnetimeAuthState;
                                 const key: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_onetimeauth_update(var state: TCryptoOnetimeAuthState;
                                   const &in: PByte;
                                   inlen: UInt64): Integer; cdecl; external SODIUM_LIB;

function crypto_onetimeauth_final(var state: TCryptoOnetimeAuthState;
                                  &out: PByte): Integer; cdecl; external SODIUM_LIB;

type
  TCryptoOnetimeAuthKey = array[0.._CRYPTO_ONETIMEAUTH_KEYBYTES -1] of Byte;

procedure crypto_onetimeauth_keygen(var k: TCryptoOnetimeAuthKey); cdecl; external SODIUM_LIB;

(* sodium/crypto_pwhash_scryptsalsa208sha256.h *)

const
  _crypto_pwhash_scryptsalsa208sha256_BYTES_MIN = 16;
function crypto_pwhash_scryptsalsa208sha256_bytes_min: NativeUInt; cdecl; external SODIUM_LIB;

function _CRYPTO_PWHASH_SCRYPTSALSA208SHA256_BYTES_MAX: UInt64; inline;
function crypto_pwhash_scryptsalsa208sha256_bytes_max: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_SCRYPTSALSA208SHA256_PASSWD_MIN = 0;
function crypto_pwhash_scryptsalsa208sha256_passwd_min: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_SCRYPTSALSA208SHA256_PASSWD_MAX = SODIUM_SIZE_MAX;
function crypto_pwhash_scryptsalsa208sha256_passwd_max: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_SCRYPTSALSA208SHA256_SALTBYTES = 32;
function crypto_pwhash_scryptsalsa208sha256_saltbytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_SCRYPTSALSA208SHA256_STRBYTES = 102;
function crypto_pwhash_scryptsalsa208sha256_strbytes: NativeUInt; cdecl; external SODIUM_LIB;

type
  TCryptoPwHashScryptSalsa208Sha256Str = array[0.._CRYPTO_PWHASH_SCRYPTSALSA208SHA256_STRBYTES -1] of Byte;

const
  _CRYPTO_PWHASH_SCRYPTSALSA208SHA256_STRPREFIX = '$7$';
function crypto_pwhash_scryptsalsa208sha256_strprefix: PAnsiChar; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_MIN = 32768;
function crypto_pwhash_scryptsalsa208sha256_opslimit_min: UInt64; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_MAX = 4294967295;
function crypto_pwhash_scryptsalsa208sha256_opslimit_max: UInt64; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_MIN = 16777216;
function crypto_pwhash_scryptsalsa208sha256_memlimit_min: NativeUInt; cdecl; external SODIUM_LIB;

function _CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_MAX: UInt64; inline;
function crypto_pwhash_scryptsalsa208sha256_memlimit_max: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE = 524288;
function crypto_pwhash_scryptsalsa208sha256_opslimit_interactive: UInt64; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE = 16777216;
function crypto_pwhash_scryptsalsa208sha256_memlimit_interactive: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_SENSITIVE = 33554432;
function crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive: UInt64; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_SENSITIVE = 1073741824;
function crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive: NativeUInt; cdecl; external SODIUM_LIB;

function crypto_pwhash_scryptsalsa208sha256(&out: PByte;
                                            outlen: UInt64;
                                            const passwd: PAnsiChar;
                                            passwdlen: UInt64;
                                            const salt: PByte;
                                            opslimit: Uint64;
                                            memlimit: NativeUInt): Integer; cdecl; external SODIUM_LIB;

function crypto_pwhash_scryptsalsa208sha256_str(var &out: TCryptoPwHashScryptSalsa208Sha256Str;
                                                const passwd: PAnsiChar;
                                                passwdlen: UInt64;
                                                opslimit: UInt64;
                                                memlimit: NativeUInt): Integer; cdecl; external SODIUM_LIB;

function crypto_pwhash_scryptsalsa208sha256_str_verify(const str: PAnsiChar;
                                                       const passwd: PAnsiChar;
                                                       passwdlen: UInt64): Integer; cdecl; external SODIUM_LIB;

function crypto_pwhash_scryptsalsa208sha256_ll(const passwd: PByte; passwdlen: NativeUInt;
                                               const salt: PByte; saltlen: NativeUInt;
                                               N: UInt64; r: Cardinal; p: Cardinal;
                                               buf: PByte; buflen: NativeUint): Integer; cdecl; external SODIUM_LIB;

function crypto_pwhash_scryptsalsa208sha256_str_needs_rehash(const str: PAnsiChar;
                                                             opslimit: UInt64;
                                                             memlimit: NativeUInt): Integer; cdecl; external SODIUM_LIB;

(* sodium/crypto_pwhash_argon2i.h *)

const
  _CRYPTO_PWHASH_ARGON2I_ALG_ARGON2I13 = 1;
function crypto_pwhash_argon2i_alg_argon2i13: Integer; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_ARGON2I_BYTES_MIN = 16;
function crypto_pwhash_argon2i_bytes_min: NativeUInt; cdecl; external SODIUM_LIB;

function _CRYPTO_PWHASH_ARGON2I_BYTES_MAX: UInt64; inline;
function crypto_pwhash_argon2i_bytes_max: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_ARGON2I_PASSWD_MIN = 0;
function crypto_pwhash_argon2i_passwd_min: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_ARGON2I_PASSWD_MAX = 4294967295;
function crypto_pwhash_argon2i_passwd_max: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_ARGON2I_SALTBYTES = 16;
function crypto_pwhash_argon2i_saltbytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_ARGON2I_STRBYTES = 128;
function crypto_pwhash_argon2i_strbytes: NativeUInt; cdecl; external SODIUM_LIB;

type
  TCryptoPwHashArgon2iStr = array[0.._CRYPTO_PWHASH_ARGON2I_STRBYTES -1] of AnsiChar;

const
  _CRYPTO_PWHASH_ARGON2I_STRPREFIX = '$argon2i$';
function crypto_pwhash_argon2i_strprefix: PAnsiChar; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_ARGON2I_OPSLIMIT_MIN = 3;
function crypto_pwhash_argon2i_opslimit_min: UInt64; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_ARGON2I_OPSLIMIT_MAX = 4294967295;
function crypto_pwhash_argon2i_opslimit_max: UInt64; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_ARGON2I_MEMLIMIT_MIN = 8192;
function crypto_pwhash_argon2i_memlimit_min: NativeUInt; cdecl; external SODIUM_LIB;

function _CRYPTO_PWHASH_ARGON2I_MEMLIMIT_MAX: UInt64; inline;
function crypto_pwhash_argon2i_memlimit_max: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_ARGON2I_OPSLIMIT_INTERACTIVE = 4;
function crypto_pwhash_argon2i_opslimit_interactive: UInt64; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_ARGON2I_MEMLIMIT_INTERACTIVE = 33554432;
function crypto_pwhash_argon2i_memlimit_interactive: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_ARGON2I_OPSLIMIT_MODERATE = 6;
function crypto_pwhash_argon2i_opslimit_moderate: UInt64; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_ARGON2I_MEMLIMIT_MODERATE = 134217728;
function crypto_pwhash_argon2i_memlimit_moderate: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_ARGON2I_OPSLIMIT_SENSITIVE = 8;
function crypto_pwhash_argon2i_opslimit_sensitive: UInt64; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_ARGON2I_MEMLIMIT_SENSITIVE = 536870912;
function crypto_pwhash_argon2i_memlimit_sensitive: NativeUInt; cdecl; external SODIUM_LIB;

function crypto_pwhash_argon2i(&out: PByte;
                               outlen: UInt64;
                               const passwd: PAnsiChar;
                               passwdlen: UInt64;
                               const salt: PByte;
                               opslimit: UInt64; memlimit: NativeUInt;
                               alg: Integer): Integer; cdecl; external SODIUM_LIB;

function crypto_pwhash_argon2i_str(var &out: TCryptoPwHashArgon2iStr;
                                   const passwd: PAnsiChar;
                                   passwdlen: UInt64;
                                   opslimit: UInt64; memlimit: NativeUInt): Integer; cdecl; external SODIUM_LIB;

function crypto_pwhash_argon2i_str_verify(const str: PAnsiChar;
                                          const passwd: PAnsiChar;
                                          passwdlen: UInt64): Integer; cdecl; external SODIUM_LIB;

function crypto_pwhash_argon2i_str_needs_rehash(const str: PAnsiChar;
                                                opslimit: UInt64; memlimit: NativeUInt): Integer; cdecl; external SODIUM_LIB;

(* sodium/crypto_pwhash_argon2id.h *)

const
  _CRYPTO_PWHASH_ARGON2ID_ALG_ARGON2ID13 = 2;
function crypto_pwhash_argon2id_alg_argon2id13: Integer; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_ARGON2ID_BYTES_MIN = 16;
function crypto_pwhash_argon2id_bytes_min: NativeUInt; cdecl; external SODIUM_LIB;

function _CRYPTO_PWHASH_ARGON2ID_BYTES_MAX: UInt64; inline;
function crypto_pwhash_argon2id_bytes_max: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_ARGON2ID_PASSWD_MIN = 0;
function crypto_pwhash_argon2id_passwd_min: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_ARGON2ID_PASSWD_MAX = 4294967295;
function crypto_pwhash_argon2id_passwd_max: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_ARGON2ID_SALTBYTES = 16;
function crypto_pwhash_argon2id_saltbytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_ARGON2ID_STRBYTES = 128;
function crypto_pwhash_argon2id_strbytes: NativeUInt; cdecl; external SODIUM_LIB;

type
  TCryptoPwHashArgon2idStr = array[0.._CRYPTO_PWHASH_ARGON2ID_STRBYTES -1] of AnsiChar;

const
  _CRYPTO_PWHASH_ARGON2ID_STRPREFIX = '$argon2id$';
function crypto_pwhash_argon2id_strprefix: PAnsiChar; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_ARGON2ID_OPSLIMIT_MIN = 1;
function crypto_pwhash_argon2id_opslimit_min: UInt64; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_ARGON2ID_OPSLIMIT_MAX = 4294967295;
function crypto_pwhash_argon2id_opslimit_max: UInt64; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_ARGON2ID_MEMLIMIT_MIN = 8192;
function crypto_pwhash_argon2id_memlimit_min: NativeUInt; cdecl; external SODIUM_LIB;

function _CRYPTO_PWHASH_ARGON2ID_MEMLIMIT_MAX: UInt64; inline;
function crypto_pwhash_argon2id_memlimit_max: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_ARGON2ID_OPSLIMIT_INTERACTIVE = 2;
function crypto_pwhash_argon2id_opslimit_interactive: UInt64; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_ARGON2ID_MEMLIMIT_INTERACTIVE = 67108864;
function crypto_pwhash_argon2id_memlimit_interactive: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_ARGON2ID_OPSLIMIT_MODERATE = 3;
function crypto_pwhash_argon2id_opslimit_moderate: UInt64; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_ARGON2ID_MEMLIMIT_MODERATE = 268435456;
function crypto_pwhash_argon2id_memlimit_moderate: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_ARGON2ID_OPSLIMIT_SENSITIVE = 4;
function crypto_pwhash_argon2id_opslimit_sensitive: UInt64; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_ARGON2ID_MEMLIMIT_SENSITIVE = 1073741824;
function crypto_pwhash_argon2id_memlimit_sensitive: NativeUInt; cdecl; external SODIUM_LIB;

function crypto_pwhash_argon2id(const &out: PByte;
                                outlen: UInt64;
                                const passwd: PAnsiChar;
                                passwdlen: UInt64;
                                const salt: PByte;
                                opslimit: UInt64; memlimit: NativeUInt;
                                alg: Integer): Integer; cdecl; external SODIUM_LIB;

function crypto_pwhash_argon2id_str(var &out: TCryptoPwHashArgon2idStr;
                                    const passwd: PAnsiChar;
                                    passwdlen: UInt64;
                                    opslimit: UInt64; memlimit: NativeUInt): Integer; cdecl; external SODIUM_LIB;

function crypto_pwhash_argon2id_str_verify(const str: PAnsiChar;
                                           const passwd: PAnsiChar;
                                           passwdlen: UInt64): Integer; cdecl; external SODIUM_LIB;

function crypto_pwhash_argon2id_str_needs_rehash(const str: PAnsiChar;
                                                 opslimit: UInt64; memlimit: NativeUInt): Integer; cdecl; external SODIUM_LIB;

(* sodium/crypto_pwhash.h *)

const
  _CRYPTO_PWHASH_ALG_ARGON2I13 = _CRYPTO_PWHASH_ARGON2I_ALG_ARGON2I13;
function crypto_pwhash_alg_argon2i13: Integer; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_ALG_ARGON2ID13 = _CRYPTO_PWHASH_ARGON2ID_ALG_ARGON2ID13;
function crypto_pwhash_alg_argon2id13: Integer; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_ALG_DEFAULT = _CRYPTO_PWHASH_ALG_ARGON2ID13;
function crypto_pwhash_alg_default: Integer; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_BYTES_MIN = _CRYPTO_PWHASH_ARGON2ID_BYTES_MIN;
function crypto_pwhash_bytes_min: NativeUInt; cdecl; external SODIUM_LIB;

function _CRYPTO_PWHASH_BYTES_MAX: UInt64; inline;
function crypto_pwhash_bytes_max: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_PASSWD_MIN = _CRYPTO_PWHASH_ARGON2ID_PASSWD_MIN;
function crypto_pwhash_passwd_min: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_PASSWD_MAX = _CRYPTO_PWHASH_ARGON2ID_PASSWD_MAX;
function crypto_pwhash_passwd_max: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_SALTBYTES = _CRYPTO_PWHASH_ARGON2ID_SALTBYTES;
function crypto_pwhash_saltbytes: NativeUInt; cdecl; external SODIUM_LIB;

type
  TCryptoPwHashSalt = array[0.._CRYPTO_PWHASH_SALTBYTES -1] of Byte;

const
  _CRYPTO_PWHASH_STRBYTES = _CRYPTO_PWHASH_ARGON2ID_STRBYTES;
function crypto_pwhash_strbytes: NativeUInt; cdecl; external SODIUM_LIB;

type
  TCryptoPwHashStr = array[0.._CRYPTO_PWHASH_STRBYTES -1] of AnsiChar;

const
  _CRYPTO_PWHASH_STRPREFIX = _CRYPTO_PWHASH_ARGON2ID_STRPREFIX;
function crypto_pwhash_strprefix: PAnsiChar; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_OPSLIMIT_MIN = _CRYPTO_PWHASH_ARGON2ID_OPSLIMIT_MIN;
function crypto_pwhash_opslimit_min: UInt64; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_OPSLIMIT_MAX = _CRYPTO_PWHASH_ARGON2ID_OPSLIMIT_MAX;
function crypto_pwhash_opslimit_max: UInt64; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_MEMLIMIT_MIN = _CRYPTO_PWHASH_ARGON2ID_MEMLIMIT_MIN;
function crypto_pwhash_memlimit_min: NativeUInt; cdecl; external SODIUM_LIB;

function _CRYPTO_PWHASH_MEMLIMIT_MAX: UInt64; inline;
function crypto_pwhash_memlimit_max: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE = _CRYPTO_PWHASH_ARGON2ID_OPSLIMIT_INTERACTIVE;
function crypto_pwhash_opslimit_interactive: UInt64; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE = _CRYPTO_PWHASH_ARGON2ID_MEMLIMIT_INTERACTIVE;
function crypto_pwhash_memlimit_interactive: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_OPSLIMIT_MODERATE = _CRYPTO_PWHASH_ARGON2ID_OPSLIMIT_MODERATE;
function crypto_pwhash_opslimit_moderate: UInt64; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_MEMLIMIT_MODERATE = _CRYPTO_PWHASH_ARGON2ID_MEMLIMIT_MODERATE;
function crypto_pwhash_memlimit_moderate: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_OPSLIMIT_SENSITIVE = _CRYPTO_PWHASH_ARGON2ID_OPSLIMIT_SENSITIVE;
function crypto_pwhash_opslimit_sensitive: UInt64; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_MEMLIMIT_SENSITIVE = _CRYPTO_PWHASH_ARGON2ID_MEMLIMIT_SENSITIVE;
function crypto_pwhash_memlimit_sensitive: NativeUInt; cdecl; external SODIUM_LIB;

(*
 * With this function, do not forget to store all parameters, including the
 * algorithm identifier in order to produce deterministic output.
 * The crypto_pwhash_* definitions, including crypto_pwhash_ALG_DEFAULT,
 * may change.
 *)
function crypto_pwhash(&out: PByte; outlen: Uint64;
                       const passwd: PAnsiChar; passwdlen: UInt64;
                       const salt: PByte;
                       opslimit: UInt64; memlimit: NativeUInt; alg: Integer): Integer; cdecl; external SODIUM_LIB;

(*
 * The output string already includes all the required parameters, including
 * the algorithm identifier. The string is all that has to be stored in
 * order to verify a password.
 *)
function crypto_pwhash_str(var &out: TCryptoPwHashStr;
                           const passwd: PAnsiChar; passwdlen: UInt64;
                           opslimit: UInt64; memlimit: NativeUInt): Integer; cdecl; external SODIUM_LIB;

function crypto_pwhash_str_alg(var &out: TCryptoPwHashStr;
                               const passwd: PAnsiChar; passwdlen: UInt64;
                               opslimit: UInt64; memlimit: NativeUInt; alg: Integer): Integer; cdecl; external SODIUM_LIB;

function crypto_pwhash_str_verify(const str: PAnsiChar;
                                  const passwd: PAnsiChar;
                                  passwdlen: UInt64): Integer; cdecl; external SODIUM_LIB;

function crypto_pwhash_str_needs_rehash(const str: PAnsiChar;
                                        opslimit: UInt64; memlimit: NativeUInt): Integer; cdecl; external SODIUM_LIB;

const
  _CRYPTO_PWHASH_PRIMITIVE = 'argon2id,argon2i';
function crypto_pwhash_primitive: PAnsiChar; cdecl; external SODIUM_LIB;

(* sodium/crypto_scalarmult_ristretto255.h *)

const
  _CRYPTO_SCALARMULT_RISTRETTO255_BYTES = 32;
function crypto_scalarmult_ristretto255_bytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_SCALARMULT_RISTRETTO255_SCALARBYTES = 32;
function crypto_scalarmult_ristretto255_scalarbytes: NativeUInt; cdecl; external SODIUM_LIB;

(*
 * NOTE: Do not use the result of this function directly for key exchange.
 *
 * Hash the result with the public keys in order to compute a shared
 * secret key: H(q || client_pk || server_pk)
 *
 * Or unless this is not an option, use the crypto_kx() API instead.
 *)
function crypto_scalarmult_ristretto255(q: PByte; const n: PByte;
                                        const p: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_scalarmult_ristretto255_base(q: PByte;
                                             const n: PByte): Integer; cdecl; external SODIUM_LIB;

(* crypto_scalarmult_ed25519.h *)

const
  _CRYPTO_SCALARMULT_ED25519_BYTES = 32;
function crypto_scalarmult_ed25519_bytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_SCALARMULT_ED25519_SCALARBYTES = 32;
function crypto_scalarmult_ed25519_scalarbytes: NativeUInt; cdecl; external SODIUM_LIB;

(*
 * NOTE: Do not use the result of this function directly for key exchange.
 *
 * Hash the result with the public keys in order to compute a shared
 * secret key: H(q || client_pk || server_pk)
 *
 * Or unless this is not an option, use the crypto_kx() API instead.
 *)
function crypto_scalarmult_ed25519(q: PByte; const n: PByte;
                                   const p: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_scalarmult_ed25519_noclamp(q: PByte; const n: PByte;
                                           const p: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_scalarmult_ed25519_base(q: PByte; const n: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_scalarmult_ed25519_base_noclamp(q: PByte; const n: PByte): Integer; cdecl; external SODIUM_LIB;

(* sodium/crypto_scalarmult_curve25519.h *)

const
  _CRYPTO_SCALARMULT_CURVE25519_BYTES = 32;
function crypto_scalarmult_curve25519_bytes: NativeUInt; cdecl; external SODIUM_LIB;

type
  TCryptoScalarMultCurve25519Key = array[0.._CRYPTO_SCALARMULT_CURVE25519_BYTES -1] of Byte;

const
  _CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES = 32;
function crypto_scalarmult_curve25519_scalarbytes: NativeUInt; cdecl; external SODIUM_LIB;

(*
 * NOTE: Do not use the result of this function directly for key exchange.
 *
 * Hash the result with the public keys in order to compute a shared
 * secret key: H(q || client_pk || server_pk)
 *
 * Or unless this is not an option, use the crypto_kx() API instead.
 *)
function crypto_scalarmult_curve25519(q: PByte; const n: PByte;
                                      const p: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_scalarmult_curve25519_base(q: PByte;
                                           const n: PByte): Integer; cdecl; external SODIUM_LIB;

(* sodium/crypto_scalarmult.h *)

const
  _CRYPTO_SCALARMULT_BYTES = _CRYPTO_SCALARMULT_CURVE25519_BYTES;
function crypto_scalarmult_bytes: NativeUInt; cdecl; external SODIUM_LIB;

type
  TCryptoScalarMultQ = array[0.._CRYPTO_SCALARMULT_BYTES -1] of Byte;

const
  _CRYPTO_SCALARMULT_SCALARBYTES = _CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES;
function crypto_scalarmult_scalarbytes: NativeUInt; cdecl; external SODIUM_LIB;

type
  TCryptoScalarMultScalar = array[0.._CRYPTO_SCALARMULT_SCALARBYTES -1] of Byte;

const
  _CRYPTO_SCALARMULT_PRIMITIVE = 'curve25519';
function crypto_scalarmult_primitive: PAnsiChar; cdecl; external SODIUM_LIB;

function crypto_scalarmult_base(q: PByte; const n: PByte): Integer; cdecl; external SODIUM_LIB;

(*
 * NOTE: Do not use the result of this function directly for key exchange.
 *
 * Hash the result with the public keys in order to compute a shared
 * secret key: H(q || client_pk || server_pk)
 *
 * Or unless this is not an option, use the crypto_kx() API instead.
 *)
function crypto_scalarmult(q: PByte; const n: PByte;
                           const p: PByte): Integer; cdecl; external SODIUM_LIB;

(* sodium/crypto_secretbox_xsalsa20poly1305.h *)

const
  _CRYPTO_SECRETBOX_XSALSA20POLY1305_KEYBYTES = 32;
function crypto_secretbox_xsalsa20poly1305_keybytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_SECRETBOX_XSALSA20POLY1305_NONCEBYTES = 24;
function crypto_secretbox_xsalsa20poly1305_noncebytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_SECRETBOX_XSALSA20POLY1305_MACBYTES = 16;
function crypto_secretbox_xsalsa20poly1305_macbytes: NativeUInt; cdecl; external SODIUM_LIB;

(* Only for the libsodium API - The NaCl compatibility API would require BOXZEROBYTES extra bytes *)
const
  _CRYPTO_SECRETBOX_XSALSA20POLY1305_MESSAGEBYTES_MAX =
    _CRYPTO_STREAM_XSALSA20_MESSAGEBYTES_MAX -
    _CRYPTO_SECRETBOX_XSALSA20POLY1305_MACBYTES;
function crypto_secretbox_xsalsa20poly1305_messagebytes_max: NativeUInt; cdecl; external SODIUM_LIB;

type
  TCryptoSecretBoxXSalsa20Poly1305Key = array[0.._CRYPTO_SECRETBOX_XSALSA20POLY1305_KEYBYTES -1] of Byte;

procedure crypto_secretbox_xsalsa20poly1305_keygen(var k: TCryptoSecretBoxXSalsa20Poly1305Key); cdecl; external SODIUM_LIB;

(* -- NaCl compatibility interface ; Requires padding -- *)

const
  _CRYPTO_SECRETBOX_XSALSA20POLY1305_BOXZEROBYTES = 16;
function crypto_secretbox_xsalsa20poly1305_boxzerobytes: NativeUInt; cdecl; external SODIUM_LIB; deprecated;

const
  _CRYPTO_SECRETBOX_XSALSA20POLY1305_ZEROBYTES =
    _CRYPTO_SECRETBOX_XSALSA20POLY1305_BOXZEROBYTES +
    _CRYPTO_SECRETBOX_XSALSA20POLY1305_MACBYTES;
function crypto_secretbox_xsalsa20poly1305_zerobytes: NativeUInt; cdecl; external SODIUM_LIB; deprecated;


function crypto_secretbox_xsalsa20poly1305(c: PByte;
                                           const m: PByte;
                                           mlen: UInt64;
                                           const n: PByte;
                                           const k: PByte): Integer; cdecl; external SODIUM_LIB; deprecated;

function crypto_secretbox_xsalsa20poly1305_open(m: PByte;
                                                const c: PByte;
                                                clen: UInt64;
                                                const n: PByte;
                                                const k: PByte): Integer; cdecl; external SODIUM_LIB; deprecated;

(* sodium/crypto_secretbox_xchacha20poly1305.h *)

const
  _CRYPTO_SECRETBOX_XCHACHA20POLY1305_KEYBYTES = 32;
function crypto_secretbox_xchacha20poly1305_keybytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_SECRETBOX_XCHACHA20POLY1305_NONCEBYTES = 24;
function crypto_secretbox_xchacha20poly1305_noncebytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_SECRETBOX_XCHACHA20POLY1305_MACBYTES = 16;
function crypto_secretbox_xchacha20poly1305_macbytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_SECRETBOX_XCHACHA20POLY1305_MESSAGEBYTES_MAX =
    _CRYPTO_STREAM_XCHACHA20_MESSAGEBYTES_MAX -
    _CRYPTO_SECRETBOX_XCHACHA20POLY1305_MACBYTES;
function crypto_secretbox_xchacha20poly1305_messagebytes_max: NativeUInt; cdecl; external SODIUM_LIB;

function crypto_secretbox_xchacha20poly1305_easy(c: PByte;
                                                 const m: PByte;
                                                 mlen: UInt64;
                                                 const n: PByte;
                                                 const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_secretbox_xchacha20poly1305_open_easy(m: PByte;
                                                      const c: PByte;
                                                      clen: UInt64;
                                                      const n: PByte;
                                                      const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_secretbox_xchacha20poly1305_detached(c: PByte;
                                                     mac: PByte;
                                                     const m: PByte;
                                                     mlen: UInt64;
                                                     const n: PByte;
                                                     const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_secretbox_xchacha20poly1305_open_detached(m: PByte;
                                                          const c: PByte;
                                                          const mac: PByte;
                                                          clen: UInt64;
                                                          const n: PByte;
                                                          const k: PByte): Integer; cdecl; external SODIUM_LIB;

(* sodium/crypto_secretbox.h *)

const
  _CRYPTO_SECRETBOX_KEYBYTES = _CRYPTO_SECRETBOX_XSALSA20POLY1305_KEYBYTES;
function crypto_secretbox_keybytes: NativeUInt; cdecl; external SODIUM_LIB;

type
  TCryptoSecretBoxKey = array[0.._CRYPTO_SECRETBOX_KEYBYTES -1] of Byte;

const
  _CRYPTO_SECRETBOX_NONCEBYTES = _CRYPTO_SECRETBOX_XSALSA20POLY1305_NONCEBYTES;
function crypto_secretbox_noncebytes: NativeUInt; cdecl; external SODIUM_LIB;

type
  TCryptoSecretBoxNonce = array[0.._CRYPTO_SECRETBOX_NONCEBYTES -1] of Byte;

const
  _CRYPTO_SECRETBOX_MACBYTES = _CRYPTO_SECRETBOX_XSALSA20POLY1305_MACBYTES;
function crypto_secretbox_macbytes: NativeUInt; cdecl; external SODIUM_LIB;

type
  TCryptoSecretBoxMac = array[0.._CRYPTO_SECRETBOX_MACBYTES -1] of Byte;

const
  _CRYPTO_SECRETBOX_PRIMITIVE = 'xsalsa20poly1305';
function crypto_secretbox_primitive: PAnsiChar; cdecl; external SODIUM_LIB;

const
  _CRYPTO_SECRETBOX_MESSAGEBYTES_MAX = _CRYPTO_SECRETBOX_XSALSA20POLY1305_MESSAGEBYTES_MAX;
function crypto_secretbox_messagebytes_max: NativeUInt; cdecl; external SODIUM_LIB;

function crypto_secretbox_easy(c: PByte; const m: PByte;
                               mlen: UInt64; const n: PByte;
                               const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_secretbox_open_easy(m: PByte; const c: PByte;
                                    clen: UInt64; const n: PByte;
                                    const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_secretbox_detached(c: PByte; mac: PByte;
                                   const m: PByte;
                                   mlen: UInt64;
                                   const n: PByte;
                                   const k: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_secretbox_open_detached(m: PByte;
                                        const c: PByte;
                                        const mac: PByte;
                                        clen: UInt64;
                                        const n: PByte;
                                        const k: PByte): Integer; cdecl; external SODIUM_LIB;

procedure crypto_secretbox_keygen(var k: TCryptoSecretBoxKey); cdecl; external SODIUM_LIB;

(* -- NaCl compatibility interface ; Requires padding -- *)

const
  _CRYPTO_SECRETBOX_ZEROBYTES = _CRYPTO_SECRETBOX_XSALSA20POLY1305_ZEROBYTES;
function crypto_secretbox_zerobytes: NativeUInt; cdecl; external SODIUM_LIB; deprecated;

const
  _CRYPTO_SECRETBOX_BOXZEROBYTES = _CRYPTO_SECRETBOX_XSALSA20POLY1305_BOXZEROBYTES;
function crypto_secretbox_boxzerobytes: NativeUInt; cdecl; external SODIUM_LIB; deprecated;

function crypto_secretbox(c: PByte; const m: PByte;
                          mlen: UInt64; const n: PByte;
                          const k: PByte): Integer; cdecl; external SODIUM_LIB; deprecated;

function crypto_secretbox_open(m: PByte; const c: PByte;
                               clen: UInt64; const n: PByte;
                               const k: PByte): Integer; cdecl; external SODIUM_LIB; deprecated;

(* sodium/crypto_secretstream_xchacha20poly1305.h *)

const
  _CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES = 1 + _CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES;
function crypto_secretstream_xchacha20poly1305_abytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES = _CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
function crypto_secretstream_xchacha20poly1305_headerbytes: NativeUInt; cdecl; external SODIUM_LIB;

type
  TCryptoSecretStreamXChacha20Poly1305Header = array[0.._CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES -1] of Byte;

const
  _CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES = _CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES;
function crypto_secretstream_xchacha20poly1305_keybytes: NativeUInt; cdecl; external SODIUM_LIB;

type
  TCryptoSecretStreamXChacha20Poly1305Key = array[0.._CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES -1] of Byte;

function _CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_MESSAGEBYTES_MAX: UInt64; inline;
function crypto_secretstream_xchacha20poly1305_messagebytes_max: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE = $00;
function crypto_secretstream_xchacha20poly1305_tag_message: Byte; cdecl; external SODIUM_LIB;

const
  _CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_PUSH = $01;
function crypto_secretstream_xchacha20poly1305_tag_push: Byte; cdecl; external SODIUM_LIB;

const
  _CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_REKEY = $02;
function crypto_secretstream_xchacha20poly1305_tag_rekey: Byte; cdecl; external SODIUM_LIB;

const _CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL =
        _CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_PUSH or
        _CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_REKEY;
function crypto_secretstream_xchacha20poly1305_tag_final: Byte; cdecl; external SODIUM_LIB;

type
  TCryptoSecretStreamXChacha20Poly1305State = record
    k: TCryptoStreamChacha20IetfKey;
    nonce: TCryptoStreamChacha20IetfNonce;
    _pad: array[0..8-1] of Byte;
  end;

function crypto_secretstream_xchacha20poly1305_statebytes: NativeUInt; cdecl; external SODIUM_LIB;

procedure crypto_secretstream_xchacha20poly1305_keygen
   (var k: TCryptoSecretStreamXChacha20Poly1305Key) cdecl; external SODIUM_LIB;

function crypto_secretstream_xchacha20poly1305_init_push
   (var state: TCryptoSecretStreamXChacha20Poly1305State;
    var header: TCryptoSecretStreamXChacha20Poly1305Header;
    const k: TCryptoSecretStreamXChacha20Poly1305Key): Integer; cdecl; external SODIUM_LIB;

function crypto_secretstream_xchacha20poly1305_push
   (var state: TCryptoSecretStreamXChacha20Poly1305State;
    c: PByte; var clen_p: UInt64;
    const m: PByte; mlen: UInt64;
    const ad: PByte; adlen: UInt64; tag: Byte): Integer; cdecl; external SODIUM_LIB;

function crypto_secretstream_xchacha20poly1305_init_pull
   (var state: TCryptoSecretStreamXChacha20Poly1305State;
    const header: TCryptoSecretStreamXChacha20Poly1305Header;
    const k: TCryptoSecretStreamXChacha20Poly1305Key): Integer; cdecl; external SODIUM_LIB;

function crypto_secretstream_xchacha20poly1305_pull
   (var state: TCryptoSecretStreamXChacha20Poly1305State;
    m: PByte; var mlen_p: UInt64; var tag_p: Byte;
    const c: PByte; clen: UInt64;
    const ad: PByte; adlen: UInt64): Integer; cdecl; external SODIUM_LIB;

procedure crypto_secretstream_xchacha20poly1305_rekey
    (var state: TCryptoSecretStreamXChacha20Poly1305State); cdecl; external SODIUM_LIB;

(* sodium/crypto_shorthash_siphash24.h *)

(* -- 64-bit output -- *)

const
  _crypto_shorthash_siphash24_BYTES = 8;
function crypto_shorthash_siphash24_bytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _crypto_shorthash_siphash24_KEYBYTES = 16;
function crypto_shorthash_siphash24_keybytes: NativeUInt; cdecl; external SODIUM_LIB;

function crypto_shorthash_siphash24(&out: PByte; const &in: PByte;
                                    inlen: UInt64; const k: PByte): Integer; cdecl; external SODIUM_LIB;

{$if not defined(SODIUM_LIBRARY_MINIMAL)}
(* -- 128-bit output -- *)

const
  _crypto_shorthash_siphashx24_BYTES = 16;
function crypto_shorthash_siphashx24_bytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _crypto_shorthash_siphashx24_KEYBYTES = 16;
function crypto_shorthash_siphashx24_keybytes: NativeUInt; cdecl; external SODIUM_LIB;

function crypto_shorthash_siphashx24(&out: PByte; const &in: PByte;
                                     inlen: UInt64; const k: PByte): Integer; cdecl; external SODIUM_LIB;
{$endif}

(* sodium/crypto_shorthash.h *)

const
  _CRYPTO_SHORTHASH_BYTES = _CRYPTO_SHORTHASH_SIPHASH24_BYTES;
function crypto_shorthash_bytes: NativeUInt; cdecl; external SODIUM_LIB;

type
  TCryptoShortHashHash = array[0.._CRYPTO_SHORTHASH_BYTES -1] of Byte;

const
  _CRYPTO_SHORTHASH_KEYBYTES = _CRYPTO_SHORTHASH_SIPHASH24_KEYBYTES;
function crypto_shorthash_keybytes: NativeUInt; cdecl; external SODIUM_LIB;

type
  TCryptoShortHashKey = array[0.._CRYPTO_SHORTHASH_KEYBYTES -1] of Byte;

const
  _CRYPTO_SHORTHASH_PRIMITIVE = 'siphash24';
function crypto_shorthash_primitive: PAnsiChar; cdecl; external SODIUM_LIB;

function crypto_shorthash(&out: PByte; const &in: PByte;
                          inlen: UInt64; const k: PByte): Integer; cdecl; external SODIUM_LIB;

procedure crypto_shorthash_keygen(var k: TCryptoShortHashKey); cdecl; external SODIUM_LIB;

(* sodium/crypto_sign_ed25519.h *)

type
  TCryptoSignEd25519PhState = record
    hs: TCryptoHashSha512State;
  end;

function crypto_sign_ed25519ph_statebytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_SIGN_ED25519_BYTES = 64;
function crypto_sign_ed25519_bytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_SIGN_ED25519_SEEDBYTES = 32;
function crypto_sign_ed25519_seedbytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_SIGN_ED25519_PUBLICKEYBYTES = 32;
function crypto_sign_ed25519_publickeybytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_SIGN_ED25519_SECRETKEYBYTES = 32 + 32;
function crypto_sign_ed25519_secretkeybytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_SIGN_ED25519_MESSAGEBYTES_MAX = SODIUM_SIZE_MAX - _CRYPTO_SIGN_ED25519_BYTES;
function crypto_sign_ed25519_messagebytes_max: NativeUInt; cdecl; external SODIUM_LIB;

function crypto_sign_ed25519(sm: PByte; var smlen_p: UInt64;
                             const m: PBYte; mlen: UInt64;
                             const sk: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_sign_ed25519_open(m: PByte; var mlen_p: UInt64;
                                  const sm: PByte; smlen: UInt64;
                                  const pk: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_sign_ed25519_detached(sig: PByte;
                                      var siglen_p: UInt64;
                                      const m: PByte;
                                      mlen: UInt64;
                                      const sk: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_sign_ed25519_verify_detached(const sig: PByte;
                                             const m: PByte;
                                             mlen: PByte;
                                             const pk: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_sign_ed25519_keypair(pk: PByte; sk: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_sign_ed25519_seed_keypair(pk: PByte; sk: PByte;
                                          const seed: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_sign_ed25519_pk_to_curve25519(curve25519_pk: PByte;
                                              const ed25519_pk: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_sign_ed25519_sk_to_curve25519(curve25519_sk: PByte;
                                              const ed25519_sk: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_sign_ed25519_sk_to_seed(seed: PByte;
                                        const sk: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_sign_ed25519_sk_to_pk(pk: PByte; const sk: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_sign_ed25519ph_init(var state: TCryptoSignEd25519PhState): Integer; cdecl; external SODIUM_LIB;

function crypto_sign_ed25519ph_update(var state: TCryptoSignEd25519PhState;
                                      const m: PByte;
                                      mlen: UInt64): Integer; cdecl; external SODIUM_LIB;

function crypto_sign_ed25519ph_final_create(var state: TCryptoSignEd25519PhState;
                                            sig: PByte;
                                            var siglen_p: UInt64;
                                            const sk: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_sign_ed25519ph_final_verify(var state: TCryptoSignEd25519PhState;
                                            const sig: PByte;
                                            const pk: PByte): Integer; cdecl; external SODIUM_LIB;

(* sodium/crypto_sign_edwards25519sha512batch.h *)

(*
 * WARNING: This construction was a prototype, which should not be used
 * any more in new projects.
 *
 * crypto_sign_edwards25519sha512batch is provided for applications
 * initially built with NaCl, but as recommended by the author of this
 * construction, new applications should use ed25519 instead.
 *
 * In Sodium, you should use the high-level crypto_sign_*() functions instead.
 *)

const _CRYPTO_SIGN_EDWARDS25519SHA512BATCH_BYTES = 64;
const _CRYPTO_SIGN_EDWARDS25519SHA512BATCH_PUBLICKEYBYTES = 32;
const _CRYPTO_SIGN_EDWARDS25519SHA512BATCH_SECRETKEYBYTES = 32 + 32;
const _CRYPTO_SIGN_EDWARDS25519SHA512BATCH_MESSAGEBYTES_MAX = SODIUM_SIZE_MAX - _CRYPTO_SIGN_EDWARDS25519SHA512BATCH_BYTES;

function crypto_sign_edwards25519sha512batch(sm: PByte;
                                             var smlen_p: UInt64;
                                             const m: PByte;
                                             mlen: UInt64;
                                             const sk: PByte): Integer; cdecl; external SODIUM_LIB; deprecated;

function crypto_sign_edwards25519sha512batch_open(m: PByte;
                                                  var mlen_p: UInt64;
                                                  const sm: PByte;
                                                  smlen: UInt64;
                                                  const pk: PByte): Integer; cdecl; external SODIUM_LIB; deprecated;

function crypto_sign_edwards25519sha512batch_keypair(pk: PByte;
                                                     sk: PByte): Integer; cdecl; external SODIUM_LIB; deprecated;

(* sodium/crypto_sign.h *)

(*
 * THREAD SAFETY: crypto_sign_keypair() is thread-safe,
 * provided that sodium_init() was called before.
 *
 * Other functions, including crypto_sign_seed_keypair() are always thread-safe.
 *)

type
  TCryptoSignState = TCryptoSignEd25519PhState;

function crypto_sign_statebytes: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_SIGN_BYTES = _CRYPTO_SIGN_ED25519_BYTES;
function crypto_sign_bytes: NativeUInt; cdecl; external SODIUM_LIB;

type
  TCryptoSignature = array[0.._CRYPTO_SIGN_BYTES -1] of Byte;

const
  _CRYPTO_SIGN_SEEDBYTES = _CRYPTO_SIGN_ED25519_SEEDBYTES;
function crypto_sign_seedbytes: NativeUInt; cdecl; external SODIUM_LIB;

type
  TCryptoSignSeed = array[0.._CRYPTO_SIGN_SEEDBYTES -1] of Byte;

const
  _CRYPTO_SIGN_PUBLICKEYBYTES = _CRYPTO_SIGN_ED25519_PUBLICKEYBYTES;
function crypto_sign_publickeybytes: NativeUInt; cdecl; external SODIUM_LIB;

type
  TCryptoSignPublicKey = array[0.._CRYPTO_SIGN_PUBLICKEYBYTES -1] of Byte;

const
  _CRYPTO_SIGN_SECRETKEYBYTES = _CRYPTO_SIGN_ED25519_SECRETKEYBYTES;
function crypto_sign_secretkeybytes: NativeUInt; cdecl; external SODIUM_LIB;

type
  TCryptoSignSecretKey = array[0.._CRYPTO_SIGN_SECRETKEYBYTES -1] of Byte;

const
  _CRYPTO_SIGN_MESSAGEBYTES_MAX = _CRYPTO_SIGN_ED25519_MESSAGEBYTES_MAX;
function crypto_sign_messagebytes_max: NativeUInt; cdecl; external SODIUM_LIB;

const
  _CRYPTO_SIGN_PRIMITIVE = 'ed25519';
function crypto_sign_primitive: PAnsiChar; cdecl; external SODIUM_LIB;

function crypto_sign_seed_keypair(pk: PByte; sk: PByte;
                                  const seed: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_sign_keypair(pk: PByte; sk: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_sign(sm: PByte; var smlen_p: UInt64;
                     const m: PByte; mlen: UInt64;
                     const sk: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_sign_open(m: PByte; var mlen_p: UInt64;
                          const sm: PByte; smlen: UInt64;
                          const pk: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_sign_detached(sig: PByte; var siglen_p: UInt64;
                              const m: PByte; mlen: UInt64;
                              const sk: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_sign_verify_detached(const sig: PByte;
                                     const m: PByte;
                                     mlen: UInt64;
                                     const pk: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_sign_init(var state: TCryptoSignState): Integer; cdecl; external SODIUM_LIB;

function crypto_sign_update(var state: TCryptoSignState;
                            const m: PByte; mlen: UInt64): Integer; cdecl; external SODIUM_LIB;

function crypto_sign_final_create(var state: TCryptoSignState; sig: PByte;
                                  var siglen_p: UInt64;
                                  const sk: PByte): Integer; cdecl; external SODIUM_LIB;

function crypto_sign_final_verify(var state: TCryptoSignState; const sig: PByte;
                                  const pk: PBYte): Integer; cdecl; external SODIUM_LIB;

(* sodium/crypto_verify_16.h *)

const
  _CRYPTO_VERIFY_16_BYTES = 16;
function crypto_verify_16_bytes: NativeUInt; cdecl; external SODIUM_LIB;

function crypto_verify_16(const x: PByte; const y: PByte): Integer; cdecl; external SODIUM_LIB;

(* sodium/crypto_verify_32.h *)

const
  _CRYPTO_VERIFY_32_BYTES = 32;
function crypto_verify_32_bytes: NativeUInt; cdecl; external SODIUM_LIB;

function crypto_verify_32(const x: PByte; const y: PByte): Integer; cdecl; external SODIUM_LIB;

(* sodium/crypto_verify_64.h *)

const
  _CRYPTO_VERIFY_64_BYTES = 64;
function crypto_verify_64_bytes: NativeUInt; cdecl; external SODIUM_LIB;

function crypto_verify_64(const x: PByte; const y: PByte): Integer; cdecl; external SODIUM_LIB;

implementation

(* sodium/export.h *)

function SODIUM_MIN(A, B: UInt64): UInt64; inline;
begin
  if A < B then
    Result := A
  else
    Result := B;
end;

(* sodium/utils.h *)

function _SODIUM_BASE64_ENCODED_LEN(BIN_LEN: NativeUInt; VARIANT: Byte): UInt64; inline;
begin
  {
    (((BIN_LEN) / 3U) * 4U + \
    ((((BIN_LEN) - ((BIN_LEN) / 3U) * 3U) | (((BIN_LEN) - ((BIN_LEN) / 3U) * 3U) >> 1)) & 1U) * \
     (4U - (~((((VARIANT) & 2U) >> 1) - 1U) & (3U - ((BIN_LEN) - ((BIN_LEN) / 3U) * 3U)))) + 1U)
  }

  Result :=
    (((BIN_LEN) div 3) * 4 +
    ((((BIN_LEN) - ((BIN_LEN) div 3) * 3) or (((BIN_LEN) - ((BIN_LEN) div 3) * 3) shr 1)) and 1) *
     (4 - (not((((VARIANT) and 2) shr 1) - 1) and (3 - ((BIN_LEN) - ((BIN_LEN) div 3) * 3)))) + 1);
end;

(* sodium/randombytes.h *)

function RANDOMBYTES_BYTES_MAX: UInt64; inline;
begin
  Result := SODIUM_MIN(SODIUM_SIZE_MAX, High(Cardinal));
end;

(* sodium/crypto_aead_aegis128l.h *)

function _CRYPTO_AEAD_AEGIS128L_MESSAGEBYTES_MAX: UInt64; inline;
begin
  Result := SODIUM_MIN(SODIUM_SIZE_MAX - _CRYPTO_AEAD_AEGIS128L_ABYTES,
    (UInt64(1) shl 61) - UInt64(1));
end;

(* sodium/crypto_aead_aegis256.h *)

function _CRYPTO_AEAD_AEGIS256_MESSAGEBYTES_MAX: UInt64; inline;
begin
  Result := SODIUM_MIN(SODIUM_SIZE_MAX - _CRYPTO_AEAD_AEGIS256_ABYTES,
    (UInt64(1) shl 61) - UInt64(1));
end;

(* sodium/crypto/aead_aegis256gcm.h *)

function _CRYPTO_AEAD_AES256GCM_MESSAGEBYTES_MAX: UInt64; inline;
begin
  Result := SODIUM_MIN(SODIUM_SIZE_MAX - _CRYPTO_AEAD_AES256GCM_ABYTES,
    (UInt64(16) * ((UInt64(1) shl 32) - UInt64(2))));
end;

(* sodium/crypto_aead_chacha20poly1305.h *)

function _CRYPTO_AEAD_CHACHA20POLY1305_IETF_MESSAGEBYTES_MAX: UInt64; inline;
begin
  Result := SODIUM_MIN(SODIUM_SIZE_MAX - _CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES,
    (UInt64(64) * ((UInt64(1) shl 32) - UInt64(1))));
end;

(* sodium/crypto_stream_chacha20.h *)

function _CRYPTO_STREAM_CHACHA20_IETF_MESSAGEBYTES_MAX: UInt64; inline;
begin
  Result := SODIUM_MIN(SODIUM_SIZE_MAX, UInt64(64) * (UInt64(1) shl 32));
end;

(* sodium/crypto_pwhash_scryptsalsa208sha256.h *)

function _CRYPTO_PWHASH_SCRYPTSALSA208SHA256_BYTES_MAX: UInt64; inline;
begin
  Result := SODIUM_MIN(SODIUM_SIZE_MAX, UInt64($1fffffffe0));
end;

function _CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_MAX: UInt64; inline;
begin
  Result := SODIUM_MIN(High(NativeUInt), UInt64(68719476736));
end;

(* sodium/crypto_pwhash_argon2i.h *)

function _CRYPTO_PWHASH_ARGON2I_BYTES_MAX: UInt64; inline;
begin
  Result := SODIUM_MIN(SODIUM_SIZE_MAX, UInt64(4294967295));
end;

function _CRYPTO_PWHASH_ARGON2I_MEMLIMIT_MAX: UInt64; inline;
begin
  if UInt64(High(NativeUInt)) >= UInt64(4398046510080) then
    Result := 4398046510080
  else if UInt64(High(NativeUInt)) >= UInt64(2147483648) then
    Result := 2147483648
  else
    Result := 32768;
end;

(* sodium/crypto_pwhash_argon2id.h *)

function _CRYPTO_PWHASH_ARGON2ID_BYTES_MAX: UInt64; inline;
begin
  Result := SODIUM_MIN(SODIUM_SIZE_MAX, UInt64(4294967295));
end;

function _CRYPTO_PWHASH_ARGON2ID_MEMLIMIT_MAX: UInt64; inline;
begin
  if UInt64(High(NativeUInt)) >= UInt64(4398046510080) then
    Result := 4398046510080
  else if UInt64(High(NativeUInt)) >= UInt64(2147483648) then
    Result := 2147483648
  else
    Result := 32768;
end;

(* sodium/crypto_pwhash.h *)

function _CRYPTO_PWHASH_BYTES_MAX: UInt64; inline;
begin
  Result := _CRYPTO_PWHASH_ARGON2ID_BYTES_MAX;
end;

function _CRYPTO_PWHASH_MEMLIMIT_MAX: UInt64; inline;
begin
  Result := _CRYPTO_PWHASH_ARGON2ID_MEMLIMIT_MAX;
end;

(* sodium/crypto_secretstream_xchacha20poly1305.h *)

function _CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_MESSAGEBYTES_MAX: UInt64; inline;
begin
  Result := SODIUM_MIN(SODIUM_SIZE_MAX - _CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES,
                       (UInt64(64) * ((UInt64(1) shl 32) - UInt64(2))));
end;

initialization
  sodium_init;

end.
