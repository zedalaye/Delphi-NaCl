unit Sodium.Utils;

interface

uses
  System.SysUtils,
  libsodium;

type
  TCryptoDataProc = reference to procedure(var Buffer: TBytes; var Done: Boolean);

type
  TSodium = record
    class function Version: string; static;
    class function LibraryVersionMajor: Integer; static;
    class function LibraryVersionMinor: Integer; static;
    class function LibraryMinimal: Integer; static;

    class function RuntimeHasNeon: Boolean; static;
    class function RuntimeHasArmCrypto: Boolean; static;
    class function RuntimeHasSse2: Boolean; static;
    class function RuntimeHasSse3: Boolean; static;
    class function RuntimeHasSsse3: Boolean; static;
    class function RuntimeHasSse41: Boolean; static;
    class function RuntimeHasAvx: Boolean; static;
    class function RuntimeHasAvx2: Boolean; static;
    class function RuntimeHasAvx512f: Boolean; static;
    class function RuntimeHasPclMul: Boolean; static;
    class function RuntimeHasAesni: Boolean; static;
    class function RuntimeHasRdRand: Boolean; static;
  end;

  TRandom = record
    class function ImplementationName: string; static;
  end;

  TRandomBytesSeed = libsodium.TRandomBytesSeed;

  TBase64Variant = (
    Original = SODIUM_BASE64_VARIANT_ORIGINAL,
    UrlSafe = SODIUM_BASE64_VARIANT_URLSAFE
  );

  TBytesHelper = record helper for TBytes
    class procedure SameSize(const A, B: TBytes); static;

    { Concatenation }
    class function Concat(const A, B: TBytes): TBytes; overload; static;
    class function Concat(const A: array of TBytes): TBytes; overload; static;

    { Reverse }
    class function Reverse(const B: TBytes): TBytes; overload; static;
    function Reverse: TBytes; overload;

    { Buffers <=> TBytes }
    class function FromBuf(const Buf; Len: NativeUInt): TBytes; overload; static;
    class function FromBuf<T>(const Buf: T): TBytes; overload; static;

    class function ToBuf(var Buf; Len: NativeUInt; const B: TBytes): Boolean; overload; static;
    class function ToBuf<T>(var Buf: T; const B: TBytes): Boolean; overload; static;

    function ToBuf(var Buf; Len: NativeUInt): Boolean; overload;
    function ToBuf<T>(var Buf: T): Boolean; overload;

    { Buffers <=> Hexadecimal encoded string }

    class function FromHex(Buf: PByte; var Len: NativeUInt; const Hex: string): Boolean; overload; static;
    class function FromHex(var Buf; Len: NativeUInt; const Hex: string): Boolean; overload; static;
    class function FromHex<T>(var Buf: T; const Hex: string): Boolean; overload; static;
    class function FromHex(var Buf: TBytes; const Hex: string): Boolean; overload; static;

    class function ToHex(const Buf; Len: NativeUInt): string; overload; static;
    class function ToHex<T>(const Buf: T): string; overload; static;

    class function ToHex(const Buf: TBytes): string; overload; static;
    function ToHex: string; overload;

    { Buffers <=> Base64 encoded string }

    class function FromBase64(Buf: PByte; var Len: NativeUInt; const Base64: string;
      Variant: TBase64Variant = TBase64Variant.Original; Padding: Boolean = True): Boolean; overload; static;
    class function FromBase64(var Buf; Len: NativeUInt; const Base64: string;
      Variant: TBase64Variant = TBase64Variant.Original; Padding: Boolean = True): Boolean; overload; static;
    class function FromBase64<T>(var Buf: T; const Base64: string;
      Variant: TBase64Variant = TBase64Variant.Original; Padding: Boolean = True): Boolean; overload; static;
    class function FromBase64(var Buf: TBytes; const Base64: string;
      Variant: TBase64Variant = TBase64Variant.Original; Padding: Boolean = True): Boolean; overload; static;

    class function ToBase64(const Buf; Len: NativeUInt;
      Variant: TBase64Variant = TBase64Variant.Original; Padding: Boolean = True): string; overload; static;
    class function ToBase64<T>(const Buf: T;
      Variant: TBase64Variant = TBase64Variant.Original; Padding: Boolean = True): string; overload; static;

    class function ToBase64(const Buf: TBytes;
      Variant: TBase64Variant = TBase64Variant.Original; Padding: Boolean = True): string; overload; static;
    function ToBase64(
      Variant: TBase64Variant = TBase64Variant.Original; Padding: Boolean = True): string; overload;

    { Zeroing Buffers }

    class function Zero(Len: NativeUInt): TBytes; overload; static;
    class procedure Zero(var Buf: TBytes); overload; static;
    class procedure Zero(var Buf; Len: NativeUInt); overload; static;
    class procedure Zero<T>(var Buf: T); overload; static;

    class function IsZero(const Buf; Len: NativeUInt): Boolean; overload; static;
    class function IsZero<T>(const Buf: T): Boolean; overload; static;

    class function IsZero(const Buf: TBytes): Boolean; overload; static;
    function IsZero: Boolean; overload;

    { Randomizing Buffers }

    class function Random: Cardinal; overload; static;
    class function RandomUniform(UpperBound: Cardinal): Cardinal; static;

    class function Random(Len: NativeUInt): TBytes; overload; static;
    class procedure Random(var Buf: TBytes); overload; static;
    class procedure Random(var Buf; Len: NativeUInt); overload; static;
    class procedure Random<T>(var Buf: T); overload; static;

    class procedure Random(var Buf: TBytes; const Seed: TRandomBytesSeed); overload; static;
    class procedure Random(var Buf; Len: NativeUInt; const Seed: TRandomBytesSeed); overload; static;
    class procedure Random<T>(var Buf: T; const Seed: TRandomBytesSeed); overload; static;

    { Comparing Buffers }

    class function Same(const A, B: TBytes): Boolean; overload; static;
    class function Same(const A, B; Len: NativeUInt): Boolean; overload; static;
    class function Same<T>(const A, B: T): Boolean; overload; static;

    { Verifying Buffers }

    class function Verify16(const A, B: PByte): Boolean; static;
    class function Verify32(const A, B: PByte): Boolean; static;
    class function Verify64(const A, B: PByte): Boolean; static;

    class function Verify(const A, B: TBytes): Boolean; overload; static;
    class function Verify(const A, B; Len: NativeUInt): Boolean; overload; static;
    class function Verify<T>(const A, B: T): Boolean; overload; static;

    { Padding Buffers }

    class function Pad(var B: TBytes; BlockSize: NativeUInt): Boolean; static;
    class function Unpad(var B: TBytes; BlockSize: NativeUInt): Boolean; static;

    { Arithmetics over big numbers stored in Buffers }

    class procedure Inc(var B: TBytes); overload; static;
    class procedure Inc(var B; Len: NativeUInt); overload; static;
    class procedure Inc<T>(var B: T); overload; static;

    class procedure Add(var A: TBytes; const B: TBytes); overload; static;
    class procedure Add(var A; const B; Len: NativeUInt); overload; static;
    class procedure Add<T>(var A: T; const B: T); overload; static;

    class procedure Sub(var A: TBytes; const B: TBytes); overload; static;
    class procedure Sub(var A; const B; Len: NativeUInt); overload; static;
    class procedure Sub<T>(var A: T; const B: T); overload; static;

    { Compare big numbers stored in Buffers }

    class function Compare(const A, B: TBytes): Integer; overload; static;
    class function Compare(const A; const B; Len: NativeUInt): Integer; overload; static;
    class function Compare<T>(const A: T; const B: T): Integer; overload; static;
  end;

{ Because @B[0] when B is empty is not nil }
function BytesPointer(B: TBytes): PByte;

(*
 * Important when writing bindings for other programming languages:
 * the state address should be 64-bytes aligned.
 *)
type
  PCryptoGenericHashState = ^TCryptoGenericHashState;
  TCryptoGenericHashState = libsodium.TCryptoGenericHashState;

{ Delphi has no method to return aligned blocks on 64 bytes boundaries,
   this one do the trick.
  Free the memory using FreeMem(BlockStart) }
function GetAlignedCryptoGenericHashState(var BlockStart: Pointer): PCryptoGenericHashState;

implementation

function BytesPointer(B: TBytes): PByte;
begin
  if Length(B) = 0 then
    Result := nil
  else
    Result := @B[0];
end;

function GetAlignedCryptoGenericHashState(var BlockStart: Pointer): PCryptoGenericHashState;
const
  ALIGN_BYTES = 64;
begin
  { Allocate a slightly bigger block keeping the whole block a multiple of 16 bytes }
  GetMem(BlockStart, SizeOf(TCryptoGenericHashState) + ALIGN_BYTES);
  { Return a slice starting at (BlockStart + 63) & -64 }
  Result := PCryptoGenericHashState((NativeUInt(BlockStart) + (ALIGN_BYTES -1)) and not(ALIGN_BYTES -1));
end;

{ TRandom }

class function TRandom.ImplementationName: string;
begin
  Result := string(randombytes_implementation_name);
end;

{ TSodium }

class function TSodium.Version: string;
begin
  Result := string(sodium_version_string);
end;

class function TSodium.LibraryMinimal: Integer;
begin
  Result := sodium_library_minimal;
end;

class function TSodium.LibraryVersionMajor: Integer;
begin
  Result := sodium_library_version_major;
end;

class function TSodium.LibraryVersionMinor: Integer;
begin
  Result := sodium_library_version_minor;
end;

class function TSodium.RuntimeHasAesni: Boolean;
begin
  Result := sodium_runtime_has_aesni = 1;
end;

class function TSodium.RuntimeHasArmCrypto: Boolean;
begin
  Result := sodium_runtime_has_armcrypto = 1;
end;

class function TSodium.RuntimeHasAvx: Boolean;
begin
  Result := sodium_runtime_has_avx = 1;
end;

class function TSodium.RuntimeHasAvx2: Boolean;
begin
  Result := sodium_runtime_has_avx2 = 1;
end;

class function TSodium.RuntimeHasAvx512f: Boolean;
begin
  Result := sodium_runtime_has_avx512f = 1;
end;

class function TSodium.RuntimeHasNeon: Boolean;
begin
  Result := sodium_runtime_has_neon = 1;
end;

class function TSodium.RuntimeHasPclMul: Boolean;
begin
  Result := sodium_runtime_has_pclmul = 1;
end;

class function TSodium.RuntimeHasRdRand: Boolean;
begin
  Result := sodium_runtime_has_rdrand = 1;
end;

class function TSodium.RuntimeHasSse2: Boolean;
begin
  Result := sodium_runtime_has_sse2 = 1;
end;

class function TSodium.RuntimeHasSse3: Boolean;
begin
  Result := sodium_runtime_has_sse3 = 1;
end;

class function TSodium.RuntimeHasSse41: Boolean;
begin
  Result := sodium_runtime_has_sse41 = 1;
end;

class function TSodium.RuntimeHasSsse3: Boolean;
begin
  Result := sodium_runtime_has_ssse3 = 1;
end;

{ TBytesHelper }

function VariantOption(Variant: TBase64Variant; Padding: Boolean): Integer; inline;
const
  PADDING_OFFSET: array[Boolean] of Integer = (2, 0); { (False, True) }
begin
  Result := Ord(Variant) + PADDING_OFFSET[Padding];
end;

class procedure TBytesHelper.SameSize(const A, B: TBytes);
begin
  if Length(A) <> Length(B) then
    raise EArgumentException.CreateFmt('SizeOf(A)=%d bytes <> SizeOf(B)=%d bytes', [Length(A), Length(B)]);
end;

class function TBytesHelper.Concat(const A, B: TBytes): TBytes;
begin
  SetLength(Result, Length(A) + Length(B));
  Move(A[0], Result[0], Length(A));
  Move(B[0], Result[Length(A)], Length(B));
end;

class function TBytesHelper.Concat(const A: array of TBytes): TBytes;
var
  Total, Offset: NativeUInt;
begin
 // Result := A[0] + A[1];
  Total := 0;
  for var Buf in A do
    Total := Total + NativeUInt(Length(Buf));
  SetLength(Result, Total);
  Offset := 0;
  for var Buf in A do
  begin
    Move(Buf[0], Result[Offset], Length(Buf));
    Offset := Offset + NativeUInt(Length(Buf));
  end;
end;

class function TBytesHelper.Reverse(const B: TBytes): TBytes;
begin
  SetLength(Result, Length(B));
  for var I := Low(B) to High(B) do
    Result[High(B) - I] := B[I];
end;

function TBytesHelper.Reverse: TBytes;
begin
  Result := TBytes.Reverse(Self);
end;

class function TBytesHelper.FromBuf(const Buf; Len: NativeUInt): TBytes;
begin
  SetLength(Result, Len);
  Move(Buf, Result[0], Len);
end;

class function TBytesHelper.FromBuf<T>(const Buf: T): TBytes;
begin
  SetLength(Result, SizeOf(T));
  Move(Buf, Result[0], SizeOf(T));
end;

class function TBytesHelper.ToBuf(var Buf; Len: NativeUInt;
  const B: TBytes): Boolean;
begin
  if NativeUInt(Length(B)) = Len then
  begin
    Move(B[0], Buf, Len);
    Result := True;
  end
  else
    Result := False;
end;

class function TBytesHelper.ToBuf<T>(var Buf: T; const B: TBytes): Boolean;
begin
  if Length(B) = SizeOf(T) then
  begin
    Move(B[0], Buf, Sizeof(T));
    Result := True;
  end
  else
    Result := False;
end;

function TBytesHelper.ToBuf(var Buf; Len: NativeUInt): Boolean;
begin
  Result := TBytes.ToBuf(Buf, Len, Self);
end;

function TBytesHelper.ToBuf<T>(var Buf: T): Boolean;
begin
  Result := TBytes.ToBuf(Buf, Self);
end;

class function TBytesHelper.FromHex(Buf: PByte; var Len: NativeUInt;
  const Hex: string): Boolean;
const
  HEX_CHARSET = ['0'..'9', 'a'..'f', 'A'..'F'];
var
  HexR: RawByteString;
  HexP, HexErr: PAnsiChar;
begin
  HexR := RawByteString(Hex);
  HexP := PAnsiChar(HexR);

  Result := sodium_hex2bin(
              Buf, Len,
              HexP, Length(HexR),    // hex strings does not contain extended characters
              PAnsiChar(' '#13#10), // ignore whitespace and newline characters
              Len,
              HexErr
            ) = 0;

  if not Result then
  begin
    if CharInSet(HexErr^, HEX_CHARSET) then
      raise EArgumentException.Create('Provided Buffer is too small')
    else
      raise EArgumentException.CreateFmt(
        'Invalid Hexadecimal string (unexpected char ''%s'' at pos %d)',
        [HexErr^, Integer(HexErr - HexP) +1]
      );
  end;
end;

class function TBytesHelper.FromHex(var Buf; Len: NativeUInt;
  const Hex: string): Boolean;
var
  BufLen: NativeUInt;
begin
  BufLen := Len;
  Result := FromHex(@Buf, BufLen, Hex);
  if Result and (Len > BufLen) then
    raise EArgumentException.CreateFmt(
      'Provided Buffer (%d bytes) is too big (expected: %d bytes)',
      [Len, BufLen]
    );
end;

class function TBytesHelper.FromHex<T>(var Buf: T; const Hex: string): Boolean;
begin
  Result := FromHex(Buf, SizeOf(T), Hex);
end;

class function TBytesHelper.FromHex(var Buf: TBytes; const Hex: string): Boolean;
var
  BufLen: NativeUInt;
begin
  BufLen := Length(Hex) div 2;
  SetLength(Buf, BufLen);
  Result := FromHex(@Buf[0], BufLen, Hex);
  if Result then
    SetLength(Buf, BufLen);
end;

class function TBytesHelper.ToHex(const Buf; Len: NativeUInt): string;
var
  Hex: RawByteString;
begin
  SetLength(Hex, Len * 2 + 1); // bin2hex adds an ending \0
  sodium_bin2hex(@Hex[1], Length(Hex), @Buf, Len);
  Result := Trim(string(Hex));
end;

class function TBytesHelper.ToHex<T>(const Buf: T): string;
begin
  Result := ToHex(Buf, SizeOf(T));
end;

class function TBytesHelper.ToHex(const Buf: TBytes): string;
begin
  Result := ToHex(Buf[0], Length(Buf));
end;

function TBytesHelper.ToHex: string;
begin
  Result := TBytes.ToHex(Self);
end;

class function TBytesHelper.FromBase64(Buf: PByte; var Len: NativeUInt;
  const Base64: string; Variant: TBase64Variant; Padding: Boolean): Boolean;

  function VariantCharset(Variant: TBase64Variant; Padding: Boolean): TSysCharSet;
  const
    BASE64_CHARSET   = ['a'..'z', 'A'..'Z', '0'..'9'];
    ORIGINAL_CHARSET = ['+', '/'];
    URLSAFE_CHARSET  = ['-', '_'];
    PADDING_CHARSET  = ['='];
  begin
    Result := BASE64_CHARSET;
    if Variant = TBase64Variant.UrlSafe then
      Result := Result + URLSAFE_CHARSET
    else
      Result := Result + ORIGINAL_CHARSET;
    if Padding then
      Result := Result + PADDING_CHARSET;
  end;

var
  B64R: RawByteString;
  B64P, B64Err: PAnsiChar;
begin
  B64R := RawByteString(Base64);
  B64P := PAnsiChar(B64R);

  Result := sodium_base642bin(
              Buf, Len,
              B64P, Length(B64R),    // base64 strings does not contain extended characters
              PAnsiChar(' '#13#10), // ignore whitespace and newline characters
              Len,
              B64Err,
              VariantOption(Variant, Padding)
            ) = 0;

  if not Result then
  begin
    if CharInSet(B64Err^, VariantCharset(Variant, Padding)) then
      raise EArgumentException.Create('Provided Buffer is too small')
    else
      raise EArgumentException.CreateFmt(
        'Invalid Base64 string (unexpected char ''%s'' at pos %d)',
        [B64Err^, Integer(B64Err - B64P) +1]
      );
  end;
end;

class function TBytesHelper.FromBase64(var Buf; Len: NativeUInt;
  const Base64: string; Variant: TBase64Variant; Padding: Boolean): Boolean;
var
  BufLen: NativeUInt;
begin
  BufLen := Len;
  Result := FromBase64(@Buf, BufLen, Base64, Variant, Padding);
  if Result and (Len > BufLen) then
    raise EArgumentException.CreateFmt(
      'Provided Buffer (%d bytes) is too big (expected: %d bytes)',
      [Len, BufLen]
    );
end;

class function TBytesHelper.FromBase64<T>(var Buf: T; const Base64: string;
  Variant: TBase64Variant; Padding: Boolean): Boolean;
begin
  Result := FromBase64(Buf, SizeOf(T), Base64, Variant, Padding);
end;

class function TBytesHelper.FromBase64(var Buf: TBytes; const Base64: string;
  Variant: TBase64Variant; Padding: Boolean): Boolean;
var
  BufLen: NativeUInt;
begin
  BufLen := Length(Base64) div 4 * 3;
  SetLength(Buf, BufLen);
  Result := FromBase64(@Buf[0], BufLen, Base64, Variant, Padding);
  if Result then
    SetLength(Buf, BufLen);
end;

class function TBytesHelper.ToBase64(const Buf; Len: NativeUInt;
  Variant: TBase64Variant; Padding: Boolean): string;
var
  V: Integer;
  B64: RawByteString;
begin
  V := VariantOption(Variant, Padding);
  SetLength(B64, _SODIUM_BASE64_ENCODED_LEN(Len, V));
  sodium_bin2base64(@B64[1], Length(B64), @Buf, Len, V);
  Result := string(B64);
end;

class function TBytesHelper.ToBase64<T>(const Buf: T; Variant: TBase64Variant;
  Padding: Boolean): string;
begin
  Result := ToBase64(Buf, SizeOf(T), Variant, Padding);
end;

class function TBytesHelper.ToBase64(const Buf: TBytes; Variant: TBase64Variant;
  Padding: Boolean): string;
begin
  Result := ToBase64(Buf[0], Length(Buf), Variant, Padding);
end;

function TBytesHelper.ToBase64(Variant: TBase64Variant;
  Padding: Boolean): string;
begin
  Result := TBytes.ToBase64(Self, Variant, Padding);
end;

class function TBytesHelper.IsZero(const Buf; Len: NativeUInt): Boolean;
begin
  Result := sodium_is_zero(@Buf, Len) = 1; // !
end;

class function TBytesHelper.IsZero(const Buf: TBytes): Boolean;
begin
  Result := sodium_is_zero(@Buf[0], Length(Buf)) = 1; // !
end;

function TBytesHelper.IsZero: Boolean;
begin
  Result := TBytes.IsZero(Self);
end;

class function TBytesHelper.IsZero<T>(const Buf: T): Boolean;
begin
  Result := sodium_is_zero(@Buf, SizeOf(T)) = 1; // !
end;

class function TBytesHelper.Zero(Len: NativeUInt): TBytes;
begin
  SetLength(Result, Len);
  sodium_memzero(@Result[0], Len);
end;

class procedure TBytesHelper.Zero(var Buf: TBytes);
begin
  sodium_memzero(@Buf[0], Length(Buf));
end;

class procedure TBytesHelper.Zero(var Buf; Len: NativeUInt);
begin
  sodium_memzero(@Buf, Len);
end;

class procedure TBytesHelper.Zero<T>(var Buf: T);
begin
  sodium_memzero(@Buf, SizeOf(T));
end;

class function TBytesHelper.Random: Cardinal;
begin
  Result := randombytes_random;
end;

class function TBytesHelper.RandomUniform(UpperBound: Cardinal): Cardinal;
begin
  Result := randombytes_uniform(UpperBound);
end;

class function TBytesHelper.Random(Len: NativeUInt): TBytes;
begin
  SetLength(Result, Len);
  randombytes_buf(@Result[0], Len);
end;

class procedure TBytesHelper.Random(var Buf: TBytes);
begin
  randombytes_buf(@Buf[0], Length(Buf));
end;

class procedure TBytesHelper.Random(var Buf; Len: NativeUInt);
begin
  randombytes_buf(@Buf, Len);
end;

class procedure TBytesHelper.Random<T>(var Buf: T);
begin
  randombytes_buf(@Buf, SizeOf(T));
end;

class procedure TBytesHelper.Random(var Buf; Len: NativeUInt;
  const Seed: TRandomBytesSeed);
begin
  randombytes_buf_deterministic(@Buf, Len, Seed);
end;

class procedure TBytesHelper.Random<T>(var Buf: T;
  const Seed: TRandomBytesSeed);
begin
  randombytes_buf_deterministic(@Buf, SizeOf(T), Seed);
end;

class procedure TBytesHelper.Random(var Buf: TBytes;
  const Seed: TRandomBytesSeed);
begin
  randombytes_buf_deterministic(@Buf[0], Length(Buf), Seed);
end;

class function TBytesHelper.Same(const A, B: TBytes): Boolean;
begin
  Result := (Length(A) = Length(B)) and (sodium_memcmp(@A[0], @B[0], Length(A)) = 0);
end;

class function TBytesHelper.Same(const A, B; Len: NativeUInt): Boolean;
begin
  Result := sodium_memcmp(@A, @B, Len) = 0;
end;

class function TBytesHelper.Same<T>(const A, B: T): Boolean;
begin
  Result := sodium_memcmp(Pointer(@A), Pointer(@B), SizeOf(T)) = 0;
end;

class function TBytesHelper.Verify(const A, B: TBytes): Boolean;
begin
  SameSize(A, B);
  var LA := Length(A);
  if LA = _CRYPTO_VERIFY_16_BYTES then
    Result := crypto_verify_16(@A[0], @B[0]) = 0
  else if LA = _CRYPTO_VERIFY_32_BYTES then
    Result := crypto_verify_32(@A[0], @B[0]) = 0
  else if LA = _CRYPTO_VERIFY_64_BYTES then
    Result := crypto_verify_64(@A[0], @B[0]) = 0
  else
    raise EArgumentException.CreateFmt('Verify Helper : Size of %d bytes is not supported', [LA])
end;

class function TBytesHelper.Verify(const A, B; Len: NativeUInt): Boolean;
begin
  if Len = _CRYPTO_VERIFY_16_BYTES then
    Result := Verify16(@A, @B)
  else if Len = _CRYPTO_VERIFY_32_BYTES then
    Result := Verify32(@A, @B)
  else if Len = _CRYPTO_VERIFY_64_BYTES then
    Result := Verify64(@A, @B)
  else
    raise EArgumentException.CreateFmt('Verify Helper : Size of %d bytes is not supported', [Len]);
end;

class function TBytesHelper.Verify<T>(const A, B: T): Boolean;
begin
  Result := Verify(A, B, SizeOf(T));
end;

class function TBytesHelper.Verify16(const A, B: PByte): Boolean;
begin
  Result := crypto_verify_16(A, B) = 0;
end;

class function TBytesHelper.Verify32(const A, B: PByte): Boolean;
begin
  Result := crypto_verify_32(A, B) = 0;
end;

class function TBytesHelper.Verify64(const A, B: PByte): Boolean;
begin
  Result := crypto_verify_64(A, B) = 0;
end;

class function TBytesHelper.Pad(var B: TBytes; BlockSize: NativeUInt): Boolean;
var
  OrgLen: NativeUInt;
  OutBufLen: NativeUInt;
begin
  OrgLen := Length(B);
  OutbufLen := ((NativeUInt(Length(B)) div BlockSize) + 1) * BlockSize;
  SetLength(B, OutbufLen);
  Result := sodium_pad(OutBufLen, @B[0], OrgLen, BlockSize, OutBufLen) = 0;
  if Result then
    SetLength(B, OutBufLen);
end;

class function TBytesHelper.Unpad(var B: TBytes;
  BlockSize: NativeUInt): Boolean;
var
  UnpaddedLen: NativeUInt;
begin
  Result := sodium_unpad(UnpaddedLen, @B[0], Length(B), BlockSize) = 0;
  if Result then
    SetLength(B, UnpaddedLen);
end;

class procedure TBytesHelper.Inc(var B; Len: NativeUInt);
begin
  sodium_increment(@B, Len);
end;

class procedure TBytesHelper.Inc<T>(var B: T);
begin
  sodium_increment(@B, SizeOf(T));
end;

class procedure TBytesHelper.Inc(var B: TBytes);
begin
  sodium_increment(@B[0], Length(B));
end;

class procedure TBytesHelper.Add(var A; const B; Len: NativeUInt);
begin
  sodium_add(@A, @B, Len);
end;

class procedure TBytesHelper.Add<T>(var A: T; const B: T);
begin
  sodium_add(@A, @B, SizeOf(T));
end;

class procedure TBytesHelper.Add(var A: TBytes; const B: TBytes);
begin
  SameSize(A, B);
  sodium_add(@A[0], @B[0], Length(A))
end;

class procedure TBytesHelper.Sub(var A; const B; Len: NativeUInt);
begin
  sodium_sub(@A, @B, Len);
end;

class procedure TBytesHelper.Sub<T>(var A: T; const B: T);
begin
  sodium_sub(@A, @B, SizeOf(T));
end;

class procedure TBytesHelper.Sub(var A: TBytes; const B: TBytes);
begin
  SameSize(A, B);
  sodium_sub(@A[0], @B[0], Length(A))
end;

class function TBytesHelper.Compare(const A; const B; Len: NativeUInt): Integer;
begin
  Result := sodium_compare(@A, @B, Len);
end;

class function TBytesHelper.Compare<T>(const A, B: T): Integer;
begin
  Result := sodium_compare(@A, @B, SizeOf(T));
end;

class function TBytesHelper.Compare(const A, B: TBytes): Integer;
begin
  SameSize(A, B);
  Result := sodium_compare(@A[0], @B[0], Length(A));
end;

end.
