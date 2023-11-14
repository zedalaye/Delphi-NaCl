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

  THexEncode = record
    class function FromBytes(Buf: PByte; BufLen: NativeUInt): string; overload; static;
    class function FromBytes(const Buf: TBytes): string; overload; static;
    class function FromBytes(const Buf; Len: NativeUInt): string; overload; static;
  end;

  TBase64Variant = (
    Original = SODIUM_BASE64_VARIANT_ORIGINAL,
    UrlSafe = SODIUM_BASE64_VARIANT_URLSAFE
  );

  TBase64Encode = record
  private
    class function VariantOption(Variant: TBase64Variant; Padding: Boolean): Integer; static;
  public
    class function FromBytes(Buf: PByte; BufLen: NativeUInt;
      Variant: TBase64Variant = TBase64Variant.Original; Padding: Boolean = True): string; overload; static;
    class function FromBytes(const Buf: TBytes;
      Variant: TBase64Variant = TBase64Variant.Original; Padding: Boolean = True): string; overload; static;
    class function FromBytes(const Buf; Len: NativeUInt;
      Variant: TBase64Variant = TBase64Variant.Original; Padding: Boolean = True): string; overload; static;

    class function ToBytes(var Buf: TBytes; const B64: string;
      Variant: TBase64Variant = TBase64Variant.Original; Padding: Boolean = True): Boolean; overload; static;
  end;

  TRandom = record
    class function ImplementationName: string; static;
  end;

  TBytesHelper = record helper for TBytes
    class procedure SameSize(const A, B: TBytes); static;

    class function FromBuf(const Buf; Len: NativeUInt): TBytes; overload; static;
    class function FromBuf<T>(const Buf: T): TBytes; overload; static;

    class function Zero(Len: NativeUInt): TBytes; overload; static;
    class procedure Zero(var Buf: TBytes); overload; static;
    class procedure Zero(var Buf; Len: NativeUInt); overload; static;
    class procedure Zero<T>(var Buf: T); overload; static;

    class function IsZero(const Buf: TBytes): Boolean; overload; static;
    class function IsZero(const Buf; Len: NativeUInt): Boolean; overload; static;
    class function IsZero<T>(const Buf: T): Boolean; overload; static;

    class function Random: Cardinal; overload; static;
    class function RandomUniform(UpperBound: Cardinal): Cardinal; static;

    class function Random(Len: NativeUInt): TBytes; overload; static;
    class procedure Random(var Buf: TBytes); overload; static;
    class procedure Random(var Buf; Len: NativeUInt); overload; static;
    class procedure Random<T>(var Buf: T); overload; static;

    class procedure Random(var Buf: TBytes; const Seed: TRandomBytesSeed); overload; static;
    class procedure Random(var Buf; Len: NativeUInt; const Seed: TRandomBytesSeed); overload; static;
    class procedure Random<T>(var Buf: T; const Seed: TRandomBytesSeed); overload; static;

    class function Same(const A, B: TBytes): Boolean; overload; static;
    class function Same(const A, B; Len: NativeUInt): Boolean; overload; static;
    class function Same<T>(const A, B: T): Boolean; overload; static;

    class function Verify16(const A, B: PByte): Boolean; static;
    class function Verify32(const A, B: PByte): Boolean; static;
    class function Verify64(const A, B: PByte): Boolean; static;

    class function Verify(const A, B: TBytes): Boolean; overload; static;
    class function Verify(const A, B; Len: NativeUInt): Boolean; overload; static;
    class function Verify<T>(const A, B: T): Boolean; overload; static;

    class function Pad(var B: TBytes; BlockSize: NativeUInt): Boolean; static;
    class function Unpad(var B: TBytes; BlockSize: NativeUInt): Boolean; static;

    class procedure Inc(var B: TBytes); overload; static;
    class procedure Inc(var B; Len: NativeUInt); overload; static;
    class procedure Inc<T>(var B: T); overload; static;

    class procedure Add(var A: TBytes; const B: TBytes); overload; static;
    class procedure Add(var A; const B; Len: NativeUInt); overload; static;
    class procedure Add<T>(var A: T; const B: T); overload; static;

    class procedure Sub(var A: TBytes; const B: TBytes); overload; static;
    class procedure Sub(var A; const B; Len: NativeUInt); overload; static;
    class procedure Sub<T>(var A: T; const B: T); overload; static;

    class function Compare(const A, B: TBytes): Integer; overload; static;
    class function Compare(const A; const B; Len: NativeUInt): Integer; overload; static;
    class function Compare<T>(const A: T; const B: T): Integer; overload; static;
  end;

{ Because @B[0] when B is empty is not nil }
function BytesPointer(B: TBytes): PByte;

implementation

function BytesPointer(B: TBytes): PByte;
begin
  if Length(B) = 0 then
    Result := nil
  else
    Result := @B[0];
end;

{ THexEncode }

class function THexEncode.FromBytes(Buf: PByte; BufLen: NativeUInt): string;
var
  Hex: TBytes;
begin
  SetLength(Hex, BufLen * 2 + 1); // bin2hex adds an ending \0
  sodium_bin2hex(@Hex[0], Length(Hex), Buf, BufLen);
  Result := string(PAnsiChar(Hex));
end;

class function THexEncode.FromBytes(const Buf: TBytes): string;
begin
  Result := THexEncode.FromBytes(@Buf[0], Length(Buf));
end;

class function THexEncode.FromBytes(const Buf; Len: NativeUInt): string;
begin
  Result := THexEncode.FromBytes(PByte(@Buf), Len);
end;

{ TRandom }

class function TRandom.ImplementationName: string;
begin
  Result := string(randombytes_implementation_name);
end;

{ TBase64Encode }

class function TBase64Encode.VariantOption(Variant: TBase64Variant;
  Padding: Boolean): Integer;
const
  PADDING_OFFSET: array[Boolean] of Integer = (2, 0); { (False, True) }
begin
  Result := Ord(Variant) + PADDING_OFFSET[Padding];
end;

class function TBase64Encode.FromBytes(Buf: PByte; BufLen: NativeUInt;
  Variant: TBase64Variant; Padding: Boolean): string;
var
  V: Integer;
  B64: AnsiString;
begin
  V := VariantOption(Variant, Padding);
  SetLength(B64, _SODIUM_BASE64_ENCODED_LEN(BufLen, V));
  sodium_bin2base64(PAnsiChar(B64), Length(B64), Buf, BufLen, V);
  Result := string(B64);
end;

class function TBase64Encode.FromBytes(const Buf: TBytes;
  Variant: TBase64Variant; Padding: Boolean): string;
begin
  Result := TBase64Encode.FromBytes(@Buf[0], Length(Buf), Variant, Padding);
end;

class function TBase64Encode.FromBytes(const Buf; Len: NativeUInt;
  Variant: TBase64Variant; Padding: Boolean): string;
begin
  Result := TBase64Encode.FromBytes(PByte(@Buf), Len, Variant, Padding);
end;

class function TBase64Encode.ToBytes(var Buf: TBytes; const B64: string;
  Variant: TBase64Variant; Padding: Boolean): Boolean;
var
  V: Integer;
  BufLen: NativeUInt;
  B64P, B64Err: PAnsiChar;
begin
  V := VariantOption(Variant, Padding);

  SetLength(Buf, Length(B64) div 4 * 3);
  B64P := PAnsiChar(AnsiString(B64));

  Result := sodium_base642bin(
    @Buf[0], Length(Buf),
    B64P, Length(B64),    // base64 strings does not contain extended characters
    PAnsiChar(' '#13#10), // ignore whitespace and newline characters
    BufLen,
    B64Err,
    V
  ) = 0;

  if not Result then
    raise EArgumentException.CreateFmt(
      'Invalid Base64 string (unexpected char ''%s'' at pos %d)',
      [B64Err^, Integer(B64Err - B64P) +1]
    );

  SetLength(Buf, BufLen);
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

class procedure TBytesHelper.SameSize(const A, B: TBytes);
begin
  if Length(A) <> Length(B) then
    raise EArgumentException.CreateFmt('SizeOf(A)=%d bytes <> SizeOf(B)=%d bytes', [Length(A), Length(B)]);
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

class function TBytesHelper.IsZero(const Buf; Len: NativeUInt): Boolean;
begin
  Result := sodium_is_zero(@Buf, Len) = 1; // !
end;

class function TBytesHelper.IsZero(const Buf: TBytes): Boolean;
begin
  Result := sodium_is_zero(@Buf[0], Length(Buf)) = 1; // !
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
