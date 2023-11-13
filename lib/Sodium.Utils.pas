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

    class function Bytes(Len: NativeUInt): TBytes; overload; static;
    class procedure Bytes(Buf: PByte; Len: NativeUInt); overload; static;
    class procedure Bytes(const Buf; Len: NativeUInt); overload; static;
  end;

  TZero = record
    class function Fill(Len: NativeUInt): TBytes; overload; static;
    class procedure Fill(Buf: PByte; Len: NativeUInt); overload; static;
    class procedure Fill(const Buf; Len: NativeUInt); overload; static;
  end;

  TBytesHelper = record helper for TBytes
    class function Same(const B1, B2: TBytes): Boolean; overload; static;
    class function Same<T>(const B1, B2: T): Boolean; overload; static;

    class function Verify(const B1, B2: TBytes): Boolean; overload; static;
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

class function TRandom.Bytes(Len: NativeUInt): TBytes;
begin
  SetLength(Result, Len);
  randombytes_buf(@Result[0], Len);
end;

class procedure TRandom.Bytes(Buf: PByte; Len: NativeUInt);
begin
  randombytes_buf(Buf, Len);
end;

class procedure TRandom.Bytes(const Buf; Len: NativeUInt);
begin
  randombytes_buf(@Buf, Len);
end;

{ TZero }

class function TZero.Fill(Len: NativeUInt): TBytes;
begin
  SetLength(Result, Len);
  sodium_memzero(@Result[0], Len);
end;

class procedure TZero.Fill(Buf: PByte; Len: NativeUInt);
begin
  sodium_memzero(Buf, Len);
end;

class procedure TZero.Fill(const Buf; Len: NativeUInt);
begin
  sodium_memzero(@Buf, Len);
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

class function TBytesHelper.Same(const B1, B2: TBytes): Boolean;
begin
  Result := (Length(B1) = Length(B2)) and (sodium_memcmp(@B1[0], @B2[0], Length(B1)) = 0);
end;

class function TBytesHelper.Same<T>(const B1, B2: T): Boolean;
begin
  Result := sodium_memcmp(Pointer(@B1), Pointer(@B2), SizeOf(T)) = 0;
end;

class function TBytesHelper.Verify(const B1, B2: TBytes): Boolean;
begin
  var LB1 := Length(B1);
  if LB1 = Length(B2) then
    if LB1 = _CRYPTO_VERIFY_16_BYTES then
      Result := crypto_verify_16(@B1[0], @B2[0]) = 0
    else if LB1 = _CRYPTO_VERIFY_32_BYTES then
      Result := crypto_verify_32(@B1[0], @B2[0]) = 0
    else if LB1 = _CRYPTO_VERIFY_64_BYTES then
      Result := crypto_verify_64(@B1[0], @B2[0]) = 0
    else
      raise EArgumentException.CreateFmt('Verify Helper : Size of %d bytes is not supported', [LB1])
  else
    raise EArgumentException.CreateFmt('Verify Helper : SizeOf(B2)=%d bytes <> SizeOf(B1)=%d bytes', [Length(B2), LB1]);
end;

end.
