unit Sodium.Kdf;

interface

uses
  System.SysUtils,
  libsodium, Sodium.Utils;

type
  TCryptoKdf = record
    class function Primitive: string; static;

    class function Keygen: TCryptoKdfKey; static;

    class function DeriveFromKey(
      var SubKey: TBytes; SubKeyLen: NativeUInt; SubKeyId: UInt64;
      const Context: TCryptoKdfContext;
      const MasterKey: TCryptoKdfKey): Boolean; static;
  end;

  TCryptoKdfHkdfSha256 = record
    class function Keygen: TCryptoKdfHkdfSha256Key; static;

    class function Extract(var MasterKey: TCryptoKdfHkdfSha256Key;
      const Salt: TBytes; const InputKeyingMaterial: TBytes): Boolean; overload; static;
    class function Extract(var MasterKey: TCryptoKdfHkdfSha256Key;
      const Salt: TBytes; const InputKeyingMaterialProc: TCryptoDataProc): Boolean; overload; static;

    class function Expand(var SubKey: TBytes; SubKeyLen: NativeUInt;
      const Context: RawByteString; const MasterKey: TCryptoKdfHkdfSha256Key): Boolean; static;
  end;

  TCryptoKdfHkdfSha512 = record
    class function Keygen: TCryptoKdfHkdfSha512Key; static;

    class function Extract(var MasterKey: TCryptoKdfHkdfSha512Key;
      const Salt: TBytes; const InputKeyingMaterial: TBytes): Boolean; overload; static;
    class function Extract(var MasterKey: TCryptoKdfHkdfSha512Key;
      const Salt: TBytes; const InputKeyingMaterialProc: TCryptoDataProc): Boolean; overload; static;

    class function Expand(var SubKey: TBytes; SubKeyLen: NativeUInt;
      const Context: RawByteString; const MasterKey: TCryptoKdfHkdfSha512Key): Boolean; static;
  end;

implementation

{ TCryptoKdf }

class function TCryptoKdf.Primitive: string;
begin
  Result := string(crypto_kdf_primitive);
end;

class function TCryptoKdf.Keygen: TCryptoKdfKey;
begin
  crypto_kdf_keygen(Result);
end;

class function TCryptoKdf.DeriveFromKey(var SubKey: TBytes;
  SubKeyLen: NativeUInt; SubKeyId: UInt64;
  const Context: TCryptoKdfContext; const MasterKey: TCryptoKdfKey): Boolean;
begin
  SetLength(SubKey, SubKeyLen);
  Result := crypto_kdf_derive_from_key(@SubKey[0], SubKeyLen, SubKeyId,
              Context, MasterKey) = 0;
end;

{ TCryptoKdfHkdfSha256 }

class function TCryptoKdfHkdfSha256.Keygen: TCryptoKdfHkdfSha256Key;
begin
  crypto_kdf_hkdf_sha256_keygen(Result);
end;

class function TCryptoKdfHkdfSha256.Extract(
  var MasterKey: TCryptoKdfHkdfSha256Key; const Salt,
  InputKeyingMaterial: TBytes): Boolean;
begin
  Result := crypto_kdf_hkdf_sha256_extract(MasterKey,
              BytesPointer(Salt), Length(Salt),
              @InputKeyingMaterial[0], Length(InputKeyingMaterial)) = 0;
end;

class function TCryptoKdfHkdfSha256.Extract(
  var MasterKey: TCryptoKdfHkdfSha256Key; const Salt: TBytes;
  const InputKeyingMaterialProc: TCryptoDataProc): Boolean;
var
  State: TCryptoKdfHkdfSha256State;
  Done: Boolean;
  Buf: TBytes;
begin
  if crypto_kdf_hkdf_sha256_extract_init(State, BytesPointer(Salt), Length(Salt)) <> 0 then
    Exit(False);

  Done := False;
  while not Done do
  begin
    InputKeyingMaterialProc(Buf, Done);
    if crypto_kdf_hkdf_sha256_extract_update(State, @Buf[0], Length(Buf)) <> 0 then
      Exit(False);
  end;

  Result := crypto_kdf_hkdf_sha256_extract_final(State, MasterKey) = 0;
end;

class function TCryptoKdfHkdfSha256.Expand(var SubKey: TBytes;
  SubKeyLen: NativeUInt; const Context: RawByteString;
  const MasterKey: TCryptoKdfHkdfSha256Key): Boolean;
begin
  SetLength(SubKey, SubKeyLen);
  Result := crypto_kdf_hkdf_sha256_expand(@SubKey[0], SubKeyLen,
              @Context[1], Length(Context),
              MasterKey) = 0;
end;

{ TCryptoKdfHkdfSha512 }

class function TCryptoKdfHkdfSha512.Keygen: TCryptoKdfHkdfSha512Key;
begin
  crypto_kdf_hkdf_sha512_keygen(Result);
end;

class function TCryptoKdfHkdfSha512.Extract(
  var MasterKey: TCryptoKdfHkdfSha512Key; const Salt,
  InputKeyingMaterial: TBytes): Boolean;
begin
  Result := crypto_kdf_hkdf_sha512_extract(MasterKey,
              BytesPointer(Salt), Length(Salt),
              @InputKeyingMaterial[0], Length(InputKeyingMaterial)) = 0;
end;

class function TCryptoKdfHkdfSha512.Extract(
  var MasterKey: TCryptoKdfHkdfSha512Key; const Salt: TBytes;
  const InputKeyingMaterialProc: TCryptoDataProc): Boolean;
var
  State: TCryptoKdfHkdfSha512State;
  Done: Boolean;
  Buf: TBytes;
begin
  if crypto_kdf_hkdf_sha512_extract_init(State, BytesPointer(Salt), Length(Salt)) <> 0 then
    Exit(False);

  Done := False;
  while not Done do
  begin
    InputKeyingMaterialProc(Buf, Done);
    if crypto_kdf_hkdf_sha512_extract_update(State, @Buf[0], Length(Buf)) <> 0 then
      Exit(False);
  end;

  Result := crypto_kdf_hkdf_sha512_extract_final(State, MasterKey) = 0;
end;

class function TCryptoKdfHkdfSha512.Expand(var SubKey: TBytes;
  SubKeyLen: NativeUInt; const Context: RawByteString;
  const MasterKey: TCryptoKdfHkdfSha512Key): Boolean;
begin
  SetLength(SubKey, SubKeyLen);
  Result := crypto_kdf_hkdf_sha512_expand(@SubKey[0], SubKeyLen,
              @Context[1], Length(Context),
              MasterKey) = 0;
end;

end.
