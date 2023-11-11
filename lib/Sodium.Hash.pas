unit Sodium.Hash;

interface

uses
  System.SysUtils,
  libsodium, Sodium.Utils;

type
  TCryptoHash = record
    class function Primitive: string; static;

    class function Sha256(var &Out: TCryptoHashSha256Hash; &In: TBytes): Boolean; overload; static;
    class function Sha256(var &Out: TCryptoHashSha256Hash; const InProc: TCryptoDataProc): Boolean; overload; static;

    class function Sha512(var &Out: TCryptoHashSha512Hash; &In: TBytes): Boolean; overload; static;
    class function Sha512(var &Out: TCryptoHashSha512Hash; const InProc: TCryptoDataProc): Boolean; overload; static;

    class function Default(var &Out: TCryptoHashHash; &In: TBytes): Boolean; overload; static;
  end;

  TCryptoGenericHash = record
  private
    class function Hash(var &Out: TCryptoGenericHashHash; &In: TBytes; const Key: PByte; KeyLen: NativeUInt): Boolean; overload; static;
    class function Hash(var &Out: TCryptoGenericHashHash; InProc: TCryptoDataProc; const Key: PByte; KeyLen: NativeUInt): Boolean; overload; static;
  public
    class function Primitive: string; static;

    class function Keygen: TCryptoGenericHashKey; overload; static;
    class function Keygen(Len: NativeUInt): TBytes; overload; static;

    class function Hash(var &Out: TCryptoGenericHashHash; &In: TBytes): Boolean; overload; static;
    class function Hash(var &Out: TCryptoGenericHashHash; &In: TBytes; const Key: TCryptoGenericHashKey): Boolean; overload; static;
    class function Hash(var &Out: TCryptoGenericHashHash; &In: TBytes; const Key: TBytes): Boolean; overload; static;

    class function Hash(var &Out: TCryptoGenericHashHash; const InProc: TCryptoDataProc): Boolean; overload; static;
    class function Hash(var &Out: TCryptoGenericHashHash; const InProc: TCryptoDataProc; const Key: TCryptoGenericHashKey): Boolean; overload; static;
    class function Hash(var &Out: TCryptoGenericHashHash; const InProc: TCryptoDataProc; const Key: TBytes): Boolean; overload; static;
  end;

implementation

{ TCryptoHash }

class function TCryptoHash.Primitive: string;
begin
  Result := string(crypto_hash_primitive);
end;

class function TCryptoHash.Sha256(var &Out: TCryptoHashSha256Hash; &In: TBytes): Boolean;
begin
  Result := crypto_hash_sha256(@&Out[0], @&In[0], Length(&In)) = 0;
end;

class function TCryptoHash.Sha256(var &Out: TCryptoHashSha256Hash;
  const InProc: TCryptoDataProc): Boolean;
var
  State: TCryptoHashSha256State;
  Buffer: TBytes;
  Done: Boolean;
begin
  if crypto_hash_sha256_init(State) <> 0 then
    Exit(False);

  Done := False;
  while not Done do
  begin
    InProc(Buffer, Done);
    if crypto_hash_sha256_update(State, @Buffer[0], Length(Buffer)) <> 0 then
      Exit(False);
  end;

  Result := crypto_hash_sha256_final(State, @&Out[0]) = 0;
end;

class function TCryptoHash.Sha512(var &Out: TCryptoHashSha512Hash;
  &In: TBytes): Boolean;
begin
  Result := crypto_hash_sha512(@&Out[0], @&In[0], Length(&In)) = 0;
end;

class function TCryptoHash.Sha512(var &Out: TCryptoHashSha512Hash;
  const InProc: TCryptoDataProc): Boolean;
var
  State: TCryptoHashSha512State;
  Buffer: TBytes;
  Done: Boolean;
begin
  if crypto_hash_sha512_init(State) <> 0 then
    Exit(False);

  Done := False;
  while not Done do
  begin
    InProc(Buffer, Done);
    if crypto_hash_sha512_update(State, @Buffer[0], Length(Buffer)) <> 0 then
      Exit(False);
  end;

  Result := crypto_hash_sha512_final(State, @&Out[0]) = 0;
end;

class function TCryptoHash.Default(var &Out: TCryptoHashHash;
  &In: TBytes): Boolean;
begin
  Result := crypto_hash(@&Out[0], @&In[0], Length(&In)) = 0;
end;

{ TCryptoGenericHash }

class function TCryptoGenericHash.Primitive: string;
begin
  Result := string(crypto_generichash_primitive);
end;

class function TCryptoGenericHash.Keygen: TCryptoGenericHashKey;
begin
  crypto_generichash_keygen(Result);
end;

class function TCryptoGenericHash.Keygen(Len: NativeUInt): TBytes;
begin
  if Len > _CRYPTO_GENERICHASH_KEYBYTES_MAX then
    raise EArgumentException.CreateFmt('Len must be <= %d', [_CRYPTO_GENERICHASH_KEYBYTES_MAX]);

  SetLength(Result, Len);
  randombytes_buf(@Result[0], Len);
end;

class function TCryptoGenericHash.Hash(var &Out: TCryptoGenericHashHash;
  &In: TBytes; const Key: PByte; KeyLen: NativeUInt): Boolean;
begin
  if KeyLen > _CRYPTO_GENERICHASH_KEYBYTES_MAX then
    raise EArgumentException.CreateFmt('Key Length must be <= %d', [_CRYPTO_GENERICHASH_KEYBYTES_MAX]);

  Result := crypto_generichash(@&Out[0], SizeOf(&Out),
                               @&In[0], Length(&In),
                               Key, KeyLen) = 0;
end;

class function TCryptoGenericHash.Hash(var &Out: TCryptoGenericHashHash;
  &In: TBytes): Boolean;
begin
  Result := TCryptoGenericHash.Hash(&Out, &In, nil, 0);
end;

class function TCryptoGenericHash.Hash(var &Out: TCryptoGenericHashHash;
  &In: TBytes; const Key: TCryptoGenericHashKey): Boolean;
begin
  Result := TCryptoGenericHash.Hash(&Out, &In, @Key[0], SizeOf(Key));
end;

class function TCryptoGenericHash.Hash(var &Out: TCryptoGenericHashHash;
  &In: TBytes; const Key: TBytes): Boolean;
begin
  Result := TCryptoGenericHash.Hash(&Out, &In, @Key[0], Length(Key));
end;

class function TCryptoGenericHash.Hash(var &Out: TCryptoGenericHashHash;
  InProc: TCryptoDataProc; const Key: PByte; KeyLen: NativeUInt): Boolean;
var
  StateP: Pointer;
  State: PCryptoGenericHashState;
  Buffer: TBytes;
  Done: Boolean;
begin
  if KeyLen > _CRYPTO_GENERICHASH_KEYBYTES_MAX then
    raise EArgumentException.CreateFmt('Key Length must be <= %d', [_CRYPTO_GENERICHASH_KEYBYTES_MAX]);

  State := GetAlignedCryptoGenericHashState(StateP);
  try
    if crypto_generichash_init(State^, Key, KeyLen, SizeOf(&Out)) <> 0 then
      Exit(False);

    Done := False;
    while not Done do
    begin
      InProc(Buffer, Done);
      if crypto_generichash_update(State^, @Buffer[0], Length(Buffer)) <> 0 then
        Exit(False);
    end;

    Result := crypto_generichash_final(State^, @&Out[0], SizeOf(&Out)) = 0;
  finally
    FreeMem(StateP);
  end;
end;

class function TCryptoGenericHash.Hash(var &Out: TCryptoGenericHashHash;
  const InProc: TCryptoDataProc): Boolean;
begin
  Result := TCryptoGenericHash.Hash(&Out, InProc, nil, 0);
end;

class function TCryptoGenericHash.Hash(var &Out: TCryptoGenericHashHash;
  const InProc: TCryptoDataProc; const Key: TCryptoGenericHashKey): Boolean;
begin
  Result := TCryptoGenericHash.Hash(&Out, InProc, @Key[0], SizeOf(Key));
end;

class function TCryptoGenericHash.Hash(var &Out: TCryptoGenericHashHash;
  const InProc: TCryptoDataProc; const Key: TBytes): Boolean;
begin
  Result := TCryptoGenericHash.Hash(&Out, InProc, @Key[0], Length(Key));
end;

end.
