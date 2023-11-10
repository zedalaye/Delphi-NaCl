unit Sodium.Hash;

interface
uses
  System.SysUtils,
  libsodium, Sodium.Utils;

type
  TCryptoHash = record
    class function Sha256(var &Out: TCryptoHashSha256Hash; &In: TBytes): Boolean; static;
    class function Sha512(var &Out: TCryptoHashSha512Hash; &In: TBytes): Boolean; static;
  end;

  TCryptoGenericHash = record
    class function Keygen: TCryptoGenericHashKey; overload; static;
    class function Keygen(Len: NativeUInt): TBytes; overload; static;

    class function Hash(var &Out: TCryptoGenericHashHash; &In: TBytes): Boolean; overload; static;
    class function Hash(var &Out: TCryptoGenericHashHash; &In: TBytes; const Key: TCryptoGenericHashKey): Boolean; overload; static;
    class function Hash(var &Out: TCryptoGenericHashHash; &In: TBytes; const Key: TBytes): Boolean; overload; static;
  end;

implementation

{ TCryptoHash }

class function TCryptoHash.Sha256(var &Out: TCryptoHashSha256Hash; &In: TBytes): Boolean;
begin
  Result := crypto_hash_sha256(@&Out[0], @&In[0], Length(&In)) = 0;
end;

class function TCryptoHash.Sha512(var Out: TCryptoHashSha512Hash;
  &In: TBytes): Boolean;
begin
  Result := crypto_hash_sha512(@&Out[0], @&In[0], Length(&In)) = 0;
end;

{ TCryptoGenericHash }

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

class function TCryptoGenericHash.Hash(var Out: TCryptoGenericHashHash;
  &In: TBytes): Boolean;
begin
  Result := crypto_generichash(@&Out[0], SizeOf(&Out),
                               @&In[0], Length(&In),
                               nil, 0) = 0;
end;

class function TCryptoGenericHash.Hash(var &Out: TCryptoGenericHashHash;
  &In: TBytes; const Key: TCryptoGenericHashKey): Boolean;
begin
  Result := crypto_generichash(@&Out[0], SizeOf(&Out),
                               @&In[0], Length(&In),
                               @Key[0], Length(Key)) = 0;
end;

class function TCryptoGenericHash.Hash(var Out: TCryptoGenericHashHash;
  &In: TBytes; const Key: TBytes): Boolean;
begin
  if Length(Key) > _CRYPTO_GENERICHASH_KEYBYTES_MAX then
    raise EArgumentException.CreateFmt('Key Length must be <= %d', [_CRYPTO_GENERICHASH_KEYBYTES_MAX]);

  Result := crypto_generichash(@&Out[0], SizeOf(&Out),
                               @&In[0], Length(&In),
                               @Key[0], Length(Key)) = 0;
end;

end.
