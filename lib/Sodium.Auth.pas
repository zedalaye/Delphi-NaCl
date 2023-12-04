unit Sodium.Auth;

interface

uses
  System.SysUtils,
  libsodium, Sodium.Utils;

type
  TCryptoAuth = record
    class function Primitive: string; static;

    class function Keygen: TCryptoAuthKey; static;

    class function Hash(var &Out: TCryptoAuthHash; const &In: TBytes; const Key): Boolean; overload; static;
    class function Verify(const Hash: TCryptoAuthHash; const &In: TBytes; const Key): Boolean; static;
  end;

  TCryptoAuthHmacSha256 = record
  public
    class function Keygen: TCryptoAuthHmacSha256Key; static;

    class function Hash(var &Out: TCryptoAuthHmacSha256Hash; const &In: TBytes; const Key): Boolean; overload; static;
    class function Hash(var &Out: TCryptoAuthHmacSha256Hash; const InProc: TCryptoDataProc; const Key; KeyLen: NativeUInt): Boolean; overload; static;

    class function Verify(const Hash: TCryptoAuthHmacSha256Hash; const &In: TBytes; const Key): Boolean; static;
  end;

  TCryptoAuthHmacSha512 = record
  public
    class function Keygen: TCryptoAuthHmacSha512Key; static;

    class function Hash(var &Out: TCryptoAuthHmacSha512Hash; const &In: TBytes; const Key): Boolean; overload; static;
    class function Hash(var &Out: TCryptoAuthHmacSha512Hash; const InProc: TCryptoDataProc; const Key; KeyLen: NativeUInt): Boolean; overload; static;

    class function Verify(const Hash: TCryptoAuthHmacSha512Hash; const &In: TBytes; const Key): Boolean; static;
  end;

  TCryptoAuthHmacSha512256 = record
  public
    class function Keygen: TCryptoAuthHmacSha512256Key; static;

    class function Hash(var &Out: TCryptoAuthHmacSha512256Hash; const &In: TBytes; const Key): Boolean; overload; static;
    class function Hash(var &Out: TCryptoAuthHmacSha512256Hash; const InProc: TCryptoDataProc; const Key; KeyLen: NativeUInt): Boolean; overload; static;

    class function Verify(const Hash: TCryptoAuthHmacSha512256Hash; const &In: TBytes; const Key): Boolean; static;
  end;

implementation

{ TCryptoAuth }

class function TCryptoAuth.Primitive: string;
begin
  Result := string(crypto_auth_primitive);
end;

class function TCryptoAuth.Keygen: TCryptoAuthKey;
begin
  crypto_auth_keygen(Result);
end;

class function TCryptoAuth.Hash(var &Out: TCryptoAuthHash; const &In: TBytes;
  const Key): Boolean;
begin
  Result := crypto_auth(@&Out[0], @&In[0], Length(&In), @Key) = 0;
end;

class function TCryptoAuth.Verify(const Hash: TCryptoAuthHash; const &In: TBytes;
  const Key): Boolean;
begin
  Result := crypto_auth_verify(@Hash[0], @&In[0], Length(&In), @Key) = 0;
end;

{ TCryptoAuthHmacSha256 }

class function TCryptoAuthHmacSha256.Keygen: TCryptoAuthHmacSha256Key;
begin
  crypto_auth_hmacsha256_keygen(Result);
end;

class function TCryptoAuthHmacSha256.Hash(var &Out: TCryptoAuthHmacSha256Hash;
  const &In: TBytes; const Key): Boolean;
begin
  Result := crypto_auth_hmacsha256(@&Out[0], @&In[0], Length(&In), @Key) = 0;
end;

class function TCryptoAuthHmacSha256.Verify(const Hash: TCryptoAuthHmacSha256Hash;
  const &In: TBytes; const Key): Boolean;
begin
  Result := crypto_auth_hmacsha256_verify(@Hash[0], @&In[0], Length(&In), @Key) = 0;
end;

class function TCryptoAuthHmacSha256.Hash(var &Out: TCryptoAuthHmacSha256Hash;
  const InProc: TCryptoDataProc; const Key; KeyLen: NativeUInt): Boolean;
var
  State: TCryptoAuthHmacSha256State;
  Done: Boolean;
  Buffer: TBytes;
begin
  if crypto_auth_hmacsha256_init(State, @Key, KeyLen) <> 0 then
    Exit(False);

  Done := False;
  while not Done do
  begin
    InProc(Buffer, Done);
    if crypto_auth_hmacsha256_update(State, @Buffer[0], Length(Buffer)) <> 0 then
      Exit(False);
  end;

  Result := crypto_auth_hmacsha256_final(State, @&Out[0]) = 0;
end;

{ TCryptoAuthHmacSha512 }

class function TCryptoAuthHmacSha512.Keygen: TCryptoAuthHmacSha512Key;
begin
  crypto_auth_hmacsha512_keygen(Result);
end;

class function TCryptoAuthHmacSha512.Hash(var &Out: TCryptoAuthHmacSha512Hash;
  const &In: TBytes; const Key): Boolean;
begin
  Result := crypto_auth_hmacsha512(@&Out[0], @&In[0], Length(&In), @Key) = 0;
end;

class function TCryptoAuthHmacSha512.Verify(const Hash: TCryptoAuthHmacSha512Hash;
  const &In: TBytes; const Key): Boolean;
begin
  Result := crypto_auth_hmacsha512_verify(@Hash[0], @&In[0], Length(&In), @Key) = 0;
end;

class function TCryptoAuthHmacSha512.Hash(var &Out: TCryptoAuthHmacSha512Hash;
  const InProc: TCryptoDataProc; const Key; KeyLen: NativeUInt): Boolean;
var
  State: TCryptoAuthHmacSha512State;
  Done: Boolean;
  Buffer: TBytes;
begin
  if crypto_auth_hmacsha512_init(State, @Key, KeyLen) <> 0 then
    Exit(False);

  Done := False;
  while not Done do
  begin
    InProc(Buffer, Done);
    if crypto_auth_hmacsha512_update(State, @Buffer[0], Length(Buffer)) <> 0 then
      Exit(False);
  end;

  Result := crypto_auth_hmacsha512_final(State, @&Out[0]) = 0;
end;

{ TCryptoAuthHmacSha512256 }

class function TCryptoAuthHmacSha512256.Keygen: TCryptoAuthHmacSha512256Key;
begin
  crypto_auth_hmacsha512256_keygen(Result);
end;

class function TCryptoAuthHmacSha512256.Hash(
  var &Out: TCryptoAuthHmacSha512256Hash; const &In: TBytes;
  const Key): Boolean;
begin
  Result := crypto_auth_hmacsha512256(@&Out[0], @&In[0], Length(&In), @Key) = 0;
end;

class function TCryptoAuthHmacSha512256.Verify(
  const Hash: TCryptoAuthHmacSha512256Hash; const &In: TBytes;
  const Key): Boolean;
begin
  Result := crypto_auth_hmacsha512256_verify(@Hash[0], @&In[0], Length(&In), @Key) = 0;
end;

class function TCryptoAuthHmacSha512256.Hash(
  var &Out: TCryptoAuthHmacSha512256Hash; const InProc: TCryptoDataProc;
  const Key; KeyLen: NativeUInt): Boolean;
var
  State: TCryptoAuthHmacSha512256State;
  Done: Boolean;
  Buffer: TBytes;
begin
  if crypto_auth_hmacsha512256_init(State, @Key, KeyLen) <> 0 then
    Exit(False);

  Done := False;
  while not Done do
  begin
    InProc(Buffer, Done);
    if crypto_auth_hmacsha512256_update(State, @Buffer[0], Length(Buffer)) <> 0 then
      Exit(False);
  end;

  Result := crypto_auth_hmacsha512256_final(State, @&Out[0]) = 0;
end;

end.
