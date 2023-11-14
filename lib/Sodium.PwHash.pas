unit Sodium.PwHash;

interface

uses
  System.SysUtils,
  libsodium, Sodium.Utils;

type
  TCryptoPwHashAlgorithm = (
    Argon2i13  = _CRYPTO_PWHASH_ALG_ARGON2I13,
    Argon2id13 = _CRYPTO_PWHASH_ARGON2ID_ALG_ARGON2ID13
  );

const
  // _CRYPTO_PWHASH_ALG_DEFAULT = _CRYPTO_PWHASH_ALG_ARGON2ID13;
  TCryptoPwHashDefaultAlgorithm = TCryptoPwHashAlgorithm.Argon2id13;

type
  TCryptoPwHash = record
     class function Primitive: string; static;

     class function DeriveKey(Key: PByte; KeyLen: UInt64;
                              const Password: string;
                              const Salt: TCryptoPwHashSalt;
                              OpsLimit: UInt64 = _CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE;
                              MemLimit: NativeUInt = _CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE;
                              Algorithm: TCryptoPwHashAlgorithm = TCryptoPwHashDefaultAlgorithm): Boolean; static;

     class function Generate(var &Out: TCryptoPwHashStr;
                             const Password: string;
                             OpsLimit: UInt64 = _CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE;
                             MemLimit: NativeUInt = _CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE): Boolean; overload; static;

     class function Generate(var &Out: TCryptoPwHashStr;
                             const Password: string;
                             Algorithm: TCryptoPwHashAlgorithm;
                             OpsLimit: UInt64 = _CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE;
                             MemLimit: NativeUInt = _CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE): Boolean; overload; static;

     class function Verify(const &In: TCryptoPwHashStr;
                           const Password: string): Boolean; overload; static;
  end;

implementation

{ TCryptoPwHash }

class function TCryptoPwHash.Primitive: string;
begin
  Result := string(crypto_pwhash_primitive);
end;

class function TCryptoPwHash.DeriveKey(Key: PByte; KeyLen: UInt64;
  const Password: string; const Salt: TCryptoPwHashSalt; OpsLimit: UInt64;
  MemLimit: NativeUInt; Algorithm: TCryptoPwHashAlgorithm): Boolean;
var
  Pwd: UTF8String;
begin
  if (KeyLen < crypto_pwhash_bytes_min) or (KeyLen > crypto_pwhash_bytes_max) then
    raise EArgumentException.CreateFmt('KeyLen of %d bytes is not valid', [KeyLen]);

  Pwd := UTF8String(Password);

  if Length(Pwd) < crypto_pwhash_passwd_min then
    raise EArgumentException.Create('Password is too short');

  if Length(Pwd) > crypto_pwhash_passwd_max then
    raise EArgumentException.Create('Password is too big');

  Result := crypto_pwhash(Key, KeyLen,
              PAnsiChar(Pwd), Length(Pwd),
              @Salt[0],
              OpsLimit, MemLimit,
              Ord(Algorithm)) = 0;
end;

class function TCryptoPwHash.Generate(var &Out: TCryptoPwHashStr;
  const Password: string; OpsLimit: UInt64; MemLimit: NativeUInt): Boolean;
var
  Pwd: UTF8String;
begin
  Pwd := UTF8String(Password);

  if Length(Pwd) < crypto_pwhash_passwd_min then
    raise EArgumentException.Create('Password is too short');

  if Length(Pwd) > crypto_pwhash_passwd_max then
    raise EArgumentException.Create('Password is too big');

  Result := crypto_pwhash_str(&Out, PAnsiChar(Pwd), Length(Pwd),
              OpsLimit, MemLimit) = 0;
end;

class function TCryptoPwHash.Generate(var Out: TCryptoPwHashStr;
  const Password: string; Algorithm: TCryptoPwHashAlgorithm;
  OpsLimit: UInt64; MemLimit: NativeUInt): Boolean;
var
  Pwd: UTF8String;
begin
  Pwd := UTF8String(Password);

  if Length(Pwd) < crypto_pwhash_passwd_min then
    raise EArgumentException.Create('Password is too short');

  if Length(Pwd) > crypto_pwhash_passwd_max then
    raise EArgumentException.Create('Password is too big');

  Result := crypto_pwhash_str_alg(&Out, PAnsiChar(Pwd), Length(Pwd),
              OpsLimit, MemLimit, Ord(Algorithm)) = 0;
end;

class function TCryptoPwHash.Verify(const &In: TCryptoPwHashStr;
  const Password: string): Boolean;
var
  Pwd: UTF8String;
begin
  Pwd := UTF8String(Password);
  Result := crypto_pwhash_str_verify(&In, PAnsiChar(Pwd), Length(Pwd)) = 0;
end;

end.
