unit Sodium.IpCrypt;

interface

uses
  System.SysUtils,
  libsodium, Sodium.Utils;

type
  TCryptoIpCryptKey = libsodium.TCryptoIpCryptKey;
  TCryptoIpCrypt = libsodium.TCryptoIpCrypt;

  TCryptoIpCryptDeterministic = record
    class function Keygen: TCryptoIpCryptKey; static;

    class function Encrypt(var CipheredIp: TCryptoIpCrypt; const Ip: string; const Key: TCryptoIpCryptKey): Boolean; static;
    class function Decrypt(var Ip: string; const CipheredIp: TCryptoIpCrypt; const Key: TCryptoIpCryptKey): Boolean; static;
  end;

  TCryptoIpCryptNdKey = libsodium.TCryptoIpCryptNdKey;
  TCryptoIpCryptNd = libsodium.TCryptoIpCryptNd;

  TCryptoIpCryptNonDeterministic = record
    class function Keygen: TCryptoIpCryptNdKey; static;

    class function Encrypt(var CipheredIp: TCryptoIpCryptNd; const Ip: string; const Key: TCryptoIpCryptNdKey): Boolean; static;
    class function Decrypt(var Ip: string; const CipheredIp: TCryptoIpCryptNd; const Key: TCryptoIpCryptNdKey): Boolean; static;
  end;

  TCryptoIpCryptNdxKey = libsodium.TCryptoIpCryptNdxKey;
  TCryptoIpCryptNdx = libsodium.TCryptoIpCryptNdx;

  TCryptoIpCryptExtendedNonDeterministic = record
    class function Keygen: TCryptoIpCryptNdxKey; static;

    class function Encrypt(var CipheredIp: TCryptoIpCryptNdx; const Ip: string; const Key: TCryptoIpCryptNdxKey): Boolean; static;
    class function Decrypt(var Ip: string; const CipheredIp: TCryptoIpCryptNdx; const Key: TCryptoIpCryptNdxKey): Boolean; static;
  end;

  TCryptoIpCryptPfxKey = libsodium.TCryptoIpCryptPfxKey;
  TCryptoIpCryptPfx = libsodium.TCryptoIpCryptPfx;

  TCryptoIpCryptPrefixPreserved = record
    class function Keygen: TCryptoIpCryptPfxKey; static;

    class function Encrypt(var CipheredIp: TCryptoIpCryptPfx; const Ip: string; const Key: TCryptoIpCryptPfxKey): Boolean; static;
    class function Decrypt(var Ip: string; const CipheredIp: TCryptoIpCryptPfx; const Key: TCryptoIpCryptPfxKey): Boolean; static;
  end;
  
implementation

{ TCryptoIpCrypt }

class function TCryptoIpCryptDeterministic.Keygen: TCryptoIpCryptKey;
begin
  crypto_ipcrypt_keygen(Result);
end;

class function TCryptoIpCryptDeterministic.Encrypt(var CipheredIp: TCryptoIpCrypt;
  const Ip: string; const Key: TCryptoIpCryptKey): Boolean;
var
  BinIp: TCryptoIpBin;
begin
  if TSodiumIp.ToBin(Ip, BinIp) then
  begin
    crypto_ipcrypt_encrypt(CipheredIp, BinIp, Key);
    Result := True;
  end
  else
    Result := False;
end;

class function TCryptoIpCryptDeterministic.Decrypt(var Ip: string;
  const CipheredIp: TCryptoIpCrypt; const Key: TCryptoIpCryptKey): Boolean;
var
  BinIp: TCryptoIpBin;
begin
  crypto_ipcrypt_decrypt(BinIp, CipheredIp, Key);
  Ip := TSodiumIp.ToIp(BinIp);
  Result := Ip <> '';
end;

{ TCryptoIpCryptNonDeterministic }

class function TCryptoIpCryptNonDeterministic.Keygen: TCryptoIpCryptNdKey;
begin
  crypto_ipcrypt_nd_keygen(Result);
end;

class function TCryptoIpCryptNonDeterministic.Encrypt(
  var CipheredIp: TCryptoIpCryptNd; const Ip: string;
  const Key: TCryptoIpCryptNdKey): Boolean;
var
  BinIp: TCryptoIpBin;
  Tweak: TCryptoIpCryptNdTweak;
begin
  if TSodiumIp.ToBin(Ip, BinIp) then
  begin
    TBytes.Random(Tweak, SizeOf(Tweak));
    crypto_ipcrypt_nd_encrypt(CipheredIp, BinIp, @Tweak[0], Key);
    Result := True;
  end
  else
    Result := False;
end;

class function TCryptoIpCryptNonDeterministic.Decrypt(var Ip: string;
  const CipheredIp: TCryptoIpCryptNd; const Key: TCryptoIpCryptNdKey): Boolean;
var
  BinIp: TCryptoIpBin;
begin
  crypto_ipcrypt_nd_decrypt(BinIp, CipheredIp, Key);
  Ip := TSodiumIp.ToIp(BinIp);
  Result := Ip <> '';
end;

{ TCryptoIpCryptExtendedNonDeterministic }

class function TCryptoIpCryptExtendedNonDeterministic.Keygen: TCryptoIpCryptNdxKey;
begin
  crypto_ipcrypt_ndx_keygen(Result);
end;

class function TCryptoIpCryptExtendedNonDeterministic.Encrypt(
  var CipheredIp: TCryptoIpCryptNdx; const Ip: string;
  const Key: TCryptoIpCryptNdxKey): Boolean;
var
  BinIp: TCryptoIpBin;
  Tweak: TCryptoIpCryptNdxTweak;
begin
  if TSodiumIp.ToBin(Ip, BinIp) then
  begin
    TBytes.Random(Tweak, SizeOf(Tweak));
    crypto_ipcrypt_ndx_encrypt(CipheredIp, BinIp, Tweak, Key);
    Result := True;
  end
  else
    Result := False;
end;

class function TCryptoIpCryptExtendedNonDeterministic.Decrypt(var Ip: string;
  const CipheredIp: TCryptoIpCryptNdx;
  const Key: TCryptoIpCryptNdxKey): Boolean;
var
  BinIp: TCryptoIpBin;
begin
  crypto_ipcrypt_ndx_decrypt(BinIp, CipheredIp, Key);
  Ip := TSodiumIp.ToIp(BinIp);
  Result := Ip <> '';
end;

{ TCryptoIpCryptPrefixPreserved }

class function TCryptoIpCryptPrefixPreserved.Keygen: TCryptoIpCryptPfxKey;
begin
  crypto_ipcrypt_pfx_keygen(Result);
end;

class function TCryptoIpCryptPrefixPreserved.Encrypt(
  var CipheredIp: TCryptoIpCryptPfx; const Ip: string;
  const Key: TCryptoIpCryptPfxKey): Boolean;
var
  BinIp: TCryptoIpBin;
begin
  if TSodiumIp.ToBin(Ip, BinIp) then
  begin
    crypto_ipcrypt_pfx_encrypt(CipheredIp, BinIp, Key);
    Result := True;
  end
  else
    Result := False;
end;

class function TCryptoIpCryptPrefixPreserved.Decrypt(var Ip: string;
  const CipheredIp: TCryptoIpCryptPfx;
  const Key: TCryptoIpCryptPfxKey): Boolean;
var
  BinIp: TCryptoIpBin;
begin
  crypto_ipcrypt_pfx_decrypt(BinIp, CipheredIp, Key);
  Ip := TSodiumIp.ToIp(BinIp);
  Result := Ip <> '';
end;

end.