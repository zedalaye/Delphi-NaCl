program test_ipcrypt;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils, System.AnsiStrings,
{$if defined(API)}
  libsodium,
{$endif}
  Sodium.Utils, Sodium.IpCrypt;

const
  IPV4 = '127.0.0.1';

{$if defined(API)}
procedure test_api;
var
  Key: TCryptoIpCryptKey;
  IpBin: TCryptoIpBin;
  CipheredIp: TCryptoIpCrypt;
  DecipheredIp: TCryptoIpBin;
begin
  WriteLn('Deterministic');

  if TSodiumIp.ToBin(IPV4, IpBin) then
  begin
    crypto_ipcrypt_keygen(Key);

    crypto_ipcrypt_encrypt(CipheredIp, IpBin, Key);
    crypto_ipcrypt_decrypt(DecipheredIp, CipheredIp, Key);

    WriteLn(TSodiumIp.ToIp(DecipheredIp), ' => ', TBytes.ToHex(CipheredIp, SizeOf(CipheredIp)));
  end
  else
    WriteLn('[ERROR] Failed to encode IP');

  WriteLn;
end;

procedure test_api_nd;
var
  Key: TCryptoIpCryptNdKey;
  Tweak: TCryptoIpCryptNdTweak;
  IpBin: TCryptoIpBin;
  CipheredIp: TCryptoIpCryptNd;
  DecipheredIp: TCryptoIpBin;
begin
  WriteLn('Non Deterministic (ND)');

  if TSodiumIp.ToBin(IPV4, IpBin) then
  begin
    crypto_ipcrypt_nd_keygen(Key);

    TBytes.Random(Tweak, SizeOf(Tweak));

    crypto_ipcrypt_nd_encrypt(CipheredIp, IpBin, @Tweak[0], Key);
    crypto_ipcrypt_nd_decrypt(DecipheredIp, CipheredIp, Key);

    WriteLn(TSodiumIp.ToIp(DecipheredIp), ' => ', TBytes.ToHex(CipheredIp, SizeOf(CipheredIp)));
  end
  else
    WriteLn('[ERROR] Failed to encode IP');

  WriteLn;
end;

procedure test_api_ndx;
var
  Key: TCryptoIpCryptNdxKey;
  Tweak: TCryptoIpCryptNdxTweak;
  IpBin: TCryptoIpBin;
  CipheredIp: TCryptoIpCryptNdx;
  DecipheredIp: TCryptoIpBin;
begin
  WriteLn('Extended Non Deterministic (NDX)');

  if TSodiumIp.ToBin(IPV4, IpBin) then
  begin
    crypto_ipcrypt_ndx_keygen(Key);

    TBytes.Random(Tweak, SizeOf(Tweak));

    crypto_ipcrypt_ndx_encrypt(CipheredIp, IpBin, Tweak, Key);
    crypto_ipcrypt_ndx_decrypt(DecipheredIp, CipheredIp, Key);

    WriteLn(TSodiumIp.ToIp(DecipheredIp), ' => ', TBytes.ToHex(CipheredIp, SizeOf(CipheredIp)));
  end
  else
    WriteLn('[ERROR] Failed to encode IP');

  WriteLn;
end;

procedure test_api_pfx;
const
  IPV4_1 = '10.120.30.50';
  IPV4_2 = '10.120.30.55';
var
  Key: TCryptoIpCryptPfxKey;
  IpBin1, IpBin2: TCryptoIpBin;
  CipheredIp1, CipheredIp2: TCryptoIpCryptPfx;
  DecipheredIp1, DecipheredIp2: TCryptoIpBin;
begin
  WriteLn('Prefix Preserved (PFX)');

  if TSodiumIp.ToBin(IPV4_1, IpBin1) and TSodiumIp.ToBin(IPV4_2, IpBin2) then
  begin
    crypto_ipcrypt_pfx_keygen(Key);

    crypto_ipcrypt_pfx_encrypt(CipheredIp1, IpBin1, Key);
    crypto_ipcrypt_pfx_decrypt(DecipheredIp1, CipheredIp1, Key);

    crypto_ipcrypt_pfx_encrypt(CipheredIp2, IpBin2, Key);
    crypto_ipcrypt_pfx_decrypt(DecipheredIp2, CipheredIp2, Key);

    WriteLn(TSodiumIp.ToIp(DecipheredIp1), ' => ', TSodiumIp.ToIp(CipheredIp1));
    WriteLn(TSodiumIp.ToIp(DecipheredIp2), ' => ', TSodiumIp.ToIp(CipheredIp2));
  end
  else
    WriteLn('[ERROR] Failed to encode IP');

  WriteLn;
end;
{$endif}

procedure test_deterministic;
var
  Key: TCryptoIpCryptKey;
  CipheredIp: TCryptoIpCrypt;
  DecipheredIp: string;
begin
  WriteLn('Deterministic');

  Key := TCryptoIpCryptDeterministic.Keygen;
  if TCryptoIpCryptDeterministic.Encrypt(CipheredIp, IPV4, Key) then
    if TCryptoIpCryptDeterministic.Decrypt(DecipheredIp, CipheredIp, Key) then
      WriteLn(DecipheredIp, ' => ', TBytes.ToHex(CipheredIp, SizeOf(CipheredIp)))
    else
      WriteLn('[ERROR] Decryption failed')
  else
    WriteLn('[ERROR] Encryption failed');

  WriteLn;
end;

procedure test_nd;
var
  Key: TCryptoIpCryptNdKey;
  CipheredIp: TCryptoIpCryptNd;
  DecipheredIp: string;
begin
  WriteLn('Non Deterministic (ND)');

  Key := TCryptoIpCryptNonDeterministic.Keygen;
  if TCryptoIpCryptNonDeterministic.Encrypt(CipheredIp, IPV4, Key) then
    if TCryptoIpCryptNonDeterministic.Decrypt(DecipheredIp, CipheredIp, Key) then
      WriteLn(DecipheredIp, ' => ', TBytes.ToHex(CipheredIp, SizeOf(CipheredIp)))
    else
      WriteLn('[ERROR] Decryption failed')
  else
    WriteLn('[ERROR] Encryption failed');

  WriteLn;
end;

procedure test_ndx;
var
  Key: TCryptoIpCryptNdxKey;
  CipheredIp: TCryptoIpCryptNdx;
  DecipheredIp: string;
begin
  WriteLn('Extended Non Deterministic (NDX)');

  Key := TCryptoIpCryptExtendedNonDeterministic.Keygen;
  if TCryptoIpCryptExtendedNonDeterministic.Encrypt(CipheredIp, IPV4, Key) then
    if TCryptoIpCryptExtendedNonDeterministic.Decrypt(DecipheredIp, CipheredIp, Key) then
      WriteLn(DecipheredIp, ' => ', TBytes.ToHex(CipheredIp, SizeOf(CipheredIp)))
    else
      WriteLn('[ERROR] Decryption failed')
  else
    WriteLn('[ERROR] Encryption failed');

  WriteLn;
end;

procedure test_pfx;
const
  IPV4_1 = '10.120.30.50';
  IPV4_2 = '10.120.30.55';
var
  Key: TCryptoIpCryptPfxKey;
  CipheredIp1, CipheredIp2: TCryptoIpCryptPfx;
  DecipheredIp1, DecipheredIp2: string;
begin
  WriteLn('Prefix Preserved (PFX)');

  Key := TCryptoIpCryptPrefixPreserved.Keygen;

  if TCryptoIpCryptPrefixPreserved.Encrypt(CipheredIp1, IPV4_1, Key) then
    if TCryptoIpCryptPrefixPreserved.Decrypt(DecipheredIp1, CipheredIp1, Key) then
      WriteLn(DecipheredIp1, ' => ', TSodiumIp.ToIp(CipheredIp1))
    else
      WriteLn('[ERROR] Decryption failed')
  else
    WriteLn('[ERROR] Encryption failed');

  if TCryptoIpCryptPrefixPreserved.Encrypt(CipheredIp2, IPV4_2, Key) then
    if TCryptoIpCryptPrefixPreserved.Decrypt(DecipheredIp2, CipheredIp2, Key) then
      WriteLn(DecipheredIp2, ' => ', TSodiumIp.ToIp(CipheredIp2))
    else
      WriteLn('[ERROR] Decryption failed')
  else
    WriteLn('[ERROR] Encryption failed');

  WriteLn;
end;

begin
  try
  {$if defined(API)}
    test_api;
    test_api_nd;
    test_api_ndx;
    test_api_pfx;
  {$endif}

    test_deterministic;
    test_nd;
    test_ndx;
    test_pfx;

    ReadLn;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
