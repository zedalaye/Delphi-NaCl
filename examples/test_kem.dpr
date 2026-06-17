program test_kem;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
{$if defined(API)}
  libsodium,
{$endif}
  Sodium.Kem,
  Sodium.Utils;

{$if defined(API)}
procedure test_api;
var
  pk: TCryptoKemPublicKey;
  sk: TCryptoKemSecretKey;
  ct: TCryptoKemCipherText;
  ss_bob: TCryptoKemSharedSecret;
  ss_alice: TCryptoKemSharedSecret;
begin
  // Alice generates a key pair and publishes pk
  if crypto_kem_keypair(@pk[0], @sk[0]) <> 0 then
  begin
    WriteLn('crypto_kem_keypair() => FAILED');
    Exit;
  end;

  // Bob encapsulates a shared secret to Alice's public key and sends ct
  if crypto_kem_enc(@ct[0], @ss_bob[0], @pk[0]) <> 0 then
  begin
    WriteLn('crypto_kem_enc() => FAILED');
    Exit;
  end;

  // Alice decapsulates ct with her secret key
  if crypto_kem_dec(@ss_alice[0], @ct[0], @sk[0]) <> 0 then
  begin
    WriteLn('crypto_kem_dec() => FAILED');
    Exit;
  end;

  if not TBytes.Same<TCryptoKemSharedSecret>(ss_alice, ss_bob) then
  begin
    WriteLn('shared secrets DIFFER => FAILED');
    Exit;
  end;

  WriteLn('SUCCESS');
  WriteLn('pk=', TBytes.ToHex(pk, SizeOf(pk)));
  WriteLn('ss=', TBytes.ToHex(ss_alice, SizeOf(ss_alice)));
end;
{$endif}

procedure test;
var
  Pk: TCryptoKemPublicKey;
  Sk: TCryptoKemSecretKey;
  Ct: TCryptoKemCipherText;
  SsBob: TCryptoKemSharedSecret;
  SsAlice: TCryptoKemSharedSecret;
begin
  // Alice generates a key pair and publishes Pk
  if not TCryptoKem.Keypair(Pk, Sk) then
  begin
    WriteLn('FAILED (KEYPAIR)');
    Exit;
  end;

  // Bob encapsulates a shared secret to Alice's public key and sends Ct
  if not TCryptoKem.Enc(Ct, SsBob, Pk) then
  begin
    WriteLn('FAILED (ENC)');
    Exit;
  end;

  // Alice decapsulates Ct with her secret key
  if not TCryptoKem.Dec(SsAlice, Ct, Sk) then
  begin
    WriteLn('FAILED (DEC)');
    Exit;
  end;

  if not TBytes.Same<TCryptoKemSharedSecret>(SsAlice, SsBob) then
  begin
    WriteLn('FAILED (SHARED SECRET MISMATCH)');
    Exit;
  end;

  WriteLn('SUCCESS');
  WriteLn('Pk=', TBytes.ToHex(Pk, SizeOf(Pk)));
  WriteLn('Ss=', TBytes.ToHex(SsAlice, SizeOf(SsAlice)));
end;

begin
  try
    WriteLn('TCryptoKem.Primitive=', TCryptoKem.Primitive);
  {$if defined(API)}
    Write('API...'); test_api;
  {$endif}
    Write('Wrapper...'); test;

    ReadLn;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
