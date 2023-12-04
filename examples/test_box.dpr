program test_box;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
{$if defined(API)}
  libsodium,
{$endif}
  Sodium.Box,
  Sodium.Utils;

{$if defined(API)}
procedure test_api(Nonce: TCryptoBoxNonce;
  AlicePublicKey: TCryptoBoxPublicKey; AliceSecretKey: TCryptoBoxSecretKey;
  BobPublicKey: TCryptoBoxPublicKey; BobSecretKey: TCryptoBoxSecretKey);
var
  M: TBytes;
  ciphertext, cleartext: TBytes;
begin
  M := TEncoding.UTF8.GetBytes('test');
  SetLength(ciphertext, _CRYPTO_BOX_MACBYTES + Length(M));

  if crypto_box_easy(@ciphertext[0], @M[0], Length(M), @Nonce[0], @BobPublicKey[0], @AliceSecretKey[0]) <> 0 then
  begin
    WriteLn('crypto_box_easy() => FAILED');
    Exit;
  end;

  SetLength(cleartext, Length(M));
  if crypto_box_open_easy(@cleartext[0], @ciphertext[0], Length(ciphertext), @Nonce[0], @AlicePublicKey[0], @BobSecretKey[0]) <> 0 then
    WriteLn('crypto_box_open_easy() => FAILED')
  else
    WriteLn('crypto_box() => OK');
end;
{$endif}

procedure test(Nonce: TCryptoBoxNonce;
  AlicePublicKey: TCryptoBoxPublicKey; AliceSecretKey: TCryptoBoxSecretKey;
  BobPublicKey: TCryptoBoxPublicKey; BobSecretKey: TCryptoBoxSecretKey);
var
  CipherBuf, ClearBuf: TBytes;
begin
  if TCryptoBox.Easy(CipherBuf, TEncoding.UTF8.GetBytes('test'), Nonce, BobPublicKey, AliceSecretKey) then
    if TCryptoBox.OpenEasy(ClearBuf, CipherBuf, Nonce, AlicePublicKey, BobSecretKey) then
      if TEncoding.UTF8.GetString(ClearBuf) = 'test' then
        WriteLn('SUCCESS')
      else
        WriteLn('FAILED (CipherBuf <> ''test'')')
    else
      WriteLn('FAILED (TCryptoBox.OpenEasy())')
  else
    WriteLn('FAILED (TCryptoBox.Easy())');
end;

procedure test_detached(Nonce: TCryptoBoxNonce;
  AlicePublicKey: TCryptoBoxPublicKey; AliceSecretKey: TCryptoBoxSecretKey;
  BobPublicKey: TCryptoBoxPublicKey; BobSecretKey: TCryptoBoxSecretKey);
var
  CipherBuf, ClearBuf: TBytes;
  AuthTag: TCryptoBoxMac;
begin
  if TCryptoBox.Detached(CipherBuf, AuthTag, TEncoding.UTF8.GetBytes('test'), Nonce, BobPublicKey, AliceSecretKey) then
    if TCryptoBox.OpenDetached(ClearBuf, CipherBuf, AuthTag, Nonce, AlicePublicKey, BobSecretKey) then
      if TEncoding.UTF8.GetString(ClearBuf) = 'test' then
        WriteLn('SUCCESS')
      else
        WriteLn('FAILED (CipherBuf <> ''test'')')
    else
      WriteLn('FAILED (TCryptoBox.OpenDetached())')
  else
    WriteLn('FAILED (TCryptoBox.Detached())');
end;

procedure test_seal(RecipientPublicKey: TCryptoBoxPublicKey; RecipientSecretKey: TCryptoBoxSecretKey);
var
  CipherBuf, ClearBuf: TBytes;
begin
  if TCryptoBox.Seal(CipherBuf, TEncoding.UTF8.GetBytes('test'), RecipientPublicKey) then
    if TCryptoBox.OpenSeal(ClearBuf, CipherBuf, RecipientPublicKey, RecipientSecretKey) then
      if TEncoding.UTF8.GetString(ClearBuf) = 'test' then
        WriteLn('SUCCESS')
      else
        WriteLn('FAILED (CipherBuf <> ''test'')')
    else
      WriteLn('FAILED (TCryptoBox.OpenSeal())')
  else
    WriteLn('FAILED (TCryptoBox.Seal())');
end;

var
  AlicePublicKey: TCryptoBoxPublicKey;
  AliceSecretKey: TCryptoBoxSecretKey;

  BobPublicKey: TCryptoBoxPublicKey;
  BobSecretKey: TCryptoBoxSecretKey;

  Nonce: TCryptoBoxNonce;

begin
  try
    if not TCryptoBox.Keypair(AlicePublicKey, AliceSecretKey) then
    begin
      WriteLn('CryptoBox.Keypair(ALICE) FAILED');
      Exit;
    end;

    if not TCryptoBox.Keypair(BobPublicKey, BobSecretKey) then
    begin
      WriteLn('CryptoBox.Keypair(BOB) FAILED');
      Exit;
    end;

    Nonce := TCryptoBox.Nonce;

  {$if defined(API)}
    Write('API...'); test_api(Nonce, AlicePublicKey, AliceSecretKey, BobPublicKey, BobSecretKey);
  {$endif}
    Write('Wrapper...'); test(Nonce, AlicePublicKey, AliceSecretKey, BobPublicKey, BobSecretKey);
    Write('Wrapper (DETACHED)...'); test_detached(Nonce, AlicePublicKey, AliceSecretKey, BobPublicKey, BobSecretKey);
    Write('Wrapper (SEAL)...'); test_seal(BobPublicKey, BobSecretKey);

    ReadLn;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
