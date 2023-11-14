program test_secretbox;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  libsodium in '..\lib\libsodium.pas',
  Sodium.Utils in '..\lib\Sodium.Utils.pas',
  Sodium.SecretBox in '..\lib\Sodium.SecretBox.pas';

procedure test_api(Key: TCryptoSecretBoxKey; Nonce: TCryptoSecretBoxNonce);
var
  ciphertext: TBytes;
  decrypted: TBytes;
begin
  var M := TEncoding.UTF8.GetBytes('test');

  SetLength(ciphertext, _CRYPTO_SECRETBOX_MACBYTES + Length(M));
  crypto_secretbox_easy(@ciphertext[0], @M[0], Length(M), @nonce[0], @key[0]);

  SetLength(decrypted, Length(M));
  if crypto_secretbox_open_easy(@decrypted[0], @ciphertext[0], Length(ciphertext), @nonce[0], @key[0]) <> 0 then
    WriteLn('crypto_secretbox() => FAILED')
  else
    WriteLn('crypto_secretbox() => SUCCESS');
end;

procedure test(Key: TCryptoSecretBoxKey; Nonce: TCryptoSecretBoxNonce);
var
  CipherBuf, ClearBuf: TBytes;
begin
  if TCryptoSecretBox.Easy(CipherBuf, TEncoding.UTF8.GetBytes('test'), Nonce, Key) then
    if TCryptoSecretBox.OpenEasy(ClearBuf, CipherBuf, Nonce, Key) then
    begin
      if TEncoding.UTF8.GetString(ClearBuf) = 'test' then
      begin
        WriteLn('SUCCESS');
        WriteLn('CipheredData=', THexEncode.FromBytes(CipherBuf));
      end
      else
        WriteLn('FAILED (Buffers do not match)');
    end
    else
      WriteLn('FAILED (TCryptoSecretBox.OpenEasy)')
  else
    WriteLn('FAILED (TCryptoSecretBox.Easy)');
end;

procedure test_detached(Key: TCryptoSecretBoxKey; Nonce: TCryptoSecretBoxNonce);
var
  CipherBuf, ClearBuf: TBytes;
  Mac: TCryptoSecretBoxMac;
begin
  if TCryptoSecretBox.Detached(CipherBuf, Mac, TEncoding.UTF8.GetBytes('test'), Nonce, Key) then
    if TCryptoSecretBox.OpenDetached(ClearBuf, CipherBuf, Mac, Nonce, Key) then
    begin
      if TEncoding.UTF8.GetString(ClearBuf) = 'test' then
      begin
        WriteLn('SUCCESS');
        WriteLn('AuthenticationTag=', THexEncode.FromBytes(Mac, SizeOf(Mac)));
        WriteLn('CipheredData=', THexEncode.FromBytes(CipherBuf));
      end
      else
        WriteLn('FAILED (Buffers do not match)');
    end
    else
      WriteLn('FAILED (TCryptoSecretBox.OpenDetached)')
  else
    WriteLn('FAILED (TCryptoSecretBox.Detached)');
end;

var
  Key: TCryptoSecretBoxKey;
  Nonce: TCryptoSecretBoxNonce;

begin
  try
    Key := TCryptoSecretBox.Keygen;
    TBytes.Random(Nonce, SizeOf(TCryptoSecretBoxNonce));

    WriteLn('TCryptoSecretBox.Primitive=', TCryptoSecretBox.Primitive);
    Write('API...'); test_api(Key, Nonce);
    Write('Wrapper...'); test(Key, Nonce);
    Write('Wrapper (DETACHED)...'); test_detached(Key, Nonce);

    ReadLn;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
