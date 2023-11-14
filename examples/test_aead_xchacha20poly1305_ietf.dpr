program test_aead_xchacha20poly1305_ietf;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  libsodium in '..\lib\libsodium.pas',
  Sodium.Utils in '..\lib\Sodium.Utils.pas',
  Sodium.Aead in '..\lib\Sodium.Aead.pas';

procedure test_api;
var
  key: TCryptoAeadXChacha20poly1305IetfKey;
  nonce: TCryptoAeadXChacha20poly1305IetfPubBytes;

  cleartext: TBytes;
  additional_data: TBytes;

  ciphertext: TBytes;
  ciphertext_len: UInt64;

  decrypted: TBytes;
  decrypted_len: UInt64;
begin
  cleartext       := TEncoding.UTF8.GetBytes('test');
  additional_data := TEncoding.UTF8.GetBytes('I should be a random string');

  crypto_aead_xchacha20poly1305_ietf_keygen(key);
  randombytes_buf(@nonce[0], SizeOf(nonce));

  SetLength(ciphertext, Length(cleartext) + _CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES);
  if crypto_aead_xchacha20poly1305_ietf_encrypt(@ciphertext[0], ciphertext_len,
                                               @cleartext[0], Length(cleartext),
                                               @additional_data[0], Length(additional_data),
                                               nil, @nonce[0], @key[0]) = 0 then
  begin
    SetLength(decrypted, Length(cleartext));
    if crypto_aead_xchacha20poly1305_ietf_decrypt(@decrypted[0], decrypted_len,
                                                 nil,
                                                 @ciphertext[0], ciphertext_len,
                                                 @additional_data[0], Length(additional_data),
                                                 @nonce[0], @key[0]) = 0 then
      WriteLn('SUCCESS')
    else
      WriteLn('FAILED (decrypt)')
  end
  else
    WriteLn('FAILED (encrypt)');
end;

procedure test;
var
  key: TCryptoAeadXChacha20poly1305IetfKey;
  nonce: TCryptoAeadXChacha20poly1305IetfPubBytes;

  cleartext: TBytes;
  ciphertext: TBytes;
  decrypted: TBytes;
begin
  cleartext := TEncoding.UTF8.GetBytes('test');

  key := TCryptoAeadXChacha20poly1305Ietf.Keygen;

  TBytes.Zero(nonce, SizeOf(nonce));
  TBytes.Random(nonce, SizeOf(nonce));

  if TCryptoAeadXChacha20poly1305Ietf.Encrypt(ciphertext, cleartext, [], nonce, key) then
    if TCryptoAeadXChacha20poly1305Ietf.Decrypt(decrypted, ciphertext, [], nonce, key) then
      WriteLn('SUCCESS')
    else
      WriteLn('FAILED (decrypt)')
  else
    WriteLn('FAILED (encrypt)');
end;

begin
  try
    Write('API...'); test_api;
    Write('Wrapper...'); test;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
