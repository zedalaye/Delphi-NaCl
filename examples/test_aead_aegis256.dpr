program test_aead_aegis256;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  libsodium in '..\lib\libsodium.pas',
  Sodium.Utils in '..\lib\Sodium.Utils.pas',
  Sodium.Aead in '..\lib\Sodium.Aead.pas';

procedure test_api;
var
  key: TCryptoAeadAegis256Key;
  nonce: TCryptoAeadAegis256PubBytes;

  cleartext: TBytes;
  additional_data: TBytes;

  ciphertext: TBytes;
  ciphertext_len: UInt64;

  decrypted: TBytes;
  decrypted_len: UInt64;
begin
  cleartext       := TEncoding.UTF8.GetBytes('test');
  additional_data := TEncoding.UTF8.GetBytes('I should be a random string');

  crypto_aead_aegis256_keygen(key);
  randombytes_buf(@nonce[0], SizeOf(nonce));

  SetLength(ciphertext, Length(cleartext) + _CRYPTO_AEAD_AEGIS256_ABYTES);
  if crypto_aead_aegis256_encrypt(@ciphertext[0], ciphertext_len,
                                  @cleartext[0], Length(cleartext),
                                  @additional_data[0], Length(additional_data),
                                  nil, @nonce[0], @key[0]) = 0 then
  begin
    SetLength(decrypted, Length(cleartext));
    if crypto_aead_aegis256_decrypt(@decrypted[0], decrypted_len,
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
  key: TCryptoAeadAegis256Key;
  nonce: TCryptoAeadAegis256PubBytes;

  cleartext: TBytes;
  ciphertext: TBytes;
  decrypted: TBytes;
begin
  cleartext := TEncoding.UTF8.GetBytes('test');

  key := TCryptoAeadAegis256.Keygen;

  TZero.Fill(nonce, SizeOf(nonce));
  TRandom.Bytes(nonce, SizeOf(nonce));

  if TCryptoAeadAegis256.Encrypt(ciphertext, cleartext, [], nonce, key) then
    if TCryptoAeadAegis256.Decrypt(decrypted, ciphertext, [], nonce, key) then
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
