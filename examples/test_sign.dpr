program test_sign;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  libsodium in '..\lib\libsodium.pas',
  Sodium.Utils in '..\lib\Sodium.Utils.pas',
  Sodium.Sign in '..\lib\Sodium.Sign.pas';

procedure test_api(PublicKey: TCryptoSignPublicKey; SecretKey: TCryptoSignSecretKey);
var
  sig: TCryptoSignature;
begin
  WriteLn(crypto_sign_primitive);

  var M := TEncoding.UTF8.GetBytes('test');

  var signed_message: TBytes; var signed_message_len: UInt64;
  SetLength(signed_message, Length(M) + _CRYPTO_SIGN_BYTES);

  crypto_sign(@signed_message[0], signed_message_len, @M[0], Length(M), @SecretKey[0]);

  WriteLn('crypto_sign() => ', TBytes.ToHex(signed_message));

  var unsigned_message: TBytes; var unsigned_message_len: UInt64;
  SetLength(unsigned_message, Length(M));

  if crypto_sign_open(@unsigned_message[0], unsigned_message_len, @signed_message[0], signed_message_len, @PublicKey[0]) <> 0 then
    WriteLn('crypto_sign_open() => FAILED')
  else
    WriteLn('crypto_sign_open() => SUCCESS');

  var sig_len: UInt64;
  crypto_sign_detached(@sig[0], sig_len, @M[0], Length(M), @SecretKey[0]);

  WriteLn('crypto_sign_detached() => ', TBytes.ToHex(sig, sig_len));

  if crypto_sign_verify_detached(@sig[0], @M[0], Length(M), @PublicKey[0]) <> 0 then
    WriteLn('crypto_sign_verify_detached() => FAILED')
  else
    WriteLn('crypto_sign_verify_detached() => SUCCESS');
end;

procedure test(PublicKey: TCryptoSignPublicKey; SecretKey: TCryptoSignSecretKey);
var
  SignedBuf: TBytes;
  UnsignedBuf: TBytes;
  Signature: TCryptoSignature;
begin
  WriteLn(TCryptoSign.Primitive);

  if TCryptoSign.Sign(SignedBuf, TEncoding.UTF8.GetBytes('test'), SecretKey) then
    if TCryptoSign.OpenSign(UnsignedBuf, SignedBuf, PublicKey) then
      if TEncoding.UTF8.GetString(UnsignedBuf) = 'test' then
      begin
        WriteLn('Embedded Signature : SUCCESS');
        WriteLn('SignedBuf=', TBytes.ToHex(SignedBuf));
      end
      else
        WriteLn('FAILED (Buffers do not match)')
    else
      WriteLn('FAILED (TCryptoSign.OpenSign())')
  else
    WriteLn('FAILED (TCryptoSign.Sign())');

  if TCryptoSign.Detached(Signature, TEncoding.UTF8.GetBytes('test'), SecretKey) then
    if TCryptoSign.VerifyDetached(Signature, TEncoding.UTF8.GetBytes('test'), PublicKey) then
    begin
      WriteLn('Detached Signature : SUCCESS');
      WriteLn('Signature=', TBytes.ToHex(Signature, SizeOf(Signature)));
    end
    else
      WriteLn('FAILED (TCryptoSign.VerifyDetached())')
  else
    WriteLn('FAILED (TCryptoSign.Detached())');
end;

procedure test_seed(PublicKey: TCryptoSignPublicKey; SecretKey: TCryptoSignSecretKey);
var
  Seed: TCryptoSignSeed;
  TestPK: TCryptoSignPublicKey;
begin
  if TCryptoSign.SecretKeyToSeed(Seed, SecretKey) then
  begin
    WriteLn('SecretKeyToSeed : SUCCESS');
    WriteLn('Seed=', TBytes.ToHex(Seed, SizeOf(Seed)));
  end
  else
    WriteLn('FAILED (TCryptoSign.SecretKeyToSeed())');

  if TCryptoSign.SecretKeyToPublicKey(TestPK, SecretKey) then
  begin
    if TBytes.Same<TCryptoSignPublicKey>(TestPK, PublicKey) then
    begin
      WriteLn('SecretKeyToPublicKey : SUCCESS');
      WriteLn('PublicKey=', TBytes.ToHex(TestPK, SizeOf(TestPK)));
    end
    else
      WriteLn('FAILED (Public Keys do not match)');
  end
  else
    WriteLn('FAILED (TCryptoSign.SecretKetToPublicKey())');
end;

procedure test_multipart(PublicKey: TCryptoSignPublicKey; SecretKey: TCryptoSignSecretKey);
const
  M: array[0..2] of string = ('Random data ', 'to be signed ', 'split on multiple lines');
var
  Signature: TCryptoSignature;
  I: Integer;
begin
  I := 0;
  if TCryptoSign.SignMultipart(Signature,
       procedure(var Buffer: TBytes; var Done: Boolean)
       begin
         Buffer := TEncoding.UTF8.GetBytes(M[I]);
         Inc(I);
         Done := I > High(M);
       end,
       SecretKey
    )
  then
  begin
    WriteLn('SignMultipart : SUCESS');
    WriteLn('Signature=', TBytes.ToHex(Signature, SizeOf(Signature)));
  end;

  I := 0;
  if TCryptoSign.VerifyMutlipart(Signature,
       procedure(var Buffer: TBytes; var Done: Boolean)
       begin
         Buffer := TEncoding.UTF8.GetBytes(M[I]);
         Inc(I);
         Done := I > High(M);
       end,
       PublicKey
     )
  then
  begin
    WriteLn('VerifyMultipart : SUCESS');
  end;
end;

var
  pk: TCryptoSignPublicKey;
  sk: TCryptoSignSecretKey;

begin
  try
    if not TCryptoSign.Keypair(pk, sk) then
    begin
      WriteLn('TCryptoSign.Keypair() => FAILED');
      Exit;
    end;

    Write('API...');     test_api(pk, sk);
    Write('Wrapper...'); test(pk, sk);
    Write('Wrapper...'); test_seed(pk, sk);
    Write('Wrapper...'); test_multipart(pk, sk);

    ReadLn;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
