program test_pwhash;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
{$if defined(API)}
  libsodium,
{$endif}
  Sodium.PwHash,
  Sodium.Box,
  Sodium.Utils;

{$if defined(API)}
procedure test_api(const Password: string; const Salt: TCryptoPwHashSalt);
var
  key: TCryptoBoxSeed;
  hashed_password: TCryptoPwHashStr;
begin
  var P := TEncoding.UTF8.GetBytes(Password);

  if crypto_pwhash(@key[0], SizeOf(key),
                   PAnsiChar(P), Length(P),
                   @salt[0],
                   _CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE, _CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
                   _CRYPTO_PWHASH_ALG_DEFAULT) <> 0 then
    WriteLn('crypto_pwhash() => FAILED')
  else
    WriteLn('crypto_pwhash() => SUCCESS key = ', TBytes.ToHex(key, SizeOf(key)));

  if crypto_pwhash_str(hashed_password,
                       PAnsiChar(P), Length(P),
                       _CRYPTO_PWHASH_OPSLIMIT_SENSITIVE, _CRYPTO_PWHASH_MEMLIMIT_SENSITIVE) <> 0 then
    WriteLn('crypto_pwhash_str() => FAILED')
  else
  begin
    WriteLn('crypto_pwhash_str() => SUCCESS');
    WriteLn('hashed_password = ', string(hashed_password));

    if crypto_pwhash_str_verify(hashed_password, PAnsiChar(P), Length(P)) <> 0 then
      WriteLn('crypto_pwhash_str_verify() => FAILED')
    else
      WriteLn('crypto_pwhash_str_verify() => SUCCESS')
  end;
end;
{$endif}

procedure test_derive_key(const Password: string; const Salt: TCryptoPwHashSalt);
var
  Key: TCryptoBoxSeed;
begin
  if TCryptoPwHash.DeriveKey(Key, SizeOf(Key), Password, Salt) then
  begin
    WriteLn('SUCCESS');
    WriteLn('Key=', TBytes.ToHex(Key, SizeOf(Key)));
  end
  else
    WriteLn('FAILED');
end;

procedure test_hash_pwd(const Password: string);
var
  hashed_password: TCryptoPwHashStr;
begin
  if TCryptoPwHash.Generate(hashed_password, Password,
                            _CRYPTO_PWHASH_OPSLIMIT_SENSITIVE, _CRYPTO_PWHASH_MEMLIMIT_SENSITIVE) then
    if TCryptoPwHash.Verify(hashed_password, Password) then
    begin
      WriteLn('SUCCESS');
      WriteLn('PasswordStr=', string(hashed_password));
    end
    else
      WriteLn('FAILED (Verify)')
  else
    WriteLn('FAILED (Generate)');
end;

const
  PASSWORD = 'Correct Horse Battery Staple';

var
  Salt: TCryptoPwHashSalt;

begin
  try
    TBytes.Random(Salt, SizeOf(Salt));

    WriteLn('TCryptoPwHash.Primitive=', TCryptoPwHash.Primitive);
  {$if defined(API)}
    Write('API...'); test_api(PASSWORD, Salt);
  {$endif}
    Write('Wrapper (DERIVE KEY)...'); test_derive_key(PASSWORD, Salt);
    Write('Wrapper (GENERATE STR - CAN TAKE SEVERAL SECONDS)...'); test_hash_pwd(PASSWORD);
    
    ReadLn;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
