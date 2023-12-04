program test_auth;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
{$if defined(API)}
  libsodium,
{$endif}
  Sodium.Auth,
  Sodium.Utils;

{$if defined(API)}
procedure test_api(Key: TCryptoAuthKey);
var
  Msg: TBytes;
  Hash: TCryptoAuthHash;
begin
  Msg := TEncoding.UTF8.GetBytes('Arbitrary data to hash');

  if crypto_auth(@Hash[0], @Msg[0], Length(Msg), @Key[0]) = 0 then
    if crypto_auth_verify(@Hash[0], @Msg[0], Length(Msg), @Key[0]) = 0 then
      WriteLn('SUCCESS (Hash=', TBytes.ToHex(Hash, SizeOf(Hash)), ')')
    else
      WriteLn('FAILED (VERIFY)')
  else
    WriteLn('FAILED');
end;
{$endif}

procedure test(Key: TCryptoAuthKey);
var
  Msg: TBytes;
  Hash: TCryptoAuthHash;
begin
  Msg := TEncoding.UTF8.GetBytes('Arbitrary data to hash');

  if TCryptoAuth.Hash(Hash, Msg, Key) then
    if TCryptoAuth.Verify(Hash, Msg, Key) then
      WriteLn('SUCCESS (Hash=', TBytes.ToHex(Hash, SizeOf(Hash)), ')')
    else
      WriteLn('FAILED (VERIFY)')
  else
    WriteLn('FAILED');
end;

var
  Key: TCryptoAuthKey;

begin
  try
    Key := TCryptoAuth.Keygen;

  	WriteLn('TCryptoAuth.Primitive=', TCryptoAuth.Primitive);
  {$if defined(API)}
    Write('API...'); test_api(Key);
  {$endif}
    Write('Wrapper...'); test(Key);

    ReadLn;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
