program test_auth;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  libsodium in '..\lib\libsodium.pas',
  Sodium.Utils in '..\lib\Sodium.Utils.pas',
  Sodium.Auth in '..\lib\Sodium.Auth.pas';

procedure test_api(Key: TCryptoAuthKey);
var
  Msg: TBytes;
  Hash: TCryptoAuthHash;
begin
  Msg := TEncoding.UTF8.GetBytes('Arbitrary data to hash');

  if crypto_auth(@Hash[0], @Msg[0], Length(Msg), @Key[0]) = 0 then
    if crypto_auth_verify(@Hash[0], @Msg[0], Length(Msg), @Key[0]) = 0 then
      WriteLn('SUCCESS (Hash=', THexEncode.FromBytes(Hash, SizeOf(Hash)), ')')
    else
      WriteLn('FAILED (VERIFY)')
  else
    WriteLn('FAILED');
end;

procedure test(Key: TCryptoAuthKey);
var
  Msg: TBytes;
  Hash: TCryptoAuthHash;
begin
  Msg := TEncoding.UTF8.GetBytes('Arbitrary data to hash');

  if TCryptoAuth.Hash(Hash, Msg, Key) then
    if TCryptoAuth.Verify(Hash, Msg, Key) then
      WriteLn('SUCCESS (Hash=', THexEncode.FromBytes(Hash, SizeOf(Hash)), ')')
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
    Write('API...'); test_api(Key);
    Write('Wrapper...'); test(Key);

    ReadLn;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
