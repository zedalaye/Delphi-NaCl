program test_auth_hmac_sha512256;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  libsodium in '..\lib\libsodium.pas',
  Sodium.Utils in '..\lib\Sodium.Utils.pas',
  Sodium.Auth in '..\lib\Sodium.Auth.pas';

procedure test_api(Key: TCryptoAuthHmacSha512256Key);
var
  Msg: TBytes;
  Hash: TCryptoAuthHmacSha512256Hash;
begin
  Msg := TEncoding.UTF8.GetBytes('Arbitrary data to hash');

  if crypto_auth_hmacsha512256(@Hash[0], @Msg[0], Length(Msg), @Key[0]) = 0 then
    if crypto_auth_hmacsha512256_verify(@Hash[0], @Msg[0], Length(Msg), @Key[0]) = 0 then
      WriteLn('SUCCESS (Hash=', TBytes.ToHex(Hash, SizeOf(Hash)), ')')
    else
      WriteLn('FAILED (VERIFY)')
  else
    WriteLn('FAILED');
end;

procedure test(Key: TCryptoAuthHmacSha512256Key);
var
  Msg: TBytes;
  Hash: TCryptoAuthHmacSha512256Hash;
begin
  Msg := TEncoding.UTF8.GetBytes('Arbitrary data to hash');

  if TCryptoAuthHmacSha512256.Hash(Hash, Msg, Key) then
    if TCryptoAuthHmacSha512256.Verify(Hash, Msg, Key) then
      WriteLn('SUCCESS (Hash=', TBytes.ToHex(Hash, SizeOf(Hash)), ')')
    else
      WriteLn('FAILED (VERIFY)')
  else
    WriteLn('FAILED');
end;

procedure test_multiple_blocks(Key: TCryptoAuthHmacSha512256Key);
const
  M: array[0..2] of string = ('Arbitrary ', 'data ', 'to hash');
var
  Hash: TCryptoAuthHmacSha512256Hash;
  I: Integer;
begin
  I := 0;
  if TCryptoAuthHmacSha512256.Hash(Hash,
       procedure(var Buffer: TBytes; var Done: Boolean)
       begin
         Buffer := TEncoding.UTF8.GetBytes(M[I]);
         Inc(I);
         Done := I > High(M);
       end,
       Key, SizeOf(Key)
     )
  then
    WriteLn('SUCCESS (Hash=', TBytes.ToHex(Hash, SizeOf(Hash)), ')')
  else
    WriteLn('FAILED');
end;

var
  Key: TCryptoAuthHmacSha512256Key;

begin
  try
    Key := TCryptoAuthHmacSha512256.Keygen;

    Write('API...'); test_api(Key);
    Write('Wrapper...'); test(Key);
    Write('Wrapper (MULTIPLE BLOCKS)...'); test_multiple_blocks(Key);

    ReadLn;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
