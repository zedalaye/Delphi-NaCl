program test_auth_hmac_sha256;

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
procedure test_api(Key: TCryptoAuthHmacSha256Key);
var
  Msg: TBytes;
  Hash: TCryptoAuthHmacSha256Hash;
begin
  Msg := TEncoding.UTF8.GetBytes('Arbitrary data to hash');

  if crypto_auth_hmacsha256(@Hash[0], @Msg[0], Length(Msg), @Key[0]) = 0 then
    if crypto_auth_hmacsha256_verify(@Hash[0], @Msg[0], Length(Msg), @Key[0]) = 0 then
      WriteLn('SUCCESS (Hash=', TBytes.ToHex(Hash, SizeOf(Hash)), ')')
    else
      WriteLn('FAILED (VERIFY)')
  else
    WriteLn('FAILED');
end;
{$endif}

procedure test(Key: TCryptoAuthHmacSha256Key);
var
  Msg: TBytes;
  Hash: TCryptoAuthHmacSha256Hash;
begin
  Msg := TEncoding.UTF8.GetBytes('Arbitrary data to hash');

  if TCryptoAuthHmacSha256.Hash(Hash, Msg, Key) then
    if TCryptoAuthHmacSha256.Verify(Hash, Msg, Key) then
      WriteLn('SUCCESS (Hash=', TBytes.ToHex(Hash, SizeOf(Hash)), ')')
    else
      WriteLn('FAILED (VERIFY)')
  else
    WriteLn('FAILED');
end;

procedure test_multiple_blocks(Key: TCryptoAuthHmacSha256Key);
const
  M: array[0..2] of string = ('Arbitrary ', 'data ', 'to hash');
var
  Hash: TCryptoAuthHmacSha256Hash;
  I: Integer;
begin
  I := 0;
  if TCryptoAuthHmacSha256.Hash(Hash,
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
  Key: TCryptoAuthHmacSha256Key;

begin
  try
    Key := TCryptoAuthHmacSha256.Keygen;

  {$if defined(API)}
    Write('API...'); test_api(Key);
  {$endif}
    Write('Wrapper...'); test(Key);
    Write('Wrapper (MULTIPLE BLOCKS)...'); test_multiple_blocks(Key);

    ReadLn;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
