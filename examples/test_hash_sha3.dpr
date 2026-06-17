program test_hash_sha3;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
{$if defined(API)}
  libsodium,
{$endif}
  Sodium.Hash,
  Sodium.Utils;

{$if defined(API)}
procedure test_api;
var
  Hash256: TCryptoHashSha3256Hash;
  Hash512: TCryptoHashSha3512Hash;
begin
  var M := TEncoding.UTF8.GetBytes('test');

  if crypto_hash_sha3256(@Hash256[0], @M[0], Length(M)) = 0 then
    WriteLn('SUCCESS (SHA3-256=', TBytes.ToHex(Hash256, SizeOf(Hash256)), ')')
  else
    WriteLn('FAILED (SHA3-256)');

  if crypto_hash_sha3512(@Hash512[0], @M[0], Length(M)) = 0 then
    WriteLn('SUCCESS (SHA3-512=', TBytes.ToHex(Hash512, SizeOf(Hash512)), ')')
  else
    WriteLn('FAILED (SHA3-512)');
end;
{$endif}

procedure test;
var
  Out256: TCryptoHashSha3256Hash;
  Out512: TCryptoHashSha3512Hash;
begin
  if TCryptoHash.Sha3256(Out256, TEncoding.UTF8.GetBytes('test')) then
    WriteLn('SUCCESS (SHA3-256=', TBytes.ToHex(Out256, SizeOf(Out256)), ')')
  else
    WriteLn('FAILED (SHA3-256)');

  if TCryptoHash.Sha3512(Out512, TEncoding.UTF8.GetBytes('test')) then
    WriteLn('SUCCESS (SHA3-512=', TBytes.ToHex(Out512, SizeOf(Out512)), ')')
  else
    WriteLn('FAILED (SHA3-512)');
end;

procedure test_multiple_blocks;
const
  M: array[0..2] of string = ('Message', 'split over', '3 lines');
var
  Out256: TCryptoHashSha3256Hash;
  Out512: TCryptoHashSha3512Hash;
begin
  var I := 0;
  if TCryptoHash.Sha3256(Out256,
       procedure(var Buffer: TBytes; var Done: Boolean)
       begin
         Buffer := TEncoding.UTF8.GetBytes(M[I]);
         Done := I >= High(M);
         Inc(I);
       end
     )
  then
    WriteLn('SUCCESS (SHA3-256=', TBytes.ToHex(Out256, SizeOf(Out256)), ')')
  else
    WriteLn('FAILED (SHA3-256)');

  I := 0;
  if TCryptoHash.Sha3512(Out512,
       procedure(var Buffer: TBytes; var Done: Boolean)
       begin
         Buffer := TEncoding.UTF8.GetBytes(M[I]);
         Done := I >= High(M);
         Inc(I);
       end
     )
  then
    WriteLn('SUCCESS (SHA3-512=', TBytes.ToHex(Out512, SizeOf(Out512)), ')')
  else
    WriteLn('FAILED (SHA3-512)');
end;

begin
  try
  {$if defined(API)}
    Write('API...'); test_api;
  {$endif}
    Write('Wrapper...'); test;
    Write('Wrapper...'); test_multiple_blocks;

    ReadLn;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
