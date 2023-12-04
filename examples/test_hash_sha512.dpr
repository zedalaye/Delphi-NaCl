program test_hash_sha512;

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
  &Out: TCryptoHashSha512Hash;
begin
  var M := TEncoding.UTF8.GetBytes('test');
  if crypto_hash_sha512(@&Out[0], @M[0], Length(M)) = 0 then
    WriteLn('SUCCESS (Hash=', TBytes.ToHex(&Out, SizeOf(&Out)), ')')
  else
    WriteLn('FAILED');
end;
{$endif}

procedure test;
var
  &Out: TCryptoHashSha512Hash;
begin
  if TCryptoHash.Sha512(&Out, TEncoding.UTF8.GetBytes('test')) then
    WriteLn('SUCCESS (Hash=', TBytes.ToHex(&Out, SizeOf(&Out)), ')')
  else
    WriteLn('FAILED');
end;

procedure test_multiple_blocks;
const
  M: array[0..2] of string = ('Message', 'split over', '3 lines');
var
  &Out: TCryptoHashSha512Hash;
begin
  var I := 0;
  if TCryptoHash.Sha512(&Out,
       procedure(var Buffer: TBytes; var Done: Boolean)
       begin
         Buffer := TEncoding.UTF8.GetBytes(M[I]);
         Done := I >= High(M);
         Inc(I);
       end
     )
  then
    WriteLn('SUCCESS (Hash=', TBytes.ToHex(&Out, SizeOf(&Out)), ')')
  else
    WriteLn('FAILED');
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
