program test_hash_sha256;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  libsodium in '..\lib\libsodium.pas',
  Sodium.Utils in '..\lib\Sodium.Utils.pas',
  Sodium.Hash in '..\lib\Sodium.Hash.pas';

procedure test_api;
var
  &Out: TCryptoHashSha256Hash;
begin
  var M := TEncoding.UTF8.GetBytes('test');
  if crypto_hash_sha256(@&Out[0], @M[0], Length(M)) = 0 then
    WriteLn('SUCCESS (Hash=', THexEncode.FromBytes(&Out, SizeOf(&Out)), ')')
  else
    WriteLn('FAILED');
end;

procedure test;
var
  &Out: TCryptoHashSha256Hash;
begin
  if TCryptoHash.Sha256(&Out, TEncoding.UTF8.GetBytes('test')) then
    WriteLn('SUCCESS (Hash=', THexEncode.FromBytes(&Out, SizeOf(&Out)), ')')
  else
    WriteLn('FAILED');
end;

procedure test_multiple_blocks;
const
  M: array[0..2] of string = ('Message', 'split over', '3 lines');
var
  &Out: TCryptoHashSha256Hash;
begin
  var I := 0;
  if TCryptoHash.Sha256(&Out,
       procedure(var Buffer: TBytes; var Done: Boolean)
       begin
         Buffer := TEncoding.UTF8.GetBytes(M[I]);
         Done := I >= High(M);
         Inc(I);
       end
     )
  then
    WriteLn('SUCCESS (Hash=', THexEncode.FromBytes(&Out, SizeOf(&Out)), ')')
  else
    WriteLn('FAILED');
end;

begin
  try
    Write('API...'); test_api;
    Write('Wrapper...'); test;
    Write('Wrapper...'); test_multiple_blocks;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
