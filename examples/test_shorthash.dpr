program test_shorthash;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  libsodium in '..\lib\libsodium.pas',
  Sodium.Utils in '..\lib\Sodium.Utils.pas',
  Sodium.ShortHash in '..\lib\Sodium.ShortHash.pas';

procedure test_api(key: TCryptoShortHashKey);
var
  hash: TCryptoShortHashHash;
begin
  var ShortData := TEncoding.UTF8.GetBytes('Sparkling water');

  if crypto_shorthash(@hash[0], @ShortData[0], Length(ShortData), @key[0]) = 0 then
    WriteLn('crypto_shorthash() = ', TBytes.ToHex(hash, SizeOf(hash)))
  else
    WriteLn('crypto_shorthash() => FAILED');
end;

procedure test(key: TCryptoShortHashKey);
var
  Hash: TCryptoShortHashHash;
begin
  if TCryptoShortHash.Generate(Hash, TEncoding.UTF8.GetBytes('Sparkling water'), Key) then
  begin
    WriteLn('SUCCESS');
    WriteLn('Hash=', TBytes.ToHex(Hash, SizeOf(Hash)));
  end
  else
    WriteLn('FAILED');
end;

var
  Key: TCryptoShortHashKey;

begin
  try
    Key := TCryptoShortHash.Keygen;

    WriteLn('TCryptoShortHash.Primitive=', TCryptoShortHash.Primitive);
    Write('API...'); test_api(Key);
    Write('Wrapper...'); test(Key);
    
    ReadLn;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
