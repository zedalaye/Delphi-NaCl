program test_hash_generichash;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  libsodium in '..\lib\libsodium.pas',
  Sodium.Utils in '..\lib\Sodium.Utils.pas',
  Sodium.Hash in '..\lib\Sodium.Hash.pas';

procedure test_api_no_key;
var
  &Out: TCryptoGenericHashHash;
begin
  var M := TEncoding.UTF8.GetBytes('test');
  if crypto_generichash(@&Out[0], SizeOf(&Out), @M[0], Length(M), nil, 0) = 0 then
    WriteLn('SUCCESS (Hash=', THexEncode.FromBytes(&Out, SizeOf(&Out)), ')')
  else
    WriteLn('FAILED');
end;

procedure test_api(Key: TCryptoGenericHashKey);
var
  &Out: TCryptoGenericHashHash;
begin
  var M := TEncoding.UTF8.GetBytes('test');
  if crypto_generichash(@&Out[0], SizeOf(&Out), @M[0], Length(M), @Key[0], SizeOf(Key)) = 0 then
    WriteLn('SUCCESS (Hash=', THexEncode.FromBytes(&Out, SizeOf(&Out)), ')')
  else
    WriteLn('FAILED');
end;

procedure test_api_big_key(Key: TBytes);
var
  &Out: TCryptoGenericHashHash;
begin
  var M := TEncoding.UTF8.GetBytes('test');
  if crypto_generichash(@&Out[0], SizeOf(&Out), @M[0], Length(M), @Key[0], SizeOf(Key)) = 0 then
    WriteLn('SUCCESS (Hash=', THexEncode.FromBytes(&Out, SizeOf(&Out)), ')')
  else
    WriteLn('FAILED');
end;

procedure test_no_key;
var
  &Out: TCryptoGenericHashHash;
begin
  if TCryptoGenericHash.Hash(&Out, TEncoding.UTF8.GetBytes('test')) then
    WriteLn('SUCCESS (Hash=', THexEncode.FromBytes(&Out, SizeOf(&Out)), ')')
  else
    WriteLn('FAILED');
end;

procedure test_no_key_multiple_blocks;
const
  M: array[0..2] of string = ('Message', 'split over', '3 lines');
var
  &Out: TCryptoGenericHashHash;
begin
  var I := 0;
  if TCryptoGenericHash.Hash(&Out,
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


procedure test(Key: TCryptoGenericHashKey);
var
  &Out: TCryptoGenericHashHash;
begin
  if TCryptoGenericHash.Hash(&Out, TEncoding.UTF8.GetBytes('test'), Key) then
    WriteLn('SUCCESS (Hash=', THexEncode.FromBytes(&Out, SizeOf(&Out)), ')')
  else
    WriteLn('FAILED');
end;

procedure test_multiple_blocks(Key: TCryptoGenericHashKey);
const
  M: array[0..2] of string = ('Message', 'split over', '3 lines');
var
  &Out: TCryptoGenericHashHash;
begin
  var I := 0;
  if TCryptoGenericHash.Hash(&Out,
       procedure(var Buffer: TBytes; var Done: Boolean)
       begin
         Buffer := TEncoding.UTF8.GetBytes(M[I]);
         Done := I >= High(M);
         Inc(I);
       end,
       Key
     )
  then
    WriteLn('SUCCESS (Hash=', THexEncode.FromBytes(&Out, SizeOf(&Out)), ')')
  else
    WriteLn('FAILED');
end;

procedure test_big_key(Key: TBytes);
var
  &Out: TCryptoGenericHashHash;
begin
  if TCryptoGenericHash.Hash(&Out, TEncoding.UTF8.GetBytes('test'), Key) then
    WriteLn('SUCCESS (Hash=', THexEncode.FromBytes(&Out, SizeOf(&Out)), ')')
  else
    WriteLn('FAILED');
end;

procedure test_big_key_multiple_blocks(Key: TBytes);
const
  M: array[0..2] of string = ('Message', 'split over', '3 lines');
var
  &Out: TCryptoGenericHashHash;
begin
  var I := 0;
  if TCryptoGenericHash.Hash(&Out,
       procedure(var Buffer: TBytes; var Done: Boolean)
       begin
         Buffer := TEncoding.UTF8.GetBytes(M[I]);
         Done := I >= High(M);
         Inc(I);
       end,
       Key
     )
  then
    WriteLn('SUCCESS (Hash=', THexEncode.FromBytes(&Out, SizeOf(&Out)), ')')
  else
    WriteLn('FAILED');
end;

var
  Key: TCryptoGenericHashKey;
  BigKey: TBytes;

begin
  try
    WriteLn('GenericHash.Primitive=', TCryptoGenericHash.Primitive);

    Write('API (NO_KEY)...'); test_api_no_key;
    Write('Wrapper (NO_KEY)...'); test_no_key;
    Write('Wrapper (NO_KEY, MULTIPLE BLOCKS)...'); test_no_key_multiple_blocks;

    Key := TCryptoGenericHash.Keygen;
    Write('API...'); test_api(Key);
    Write('Wrapper...'); test(Key);
    Write('Wrapper (MULTIPLE BLOCKS)...'); test_multiple_blocks(Key);

    BigKey := TCryptoGenericHash.Keygen(_CRYPTO_GENERICHASH_KEYBYTES_MAX);
    Write('API (BIG_KEY)...'); test_api_big_key(BigKey);
    Write('Wrapper (BIG_KEY)...'); test_big_key(BigKey);
    Write('Wrapper (BIG_KEY, MULTIPLE BLOCKS)...'); test_big_key_multiple_blocks(BigKey);

    Readln;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;

  end.
