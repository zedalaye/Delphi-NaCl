program test_onetimeauth;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
{$if defined(API)}
  libsodium,
{$endif}
  Sodium.OnetimeAuth,
  Sodium.Utils;

{$if defined(API)}
procedure test_api(key: TCryptoOnetimeAuthKey);
var
  &out: TCryptoOnetimeAuthTag;
begin
  var M := TEncoding.UTF8.GetBytes('Data to authenticate');

  if crypto_onetimeauth(@&out[0], @M[0], Length(M), @key[0]) = 0 then
  begin
    WriteLn('crypto_onetimeauth() => ', TBytes.ToHex(&out, SizeOf(&out)));

    if crypto_onetimeauth_verify(@&out[0], @M[0], Length(M), @key[0]) = 0 then
      WriteLn('crypto_onetimeauth_verify() => SUCCESS')
    else
      WriteLn('crypto_onetimeauth_verify() => FAILED')
  end
  else
    WriteLn('crypto_onetimeauth() => FAILED');
end;
{$endif}

procedure test(key: TCryptoOnetimeAuthKey);
var
  Tag: TCryptoOnetimeAuthTag;
begin
  if TCryptoOnetimeAuth.Generate(Tag, TEncoding.UTF8.GetBytes('Data to authenticate'), Key) then
    if TCryptoOnetimeAuth.Verify(Tag, TEncoding.UTF8.GetBytes('Data to authenticate'), Key) then
    begin
      WriteLn('SUCCESS');
      WriteLn('Tag=', TBytes.ToHex(Tag, SizeOf(Tag)));
    end
    else
      WriteLn('FAILED');
end;

procedure test_multipart(key: TCryptoOnetimeAuthKey);
const
  M: array[0..2] of string = ('Data', ' to ', 'authenticate');
var
  Tag: TCryptoOnetimeAuthTag;
  I: Integer;
begin
  I := 0;
  if TCryptoOnetimeAuth.Generate(Tag,
       procedure(var Buf: TBytes; var Done: Boolean)
       begin
         Buf := TEncoding.UTF8.GetBytes(M[I]);
         Inc(I);
         Done := I > High(M);
       end,
       Key)
  then
  begin
    I := 0;
    if TCryptoOnetimeAuth.Verify(Tag,
         procedure(var Buf: TBytes; var Done: Boolean)
         begin
           Buf := TEncoding.UTF8.GetBytes(M[I]);
           Inc(I);
           Done := I > High(M);
         end,
         Key)
    then
    begin
      WriteLn('SUCCESS');
      WriteLn('Tag=', TBytes.ToHex(Tag, SizeOf(Tag)));
    end
    else
      WriteLn('FAILED');
  end;
end;

var
  key: TCryptoOnetimeAuthKey;

begin
  try
    key := TCryptoOnetimeAuth.Keygen;

    WriteLn('TCryptoOnetimeAuth.Primitive=', TCryptoOnetimeAuth.Primitive);
  {$if defined(API)}
    Write('API...'); test_api(key);
  {$endif}
    Write('Wrapper...'); test(key);
    Write('Wrapper (MULTIPART)...'); test_multipart(key);
    
    ReadLn;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
