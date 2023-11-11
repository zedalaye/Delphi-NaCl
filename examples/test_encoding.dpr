program test_encoding;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  libsodium in '..\lib\libsodium.pas',
  Sodium.Utils in '..\lib\Sodium.Utils.pas';

function check_buffers(B1, B2: TBytes): Boolean;
begin
  Result := (Length(B1) = Length(B2)) and (sodium_memcmp(@B1[0], @B2[0], Length(B1)) = 0);
end;

procedure test(Buf: TBytes; Variant: TBase64Variant; Padding: Boolean);
const
  VariantName: array[TBase64Variant] of string = ('Original', 'O1', 'O2', 'O3', 'UrlSafe');
  PaddingName: array[Boolean] of string = ('No Padding', 'Padding');
var
  B64: string;
  DecodedBuf: TBytes;
begin
  Write('test (Variant=', VariantName[Variant], ', ', PaddingName[Padding], ')');

  B64 := TBase64Encode.FromBytes(Buf, Variant, Padding);
//  Insert('!', B64, 12);
  if TBase64Encode.ToBytes(DecodedBuf, B64, Variant, Padding) then
    if check_buffers(Buf, DecodedBuf) then
      WriteLn(' => OK')
    else
      WriteLn(' => FAILED (Buffers are not the same)')
  else
    WriteLn(' => FAILED (TBase64Encode.ToBytes())');
end;

function MakeBuf(Len: NativeUInt): TBytes;
begin
  SetLength(Result, Len);
  for var I := 0 to High(Result) do
    Result[I] := Random(256);
end;

var
  Buf: TBytes;

begin
  try
    Buf := MakeBuf(30);

    test(Buf, TBase64Variant.Original, True);
    test(Buf, TBase64Variant.Original, False);
    test(Buf, TBase64Variant.UrlSafe,  True);
    test(Buf, TBase64Variant.UrlSafe,  False);

    ReadLn;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
