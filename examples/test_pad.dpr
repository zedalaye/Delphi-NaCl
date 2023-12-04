program test_pad;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
{$if defined(API)}
  libsodium,
{$endif}
  Sodium.Utils;

{$if defined(API)}
procedure test_api(const Buffer: TBytes);
var
  PaddedBuffer: TBytes;
  PaddedBufferLen: NativeUInt;
  UnpaddedBufferLen: NativeUInt;
begin
  SetLength(PaddedBuffer, 100);
  Move(Buffer[0], PaddedBuffer[0], Length(Buffer));

  if sodium_pad(PaddedBufferLen, @PaddedBuffer[0], Length(Buffer), 16, Length(PaddedBuffer)) = 0 then
  begin
    SetLength(PaddedBuffer, PaddedBufferLen);
    WriteLn('SUCCESS');
    WriteLn('Padded Buffer=', TBytes.ToHex(PaddedBuffer));

    if sodium_unpad(UnpaddedBufferLen, @PaddedBuffer[0], Length(PaddedBuffer), 16) = 0 then
    begin
      SetLength(PaddedBuffer, UnpaddedBufferLen);
      WriteLn('Unpadded Buffer=', TBytes.ToHex(PaddedBuffer));
    end
    else
      WriteLn('FAILED (unpad)');
  end
  else
    Writeln('FAILED (pad)');
end;
{$endif}

procedure test(const Buffer: TBytes);
var
  PaddedBuffer: TBytes;
begin
  SetLength(PaddedBuffer, Length(Buffer));
  Move(Buffer[0], PaddedBuffer[0], Length(Buffer));

  if TBytes.Pad(PaddedBuffer, 16) then
  begin
    WriteLn('SUCCESS');
    WriteLn('Padded Buffer=', TBytes.ToHex(PaddedBuffer));

    if TBytes.Unpad(PaddedBuffer, 16) then
      WriteLn('Unpadded Buffer=', TBytes.ToHex(PaddedBuffer))
    else
      WriteLn('Unpad : FAILED');
  end
  else
    WriteLn('FAILED (pad)');
end;

var
  Buffer: TBytes;

begin
  try
    Buffer := TBytes.Random(16);

  {$if defined(API)}
    Write('API...'); test_api(Buffer);
  {$endif}
    Write('Wrapper...'); test(Buffer);
    
    ReadLn;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
