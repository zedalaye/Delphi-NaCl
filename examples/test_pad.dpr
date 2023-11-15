program test_pad;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  libsodium in '..\lib\libsodium.pas',
  Sodium.Utils in '..\lib\Sodium.Utils.pas';

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

    Write('API...'); test_api(Buffer);
    Write('Wrapper...'); test(Buffer);
    
    ReadLn;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
