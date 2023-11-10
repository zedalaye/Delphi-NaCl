unit Sodium.Utils;

interface

uses
  System.SysUtils,
  libsodium;

type
  THexEncode = record
    class function FromBytes(Buf: PByte; BufLen: NativeUInt): string; overload; static;
    class function FromBytes(const Buf: TBytes): string; overload; static;
    class function FromBytes(const Buf; Len: NativeUInt): string; overload; static;
  end;

  TRandom = record
    class function Bytes(Len: NativeUInt): TBytes; overload; static;
    class procedure Bytes(Buf: PByte; Len: NativeUInt); overload; static;
    class procedure Bytes(const Buf; Len: NativeUInt); overload; static;
  end;

  TZero = record
    class function Fill(Len: NativeUInt): TBytes; overload; static;
    class procedure Fill(Buf: PByte; Len: NativeUInt); overload; static;
    class procedure Fill(const Buf; Len: NativeUInt); overload; static;
  end;

implementation

{ THexEncode }

class function THexEncode.FromBytes(Buf: PByte; BufLen: NativeUInt): string;
var
  Hex: TBytes;
begin
  SetLength(Hex, BufLen * 2 + 1); // bin2hex adds an ending \0
  sodium_bin2hex(@Hex[0], Length(Hex), Buf, BufLen);
  Result := string(PAnsiChar(Hex));
end;

class function THexEncode.FromBytes(const Buf: TBytes): string;
begin
  Result := THexEncode.FromBytes(@Buf[0], Length(Buf));
end;

class function THexEncode.FromBytes(const Buf; Len: NativeUInt): string;
begin
  Result := THexEncode.FromBytes(PByte(@Buf), Len);
end;

{ TRandom }

class function TRandom.Bytes(Len: NativeUInt): TBytes;
begin
  SetLength(Result, Len);
  randombytes_buf(@Result[0], Len);
end;

class procedure TRandom.Bytes(Buf: PByte; Len: NativeUInt);
begin
  randombytes_buf(Buf, Len);
end;

class procedure TRandom.Bytes(const Buf; Len: NativeUInt);
begin
  randombytes_buf(@Buf, Len);
end;

{ TZero }

class function TZero.Fill(Len: NativeUInt): TBytes;
begin
  SetLength(Result, Len);
  sodium_memzero(@Result[0], Len);
end;

class procedure TZero.Fill(Buf: PByte; Len: NativeUInt);
begin
  sodium_memzero(Buf, Len);
end;

class procedure TZero.Fill(const Buf; Len: NativeUInt);
begin
  sodium_memzero(@Buf, Len);
end;

end.
