program test_kdf_hkdf_sha256;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
{$if defined(API)}
  libsodium,
{$endif}
  Sodium.Kdf,
  Sodium.Utils;

{$if defined(API)}
procedure test_api(const MasterKey: TCryptoKdfHkdfSha256Key);
var
  subkey_1: array[0..31] of Byte;
  subkey_2: array[0..31] of Byte;
  subkey_3: array[0..63] of Byte;
begin
  crypto_kdf_hkdf_sha256_expand(@subkey_1[0], Sizeof(subkey_1), PAnsiChar('key for encryption'), Length('key for encryption'), MasterKey);
  WriteLn('subkey_1=', TBytes.ToHex(subkey_1, SizeOf(subkey_1)));

  crypto_kdf_hkdf_sha256_expand(@subkey_2[0], Sizeof(subkey_2), PAnsiChar('key for signature'), Length('key for signature'), MasterKey);
  WriteLn('subkey_2=', TBytes.ToHex(subkey_2, SizeOf(subkey_2)));

  crypto_kdf_hkdf_sha256_expand(@subkey_3[0], Sizeof(subkey_3), PAnsiChar('key for something else'), Length('key for something else'), MasterKey);
  WriteLn('subkey_3=', TBytes.ToHex(subkey_3, SizeOf(subkey_3)));
end;
{$endif}

procedure test(const MasterKey: TCryptoKdfHkdfSha256Key);
const
  KeyLengths: array[0..2] of NativeUInt = (32, 32, 64);
  KeyContexts: array[0..2] of RawByteString = ('key for encryption', 'key for signature', 'key for something else');
var
  SubKeys: array[0..2] of TBytes;
  I: UInt64;
begin
  for I := Low(SubKeys) to High(SubKeys) do
  begin
    SetLength(SubKeys[I], KeyLengths[I]);
    if TCryptoKdfHkdfSha256.Expand(SubKeys[I][0], KeyLengths[I], KeyContexts[I], MasterKey) then
      WriteLn('SubKey', I+1, ' (', KeyContexts[I], ') = ', TBytes.ToHex(SubKeys[I]));
  end;
end;

procedure test_extract(const Salt, IKM: string);
var
  MasterKey: TCryptoKdfHkdfSha256Key;
begin
  if TCryptoKdfHkdfSha256.Extract(MasterKey, TEncoding.UTF8.GetBytes(Salt), TEncoding.UTF8.GetBytes(IKM)) then
  begin
    WriteLn('SUCCESS');
    WriteLn('MasterKey=', TBytes.ToHex(MasterKey, SizeOf(MasterKey)));
  end
  else
    WriteLn('FAILED');
end;

procedure test_extract_incremental(const Salt: string; const IKM: array of string);
var
  MasterKey: TCryptoKdfHkdfSha256Key;
  LocalIKM: TArray<TBytes>;
  I: Integer;
begin
  SetLength(LocalIKM, Length(IKM));
  for I := Low(IKM) to High(IKM) do
    LocalIKM[I] := TEncoding.UTF8.GetBytes(IKM[I]);

  I := 0;
  if TCryptoKdfHkdfSha256.Extract(MasterKey,
       TEncoding.UTF8.GetBytes(Salt),
       procedure(var Buf: TBytes; var Done: Boolean)
       begin
         Buf := LocalIKM[I];
         Inc(I);
         Done := I > High(LocalIKM);
       end
     )
  then
  begin
    WriteLn('SUCCESS');
    WriteLn('MasterKey=', TBytes.ToHex(MasterKey, SizeOf(MasterKey)));
  end
  else
    WriteLn('FAILED');
end;

var
  MasterKey: TCryptoKdfHkdfSha256Key;

begin
  try
    MasterKey := TCryptoKdfHkdfSha256.Keygen;

  {$if defined(API)}
    Write('API...'); test_api(MasterKey);
  {$endif}
    Write('Wrapper (EXPAND)...'); test(MasterKey);
    Write('Wrapper (EXTRACT)...'); test_extract('6723D3AA-C6CA-4F3C-8F24-94B550C5F10A', 'John Doe - 951a 6158 4fe0 8a0b ad7c b57b 7687 09b6');
    Write('Wrapper (INCREMENTAL)...'); test_extract_incremental('6723D3AA-C6CA-4F3C-8F24-94B550C5F10A', [
      'John Doe', ' - ', '951a 6158 4fe0 8a0b ad7c b57b 7687 09b6'
    ]);
    
    ReadLn;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
