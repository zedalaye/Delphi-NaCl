program test_kdf;

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
procedure test_api(const MasterKey: TCryptoKdfKey; const Context: RawByteString);
var
  Ctx: TCryptoKdfContext;
  subkey_1: array[0..31] of Byte;
  subkey_2: array[0..31] of Byte;
  subkey_3: array[0..63] of Byte;
begin
  Move(Context[1], Ctx[0], Length(Context));

  WriteLn('master_key=', TBytes.ToHex(MasterKey, SizeOf(MasterKey)));

  crypto_kdf_derive_from_key(@subkey_1[0], SizeOf(subkey_1), 1, Ctx, MasterKey);
  WriteLn('subkey_1=',   TBytes.ToHex(subkey_1, SizeOf(subkey_1)));

  crypto_kdf_derive_from_key(@subkey_2[0], SizeOf(subkey_2), 2, Ctx, MasterKey);
  WriteLn('subkey_2=',   TBytes.ToHex(subkey_2, SizeOf(subkey_2)));

  crypto_kdf_derive_from_key(@subkey_3[0], SizeOf(subkey_3), 3, Ctx, MasterKey);
  WriteLn('subkey_3=',   TBytes.ToHex(subkey_3, SizeOf(subkey_3)));
end;
{$endif}

procedure test(const MasterKey: TCryptoKdfKey; Context: TCryptoKdfContext);
const
  KeyLengths: array[0..2] of NativeUInt = (32, 32, 64);
var
  SubKeys: array[0..2] of TBytes;
  I: UInt64;
begin
  for I := Low(SubKeys) to High(SubKeys) do
  begin
    SetLength(SubKeys[I], KeyLengths[I]);
    if not TCryptoKdf.DeriveFromKey(SubKeys[I][0], KeyLengths[I], I +1, Context, MasterKey) then
    begin
      WriteLn('FAILED');
      Exit;
    end;
  end;

  WriteLn('SUCCESS');
  for I := Low(SubKeys) to High(SubKeys) do
    WriteLn('SubKey', I+1, '=', TBytes.ToHex(SubKeys[I]));
end;

var
  MasterKey: TCryptoKdfKey;

begin
  try
    MasterKey := TCryptoKdf.Keygen;

    WriteLn('TCryptoKdf.Primitive=', TCryptoKdf.Primitive);
  {$if defined(API)}
    Write('API...'); test_api(MasterKey, 'Examples');
  {$endif}
    Write('Wrapper...'); test(MasterKey, 'Examples');
    
    ReadLn;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
