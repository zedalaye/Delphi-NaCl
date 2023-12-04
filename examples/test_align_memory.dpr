program test_align_memory;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  Sodium.Aead,
  Sodium.Utils;

procedure test_getmem;
var
  AR: TCryptoGenericHashState;
  PA: PCryptoGenericHashState;
  PAA: array[0..99] of Pointer;
begin
  WriteLn(Format('AR=%p, @AR mod 64 = %d', [@AR, NativeUInt(@AR) mod 64]), ', SizeOf(AR)=', SizeOf(AR));

  for var I := 0 to High(PAA) do
  begin
    GetMem(PA, SizeOf(TCryptoGenericHashState) + 63);
    var HighPA := NativeUInt(PA) + SizeOf(TCryptoGenericHashState) + 63;
    PAA[I] := PA;
    PA := PCryptoGenericHashState((NativeUInt(PA) + 63) and not(63));
    WriteLn(Format('PA=%p, Offset=%2d, @PA mod 64 = %d', [PA, NativeUInt(PA) - NativeUInt(PAA[I]), NativeUInt(PA) mod 64]), ', SizeOf(PA)=', SizeOf(PA^));
    Assert(NativeUInt(PA) + SizeOf(TCryptoGenericHashState) <= HighPA);
  end;

  for var I := High(PAA) downto 0 do
    FreeMem(PAA[I]);
end;

procedure test;
var
  AR: TCryptoGenericHashState;
  PA: PCryptoGenericHashState;
  PAA: array[0..99] of Pointer;
begin
  WriteLn(Format('AR=%p, @AR mod 64 = %d', [@AR, NativeUInt(@AR) mod 64]), ', SizeOf(AR)=', SizeOf(AR));

  for var I := 0 to High(PAA) do
  begin
    PA := GetAlignedCryptoGenericHashState(PAA[I]);
    WriteLn(Format('PA=%p, Offset=%2d, @PA mod 64 = %d', [PA, NativeUInt(PA) - NativeUInt(PAA[I]), NativeUInt(PA) mod 64]), ', SizeOf(PA)=', SizeOf(PA^));
  end;

  for var I := High(PAA) downto 0 do
    FreeMem(PAA[I]);
end;

begin
  try
    Write('GetMem()...'); test_getmem;
    Write('Wrapper...'); test;

    ReadLn;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
