program test_library_info;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  Sodium.Utils;

procedure test;
begin
  WriteLn('TSodium.Version=', TSodium.Version);
  WriteLn('TSodium.LibraryVersionMajor=', TSodium.LibraryVersionMajor);
  WriteLn('TSodium.LibraryVersionMinor=', TSodium.LibraryVersionMinor);
  WriteLn('TSodium.LibraryMinimal=', TSodium.LibraryMinimal);

  WriteLn('TSodium.RuntimeHasNeon=', TSodium.RuntimeHasNeon);
  WriteLn('TSodium.RuntimeHasArmCrypto=', TSodium.RuntimeHasArmCrypto);
  WriteLn('TSodium.RuntimeHasSse2=', TSodium.RuntimeHasSse2);
  WriteLn('TSodium.RuntimeHasSse3=', TSodium.RuntimeHasSse3);
  WriteLn('TSodium.RuntimeHasSsse3=', TSodium.RuntimeHasSsse3);
  WriteLn('TSodium.RuntimeHasSse41=', TSodium.RuntimeHasSse41);
  WriteLn('TSodium.RuntimeHasAvx=', TSodium.RuntimeHasAvx);
  WriteLn('TSodium.RuntimeHasAvx2=', TSodium.RuntimeHasAvx2);
  WriteLn('TSodium.RuntimeHasAvx512f=', TSodium.RuntimeHasAvx512f);
  WriteLn('TSodium.RuntimeHasPclMul=', TSodium.RuntimeHasPclMul);
  WriteLn('TSodium.RuntimeHasAesni=', TSodium.RuntimeHasAesni);
  WriteLn('TSodium.RuntimeHasRdRand=', TSodium.RuntimeHasRdRand);

  WriteLn('TRandom.ImplementationName=', TRandom.ImplementationName);
end;

begin
  try
    test;
    ReadLn;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
