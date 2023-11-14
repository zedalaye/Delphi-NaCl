program test_bytes;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  libsodium in '..\lib\libsodium.pas',
  Sodium.Utils in '..\lib\Sodium.Utils.pas';

procedure test;
var
  A, B, C: TBytes;
  Seed: TRandomBytesSeed;
begin
  B := TBytes.Zero(16);
  WriteLn('B=', THexEncode.FromBytes(B));
  WriteLn('IsZero(B)=', TBytes.IsZero(B));

  A := TBytes.Random(16);
  WriteLn('A=', THexEncode.FromBytes(A));

  TBytes.Add(A, B);
  WriteLn('A+B=', THexEncode.FromBytes(A));

  C := TBytes.Zero(16);
  C[0] := 1;
  WriteLn('C=', THexEncode.FromBytes(C));

  TBytes.Add(A, C);
  WriteLn('A+C=', THexEncode.FromBytes(A));

  TBytes.Sub(A, C);
  WriteLn('A-C=', THexEncode.FromBytes(A));

  WriteLn('Compare(A,C)=', TBytes.Compare(A, C));
  WriteLn('Compare(C,A)=', TBytes.Compare(C, A));
  WriteLn('Compare(A,A)=', TBytes.Compare(A, A));

  WriteLn('Same(A,C)=', TBytes.Same(A, C));
  WriteLn('Same(A,A)=', TBytes.Same(A, A));

  TBytes.Inc(C);
  WriteLn('Inc(C)', THexEncode.FromBytes(C));

  WriteLn('Random=', TBytes.Random);
  WriteLn('RandomUniform(255)=', TBytes.RandomUniform(255));

  TBytes.Random(Seed, SizeOf(Seed));
  TBytes.Random(A, Seed);
  WriteLn('Seed=', THexEncode.FromBytes(Seed, SizeOf(Seed)));
  WriteLn('Same(Seed, Seed)=', TBytes.Same(Seed, Seed, SizeOf(Seed)));
  WriteLn('Same<TSeed>(Seed, Seed)=', TBytes.Same<TRandomBytesSeed>(Seed, Seed));
  WriteLn('Random(Seed)=', THexEncode.FromBytes(A));
  TBytes.Random(A, Seed);
  WriteLn('Random(Seed)=', THexEncode.FromBytes(A));
end;

begin
  try
    Write('Wrapper...'); test;

    ReadLn;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
