program test_bytes;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  Sodium.Utils;

procedure test;
var
  A, B, C: TBytes;
  Seed: TRandomBytesSeed;
  SeedBytes: TBytes;
begin
  B := TBytes.Zero(16);
  WriteLn('B=', B.ToHex);
  WriteLn('B.IsZero=', B.IsZero);

  A := TBytes.Random(16);
  WriteLn('A=', A.ToHex);

  TBytes.Add(A, B);
  WriteLn('A+B=', A.ToHex);

  C := TBytes.Zero(16);
  C[0] := 1;
  WriteLn('C=', C.ToHex);

  TBytes.Add(A, C);
  WriteLn('A+C=', A.ToHex);

  TBytes.Sub(A, C);
  WriteLn('A-C=', A.ToHex);

  WriteLn('Compare(A,C)=', TBytes.Compare(A, C));
  WriteLn('Compare(C,A)=', TBytes.Compare(C, A));
  WriteLn('Compare(A,A)=', TBytes.Compare(A, A));

  WriteLn('Same(A,C)=', TBytes.Same(A, C));
  WriteLn('Same(A,A)=', TBytes.Same(A, A));

  TBytes.Inc(C);
  WriteLn('Inc(C)=', C.ToHex);

  WriteLn('Random=', TBytes.Random);
  WriteLn('RandomUniform(255)=', TBytes.RandomUniform(255));

  TBytes.Random(Seed, SizeOf(Seed));
  TBytes.Random(A, Seed);
  WriteLn('Seed=', TBytes.ToHex(Seed, SizeOf(Seed)));
  WriteLn('Seed=', TBytes.ToHex(Seed[0], SizeOf(Seed)));
  WriteLn('Seed=', TBytes.ToHex<TRandomBytesSeed>(Seed));
  WriteLn('Same(Seed, Seed)=', TBytes.Same(Seed, Seed, SizeOf(Seed)));
  WriteLn('Same<TSeed>(Seed, Seed)=', TBytes.Same<TRandomBytesSeed>(Seed, Seed));
  WriteLn('Random(Seed)=', A.ToHex);
  TBytes.Random(A, Seed);
  WriteLn('Random(Seed)=', A.ToHex);

  var SeedHex := TBytes.ToHex(Seed, SizeOf(Seed));

  TBytes.Zero(Seed, SizeOf(Seed));
  if TBytes.FromHex(Seed, SizeOf(Seed), SeedHex) then
    WriteLn('Seed from Hex = ', TBytes.ToHex(Seed, SizeOf(Seed)))
  else
    WriteLn('TBytes.FromHex(Buf, Size) FAILED');

  TBytes.Zero(Seed, SizeOf(Seed));
  if TBytes.FromHex<TRandomBytesSeed>(Seed, SeedHex) then
    WriteLn('Seed from Hex = ', TBytes.ToHex(Seed, SizeOf(Seed)))
  else
    WriteLn('TBytes.FromHex<T>(Buf) FAILED');

  if TBytes.FromHex(SeedBytes, SeedHex) then
    WriteLn('SeedBytes from Hex = ', TBytes.ToHex(SeedBytes))
  else
    WriteLn('TBytes.FromHex(TBytes) FAILED');

  var SeedB64 := TBytes.ToBase64(Seed, SizeOf(Seed));
  WriteLn('Base64(Seed) = ', SeedB64);

  TBytes.Zero(Seed, SizeOf(Seed));
  if TBytes.FromBase64(Seed, SizeOf(Seed), SeedB64) then
    WriteLn('Seed from Base64 = ', TBytes.ToHex(Seed, SizeOf(Seed)))
  else
    WriteLn('TBytes.FromBase64(Buf, Size) FAILED');

  TBytes.Zero(Seed, SizeOf(Seed));
  if TBytes.FromBase64<TRandomBytesSeed>(Seed, SeedB64) then
    WriteLn('Seed from Base64 = ', TBytes.ToHex(Seed, SizeOf(Seed)))
  else
    WriteLn('TBytes.FromBase64<T>(Buf) FAILED');

  if TBytes.FromHex(SeedBytes, SeedHex) then
    WriteLn('SeedBytes from Base64 = ', TBytes.ToHex(SeedBytes))
  else
    WriteLn('TBytes.FromBase64(TBytes) FAILED');

  WriteLn('A+B=', A.ToHex, '+', B.ToHex, '=', (A+B).ToHex);
  var D := TBytes.Concat(A, B);
  WriteLn('TBytes.Concat(A, B)=', D.ToHex);
end;

procedure test_errors;
var
  Seed: TRandomBytesSeed;
  Hex: string;
  BiggerSeed: array[0..SizeOf(TRandomBytesSeed) * 2] of Byte;
  SmallerSeed: array[0..SizeOf(TRandomBytesSeed) div 2] of Byte;
begin
  TBytes.Random(Seed, SizeOf(Seed));

  Hex := TBytes.ToHex(Seed, SizeOf(Seed));
  WriteLn('Seed=', Hex);

  try
    if TBytes.FromHex(BiggerSeed, SizeOf(BiggerSeed), Hex) then
      WriteLn('BiggerSeed=', TBytes.ToHex(BiggerSeed, SizeOf(BiggerSeed)));
  except
    on E: EArgumentException do
      WriteLn('TBytes.FromHex(BiggerSeed) FAILED : ', E.Message);
  end;

  try
    if TBytes.FromHex(SmallerSeed, SizeOf(SmallerSeed), Hex) then
      WriteLn('SmallerSeed=', TBytes.ToHex(SmallerSeed, SizeOf(SmallerSeed)));
  except
    on E: EArgumentException do
      WriteLn('TBytes.FromHex(SmallerSeed) FAILED : ', E.Message);
  end;
end;

begin
  try
    WriteLn('Wrapper (BYTES)...');
    test;

    WriteLn;
    WriteLn('Wrapper (ERRORS)...');
    test_errors;

    ReadLn;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
