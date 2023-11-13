program test_secretstream;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils, System.Classes,
  libsodium in '..\lib\libsodium.pas',
  Sodium.Utils in '..\lib\Sodium.Utils.pas',
  Sodium.SecretStream in '..\lib\Sodium.SecretStream.pas';

procedure test_api(key: TCryptoSecretStreamXChacha20Poly1305Key);
var
  state: TCryptoSecretStreamXChacha20Poly1305State;
  header: TCryptoSecretStreamXChacha20Poly1305Header;
  tag: Byte;
begin
  var M1 := TEncoding.UTF8.GetBytes('Arbitrary data to encrypt');
  var M2 := TEncoding.UTF8.GetBytes('split into');
  var M3 := TEncoding.UTF8.GetBytes('three messages');

  (* Shared secret key required to encrypt/decrypt the stream *)
  crypto_secretstream_xchacha20poly1305_keygen(key);
  (* Set up a new stream: initialize the state and create the header *)
  crypto_secretstream_xchacha20poly1305_init_push(state, header, key);
  (* Now, encrypt the first chunk. `c1` will contain an encrypted,
   * authenticated representation of `MESSAGE_PART1`. *)
  var C1: TBytes; var C1L: UInt64;
  SetLength(C1, Length(M1) + _CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES);
  crypto_secretstream_xchacha20poly1305_push(state, @C1[0], C1L, @M1[0], Length(M1), nil, 0, 0);
  (* Encrypt the second chunk. `c2` will contain an encrypted, authenticated
   * representation of `MESSAGE_PART2`. *)
  var C2: TBytes; var C2L: UInt64;
  SetLength(C2, Length(M2) + _CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES);
  crypto_secretstream_xchacha20poly1305_push(state, @C2[0], C2L, @M2[0], Length(M2), nil, 0, 0);
  (* Encrypt the last chunk, and store the ciphertext into `c3`.
   * Note the `TAG_FINAL` tag to indicate that this is the final chunk. *)
  var C3: TBytes; var C3L: UInt64;
  SetLength(C3, Length(M3) + _CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES);
  crypto_secretstream_xchacha20poly1305_push(state, @C3[0], C3L, @M3[0], Length(M3), nil, 0,
    _CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL);

  (* Decrypt the stream: initializes the state, using the key and a header *)
  if (crypto_secretstream_xchacha20poly1305_init_pull(state, header, key) <> 0) then
  begin
    WriteLn('crypto_secretstream_xchacha20poly1305_init_pull() => Invalid Header');
    Exit;
  end;
  (* Decrypt the first chunk. A real application would probably use
   * a loop, that reads data from the network or from disk, and exits after
   * an error, or after the last chunk (with a `TAG_FINAL` tag) has been
   * decrypted. *)
  var D1: TBytes; var D1L: UInt64;
  SetLength(D1, Length(M1));
  if (crypto_secretstream_xchacha20poly1305_pull(state, @D1[0], D1L, tag, @C1[0], Length(C1), nil, 0) <> 0) then
  begin
    WriteLn('crypto_secretstream_xchacha20poly1305_pull(C1) => Invalid CipherText');
    Exit;
  end;
  Assert(tag = 0); (* The tag is the one we attached to this chunk: 0 *)
  (* Decrypt the second chunk, store the result into `m2` *)
  var D2: TBytes; var D2L: UInt64;
  SetLength(D2, Length(M2));
  if (crypto_secretstream_xchacha20poly1305_pull(state, @D2[0], D2L, tag, @C2[0], Length(C2), nil, 0) <> 0) then
  begin
    WriteLn('crypto_secretstream_xchacha20poly1305_pull(C2) => Invalid CipherText');
    Exit;
  end;
  Assert(tag = 0); (* Not the end of the stream yet *)
  (* Decrypt the last chunk, store the result into `m3` *)
  var D3: TBytes; var D3L: UInt64;
  SetLength(D3, Length(M3));
  if (crypto_secretstream_xchacha20poly1305_pull(state, @D3[0], D3L, tag, @C3[0], Length(C3), nil, 0) <> 0) then
  begin
    WriteLn('crypto_secretstream_xchacha20poly1305_pull(C3) => Invalid CipherText');
    Exit;
  end;
  (* The tag indicates that this is the final chunk, no need to read and decrypt more *)
  Assert(tag = _CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL);

  WriteLn('crypto_secret_stream => SUCCESS');
end;

procedure test(Key: TCryptoSecretStreamXChacha20Poly1305Key);
const
  M: array[0..2] of string = ('Arbitrary data to encrypt', 'split into', 'three messages');
var
  Header: TCryptoSecretStreamXChacha20Poly1305Header;
  I: Integer;
  C: array[0..2] of TBytes;
begin
  I := 0;
  if TCryptoSecretStream.Push(Header,
       procedure(var Buf, AdditionalData: TBytes; var Tag: TCryptoStreamTag; var Done: Boolean)
       begin
         { Set Tag to
             => Push to mark the end of a set of messages,
             => Rekey to force a new key and
           Done to True to mark the end of the stream }

         SetLength(AdditionalData, 0);
         Buf := TEncoding.UTF8.GetBytes(M[I]);
         Inc(I);
         Done := I > High(M);
       end,
       procedure(const Buf: TBytes)
       begin
         C[I -1] := Buf;
       end,
       Key
     )
  then
  begin
    I := 0;
    if TCryptoSecretStream.Pull(Header,
         procedure(var Buf, AdditionalData: TBytes)
         begin
           SetLength(AdditionalData, 0);
           Buf := C[I];
           Inc(I);
         end,
         procedure(const Buf: TBytes; const Tag: TCryptoStreamTag; Done: Boolean)
         begin
           { Done should be true for the last message }
           Assert(
            ((not Done) and (I <= High(M))) or (Done and (I > High(M)))
           );
           Assert(TEncoding.UTF8.GetString(Buf) = M[I -1]);
         end,
         Key
    ) then
      WriteLn('TCryptoSecretStream (BLOCKS) => SUCCESS')
    else
      WriteLn('TCryptoSecretStream.Pull() => FAILED');
  end
  else
    WriteLn('TCryptoSecretStream.Push() => FAILED');
end;

procedure test_stream(Key: TCryptoSecretStreamXChacha20Poly1305Key);
const
  M = 'This is a string, wrapped in a stream';
var
  InStream: TStringStream;
  OutStream: TMemoryStream;
begin
  OutStream := TMemoryStream.Create;
  try
    InStream := TStringStream.Create(M, TEncoding.UTF8);
    try
      if TCryptoSecretStream.PushStream(InStream, OutStream, Key) then
      begin
        OutStream.Seek(0, soFromBeginning);
        InStream.Clear;

        if TCryptoSecretStream.PullStream(OutStream, InStream, Key) then
        begin
          InStream.Seek(0, soFromBeginning);
          if InStream.ReadString(InStream.Size) = M then
            WriteLn('TCryptoSecretStream (STREAM) => SUCCESS')
          else
            WriteLn('TCryptoSecretStream (STREAM) => FAILED (Strings do not match)')
        end
        else
          WriteLn('TCryptoSecretStream.PullStream() => FAILED');
      end
      else
        WriteLn('TCryptoSecretStream.PushStream() => FAILED');
    finally
      InStream.Free;
    end;
  finally
    OutStream.Free;
  end;
end;

var
  key: TCryptoSecretStreamXChacha20Poly1305Key;

begin
  try
    key := TCryptoSecretStream.Keygen;

    Write('API...'); test_api(key);
    Write('Wrapper...'); test(key);
    Write('Wrapper...'); test_stream(key);

    ReadLn;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
