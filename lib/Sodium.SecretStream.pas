unit Sodium.SecretStream;

interface

uses
  System.SysUtils, System.Classes,
  libsodium, Sodium.Utils;

type
  TCryptoStreamTag = (
    Message = _CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE,
    Push    = _CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_PUSH,
    Rekey   = _CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_REKEY
  );

  TCryptoSecretStreamPushInProc = reference to procedure(
    var Buf: TBytes;
    var AdditionalData: TBytes;
    var Tag: TCryptoStreamTag;
    var Done: Boolean           // Will force TAG_FINAL
  );

  TCryptoSecretStreamPushOutProc = reference to procedure(
    const Buf: TBytes
  );

  TCryptoSecretStreamPullInProc = reference to procedure(
    var Buf: TBytes;
    var AdditionalData: TBytes
  );

  TCryptoSecretStreamPullOutProc = reference to procedure(
    const Buf: TBytes; const Tag: TCryptoStreamTag; Done: Boolean
  );

  TCryptoSecretStream = record
    class function Keygen: TCryptoSecretStreamXChacha20Poly1305Key; static;

    class function Push(
      var Header: TCryptoSecretStreamXChacha20Poly1305Header;
      const InProc: TCryptoSecretStreamPushInProc;
      const OutProc: TCryptoSecretStreamPushOutProc;
      const Key: TCryptoSecretStreamXChacha20Poly1305Key): Boolean; static;

    class function Pull(
      const Header: TCryptoSecretStreamXChacha20Poly1305Header;
      const InProc: TCryptoSecretStreamPullInProc;
      const OutProc: TCryptoSecretStreamPullOutProc;
      const Key: TCryptoSecretStreamXChacha20Poly1305Key): Boolean; static;

    class function PushStream(
      const InStream, OutStream: TStream;
      const Key: TCryptoSecretStreamXChacha20Poly1305Key): Boolean; static;

    class function PullStream(
      const InStream, OutStream: TStream;
      const Key: TCryptoSecretStreamXChacha20Poly1305Key): Boolean; static;
  end;

implementation

{ TCryptoSecretStream }

class function TCryptoSecretStream.Keygen: TCryptoSecretStreamXChacha20Poly1305Key;
begin
  crypto_secretstream_xchacha20poly1305_keygen(Result);
end;

class function TCryptoSecretStream.Push(
  var Header: TCryptoSecretStreamXChacha20Poly1305Header;
  const InProc: TCryptoSecretStreamPushInProc;
  const OutProc: TCryptoSecretStreamPushOutProc;
  const Key: TCryptoSecretStreamXChacha20Poly1305Key): Boolean;
var
  State: TCryptoSecretStreamXChacha20Poly1305State;
  Done: Boolean;
  InBuf: TBytes;
  AdBuf: TBytes;
  OutBuf: TBytes;
  OutBufLen: UInt64;
begin
  if crypto_secretstream_xchacha20poly1305_init_push(State, Header, Key) <> 0 then
    Exit(False);

  Done := False;
  while not Done do
  begin
    var Tag := TCryptoStreamTag.Message;
    InProc(InBuf, AdBuf, Tag, Done);

    var TagByte := Ord(Tag);
    if Done then
      TagByte := _CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL;

    SetLength(OutBuf, Length(InBuf) + _CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES);
    if crypto_secretstream_xchacha20poly1305_push(State,
         @OutBuf[0], OutBufLen,
         @InBuf[0], Length(InBuf),
         BytesPointer(AdBuf), Length(AdBuf),
         TagByte) <> 0
    then
      Exit(False);

    SetLength(OutBuf, OutBufLen);
    OutProc(OutBuf);
  end;

  Result := True;
end;

class function TCryptoSecretStream.Pull(
  const Header: TCryptoSecretStreamXChacha20Poly1305Header;
  const InProc: TCryptoSecretStreamPullInProc;
  const OutProc: TCryptoSecretStreamPullOutProc;
  const Key: TCryptoSecretStreamXChacha20Poly1305Key): Boolean;
var
  State: TCryptoSecretStreamXChacha20Poly1305State;
  Done: Boolean;
  InBuf: TBytes;
  AdBuf: TBytes;
  OutBuf: TBytes;
  OutBufLen: UInt64;
  TagByte: Byte;
begin
  if crypto_secretstream_xchacha20poly1305_init_pull(State, Header, Key) <> 0 then
    Exit(False);

  Done := False;
  while not Done do
  begin
    InProc(InBuf, AdBuf);

    SetLength(OutBuf, Length(InBuf) - _CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES);
    if crypto_secretstream_xchacha20poly1305_pull(State,
         @OutBuf[0], OutBufLen, TagByte,
         @InBuf[0], Length(InBuf),
         BytesPointer(AdBuf), Length(AdBuf)) <> 0
    then
      Exit(False);

    var Tag := TCryptoStreamTag.Message;
    if TagByte = _CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL then
      Done := True
    else
      Tag := TCryptoStreamTag(TagByte);

    SetLength(OutBuf, OutBufLen);
    OutProc(OutBuf, Tag, Done);
  end;

  Result := True;
end;

class function TCryptoSecretStream.PushStream(
  const InStream, OutStream: TStream;
  const Key: TCryptoSecretStreamXChacha20Poly1305Key): Boolean;
const
  CHUNK_SIZE = 4096;
var
  State: TCryptoSecretStreamXChacha20Poly1305State;
  Header: TCryptoSecretStreamXChacha20Poly1305Header;
  InBuf: array[0..CHUNK_SIZE -1] of Byte;
  OutBuf: array[0..CHUNK_SIZE + _CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES -1] of Byte;
  InBytes, OutBytes: UInt64;
  Tag: Byte;
  EOS: Boolean;
begin
  if crypto_secretstream_xchacha20poly1305_init_push(State, Header, Key) <> 0 then
    Exit(False);

  OutStream.Write(Header, SizeOf(Header));

  repeat
    InBytes := InStream.Read(InBuf, CHUNK_SIZE);
    EOS := InStream.Position >= InStream.Size;

    if EOS then
      Tag := _CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL
    else
      Tag := _CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE;

    if crypto_secretstream_xchacha20poly1305_push(
         State,
         @OutBuf[0], OutBytes,
         @InBuf[0], InBytes,
         nil, 0,
         Tag
       ) <> 0
    then
      Exit(False);

    OutStream.Write(OutBuf, OutBytes);
  until EOS;

  Result := True;
end;

class function TCryptoSecretStream.PullStream(
  const InStream, OutStream: TStream;
  const Key: TCryptoSecretStreamXChacha20Poly1305Key): Boolean;
const
  CHUNK_SIZE = 4096;
var
  State: TCryptoSecretStreamXChacha20Poly1305State;
  Header: TCryptoSecretStreamXChacha20Poly1305Header;
  InBuf: array[0..CHUNK_SIZE + _CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES -1] of Byte;
  OutBuf: array[0..CHUNK_SIZE -1] of Byte;
  InBytes, OutBytes: UInt64;
  Tag: Byte;
  EOS: Boolean;
begin
  InStream.Read(Header, SizeOf(Header));

  if crypto_secretstream_xchacha20poly1305_init_pull(State, Header, Key) <> 0 then
    Exit(False);

  repeat
    InBytes := InStream.Read(InBuf, CHUNK_SIZE);
    EOS := InStream.Position >= InStream.Size;

    if crypto_secretstream_xchacha20poly1305_pull(
         State,
         @OutBuf[0], OutBytes, Tag,
         @InBuf[0], InBytes,
         nil, 0
       ) <> 0
    then
      Exit(False); // Corrupted chunk

    if Tag = _CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL then
    begin
      if not EOS then
        Exit(False); // Got end of SecretStream before end of InStream
    end
    else
      if EOS then
        Exit(False); // Got end of InStream before end of SecretStream

    OutStream.Write(OutBuf, OutBytes)
  until EOS;

  Result := True;
end;

end.
