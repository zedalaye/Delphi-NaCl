program SodiumTest;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  Winapi.Windows,
  System.SysUtils,
  System.NetEncoding,
  System.Hash,
  libsodium in '..\lib\libsodium.pas',
  Sodium.Utils in '..\lib\Sodium.Utils.pas';

procedure crypto_kdf_test;
const
  CONTEXT: RawByteString = 'CONTEXT';
var
  master_key: TCryptoKdfKey;
  ctx: TCryptoKdfContext;
  subkey_1: array[0..31] of Byte;
  subkey_2: array[0..31] of Byte;
  subkey_3: array[0..63] of Byte;
begin
  Move(CONTEXT[1], ctx[0], SizeOf(ctx));

  crypto_kdf_keygen(master_key);

  crypto_kdf_derive_from_key(@subkey_1[0], SizeOf(subkey_1), 1, ctx, master_key);
  crypto_kdf_derive_from_key(@subkey_2[0], SizeOf(subkey_2), 2, ctx, master_key);
  crypto_kdf_derive_from_key(@subkey_3[0], SizeOf(subkey_3), 3, ctx, master_key);

  WriteLn('master_key=', THexEncode.FromBytes(master_key, SizeOf(master_key)));
  WriteLn('subkey_1=',   THexEncode.FromBytes(@subkey_1[0], SizeOf(subkey_1)));
  WriteLn('subkey_2=',   THexEncode.FromBytes(@subkey_2[0], SizeOf(subkey_2)));
  WriteLn('subkey_3=',   THexEncode.FromBytes(@subkey_3[0], SizeOf(subkey_3)));
end;

procedure crypto_kx_test;
var
  client_pk: TCryptoKxPublicKey;
  client_sk: TCryptoKxSecretKey;
  client_rx: TCryptoKxSessionKey;
  client_tx: TCryptoKxSessionKey;

  server_pk: TCryptoKxPublicKey;
  server_sk: TCryptoKxSecretKey;
  server_rx: TCryptoKxSessionKey;
  server_tx: TCryptoKxSessionKey;
begin
  crypto_kx_keypair(client_pk, client_sk);
  crypto_kx_keypair(server_pk, server_sk);

  if crypto_kx_client_session_keys(client_rx, client_tx, client_pk, client_sk, server_pk) <> 0 then
  begin
    WriteLn('crypto_kx_client_session_keys() => FAILED');
    Exit;
  end;

  if crypto_kx_server_session_keys(server_rx, server_tx, server_pk, server_sk, client_pk) <> 0 then
  begin
    WriteLn('crypto_kx_server_session_keys() => FAILED');
    Exit;
  end;

  WriteLn('client_pk=', THexEncode.FromBytes(@client_pk[0], SizeOf(client_pk)));
  WriteLn('client_sk=', THexEncode.FromBytes(@client_sk[0], SizeOf(client_sk)));
  WriteLn('client_rx=', THexEncode.FromBytes(@client_rx[0], SizeOf(client_rx)));
  WriteLn('client_tx=', THexEncode.FromBytes(@client_tx[0], SizeOf(client_tx)));

  WriteLn('server_pk=', THexEncode.FromBytes(@server_pk[0], SizeOf(server_pk)));
  WriteLn('server_sk=', THexEncode.FromBytes(@server_sk[0], SizeOf(server_sk)));
  WriteLn('server_rx=', THexEncode.FromBytes(@server_rx[0], SizeOf(server_rx)));
  WriteLn('server_tx=', THexEncode.FromBytes(@server_tx[0], SizeOf(server_tx)));
end;

procedure crypto_onetimeauth_test;
var
  &out: TCryptoOnetimeAuth;
  key: TCryptoOnetimeAuthKey;
begin
  var M := TEncoding.UTF8.GetBytes('Data to authenticate');

  crypto_onetimeauth_keygen(key);

  if crypto_onetimeauth(@&out[0], @M[0], Length(M), @key[0]) = 0 then
  begin
    WriteLn('crypto_onetimeauth() => ', THexEncode.FromBytes(@&out[0], SizeOf(&out)));

    if crypto_onetimeauth_verify(@&out[0], @M[0], Length(M), @key[0]) = 0 then
      WriteLn('crypto_onetimeauth_verify() => SUCCESS')
    else
      WriteLn('crypto_onetimeauth_verify() => FAILED')
  end
  else
    WriteLn('crypto_onetimeauth() => FAILED');
end;

procedure crypto_pwhash_test;
var
  salt: TCryptoPwHashSalt;
  key: TCryptoBoxSeed;
  hashed_password: TCryptoPwHashStr;
begin
  randombytes_buf(@salt[0], SizeOf(salt));

  var P := TEncoding.UTF8.GetBytes('Correct Horse Battery Staple');

  if crypto_pwhash(@key[0], SizeOf(key),
                   PAnsiChar(P), Length(P),
                   @salt[0],
                   _CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE, _CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
                   _CRYPTO_PWHASH_ALG_DEFAULT) <> 0 then
    WriteLn('crypto_pwhash() => FAILED')
  else
    WriteLn('crypto_pwhash() => SUCCESS key = ', THexEncode.FromBytes(@key[0], SizeOf(key)));

  if crypto_pwhash_str(hashed_password,
                       PAnsiChar(P), Length(P),
                       _CRYPTO_PWHASH_OPSLIMIT_SENSITIVE, _CRYPTO_PWHASH_MEMLIMIT_SENSITIVE) <> 0 then
    WriteLn('crypto_pwhash_str() => FAILED')
  else
  begin
    WriteLn('crypto_pwhash_str() => SUCCESS');
    WriteLn('hashed_password = ', string(hashed_password));

    if crypto_pwhash_str_verify(hashed_password, PAnsiChar(P), Length(P)) <> 0 then
      WriteLn('crypto_pwhash_str_verify() => FAILED')
    else
      WriteLn('crypto_pwhash_str_verify() => SUCCESS')
  end;
end;

procedure crypto_scalarmult_test;
var
  client_pk: TCryptoBoxPublicKey;
  client_sk: TCryptoBoxSecretKey;
  server_pk: TCryptoBoxPublicKey;
  server_sk: TCryptoBoxSecretKey;
  scalarmult_q_by_client: TCryptoScalarMultQ;
  scalarmult_q_by_server: TCryptoScalarMultQ;
  sharedkey_by_client: TCryptoGenericHashHash;
  sharedkey_by_server: TCryptoGenericHashHash;
  h: TCryptoGenericHashState;
begin
  (* Create client's secret and public keys *)
  randombytes_buf(@client_sk[0], SizeOf(client_sk));
  crypto_scalarmult_base(@client_pk[0], @client_sk[0]);

  (* Create server's secret and public keys *)
  randombytes_buf(@server_sk[0], SizeOf(server_sk));
  crypto_scalarmult_base(@server_pk[0], @server_sk[0]);

  (* The client derives a shared key from its secret key and the server's public key *)
  (* shared key = h(q ‖ client_publickey ‖ server_publickey) *)

  if crypto_scalarmult(@scalarmult_q_by_client[0], @client_sk[0], @server_pk[0]) <> 0 then
  begin
    WriteLn('crypto_scalarmult(q_by_client) => FAILED');
    Exit;
  end;

  WriteLn('crypto_scalarmult(q_by_client) = ', THexEncode.FromBytes(@scalarmult_q_by_client[0], SizeOf(scalarmult_q_by_client)));

  crypto_generichash_init(h, nil, 0, SizeOf(sharedkey_by_client));
  crypto_generichash_update(h, @scalarmult_q_by_client[0], SizeOf(scalarmult_q_by_client));
  crypto_generichash_update(h, @client_pk[0], SizeOf(client_pk));
  crypto_generichash_update(h, @server_pk[0], SizeOf(server_pk));
  crypto_generichash_final(h, @sharedkey_by_client[0], SizeOf(sharedkey_by_client));

  WriteLn('sharedkey_by_client = ', THexEncode.FromBytes(@sharedkey_by_client[0], SizeOf(sharedkey_by_client)));

  (* The server derives a shared key from its secret key and the client's public key *)
  (* shared key = h(q ‖ client_publickey ‖ server_publickey) *)
  if crypto_scalarmult(@scalarmult_q_by_server[0], @server_sk[0], @client_pk[0]) <> 0 then
  begin
    WriteLn('crypto_scalarmult(q_by_server) => FAILED');
    Exit;
  end;
  WriteLn('crypto_scalarmult(q_by_server) = ', THexEncode.FromBytes(@scalarmult_q_by_server[0], SizeOf(scalarmult_q_by_server)));
  crypto_generichash_init(h, nil, 0, SizeOf(sharedkey_by_server));
  crypto_generichash_update(h, @scalarmult_q_by_server[0], SizeOf(scalarmult_q_by_server));
  crypto_generichash_update(h, @client_pk[0], SizeOf(client_pk));
  crypto_generichash_update(h, @server_pk[0], SizeOf(server_pk));
  crypto_generichash_final(h, @sharedkey_by_server[0], SizeOf(sharedkey_by_server));
  WriteLn('sharedkey_by_server = ', THexEncode.FromBytes(@sharedkey_by_server[0], SizeOf(sharedkey_by_server)));
  (* sharedkey_by_client and sharedkey_by_server are identical *)

  if sodium_memcmp(@sharedkey_by_client[0], @sharedkey_by_server[0], SizeOf(TCryptoGenericHashHash)) <> 0 then
    WriteLn('crypto_scalarmult() generation of shared key => FAILED')
  else
    WriteLn('crypto_scalarmult() generation of shared key => SUCCESS')
end;

procedure crypto_secretbox_test;
var
  key: TCryptoSecretBoxKey;
  nonce: TCryptoSecretBoxNonce;
  ciphertext: TBytes;
  decrypted: TBytes;
begin
  var M := TEncoding.UTF8.GetBytes('test');
  SetLength(ciphertext, _CRYPTO_SECRETBOX_MACBYTES + Length(M));

  crypto_secretbox_keygen(key);
  randombytes_buf(@nonce[0], SizeOf(nonce));

  crypto_secretbox_easy(@ciphertext[0], @M[0], Length(M), @nonce[0], @key[0]);

  SetLength(decrypted, Length(M));
  if crypto_secretbox_open_easy(@decrypted[0], @ciphertext[0], Length(ciphertext), @nonce[0], @key[0]) <> 0 then
    WriteLn('crypto_secretbox() => FAILED')
  else
    WriteLn('crypto_secretbox() => SUCCESS');
end;

procedure crypto_secret_stream_test;
var
  state: TCryptoSecretStreamXChacha20Poly1305State;
  key: TCryptoSecretStreamXChacha20Poly1305Key;
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

procedure crypto_short_hash_test;
var
  hash: TCryptoShortHash;
  key: TCryptoShortHashKey;
begin
  var ShortData := TEncoding.UTF8.GetBytes('Sparkling water');

  crypto_shorthash_keygen(key);
  if crypto_shorthash(@hash[0], @ShortData[0], Length(ShortData), @key[0]) = 0 then
    WriteLn('crypto_shorthash() = ', THexEncode.FromBytes(@hash[0], SizeOf(hash)))
  else
    WriteLn('crypto_shorthash() => FAILED');
end;

begin
  try
    crypto_short_hash_test;
    crypto_secretbox_test;
    crypto_secret_stream_test;
    crypto_kdf_test;
    crypto_kx_test;
    crypto_onetimeauth_test;
    crypto_scalarmult_test;
    crypto_pwhash_test;

    ReadLn;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
