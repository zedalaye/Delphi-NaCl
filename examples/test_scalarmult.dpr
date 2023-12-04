program test_scalarmult;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
{$if defined(API)}
  libsodium,
{$endif}
  Sodium.ScalarMult,
  Sodium.Box,
  Sodium.Hash,
  Sodium.Utils;

{$if defined(API)}
procedure test_api(const ClientSecretKey, ServerSecretKey: TCryptoBoxSecretKey);
var
  client_pk: TCryptoBoxPublicKey;
  server_pk: TCryptoBoxPublicKey;
  scalarmult_q_by_client: TCryptoScalarMultQ;
  scalarmult_q_by_server: TCryptoScalarMultQ;
  sharedkey_by_client: TCryptoGenericHashHash;
  sharedkey_by_server: TCryptoGenericHashHash;
  h: TCryptoGenericHashState;
begin
  (* Create client's secret and public keys *)
  crypto_scalarmult_base(@client_pk[0], @ClientSecretKey[0]);

  (* Create server's secret and public keys *)
  crypto_scalarmult_base(@server_pk[0], @ServerSecretKey[0]);

  (* The client derives a shared key from its secret key and the server's public key *)
  (* shared key = h(q ‖ client_publickey ‖ server_publickey) *)

  if crypto_scalarmult(@scalarmult_q_by_client[0], @ClientSecretKey[0], @server_pk[0]) <> 0 then
  begin
    WriteLn('crypto_scalarmult(q_by_client) => FAILED');
    Exit;
  end;

  WriteLn('crypto_scalarmult(q_by_client) = ', TBytes.ToHex(scalarmult_q_by_client, SizeOf(scalarmult_q_by_client)));

  crypto_generichash_init(h, nil, 0, SizeOf(sharedkey_by_client));
  crypto_generichash_update(h, @scalarmult_q_by_client[0], SizeOf(scalarmult_q_by_client));
  crypto_generichash_update(h, @client_pk[0], SizeOf(client_pk));
  crypto_generichash_update(h, @server_pk[0], SizeOf(server_pk));
  crypto_generichash_final(h, @sharedkey_by_client[0], SizeOf(sharedkey_by_client));

  WriteLn('sharedkey_by_client = ', TBytes.ToHex(sharedkey_by_client, SizeOf(sharedkey_by_client)));

  (* The server derives a shared key from its secret key and the client's public key *)
  (* shared key = h(q ‖ client_publickey ‖ server_publickey) *)
  if crypto_scalarmult(@scalarmult_q_by_server[0], @ServerSecretKey[0], @client_pk[0]) <> 0 then
  begin
    WriteLn('crypto_scalarmult(q_by_server) => FAILED');
    Exit;
  end;
  WriteLn('crypto_scalarmult(q_by_server) = ', TBytes.ToHex(scalarmult_q_by_server, SizeOf(scalarmult_q_by_server)));
  crypto_generichash_init(h, nil, 0, SizeOf(sharedkey_by_server));
  crypto_generichash_update(h, @scalarmult_q_by_server[0], SizeOf(scalarmult_q_by_server));
  crypto_generichash_update(h, @client_pk[0], SizeOf(client_pk));
  crypto_generichash_update(h, @server_pk[0], SizeOf(server_pk));
  crypto_generichash_final(h, @sharedkey_by_server[0], SizeOf(sharedkey_by_server));
  WriteLn('sharedkey_by_server = ', TBytes.ToHex(sharedkey_by_server, SizeOf(sharedkey_by_server)));
  (* sharedkey_by_client and sharedkey_by_server are identical *)

  if sodium_memcmp(@sharedkey_by_client[0], @sharedkey_by_server[0], SizeOf(TCryptoGenericHashHash)) <> 0 then
    WriteLn('crypto_scalarmult() generation of shared key => FAILED')
  else
    WriteLn('crypto_scalarmult() generation of shared key => SUCCESS')
end;
{$endif}

procedure test_client(const ClientSecretKey, ServerSecretKey: TCryptoBoxSecretKey);
var
  ClientPublicKey: TCryptoBoxPublicKey;
  ServerPublicKey: TCryptoBoxSecretKey;
  ScalarmultQByClient: TCryptoScalarMultQ;
  SharedKeyByClient: TCryptoGenericHashHash;
begin
  (* Create client's secret and public keys *)
  if
    TCryptoScalarMult.Base(ClientPublicKey, ClientSecretKey) and
    TCryptoScalarMult.Base(ServerPublicKey, ServerSecretKey)
  then

    (* The client derives a shared key from its secret key and the server's public key *)
    (* shared key = h(q ‖ client_publickey ‖ server_publickey) *)

    if TCryptoScalarMult.Compute(ScalarmultQByClient, ClientSecretKey, ServerPublicKey) then
    begin
      WriteLn('SUCCESS');
      WriteLn('Q By Client = ', TBytes.ToHex(ScalarmultQByClient, SizeOf(ScalarmultQByClient)));

      var I := 0;
      TCryptoGenericHash.Hash(
        SharedKeyByClient,
        procedure(var Buf: TBytes; var Done: Boolean)
        begin
          case I of
          0: Buf := TBytes.FromBuf(ScalarmultQByClient, SizeOf(ScalarmultQByClient));
          1: Buf := TBytes.FromBuf(ClientPublicKey, SizeOf(ClientPublicKey));
          2: Buf := TBytes.FromBuf(ServerPublicKey, SizeOf(ServerPublicKey));
          end;
          Inc(I);
          Done := I > 2;
        end
      );

      WriteLn('SharedKeyByClient=', TBytes.ToHex(SharedKeyByClient, SizeOf(SharedKeyByClient)));
    end
    else
      WriteLn('FAILED (TCryptoScalarMult.Compute)')

  else
    WriteLn('FAILED (TCryptoScalarMult.Base)');
end;

procedure test_server(const ClientSecretKey, ServerSecretKey: TCryptoBoxSecretKey);
var
  ClientPublicKey: TCryptoBoxPublicKey;
  ServerPublicKey: TCryptoBoxSecretKey;
  ScalarmultQByServer: TCryptoScalarMultQ;
  SharedKeyByServer: TCryptoGenericHashHash;
begin
  (* Create client's secret and public keys *)
  if
    TCryptoScalarMult.Base(ClientPublicKey, ClientSecretKey) and
    TCryptoScalarMult.Base(ServerPublicKey, ServerSecretKey)
  then

    (* The client derives a shared key from its secret key and the server's public key *)
    (* shared key = h(q ‖ client_publickey ‖ server_publickey) *)

    if TCryptoScalarMult.Compute(ScalarmultQByServer, ServerSecretKey, ClientPublicKey) then
    begin
      WriteLn('SUCCESS');
      WriteLn('Q By Server = ', TBytes.ToHex(ScalarmultQByServer, SizeOf(ScalarmultQByServer)));

      var I := 0;
      TCryptoGenericHash.Hash(
        SharedKeyByServer,
        procedure(var Buf: TBytes; var Done: Boolean)
        begin
          case I of
          0: Buf := TBytes.FromBuf(ScalarmultQByServer, SizeOf(ScalarmultQByServer));
          1: Buf := TBytes.FromBuf(ClientPublicKey, SizeOf(ClientPublicKey));
          2: Buf := TBytes.FromBuf(ServerPublicKey, SizeOf(ServerPublicKey));
          end;
          Inc(I);
          Done := I > 2;
        end
      );

      WriteLn('SharedKeyByServer=', TBytes.ToHex(SharedKeyByServer, SizeOf(SharedKeyByServer)));
    end
    else
      WriteLn('FAILED (TCryptoScalarMult.Compute)')

  else
    WriteLn('FAILED (TCryptoScalarMult.Base)');
end;

var
  ClientSecretKey: TCryptoBoxSecretKey;
  ServerSecretKey: TCryptoBoxSecretKey;

begin
  try
    TBytes.Random(ClientSecretKey, SizeOf(ClientSecretKey));
    TBytes.Random(ServerSecretKey, SizeOf(ServerSecretKey));

    WriteLn('TCryptoScalarMult.Primirive=', TCryptoScalarMult.Primitive);
  {$if defined(API)}
    Write('API...'); test_api(ClientSecretKey, ServerSecretKey);
  {$endif}
    Write('Wrapper (CLIENT)...'); test_client(ClientSecretKey, ServerSecretKey);
    Write('Wrapper (SERVER)...'); test_server(ClientSecretKey, ServerSecretKey);

    ReadLn;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
