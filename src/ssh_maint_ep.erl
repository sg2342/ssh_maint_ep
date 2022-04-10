-module(ssh_maint_ep).
-behaviour(ssh_server_key_api).
-behaviour(gen_statem).

-export([host_key/2, is_auth_key/3]).
-export([start_link/0, auth_add/2, auth_del/1, auth_del/2, auth_dump/0,
	 fail_event/3 ,connect_event/3]).
-export([init/1, callback_mode/0, handle_event/4, terminate/3]).
-ignore_xref({start_link, 0}).
-ignore_xref({auth_add, 2}).
-ignore_xref({auth_del, 1}).
-ignore_xref({auth_del, 2}).
-ignore_xref({auth_dump, 0}).
-ignore_xref({fail_event, 3}).
-ignore_xref({connect_event, 3}).

-include_lib("kernel/include/logger.hrl").
-include_lib("public_key/include/public_key.hrl").

-define(SERVER, ?MODULE).
-define(DTAB, ?SERVER).

-type user() :: nonempty_string().
-type curveOid() ::?'id-Ed25519' | ?secp256r1 | ?secp384r1 | ?secp521r1.
-type public_user_key() :: #'RSAPublicKey'{} |
			   {#'ECPoint'{ }, {namedCurve, curveOid()}}.


start_link() -> gen_statem:start_link({local, ?SERVER}, ?MODULE, [], []).

-spec auth_add(user(), public_user_key() | base64:base64_string()) ->
	  ok | {error, term()}.
auth_add(User = [_|_], PublicUserKey) ->
    auth_add1(User, decPKInput(PublicUserKey));
auth_add(_,_) -> {error, invalid_input}.

auth_add1(_, invalid) -> {error, invalid_input};
auth_add1(U, K) -> gen_statem:call(?SERVER, {auth, {add, U, K}}).


-spec auth_del(user(), public_user_key() | base64:base64_string()) ->
	  ok | {error, term()}.
auth_del(User = [_|_], PublicUserKey) ->
    auth_del1(User, decPKInput(PublicUserKey));
auth_del(_,_) -> {error, invalid_input}.

auth_del1(_, invalid) -> {error, invalid_input};
auth_del1(U, K) -> gen_statem:call(?SERVER, {auth, {del, U, K}}).


-spec auth_del(user()) -> ok | {error, term()}.
auth_del(User = [_|_]) -> gen_statem:call(?SERVER, {auth, {del, User}});
auth_del(_) -> {error, invalid_input}.


-spec auth_dump() -> {ok, [{user(), public_user_key()}]} | {error, term()}.
auth_dump() -> gen_statem:call(?SERVER, {auth, dump}).


host_key(Algorithm, [{key_cb_private, [#'RSAPrivateKey'{} = Key]}|_])
  when Algorithm == 'ssh-rsa' ; Algorithm == 'rsa-sha2-256' ;
       Algorithm == 'rsa-sha2-384' ; Algorithm == 'rsa-sha2-512' -> {ok, Key};
host_key(Algorithm,[{key_cb_private,
		     [#'ECPrivateKey'{parameters = {namedCurve, C}} = Key]}|_])
  when   ((Algorithm == 'ssh-ed25519') and (C == ?'id-Ed25519')) 
       ; ((Algorithm == 'ecdsa-sha2-nistp256') and (C == ?secp256r1))
       ; ((Algorithm == 'ecdsa-sha2-nistp384') and (C == ?secp384r1))
       ; ((Algorithm == 'ecdsa-sha2-nistp521') and (C == ?secp521r1)) ->
    {ok, Key};
host_key(_Algorithm, _Opts) -> {error, no}.


is_auth_key({ed_pub, ed25519, PK}, User, DaemonOptions) ->
    PublicUserKey = {#'ECPoint'{ point = PK }, {namedCurve, ?'id-Ed25519'}},
    is_auth_key(PublicUserKey, User, DaemonOptions);
is_auth_key(PublicUserKey, User, DaemonOptions) ->
    gen_statem:call(?SERVER, {is_auth_key, PublicUserKey, User, DaemonOptions}).


fail_event(User, PeerAddr, Reason) ->
    ?LOG_ERROR(#{ ?SERVER => failed
		, user => User
		, from => PeerAddr
		, reason => Reason}).


connect_event(User, PeerAddr, Method) ->
    ?LOG_INFO(#{ ?SERVER => connect
	       , user => User
	       , from => PeerAddr
	       , method => Method}).


callback_mode() -> handle_event_function.


init([]) ->
    _ = erlang:process_flag(trap_exit, true),
    {ok, undefined, #{}, 0}.


handle_event(timeout, _, undefined, D0) ->
    D = init_auth_key_table(D0),
    HostKey = load_or_generate_sshd_key(),
    {ok, L0} = application:get_env(listen),
    Opts = [{key_cb, {?SERVER, [HostKey]}}
	   ,{failfun, fun ?MODULE:fail_event/3}
	   ,{connectfun, fun ?MODULE:connect_event/3}],
    L = lists:map(fun({Port, Opts0}) ->
			  {ok, Sshd} = ssh:daemon(Port, Opts ++ Opts0), Sshd end,
		  L0),
    {next_state, daemon, D#{sshd => L}};
handle_event({call, From}, {is_auth_key, PubUserKey, User, _O}, daemon,
	     #{auth_empty := true} = D) ->
    {ok, Maybe} = application:get_env(trust_first_user_key),
    handle_empty_auth_db(Maybe, From, PubUserKey, User, D);
handle_event({call, From}, {is_auth_key, PubUserKey, User, _O}, daemon, _D) ->
    R = lists:keymember(PubUserKey, 2, dets:lookup(?DTAB, User)),
    {keep_state_and_data, [{reply, From, R}]};
handle_event({call, From}, {auth, A}, _State, D) ->
    R = auth_db(A),
    Empty = (dets:first(?DTAB) == '$end_of_table'),
    {keep_state, D#{auth_empty => Empty}, [{reply, From, R}]}.


handle_empty_auth_db(true, From, PubUserKey, User, D) ->
    ?LOG_NOTICE(#{ ?SERVER => "empty auth db, trust this key"
		 , trust_first_user_key => true
		 , user => User}),
    dets:insert(?DTAB, {User, PubUserKey}),
    {keep_state, D#{auth_empty => false}, [{reply, From, true}]};
handle_empty_auth_db(_, From, _PubUserKey, _User, _D) ->
    ?LOG_NOTICE(#{ ?SERVER => "empty auth db, try application:set_env"
		   "(ssh_maint_ep, trust_first_user_key, true)."}),
    {keep_state_and_data, [{reply, From, false}]}.


auth_db(dump) -> {ok, dets:traverse(?DTAB, fun(V) -> {continue, V} end)};
auth_db({add, User, Key}) -> dets:insert(?DTAB, {User, Key});
auth_db({del, User, Key}) ->  dets:delete_object(?DTAB, {User, Key});
auth_db({del, User}) ->  dets:delete(?DTAB, User).


terminate(_Reason, _, #{sshd := L}) ->
    dets:close(?DTAB),
    lists:foreach(
      fun(Sshd) -> _ = ssh:stop_listener(Sshd),
		   ssh:stop_daemon(Sshd) end,
      L);
terminate(_,_,_) -> dets:close(?DTAB).


init_auth_key_table(D) ->
    {ok, TabFile} = application:get_env(auth_db),
    ok = filelib:ensure_dir(TabFile),
    {ok, ?DTAB} = dets:open_file(?DTAB, [{file, TabFile}
					,{repair, force}
					,{type, duplicate_bag}
					,{access, read_write}
					,{auto_save, 1000}]),
    dets:traverse(?DTAB, fun convert_legacy_ed25519/1),
    Empty = (dets:first(?DTAB) == '$end_of_table'),
    D#{auth_empty => Empty}.


convert_legacy_ed25519({User, {ed_pub, ed25519, PK}}) ->
    {continue, {User, {#'ECPoint'{ point = PK }, {namedCurve, ?'id-Ed25519'}}}};
convert_legacy_ed25519(_) -> continue.


load_or_generate_sshd_key() ->
    {ok, HostKeyFile} = application:get_env(server_key_pem),
    MaybeOk = file:read_file(HostKeyFile),
    load_or_generate_sshd_key(MaybeOk, HostKeyFile).

load_or_generate_sshd_key({error, enoent}, HostKeyFile) ->
    ?LOG_NOTICE(#{ ?SERVER => "SSH host key not found: generate" }),
    ok = filelib:ensure_dir(HostKeyFile),
    Key = public_key:generate_key({namedCurve, ?'id-Ed25519'}),
    {ok, DERKey} = 'OTP-PUB-KEY':encode('ECPrivateKey', Key),
    BIN = public_key:pem_encode([{'ECPrivateKey',
				  iolist_to_binary(DERKey),
				  not_encrypted}]),
    ok = file:write_file(HostKeyFile, BIN),
    Key;
load_or_generate_sshd_key({ok, Bin}, _HostKeyFile) ->
    [K|_] = lists:filter(
	      fun({'ECPrivateKey', _, not_encrypted}) -> true;
		 ({'RSAPrivateKey', _, not_encrypted}) -> true;
		 (_) -> false end, public_key:pem_decode(Bin)),
    public_key:pem_entry_decode(K).


-spec decPKInput(public_user_key() | binary()) -> public_user_key() | invalid.
decPKInput(#'RSAPublicKey'{} = Key) -> Key;
decPKInput({#'ECPoint'{}, {namedCurve, C}} = Key)
  when C == ?'id-Ed25519'; C == ?secp256r1 ; C == ?secp384r1 ; C == ?secp521r1 ->
    Key;
decPKInput(B64Key = [_|_]) -> decB64Key(list_to_binary(B64Key));
decPKInput(B64Key) when is_binary(B64Key) -> decB64Key(B64Key);
decPKInput(_) -> invalid.


-spec decB64Key(binary()) -> public_user_key() | invalid.
decB64Key(<<"ssh-ed25519 ", R/binary>>) -> decB64Key(R);
decB64Key(<<"ssh-rsa ", R/binary>>) -> decB64Key(R);
decB64Key(<<"ecdsa-sha2-nistp256 ", R/binary>>) -> decB64Key(R);
decB64Key(<<"ecdsa-sha2-nistp384 ", R/binary>>) -> decB64Key(R);
decB64Key(<<"ecdsa-sha2-nistp521 ", R/binary>>) -> decB64Key(R);
decB64Key(Bin0) ->
    [Bin|_] = binary:split(Bin0, <<" ">>, [trim_all, global]),
    try decKey(base64:decode(Bin)) catch _:_ -> invalid end.

decKey(<< SigKInfoLen:32, SigKInfo:SigKInfoLen/binary
	, ELen:32, E:ELen/big-signed-integer-unit:8
	, NLen:32, N:NLen/big-signed-integer-unit:8 >>)
  when SigKInfo == <<"ssh-rsa">> ->
    #'RSAPublicKey'{ modulus = N, publicExponent = E};
decKey(<< SigKInfoLen:32, SigKInfo:SigKInfoLen/binary
	, PKLen:32, PK:PKLen/binary >>)
  when SigKInfo == <<"ssh-ed25519">> ->
    { #'ECPoint'{ point = PK }, {namedCurve, ?'id-Ed25519'} };
decKey(<< SigKInfoLen:32, SigKInfo:SigKInfoLen/binary
	, CurveLen:32, Curve:CurveLen/binary
	, PKLen:32, PK:PKLen/binary >>)
  when SigKInfo == <<"ecdsa-sha2-nistp256">> ;
       SigKInfo == <<"ecdsa-sha2-nistp384">> ;
       SigKInfo == <<"ecdsa-sha2-nistp521">> ->
    {#'ECPoint'{ point = PK }, {namedCurve, curvename2oid(Curve)} }.

curvename2oid(<<"nistp256">>) -> ?secp256r1;
curvename2oid(<<"nistp384">>) -> ?secp384r1;
curvename2oid(<<"nistp521">>) -> ?secp521r1.
