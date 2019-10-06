-module(ssh_maint_ep).
-behaviour(ssh_server_key_api).
-behaviour(gen_statem).

-export([host_key/2, is_auth_key/3]).
-export([start_link/0, auth_add/2, auth_del/1, auth_del/2, fail_event/3
	,connect_event/3]).
-export([init/1, callback_mode/0, handle_event/4, terminate/3]).
-ignore_xref({start_link, 0}).
-ignore_xref({auth_add, 2}).
-ignore_xref({auth_del, 1}).
-ignore_xref({auth_del, 2}).
-ignore_xref({fail_event, 3}).
-ignore_xref({connect_event, 3}).

-define(SERVER, ?MODULE).
-define(DTAB, ?SERVER).

start_link() -> gen_statem:start_link({local, ?SERVER}, ?MODULE, [], []).


auth_add(User, Key) -> gen_statem:call(?SERVER, {auth, {add, User, Key}}).


auth_del(User, Key) -> gen_statem:call(?SERVER, {auth, {del, User, Key}}).


auth_del(User) -> gen_statem:call(?SERVER, {auth, {del, User}}).


host_key(Algorithm, [{key_cb_private, [Key]}|_])
  when Algorithm == 'ssh-rsa' ; Algorithm == 'rsa-sha2-256' ;
       Algorithm == 'rsa-sha2-384' ; Algorithm == 'rsa-sha2-512' -> {ok, Key};
host_key(_Algorithm, _Opts) -> {error, no}.


is_auth_key(PublicUserKey, User, DaemonOptions) ->
    gen_statem:call(?SERVER, {is_auth_key, PublicUserKey, User, DaemonOptions}).


fail_event(User, PeerAddr, Reason) ->
    error_logger:error_report([?SERVER
			      ,{failed, #{user => User
					 ,from => PeerAddr
					 ,reason => Reason}}]).


connect_event(User, PeerAddr, Method) ->
    error_logger:info_report([?SERVER
			     ,{connect, #{user => User
					 ,from => PeerAddr
					 ,method => Method}}]).


callback_mode() -> handle_event_function.


init([]) ->
    _ = erlang:process_flag(trap_exit, true),
    {ok, undefined, #{}, 0}.


handle_event(timeout, _, undefined, D0) ->
    D = init_auth_key_table(D0),
    HostKey = load_or_generate_sshd_key(),
    {ok, Port} = application:get_env(port),
    {ok, Opts0} = application:get_env(opts),
    Opts = [{key_cb, {?SERVER, [HostKey]}}
	   ,{failfun, fun ?MODULE:fail_event/3}
	   ,{connectfun, fun ?MODULE:connect_event/3}|Opts0],
    {ok, Sshd} = ssh:daemon(Port, Opts),
    {next_state, daemon, D#{sshd => Sshd}};
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
    error_logger:info_report([?SERVER, {trust_first_user_key, true}
			     , {user, User}
			     , "empty auth db, trust this key"]),
    dets:insert(?DTAB, {User, PubUserKey}),
    {keep_state, D#{auth_empty => false}, [{reply, From, true}]};
handle_empty_auth_db(_, From, _PubUserKey, _User, _D) ->
    error_logger:info_report([?SERVER, "empty auth db, try application:set_env"
			      "(ssh_maint_ep, trust_first_user_key, true)."]),
    {keep_state_and_data, [{reply, From, false}]}.


auth_db({add, User, Key}) -> dets:insert(?DTAB, {User, Key});
auth_db({del, User, Key}) ->  dets:delete_object(?DTAB, {User, Key});
auth_db({del, User}) ->  dets:delete(?DTAB, User).


terminate(_Reason, _, #{sshd := Sshd}) ->
    dets:close(?DTAB),
    _ = ssh:stop_listener(Sshd),
    ssh:stop_daemon(Sshd);
terminate(_,_,_) -> dets:close(?DTAB).


init_auth_key_table(D) ->
    {ok, TabFile} = application:get_env(auth_db),
    ok = filelib:ensure_dir(TabFile),
    {ok, ?DTAB} = dets:open_file(?DTAB, [{file, TabFile}
					,{repair, force}
					,{type, duplicate_bag}
					,{access, read_write}
					,{auto_save, 1000}]),
    Empty = (dets:first(?DTAB) == '$end_of_table'),
    D#{auth_empty => Empty}.


load_or_generate_sshd_key() ->
    {ok, HostKeyFile} = application:get_env(server_key_pem),
    MaybeOk = file:read_file(HostKeyFile),
    load_or_generate_sshd_key(MaybeOk, HostKeyFile).

load_or_generate_sshd_key({error, enoent}, HostKeyFile) ->
    error_logger:info_report([?SERVER, "SSH host key not found: generate"]),
    ok = filelib:ensure_dir(HostKeyFile),
    Key = public_key:generate_key({rsa, 4096, 65537}),
    {ok, DERKey} = 'OTP-PUB-KEY':encode('RSAPrivateKey', Key),
    BIN = public_key:pem_encode([{'RSAPrivateKey',
				  iolist_to_binary(DERKey),
				  not_encrypted}]),
    ok = file:write_file(HostKeyFile, BIN),
    Key;
load_or_generate_sshd_key({ok, Bin}, _HostKeyFile) ->
    {'RSAPrivateKey', _, not_encrypted} = E =
	lists:keyfind('RSAPrivateKey', 1, public_key:pem_decode(Bin)),
    public_key:pem_entry_decode(E).
