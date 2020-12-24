ssh_maint_ep
=====

SSH maintenance end point: provide access to the erlang shell.

Application Environment
-----
~~~~
{listen,  [{inet:port_number(), [ssh:daemon_option()]}]}.
{server_key_pem, file:name_all()}.
{auth_db, file:name_all()}.
{trust_first_user_key, true|false}.
~~~~

listen: port numbers and ssh daemon options.
defaults to `[{15522, [inet]}, {15522, [inet6]}]}`.

server_key_pem : location of SSH server key PEM file; generated if not present.
defaults is  `"/tmp/ssh_maint_ep/server_key.pem"`.

auth_db: location of the authentication database; empty db is created if
not present. default is "/tmp/ssh_maint_ep/auth_db.dets"`.

trust_first_user_key : if true, and the authentication database is empty:
the first connecting User/PuplicKey is added to the authentication database.
default is `false`.

Build
-----

    $ rebar3 compile
