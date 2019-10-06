ssh_maint_ep
=====

SSH maintenance end point: provide access to the erlang shell.

Application Environment
-----

port : the SSH listening port
    (default 15522)

opts : ssh daemon options
    (default [])

server_key_pem : location of SSH server key PEM file; generated if not present
    (default "/tmp/ssh_maint_ep/server_key.pem")

auth_db: location of the authentication database; empty db is created if
not present
    (default "/tmp/ssh_maint_ep/auth_db.dets")

trust_first_user_key : if true, and the authentication databse is empty:
the first connecting User/PuplicKey is added to the authentication database
    (default false)

Build
-----

    $ rebar3 compile
