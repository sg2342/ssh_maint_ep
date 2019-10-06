-module(ssh_maint_ep_app).

-behaviour(application).

-export([start/2, stop/1]).

start(_StartType, _StartArgs) -> ssh_maint_ep_sup:start_link().

stop(_State) -> ok.
