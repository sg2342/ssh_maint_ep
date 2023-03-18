-module(ssh_maint_ep_sup).

-behaviour(supervisor).

-export([start_link/0]).

-export([init/1]).

-define(SERVER, ?MODULE).

start_link() -> supervisor:start_link({local, ?SERVER}, ?MODULE, []).

init([]) ->
    SupFlags = #{
        strategy => one_for_all,
        intensity => 0,
        period => 1
    },
    ChildSpecs = [
        #{
            id => ssh_maint_ep,
            start => {ssh_maint_ep, start_link, []}
        }
    ],
    {ok, {SupFlags, ChildSpecs}}.
