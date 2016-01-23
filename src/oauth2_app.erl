-module(oauth2_app).
-behaviour(application).

-export([
    start/2,
    stop/1]).

start(_Type, []) ->
    oauth_sup:start_link().

stop([]) ->
    ok.
