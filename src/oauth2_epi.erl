-module(oauth2_epi).

-behaviour(couch_epi_plugin).

-export([
    app/0,
    providers/0,
    services/0,
    data_subscriptions/0,
    data_providers/0,
    processes/0,
    notify/3]).

app() ->
    oauth2.

providers() -> [
    {chttpd_handlers, oauth2_httpd_handlers},
    {chttpd_auth, oauth2_plugin_chttpd_auth}].

services() ->
    [].

data_subscriptions() ->
    [].

data_providers() ->
    [].

processes() ->
    [].

notify(_Key, _Old, _New) ->
    ok.
