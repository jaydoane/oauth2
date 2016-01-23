-module(oauth2).

-export([
    handle_session_req/1,
    token_authentication_handler/1]).

-include_lib("couch/include/couch_db.hrl").

-type request() :: #httpd{}.
-type mochiweb_response() :: term().

-define(AUTHORIZATION_HEADER, "Authorization").
-define(BEARER_TOKEN, "Bearer").

%% config() ->
%%     config:get("oauth2", "authorization_server", "https://localhost:3000").

-spec token_authentication_handler(request()) -> request().
token_authentication_handler(#httpd{mochi_req=MochiReq}=Req) ->
    couch_log:info("oauth2:token_authentication_handler", []),
    case MochiReq:get_header_value(?AUTHORIZATION_HEADER) of
        undefined ->
            Req;
        [] ->
            Req;
        Header ->
            couch_log:notice("oauth2 Authorization header ~p", [Header]),
            Req
    end.

-spec handle_session_req(request()) -> {ok, mochiweb_response()}.
%% handle_session_req(#httpd{method='POST'}=Req) ->
%%     chttpd_auth:handle_session_req(Req)
handle_session_req(Req) ->
    couch_log:info("oauth2:handle_session_req", []),
    chttpd_auth:handle_session_req(Req).
