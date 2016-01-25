-module(oauth2).

-export([
    handle_session_req/1]).
    %% token_authentication_handler/1]).

-include_lib("couch/include/couch_db.hrl").

-type request() :: #httpd{}.
-type mochiweb_response() :: term().

-define(AUTHORIZATION_HEADER, "Authorization").
-define(BEARER_PREFIX, "Bearer ").

%% -spec token_authentication_handler(request()) -> request().
%% token_authentication_handler(Req) ->
%%     couch_log:info("oauth2:token_authentication_handler", []),
%%     Req.

-spec handle_session_req(request()) -> {ok, mochiweb_response()}.
handle_session_req(#httpd{method = 'POST'} = Req) ->
    couch_log:info("oauth2:handle_session_req", []),
    case couch_httpd:header_value(Req, ?AUTHORIZATION_HEADER) of
        undefined ->
            throw({unauthorized, <<"Authorization header required">>});
        ?BEARER_PREFIX ++ Token ->
            handle_bearer_token(Req, Token);
        _ ->
            throw({unauthorized, <<"Malformed Bearer token">>})
    end;
handle_session_req(Req) ->
    Req.

handle_bearer_token(Req, Token) ->
    couch_log:info("oauth2:handle_bearer_token ~p", [Token]),
    case blueid:verify(?l2b(Token)) of
        {error, verify_failed} ->
            throw({unauthorized, <<"Authorization verification failed">>});
        {ok, #{<<"sub">> := Username, <<"iat">> := _Iat, <<"exp">> := _Exp}} ->
            Now = now_epoch(),
            % TODO: only auth when iat <= now <= exp
            case cloudant_auth_cache:get_user_creds(Req, Username) of
                nil ->
                    throw({unauthorized, <<"User account non-existent">>});
                {ok, UserProps, _} ->
                    Secret = ?l2b(couch_httpd_auth:ensure_cookie_auth_secret()),
                    Salt = couch_util:get_value(<<"salt">>, UserProps),
                    Cookie = auth_cookie(Req, Username, Secret, Salt, Now),
                    Code = 200,
                    Json = {[
                        {ok, true},
                        {name, Username}]},
                    couch_httpd:send_json(Req, Code, [Cookie], Json)
            end
    end.


auth_cookie(Req, Username, Secret, Salt, EpochSeconds) ->
    couch_httpd_auth:cookie_auth_cookie(
        Req, ?b2l(Username), <<Secret/binary, Salt/binary>>, EpochSeconds).
    
now_epoch() ->
    os:system_time(seconds).
