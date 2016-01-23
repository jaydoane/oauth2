-module(oauth2_plugin_chttpd_auth).

-export([authorize/1,
         authenticate/1]).

-include_lib("couch/include/couch_db.hrl").

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

authorize(#httpd{path_parts=[<<"_oauth2_session">>|_], method = 'POST'} = Req) ->
    {decided, Req};
authorize(_Req) ->
    no_decision.

authenticate(Req) ->
    AuthenticationFuns =
        [{<<"oauth2_token">>, fun oauth2:token_authentication_handler/1}],
    case chttpd:authenticate_request(Req, cloudant_auth_cache, AuthenticationFuns) of
        #httpd{user_ctx = undefined} ->
            no_decision;
        #httpd{user_ctx = #user_ctx{roles=[_ | _]}} = Res ->
            {decided, Res}
    end.
