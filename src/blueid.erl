-module(blueid).

-compile([export_all]).

-include_lib("jose/include/jose.hrl").

-define(ALLOWED_ALGOS, [<<"RS256">>]).

pem() -> <<
    "-----BEGIN PUBLIC KEY-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtbLV6yge386z4xvlRAuX\n"
    "76/Uj1Ef/98JQSIFN0CqqzwF4KT/4o1jsdaPNp+kJdkPaOkBHe7n9faIXuT+gN4S\n"
    "iWQodh2y0xsj31luJF0WnLjmdkDcDRSm/d1TcnAst8DA/0MkhRKBYcXA9YEpAvea\n"
    "aPOq9O+0wyPsccuIsxMez9ix4NjkIEds8q6VvWYOnUfF+vxbi/aVXRN7JRV8k8XV\n"
    "0ipcaLO5oNnENMzQKAkyhuUw3HkRChbtW5uD7StyIn58J6o6ux2aNJwjtga1ZnQ7\n"
    "03YLci20ahRex2T33IgmrxJNORGFy/MJd+Nxm3IoXCLwEBoOou0HjQ0dX8V45kLb\n"
    "PwIDAQAB\n"
    "-----END PUBLIC KEY-----\n"
    >>.

id_token() ->
    <<"eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJpZGFhcy5pYW0uaWJtLmNvbSIsImV4dCI6IntcImZpcnN0TmFtZVwiOlwiTWluZ1wiLFwibGFzdE5hbWVcIjpcIkx1XCIsXCJyZWFsbU5hbWVcIjpcInd3dy5pYm0uY29tXCIsXCJ0ZW5hbnRJZFwiOlwiaWRhYXMuaWFtLmlibS5jb21cIn0iLCJhdF9oYXNoIjoiTjh6ZTk0bDE1YnZBeXJhUXl1NE9fdyIsInN1YiI6Im1sdUB1cy5pYm0uY29tIiwiYXVkIjoiZTA4Y2xpZW50cCIsImVtYWlsQWRkcmVzcyI6Im1sdUB1cy5pYm0uY29tIiwicmVhbG1OYW1lIjoibWdhIiwidW5pcXVlU2VjdXJpdHlOYW1lIjoibWx1QHVzLmlibS5jb20iLCJleHAiOjE0NDQ0MjYxMTcsImlhdCI6MTQ0NDQyNTgxN30.aJpy69Qf7QTnECiu4ASrUb63yamv_NnGhgHGxwlquT8lJ3EzREgcTYoLx008udjYfRsa3Weyj5OfcE7EB7qlp6JvMOee-cQtiJ8gvLjqTKPndn05XcnYdAgd5ajuRkZohGB_GaqLlkFCVnqFg-r9eyzufqCUfXhnbpp8K7bX1UNfyln0CiYHEBkukp_iD6Up5NMk6N1K4QPLu12x5DvV0gGr0hllSSSpdGaZBxfTEd3A9faSZh_hP-QJj3lSoYwp-UocCgMMx1Aw_D8XAg8QywDHrHr-9STADu6FxjfX8Ou-WoHGiHkOySdHsfGJ0p7hRGkXu3vH3dRshNorKSCS8g">>.

verify() ->
    verify(id_token(), jose_jwk:from_pem(pem())).

verify(Token, JWK) ->
    case jose_jwk:verify_strict(Token, ?ALLOWED_ALGOS, JWK) of
        {true, JWTBin, _JWS} ->
            #jose_jwt{fields = Fields} = jose_jwt:from_binary(JWTBin),
            {ok, Fields};
        _ ->
            {error, verify_failed}
    end.

peek() ->
    jose_jwt:peek(id_token()).
