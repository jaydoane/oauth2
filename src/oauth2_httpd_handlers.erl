-module(oauth2_httpd_handlers).

-export([url_handler/1, db_handler/1, design_handler/1]).

url_handler(<<"_oauth2_session">>) -> fun oauth2:handle_session_req/1;
url_handler(_) -> no_match.

db_handler(_) -> no_match.

design_handler(_) -> no_match.
