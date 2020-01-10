module AuthInterface exposing (..)

{-| Trying to capture authentication as an interface - so that multiple
implementations can exist that are easily substitutable.
-}


type alias Credentials =
    { username : String
    , password : String
    }


type Status
    = LoggedOut
    | Failed
    | LoggedIn { scopes : List String, subject : String }


type alias AuthI config model msg =
    { init : config -> model
    , unauthed : Cmd msg
    , logout : Cmd msg
    , login : Credentials -> Cmd msg
    , refresh : Cmd msg
    , update : msg -> model -> ( model, Cmd msg, Maybe Status )
    }
