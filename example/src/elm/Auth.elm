module Auth exposing (..)

import AWS.CognitoIdentityProvider as CIP


{-| The configuration specifying the API root to authenticate against.
-}
type alias Config =
    { authApiRoot : String
    }


{-| Username and password based login credentials.
-}
type alias Credentials =
    { username : String
    , password : String
    }


type alias Model =
    {}


type alias Msg =
    ()


type Status
    = LoggedOut
    | Failed
    | LoggedIn { scopes : List String, subject : String }


init : Config -> Model
init _ =
    {}


unauthed : Cmd Msg
unauthed =
    Cmd.none


logout : Cmd Msg
logout =
    Cmd.none


login : Credentials -> Cmd Msg
login _ =
    Cmd.none


refresh : Cmd Msg
refresh =
    Cmd.none


update : Msg -> Model -> ( Model, Cmd Msg, Maybe Status )
update msg model =
    ( model, Cmd.none, Nothing )
