module Auth exposing
    ( Config, Credentials, Status(..)
    , login, refresh, logout, unauthed
    , Model, Msg, init, update
    )

{-| Manages the state of the authentication process, and provides an API
to request authentication operations.

@docs Config, Credentials, Status
@docs login, refresh, logout, unauthed
@docs Model, Msg, init, update

-}

import AWS.CognitoIdentityProvider as CIP
import AWS.Core.Service exposing (Region)
import Task.Extra


{-| The configuration specifying the API root to authenticate against.
-}
type alias Config =
    { clientId : String
    , userPoolId : String
    , region : Region
    }


{-| Username and password based login credentials.
-}
type alias Credentials =
    { username : String
    , password : String
    }


type alias Model =
    { config : Config
    }


type Msg
    = LogIn Credentials
    | Refresh
    | LogOut
    | NotAuthed



-- | LogInResponse (Result.Result Http.Error Model.AuthResponse)
-- | RefreshResponse (Result.Result Http.Error Model.AuthResponse)
-- | LogOutResponse (Result.Result Http.Error ())


type Status
    = LoggedOut
    | Failed
    | LoggedIn { scopes : List String, subject : String }


init : Config -> Model
init config =
    { config = config }


unauthed : Cmd Msg
unauthed =
    Cmd.none


logout : Cmd Msg
logout =
    Cmd.none


login : Credentials -> Cmd Msg
login credentials =
    LogIn credentials |> Task.Extra.message


refresh : Cmd Msg
refresh =
    Refresh |> Task.Extra.message


update : Msg -> Model -> ( Model, Cmd Msg, Maybe Status )
update msg model =
    case msg of
        LogIn credentials ->
            ( model, Cmd.none, Nothing )

        Refresh ->
            ( model, Cmd.none, Just LoggedOut )

        _ ->
            ( model, Cmd.none, Nothing )
