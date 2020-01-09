module Auth exposing (..)


type alias Model =
    ()


type alias Msg =
    ()


type Status
    = LoggedOut
    | Failed
    | LoggedIn { scopes : List String, subject : String }


init =
    Debug.todo "init"


unauthed =
    Debug.todo "unauthed"


login =
    Debug.todo "login"


refresh =
    Debug.todo "refresh"


update =
    Debug.todo "update"
