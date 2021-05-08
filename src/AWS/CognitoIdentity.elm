module AWS.CognitoIdentity exposing
    ( service
    , createIdentityPool, deleteIdentities, deleteIdentityPool, describeIdentity, describeIdentityPool, getCredentialsForIdentity, getId
    , getIdentityPoolRoles, getOpenIdToken, getOpenIdTokenForDeveloperIdentity, listIdentities, listIdentityPools, listTagsForResource
    , lookupDeveloperIdentity, mergeDeveloperIdentities, setIdentityPoolRoles, tagResource, unlinkDeveloperIdentity, unlinkIdentity
    , untagResource, updateIdentityPool
    , AmbiguousRoleResolutionType(..), CognitoIdentityProvider, CognitoIdentityProviderList, CreateIdentityPoolInput, Credentials
    , DeleteIdentitiesInput, DeleteIdentitiesResponse, DeleteIdentityPoolInput, DescribeIdentityInput, DescribeIdentityPoolInput
    , DeveloperUserIdentifierList, ErrorCode(..), GetCredentialsForIdentityInput, GetCredentialsForIdentityResponse, GetIdInput
    , GetIdResponse, GetIdentityPoolRolesInput, GetIdentityPoolRolesResponse, GetOpenIdTokenForDeveloperIdentityInput
    , GetOpenIdTokenForDeveloperIdentityResponse, GetOpenIdTokenInput, GetOpenIdTokenResponse, IdentitiesList, IdentityDescription
    , IdentityIdList, IdentityPool, IdentityPoolShortDescription, IdentityPoolTagsListType, IdentityPoolTagsType, IdentityPoolsList
    , IdentityProviders, ListIdentitiesInput, ListIdentitiesResponse, ListIdentityPoolsInput, ListIdentityPoolsResponse
    , ListTagsForResourceInput, ListTagsForResourceResponse, LoginsList, LoginsMap, LookupDeveloperIdentityInput
    , LookupDeveloperIdentityResponse, MappingRule, MappingRuleMatchType(..), MappingRulesList, MergeDeveloperIdentitiesInput
    , MergeDeveloperIdentitiesResponse, OidcproviderList, RoleMapping, RoleMappingMap, RoleMappingType(..), RolesMap, RulesConfigurationType
    , SamlproviderList, SetIdentityPoolRolesInput, TagResourceInput, TagResourceResponse, UnlinkDeveloperIdentityInput
    , UnlinkIdentityInput, UnprocessedIdentityId, UnprocessedIdentityIdList, UntagResourceInput, UntagResourceResponse
    , ambiguousRoleResolutionType, errorCode, mappingRuleMatchType, roleMappingType
    )

{-|


## Amazon Cognito Federated Identities

Amazon Cognito Federated Identities is a web service that delivers scoped temporary credentials to mobile devices and other untrusted environments. It uniquely identifies a device and supplies the user with a consistent identity over the lifetime of an application.

Using Amazon Cognito Federated Identities, you can enable authentication with one or more third-party identity providers (Facebook, Google, or Login with Amazon) or an Amazon Cognito user pool, and you can also choose to support unauthenticated access from your app. Cognito delivers a unique identifier for each user and acts as an OpenID token provider trusted by AWS Security Token Service (STS) to access temporary, limited-privilege AWS credentials.

For a description of the authentication flow from the Amazon Cognito Developer Guide see `Authentication Flow`.

For more information see `Amazon Cognito Federated Identities`.


# Service definition.

@docs service


# Service endpoints.

@docs createIdentityPool, deleteIdentities, deleteIdentityPool, describeIdentity, describeIdentityPool, getCredentialsForIdentity, getId
@docs getIdentityPoolRoles, getOpenIdToken, getOpenIdTokenForDeveloperIdentity, listIdentities, listIdentityPools, listTagsForResource
@docs lookupDeveloperIdentity, mergeDeveloperIdentities, setIdentityPoolRoles, tagResource, unlinkDeveloperIdentity, unlinkIdentity
@docs untagResource, updateIdentityPool


# API data model.

@docs AmbiguousRoleResolutionType, CognitoIdentityProvider, CognitoIdentityProviderList, CreateIdentityPoolInput, Credentials
@docs DeleteIdentitiesInput, DeleteIdentitiesResponse, DeleteIdentityPoolInput, DescribeIdentityInput, DescribeIdentityPoolInput
@docs DeveloperUserIdentifierList, ErrorCode, GetCredentialsForIdentityInput, GetCredentialsForIdentityResponse, GetIdInput
@docs GetIdResponse, GetIdentityPoolRolesInput, GetIdentityPoolRolesResponse, GetOpenIdTokenForDeveloperIdentityInput
@docs GetOpenIdTokenForDeveloperIdentityResponse, GetOpenIdTokenInput, GetOpenIdTokenResponse, IdentitiesList, IdentityDescription
@docs IdentityIdList, IdentityPool, IdentityPoolShortDescription, IdentityPoolTagsListType, IdentityPoolTagsType, IdentityPoolsList
@docs IdentityProviders, ListIdentitiesInput, ListIdentitiesResponse, ListIdentityPoolsInput, ListIdentityPoolsResponse
@docs ListTagsForResourceInput, ListTagsForResourceResponse, LoginsList, LoginsMap, LookupDeveloperIdentityInput
@docs LookupDeveloperIdentityResponse, MappingRule, MappingRuleMatchType, MappingRulesList, MergeDeveloperIdentitiesInput
@docs MergeDeveloperIdentitiesResponse, OidcproviderList, RoleMapping, RoleMappingMap, RoleMappingType, RolesMap, RulesConfigurationType
@docs SamlproviderList, SetIdentityPoolRolesInput, TagResourceInput, TagResourceResponse, UnlinkDeveloperIdentityInput
@docs UnlinkIdentityInput, UnprocessedIdentityId, UnprocessedIdentityIdList, UntagResourceInput, UntagResourceResponse
@docs ambiguousRoleResolutionType, errorCode, mappingRuleMatchType, roleMappingType

-}

import AWS.Config
import AWS.Http
import AWS.KVDecode exposing (KVDecoder)
import AWS.Service
import Codec exposing (Codec)
import Dict exposing (Dict)
import Enum exposing (Enum)
import Json.Decode exposing (Decoder, Value)
import Json.Decode.Pipeline as Pipeline
import Json.Encode exposing (Value)
import Json.Encode.Optional as EncodeOpt


{-| Configuration for this service.
-}
service : AWS.Config.Region -> AWS.Service.Service
service region =
    AWS.Config.defineRegional "cognito-identity" "2014-06-30" AWS.Config.JSON AWS.Config.SignV4 region
        |> AWS.Config.withJsonVersion "1.1"
        |> AWS.Config.withTargetPrefix "AWSCognitoIdentityService"
        |> AWS.Service.service


{-| Updates an identity pool.

You must use AWS Developer credentials to call this API.

-}
updateIdentityPool : IdentityPool -> AWS.Http.Request AWS.Http.AWSAppError IdentityPool
updateIdentityPool req =
    let
        encoder val =
            [ ( "SupportedLoginProviders", val.supportedLoginProviders )
                |> EncodeOpt.optionalField (Codec.encoder identityProvidersCodec)
            , ( "SamlProviderARNs", val.samlProviderArns )
                |> EncodeOpt.optionalField (Codec.encoder samlproviderListCodec)
            , ( "OpenIdConnectProviderARNs", val.openIdConnectProviderArns )
                |> EncodeOpt.optionalField (Codec.encoder oidcproviderListCodec)
            , ( "IdentityPoolTags", val.identityPoolTags )
                |> EncodeOpt.optionalField (Codec.encoder identityPoolTagsTypeCodec)
            , ( "IdentityPoolName", val.identityPoolName ) |> EncodeOpt.field Json.Encode.string
            , ( "IdentityPoolId", val.identityPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "DeveloperProviderName", val.developerProviderName ) |> EncodeOpt.optionalField Json.Encode.string
            , ( "CognitoIdentityProviders", val.cognitoIdentityProviders )
                |> EncodeOpt.optionalField (Codec.encoder cognitoIdentityProviderListCodec)
            , ( "AllowUnauthenticatedIdentities", val.allowUnauthenticatedIdentities )
                |> EncodeOpt.field Json.Encode.bool
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\supportedLoginProvidersFld samlProviderArnsFld openIdConnectProviderArnsFld identityPoolTagsFld identityPoolNameFld identityPoolIdFld developerProviderNameFld cognitoIdentityProvidersFld allowUnauthenticatedIdentitiesFld ->
                { allowUnauthenticatedIdentities = allowUnauthenticatedIdentitiesFld
                , cognitoIdentityProviders = cognitoIdentityProvidersFld
                , developerProviderName = developerProviderNameFld
                , identityPoolId = identityPoolIdFld
                , identityPoolName = identityPoolNameFld
                , identityPoolTags = identityPoolTagsFld
                , openIdConnectProviderArns = openIdConnectProviderArnsFld
                , samlProviderArns = samlProviderArnsFld
                , supportedLoginProviders = supportedLoginProvidersFld
                }
             )
                |> Json.Decode.succeed
            )
                |> Pipeline.optional
                    "SupportedLoginProviders"
                    (Json.Decode.maybe (Codec.decoder identityProvidersCodec))
                    Nothing
                |> Pipeline.optional
                    "SamlProviderARNs"
                    (Json.Decode.maybe (Codec.decoder samlproviderListCodec))
                    Nothing
                |> Pipeline.optional
                    "OpenIdConnectProviderARNs"
                    (Json.Decode.maybe (Codec.decoder oidcproviderListCodec))
                    Nothing
                |> Pipeline.optional
                    "IdentityPoolTags"
                    (Json.Decode.maybe (Codec.decoder identityPoolTagsTypeCodec))
                    Nothing
                |> Pipeline.required "IdentityPoolName" Json.Decode.string
                |> Pipeline.required "IdentityPoolId" Json.Decode.string
                |> Pipeline.optional "DeveloperProviderName" (Json.Decode.maybe Json.Decode.string) Nothing
                |> Pipeline.optional
                    "CognitoIdentityProviders"
                    (Json.Decode.maybe (Codec.decoder cognitoIdentityProviderListCodec))
                    Nothing
                |> Pipeline.required "AllowUnauthenticatedIdentities" Json.Decode.bool
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "UpdateIdentityPool" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Removes the specified tags from an Amazon Cognito identity pool. You can use this action up to 5 times per second, per account
-}
untagResource : UntagResourceInput -> AWS.Http.Request AWS.Http.AWSAppError ()
untagResource req =
    let
        encoder val =
            [ ( "TagKeys", val.tagKeys ) |> EncodeOpt.optionalField identityPoolTagsListTypeEncoder
            , ( "ResourceArn", val.resourceArn ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "UntagResource" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Unlinks a federated identity from an existing account. Unlinked logins will be considered new identities next time they are seen. Removing the last linked login will make this identity inaccessible.

This is a public API. You do not need any credentials to call this API.

-}
unlinkIdentity : UnlinkIdentityInput -> AWS.Http.Request AWS.Http.AWSAppError ()
unlinkIdentity req =
    let
        encoder val =
            [ ( "LoginsToRemove", val.loginsToRemove ) |> EncodeOpt.field (Codec.encoder loginsListCodec)
            , ( "Logins", val.logins ) |> EncodeOpt.field loginsMapEncoder
            , ( "IdentityId", val.identityId ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "UnlinkIdentity" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Unlinks a `DeveloperUserIdentifier` from an existing identity. Unlinked developer users will be considered new identities next time they are seen. If, for a given Cognito identity, you remove all federated identities as well as the developer user identifier, the Cognito identity becomes inaccessible.

You must use AWS Developer credentials to call this API.

-}
unlinkDeveloperIdentity : UnlinkDeveloperIdentityInput -> AWS.Http.Request AWS.Http.AWSAppError ()
unlinkDeveloperIdentity req =
    let
        encoder val =
            [ ( "IdentityPoolId", val.identityPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "IdentityId", val.identityId ) |> EncodeOpt.field Json.Encode.string
            , ( "DeveloperUserIdentifier", val.developerUserIdentifier ) |> EncodeOpt.field Json.Encode.string
            , ( "DeveloperProviderName", val.developerProviderName ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "UnlinkDeveloperIdentity" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Assigns a set of tags to an Amazon Cognito identity pool. A tag is a label that you can use to categorize and manage identity pools in different ways, such as by purpose, owner, environment, or other criteria.

Each tag consists of a key and value, both of which you define. A key is a general category for more specific values. For example, if you have two versions of an identity pool, one for testing and another for production, you might assign an `Environment` tag key to both identity pools. The value of this key might be `Test` for one identity pool and `Production` for the other.

Tags are useful for cost tracking and access control. You can activate your tags so that they appear on the Billing and Cost Management console, where you can track the costs associated with your identity pools. In an IAM policy, you can constrain permissions for identity pools based on specific tags or tag values.

You can use this action up to 5 times per second, per account. An identity pool can have as many as 50 tags.

-}
tagResource : TagResourceInput -> AWS.Http.Request AWS.Http.AWSAppError ()
tagResource req =
    let
        encoder val =
            [ ( "Tags", val.tags ) |> EncodeOpt.optionalField (Codec.encoder identityPoolTagsTypeCodec)
            , ( "ResourceArn", val.resourceArn ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "TagResource" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Sets the roles for an identity pool. These roles are used when making calls to `GetCredentialsForIdentity` action.

You must use AWS Developer credentials to call this API.

-}
setIdentityPoolRoles : SetIdentityPoolRolesInput -> AWS.Http.Request AWS.Http.AWSAppError ()
setIdentityPoolRoles req =
    let
        encoder val =
            [ ( "Roles", val.roles ) |> EncodeOpt.field (Codec.encoder rolesMapCodec)
            , ( "RoleMappings", val.roleMappings ) |> EncodeOpt.optionalField (Codec.encoder roleMappingMapCodec)
            , ( "IdentityPoolId", val.identityPoolId ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "SetIdentityPoolRoles" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Merges two users having different `IdentityId`s, existing in the same identity pool, and identified by the same developer provider. You can use this action to request that discrete users be merged and identified as a single user in the Cognito environment. Cognito associates the given source user (`SourceUserIdentifier`) with the `IdentityId` of the `DestinationUserIdentifier`. Only developer-authenticated users can be merged. If the users to be merged are associated with the same public provider, but as two different users, an exception will be thrown.

The number of linked logins is limited to 20. So, the number of linked logins for the source user, `SourceUserIdentifier`, and the destination user, `DestinationUserIdentifier`, together should not be larger than 20. Otherwise, an exception will be thrown.

You must use AWS Developer credentials to call this API.

-}
mergeDeveloperIdentities : MergeDeveloperIdentitiesInput -> AWS.Http.Request AWS.Http.AWSAppError MergeDeveloperIdentitiesResponse
mergeDeveloperIdentities req =
    let
        encoder val =
            [ ( "SourceUserIdentifier", val.sourceUserIdentifier ) |> EncodeOpt.field Json.Encode.string
            , ( "IdentityPoolId", val.identityPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "DeveloperProviderName", val.developerProviderName ) |> EncodeOpt.field Json.Encode.string
            , ( "DestinationUserIdentifier", val.destinationUserIdentifier ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\identityIdFld -> { identityId = identityIdFld }) |> Json.Decode.succeed)
                |> Pipeline.optional "IdentityId" (Json.Decode.maybe Json.Decode.string) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "MergeDeveloperIdentities" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Retrieves the `IdentityID` associated with a `DeveloperUserIdentifier` or the list of `DeveloperUserIdentifier` values associated with an `IdentityId` for an existing identity. Either `IdentityID` or `DeveloperUserIdentifier` must not be null. If you supply only one of these values, the other value will be searched in the database and returned as a part of the response. If you supply both, `DeveloperUserIdentifier` will be matched against `IdentityID`. If the values are verified against the database, the response returns both values and is the same as the request. Otherwise a `ResourceConflictException` is thrown.

`LookupDeveloperIdentity` is intended for low-throughput control plane operations: for example, to enable customer service to locate an identity ID by username. If you are using it for higher-volume operations such as user authentication, your requests are likely to be throttled. `GetOpenIdTokenForDeveloperIdentity` is a better option for higher-volume operations for user authentication.

You must use AWS Developer credentials to call this API.

-}
lookupDeveloperIdentity : LookupDeveloperIdentityInput -> AWS.Http.Request AWS.Http.AWSAppError LookupDeveloperIdentityResponse
lookupDeveloperIdentity req =
    let
        encoder val =
            [ ( "NextToken", val.nextToken ) |> EncodeOpt.optionalField Json.Encode.string
            , ( "MaxResults", val.maxResults ) |> EncodeOpt.optionalField Json.Encode.int
            , ( "IdentityPoolId", val.identityPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "IdentityId", val.identityId ) |> EncodeOpt.optionalField Json.Encode.string
            , ( "DeveloperUserIdentifier", val.developerUserIdentifier ) |> EncodeOpt.optionalField Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\nextTokenFld identityIdFld developerUserIdentifierListFld ->
                { developerUserIdentifierList = developerUserIdentifierListFld
                , identityId = identityIdFld
                , nextToken = nextTokenFld
                }
             )
                |> Json.Decode.succeed
            )
                |> Pipeline.optional "NextToken" (Json.Decode.maybe Json.Decode.string) Nothing
                |> Pipeline.optional "IdentityId" (Json.Decode.maybe Json.Decode.string) Nothing
                |> Pipeline.optional
                    "DeveloperUserIdentifierList"
                    (Json.Decode.maybe developerUserIdentifierListDecoder)
                    Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "LookupDeveloperIdentity" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Lists the tags that are assigned to an Amazon Cognito identity pool.

A tag is a label that you can apply to identity pools to categorize and manage them in different ways, such as by purpose, owner, environment, or other criteria.

You can use this action up to 10 times per second, per account.

-}
listTagsForResource : ListTagsForResourceInput -> AWS.Http.Request AWS.Http.AWSAppError ListTagsForResourceResponse
listTagsForResource req =
    let
        encoder val =
            [ ( "ResourceArn", val.resourceArn ) |> EncodeOpt.field Json.Encode.string ] |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\tagsFld -> { tags = tagsFld }) |> Json.Decode.succeed)
                |> Pipeline.optional "Tags" (Json.Decode.maybe (Codec.decoder identityPoolTagsTypeCodec)) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "ListTagsForResource" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Lists all of the Cognito identity pools registered for your account.

You must use AWS Developer credentials to call this API.

-}
listIdentityPools : ListIdentityPoolsInput -> AWS.Http.Request AWS.Http.AWSAppError ListIdentityPoolsResponse
listIdentityPools req =
    let
        encoder val =
            [ ( "NextToken", val.nextToken ) |> EncodeOpt.optionalField Json.Encode.string
            , ( "MaxResults", val.maxResults ) |> EncodeOpt.field Json.Encode.int
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\nextTokenFld identityPoolsFld -> { identityPools = identityPoolsFld, nextToken = nextTokenFld })
                |> Json.Decode.succeed
            )
                |> Pipeline.optional "NextToken" (Json.Decode.maybe Json.Decode.string) Nothing
                |> Pipeline.optional "IdentityPools" (Json.Decode.maybe identityPoolsListDecoder) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "ListIdentityPools" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Lists the identities in an identity pool.

You must use AWS Developer credentials to call this API.

-}
listIdentities : ListIdentitiesInput -> AWS.Http.Request AWS.Http.AWSAppError ListIdentitiesResponse
listIdentities req =
    let
        encoder val =
            [ ( "NextToken", val.nextToken ) |> EncodeOpt.optionalField Json.Encode.string
            , ( "MaxResults", val.maxResults ) |> EncodeOpt.field Json.Encode.int
            , ( "IdentityPoolId", val.identityPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "HideDisabled", val.hideDisabled ) |> EncodeOpt.optionalField Json.Encode.bool
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\nextTokenFld identityPoolIdFld identitiesFld ->
                { identities = identitiesFld, identityPoolId = identityPoolIdFld, nextToken = nextTokenFld }
             )
                |> Json.Decode.succeed
            )
                |> Pipeline.optional "NextToken" (Json.Decode.maybe Json.Decode.string) Nothing
                |> Pipeline.optional "IdentityPoolId" (Json.Decode.maybe Json.Decode.string) Nothing
                |> Pipeline.optional "Identities" (Json.Decode.maybe identitiesListDecoder) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "ListIdentities" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Registers (or retrieves) a Cognito `IdentityId` and an OpenID Connect token for a user authenticated by your backend authentication process. Supplying multiple logins will create an implicit linked account. You can only specify one developer provider as part of the `Logins` map, which is linked to the identity pool. The developer provider is the "domain" by which Cognito will refer to your users.

You can use `GetOpenIdTokenForDeveloperIdentity` to create a new identity and to link new logins (that is, user credentials issued by a public provider or developer provider) to an existing identity. When you want to create a new identity, the `IdentityId` should be null. When you want to associate a new login with an existing authenticated/unauthenticated identity, you can do so by providing the existing `IdentityId`. This API will create the identity in the specified `IdentityPoolId`.

You must use AWS Developer credentials to call this API.

-}
getOpenIdTokenForDeveloperIdentity :
    GetOpenIdTokenForDeveloperIdentityInput
    -> AWS.Http.Request AWS.Http.AWSAppError GetOpenIdTokenForDeveloperIdentityResponse
getOpenIdTokenForDeveloperIdentity req =
    let
        encoder val =
            [ ( "TokenDuration", val.tokenDuration ) |> EncodeOpt.optionalField Json.Encode.int
            , ( "Logins", val.logins ) |> EncodeOpt.field loginsMapEncoder
            , ( "IdentityPoolId", val.identityPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "IdentityId", val.identityId ) |> EncodeOpt.optionalField Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\tokenFld identityIdFld -> { identityId = identityIdFld, token = tokenFld }) |> Json.Decode.succeed)
                |> Pipeline.optional "Token" (Json.Decode.maybe Json.Decode.string) Nothing
                |> Pipeline.optional "IdentityId" (Json.Decode.maybe Json.Decode.string) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "GetOpenIdTokenForDeveloperIdentity" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Gets an OpenID token, using a known Cognito ID. This known Cognito ID is returned by `GetId`. You can optionally add additional logins for the identity. Supplying multiple logins creates an implicit link.

The OpenId token is valid for 10 minutes.

This is a public API. You do not need any credentials to call this API.

-}
getOpenIdToken : GetOpenIdTokenInput -> AWS.Http.Request AWS.Http.AWSAppError GetOpenIdTokenResponse
getOpenIdToken req =
    let
        encoder val =
            [ ( "Logins", val.logins ) |> EncodeOpt.optionalField loginsMapEncoder
            , ( "IdentityId", val.identityId ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\tokenFld identityIdFld -> { identityId = identityIdFld, token = tokenFld }) |> Json.Decode.succeed)
                |> Pipeline.optional "Token" (Json.Decode.maybe Json.Decode.string) Nothing
                |> Pipeline.optional "IdentityId" (Json.Decode.maybe Json.Decode.string) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "GetOpenIdToken" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Gets the roles for an identity pool.

You must use AWS Developer credentials to call this API.

-}
getIdentityPoolRoles : GetIdentityPoolRolesInput -> AWS.Http.Request AWS.Http.AWSAppError GetIdentityPoolRolesResponse
getIdentityPoolRoles req =
    let
        encoder val =
            [ ( "IdentityPoolId", val.identityPoolId ) |> EncodeOpt.field Json.Encode.string ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\rolesFld roleMappingsFld identityPoolIdFld ->
                { identityPoolId = identityPoolIdFld, roleMappings = roleMappingsFld, roles = rolesFld }
             )
                |> Json.Decode.succeed
            )
                |> Pipeline.optional "Roles" (Json.Decode.maybe (Codec.decoder rolesMapCodec)) Nothing
                |> Pipeline.optional "RoleMappings" (Json.Decode.maybe (Codec.decoder roleMappingMapCodec)) Nothing
                |> Pipeline.optional "IdentityPoolId" (Json.Decode.maybe Json.Decode.string) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "GetIdentityPoolRoles" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Generates (or retrieves) a Cognito ID. Supplying multiple logins will create an implicit linked account.

This is a public API. You do not need any credentials to call this API.

-}
getId : GetIdInput -> AWS.Http.Request AWS.Http.AWSAppError GetIdResponse
getId req =
    let
        encoder val =
            [ ( "Logins", val.logins ) |> EncodeOpt.optionalField loginsMapEncoder
            , ( "IdentityPoolId", val.identityPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "AccountId", val.accountId ) |> EncodeOpt.optionalField Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\identityIdFld -> { identityId = identityIdFld }) |> Json.Decode.succeed)
                |> Pipeline.optional "IdentityId" (Json.Decode.maybe Json.Decode.string) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "GetId" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Returns credentials for the provided identity ID. Any provided logins will be validated against supported login providers. If the token is for cognito-identity.amazonaws.com, it will be passed through to AWS Security Token Service with the appropriate role for the token.

This is a public API. You do not need any credentials to call this API.

-}
getCredentialsForIdentity : GetCredentialsForIdentityInput -> AWS.Http.Request AWS.Http.AWSAppError GetCredentialsForIdentityResponse
getCredentialsForIdentity req =
    let
        encoder val =
            [ ( "Logins", val.logins ) |> EncodeOpt.optionalField loginsMapEncoder
            , ( "IdentityId", val.identityId ) |> EncodeOpt.field Json.Encode.string
            , ( "CustomRoleArn", val.customRoleArn ) |> EncodeOpt.optionalField Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\identityIdFld credentialsFld -> { credentials = credentialsFld, identityId = identityIdFld })
                |> Json.Decode.succeed
            )
                |> Pipeline.optional "IdentityId" (Json.Decode.maybe Json.Decode.string) Nothing
                |> Pipeline.optional "Credentials" (Json.Decode.maybe credentialsDecoder) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "GetCredentialsForIdentity" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Gets details about a particular identity pool, including the pool name, ID description, creation date, and current number of users.

You must use AWS Developer credentials to call this API.

-}
describeIdentityPool : DescribeIdentityPoolInput -> AWS.Http.Request AWS.Http.AWSAppError IdentityPool
describeIdentityPool req =
    let
        encoder val =
            [ ( "IdentityPoolId", val.identityPoolId ) |> EncodeOpt.field Json.Encode.string ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\supportedLoginProvidersFld samlProviderArnsFld openIdConnectProviderArnsFld identityPoolTagsFld identityPoolNameFld identityPoolIdFld developerProviderNameFld cognitoIdentityProvidersFld allowUnauthenticatedIdentitiesFld ->
                { allowUnauthenticatedIdentities = allowUnauthenticatedIdentitiesFld
                , cognitoIdentityProviders = cognitoIdentityProvidersFld
                , developerProviderName = developerProviderNameFld
                , identityPoolId = identityPoolIdFld
                , identityPoolName = identityPoolNameFld
                , identityPoolTags = identityPoolTagsFld
                , openIdConnectProviderArns = openIdConnectProviderArnsFld
                , samlProviderArns = samlProviderArnsFld
                , supportedLoginProviders = supportedLoginProvidersFld
                }
             )
                |> Json.Decode.succeed
            )
                |> Pipeline.optional
                    "SupportedLoginProviders"
                    (Json.Decode.maybe (Codec.decoder identityProvidersCodec))
                    Nothing
                |> Pipeline.optional
                    "SamlProviderARNs"
                    (Json.Decode.maybe (Codec.decoder samlproviderListCodec))
                    Nothing
                |> Pipeline.optional
                    "OpenIdConnectProviderARNs"
                    (Json.Decode.maybe (Codec.decoder oidcproviderListCodec))
                    Nothing
                |> Pipeline.optional
                    "IdentityPoolTags"
                    (Json.Decode.maybe (Codec.decoder identityPoolTagsTypeCodec))
                    Nothing
                |> Pipeline.required "IdentityPoolName" Json.Decode.string
                |> Pipeline.required "IdentityPoolId" Json.Decode.string
                |> Pipeline.optional "DeveloperProviderName" (Json.Decode.maybe Json.Decode.string) Nothing
                |> Pipeline.optional
                    "CognitoIdentityProviders"
                    (Json.Decode.maybe (Codec.decoder cognitoIdentityProviderListCodec))
                    Nothing
                |> Pipeline.required "AllowUnauthenticatedIdentities" Json.Decode.bool
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "DescribeIdentityPool" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Returns metadata related to the given identity, including when the identity was created and any associated linked logins.

You must use AWS Developer credentials to call this API.

-}
describeIdentity : DescribeIdentityInput -> AWS.Http.Request AWS.Http.AWSAppError IdentityDescription
describeIdentity req =
    let
        encoder val =
            [ ( "IdentityId", val.identityId ) |> EncodeOpt.field Json.Encode.string ] |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\loginsFld lastModifiedDateFld identityIdFld creationDateFld ->
                { creationDate = creationDateFld
                , identityId = identityIdFld
                , lastModifiedDate = lastModifiedDateFld
                , logins = loginsFld
                }
             )
                |> Json.Decode.succeed
            )
                |> Pipeline.optional "Logins" (Json.Decode.maybe (Codec.decoder loginsListCodec)) Nothing
                |> Pipeline.optional "LastModifiedDate" (Json.Decode.maybe Json.Decode.string) Nothing
                |> Pipeline.optional "IdentityId" (Json.Decode.maybe Json.Decode.string) Nothing
                |> Pipeline.optional "CreationDate" (Json.Decode.maybe Json.Decode.string) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "DescribeIdentity" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Deletes an identity pool. Once a pool is deleted, users will not be able to authenticate with the pool.

You must use AWS Developer credentials to call this API.

-}
deleteIdentityPool : DeleteIdentityPoolInput -> AWS.Http.Request AWS.Http.AWSAppError ()
deleteIdentityPool req =
    let
        encoder val =
            [ ( "IdentityPoolId", val.identityPoolId ) |> EncodeOpt.field Json.Encode.string ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "DeleteIdentityPool" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Deletes identities from an identity pool. You can specify a list of 1-60 identities that you want to delete.

You must use AWS Developer credentials to call this API.

-}
deleteIdentities : DeleteIdentitiesInput -> AWS.Http.Request AWS.Http.AWSAppError DeleteIdentitiesResponse
deleteIdentities req =
    let
        encoder val =
            [ ( "IdentityIdsToDelete", val.identityIdsToDelete ) |> EncodeOpt.field identityIdListEncoder ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\unprocessedIdentityIdsFld -> { unprocessedIdentityIds = unprocessedIdentityIdsFld })
                |> Json.Decode.succeed
            )
                |> Pipeline.optional
                    "UnprocessedIdentityIds"
                    (Json.Decode.maybe unprocessedIdentityIdListDecoder)
                    Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "DeleteIdentities" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Creates a new identity pool. The identity pool is a store of user identity information that is specific to your AWS account. The limit on identity pools is 60 per account. The keys for `SupportedLoginProviders` are as follows:

  - Facebook: `graph.facebook.com` Google: `accounts.google.com` Amazon: `www.amazon.com` Twitter: `api.twitter.com` Digits: `www.digits.com`

You must use AWS Developer credentials to call this API.

-}
createIdentityPool : CreateIdentityPoolInput -> AWS.Http.Request AWS.Http.AWSAppError IdentityPool
createIdentityPool req =
    let
        encoder val =
            [ ( "SupportedLoginProviders", val.supportedLoginProviders )
                |> EncodeOpt.optionalField (Codec.encoder identityProvidersCodec)
            , ( "SamlProviderARNs", val.samlProviderArns )
                |> EncodeOpt.optionalField (Codec.encoder samlproviderListCodec)
            , ( "OpenIdConnectProviderARNs", val.openIdConnectProviderArns )
                |> EncodeOpt.optionalField (Codec.encoder oidcproviderListCodec)
            , ( "IdentityPoolTags", val.identityPoolTags )
                |> EncodeOpt.optionalField (Codec.encoder identityPoolTagsTypeCodec)
            , ( "IdentityPoolName", val.identityPoolName ) |> EncodeOpt.field Json.Encode.string
            , ( "DeveloperProviderName", val.developerProviderName ) |> EncodeOpt.optionalField Json.Encode.string
            , ( "CognitoIdentityProviders", val.cognitoIdentityProviders )
                |> EncodeOpt.optionalField (Codec.encoder cognitoIdentityProviderListCodec)
            , ( "AllowUnauthenticatedIdentities", val.allowUnauthenticatedIdentities )
                |> EncodeOpt.field Json.Encode.bool
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\supportedLoginProvidersFld samlProviderArnsFld openIdConnectProviderArnsFld identityPoolTagsFld identityPoolNameFld identityPoolIdFld developerProviderNameFld cognitoIdentityProvidersFld allowUnauthenticatedIdentitiesFld ->
                { allowUnauthenticatedIdentities = allowUnauthenticatedIdentitiesFld
                , cognitoIdentityProviders = cognitoIdentityProvidersFld
                , developerProviderName = developerProviderNameFld
                , identityPoolId = identityPoolIdFld
                , identityPoolName = identityPoolNameFld
                , identityPoolTags = identityPoolTagsFld
                , openIdConnectProviderArns = openIdConnectProviderArnsFld
                , samlProviderArns = samlProviderArnsFld
                , supportedLoginProviders = supportedLoginProvidersFld
                }
             )
                |> Json.Decode.succeed
            )
                |> Pipeline.optional
                    "SupportedLoginProviders"
                    (Json.Decode.maybe (Codec.decoder identityProvidersCodec))
                    Nothing
                |> Pipeline.optional
                    "SamlProviderARNs"
                    (Json.Decode.maybe (Codec.decoder samlproviderListCodec))
                    Nothing
                |> Pipeline.optional
                    "OpenIdConnectProviderARNs"
                    (Json.Decode.maybe (Codec.decoder oidcproviderListCodec))
                    Nothing
                |> Pipeline.optional
                    "IdentityPoolTags"
                    (Json.Decode.maybe (Codec.decoder identityPoolTagsTypeCodec))
                    Nothing
                |> Pipeline.required "IdentityPoolName" Json.Decode.string
                |> Pipeline.required "IdentityPoolId" Json.Decode.string
                |> Pipeline.optional "DeveloperProviderName" (Json.Decode.maybe Json.Decode.string) Nothing
                |> Pipeline.optional
                    "CognitoIdentityProviders"
                    (Json.Decode.maybe (Codec.decoder cognitoIdentityProviderListCodec))
                    Nothing
                |> Pipeline.required "AllowUnauthenticatedIdentities" Json.Decode.bool
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "CreateIdentityPool" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| The UntagResourceResponse data model.
-}
type alias UntagResourceResponse =
    {}


{-| The UntagResourceInput data model.
-}
type alias UntagResourceInput =
    { resourceArn : String, tagKeys : Maybe IdentityPoolTagsListType }


{-| The UnprocessedIdentityIdList data model.
-}
type alias UnprocessedIdentityIdList =
    List UnprocessedIdentityId


{-| The UnprocessedIdentityId data model.
-}
type alias UnprocessedIdentityId =
    { errorCode : Maybe ErrorCode, identityId : Maybe String }


{-| The UnlinkIdentityInput data model.
-}
type alias UnlinkIdentityInput =
    { identityId : String, logins : LoginsMap, loginsToRemove : LoginsList }


{-| The UnlinkDeveloperIdentityInput data model.
-}
type alias UnlinkDeveloperIdentityInput =
    { developerProviderName : String, developerUserIdentifier : String, identityId : String, identityPoolId : String }


{-| The TagResourceResponse data model.
-}
type alias TagResourceResponse =
    {}


{-| The TagResourceInput data model.
-}
type alias TagResourceInput =
    { resourceArn : String, tags : Maybe IdentityPoolTagsType }


{-| The SetIdentityPoolRolesInput data model.
-}
type alias SetIdentityPoolRolesInput =
    { identityPoolId : String, roleMappings : Maybe RoleMappingMap, roles : RolesMap }


{-| The SamlproviderList data model.
-}
type alias SamlproviderList =
    List String


{-| The RulesConfigurationType data model.
-}
type alias RulesConfigurationType =
    { rules : MappingRulesList }


{-| The RolesMap data model.
-}
type alias RolesMap =
    Dict String String


{-| The RoleMappingType data model.
-}
type RoleMappingType
    = RoleMappingTypeToken
    | RoleMappingTypeRules


{-| The RoleMappingType data model.
-}
roleMappingType : Enum RoleMappingType
roleMappingType =
    Enum.define
        [ RoleMappingTypeToken, RoleMappingTypeRules ]
        (\val ->
            case val of
                RoleMappingTypeToken ->
                    "Token"

                RoleMappingTypeRules ->
                    "Rules"
        )


{-| The RoleMappingMap data model.
-}
type alias RoleMappingMap =
    Dict String RoleMapping


{-| The RoleMapping data model.
-}
type alias RoleMapping =
    { ambiguousRoleResolution : Maybe AmbiguousRoleResolutionType
    , rulesConfiguration : Maybe RulesConfigurationType
    , type_ : RoleMappingType
    }


{-| The OidcproviderList data model.
-}
type alias OidcproviderList =
    List String


{-| The MergeDeveloperIdentitiesResponse data model.
-}
type alias MergeDeveloperIdentitiesResponse =
    { identityId : Maybe String }


{-| The MergeDeveloperIdentitiesInput data model.
-}
type alias MergeDeveloperIdentitiesInput =
    { destinationUserIdentifier : String
    , developerProviderName : String
    , identityPoolId : String
    , sourceUserIdentifier : String
    }


{-| The MappingRulesList data model.
-}
type alias MappingRulesList =
    List MappingRule


{-| The MappingRuleMatchType data model.
-}
type MappingRuleMatchType
    = MappingRuleMatchTypeEquals
    | MappingRuleMatchTypeContains
    | MappingRuleMatchTypeStartsWith
    | MappingRuleMatchTypeNotEqual


{-| The MappingRuleMatchType data model.
-}
mappingRuleMatchType : Enum MappingRuleMatchType
mappingRuleMatchType =
    Enum.define
        [ MappingRuleMatchTypeEquals
        , MappingRuleMatchTypeContains
        , MappingRuleMatchTypeStartsWith
        , MappingRuleMatchTypeNotEqual
        ]
        (\val ->
            case val of
                MappingRuleMatchTypeEquals ->
                    "Equals"

                MappingRuleMatchTypeContains ->
                    "Contains"

                MappingRuleMatchTypeStartsWith ->
                    "StartsWith"

                MappingRuleMatchTypeNotEqual ->
                    "NotEqual"
        )


{-| The MappingRule data model.
-}
type alias MappingRule =
    { claim : String, matchType : MappingRuleMatchType, roleArn : String, value : String }


{-| The LookupDeveloperIdentityResponse data model.
-}
type alias LookupDeveloperIdentityResponse =
    { developerUserIdentifierList : Maybe DeveloperUserIdentifierList
    , identityId : Maybe String
    , nextToken : Maybe String
    }


{-| The LookupDeveloperIdentityInput data model.
-}
type alias LookupDeveloperIdentityInput =
    { developerUserIdentifier : Maybe String
    , identityId : Maybe String
    , identityPoolId : String
    , maxResults : Maybe Int
    , nextToken : Maybe String
    }


{-| The LoginsMap data model.
-}
type alias LoginsMap =
    Dict String String


{-| The LoginsList data model.
-}
type alias LoginsList =
    List String


{-| The ListTagsForResourceResponse data model.
-}
type alias ListTagsForResourceResponse =
    { tags : Maybe IdentityPoolTagsType }


{-| The ListTagsForResourceInput data model.
-}
type alias ListTagsForResourceInput =
    { resourceArn : String }


{-| The ListIdentityPoolsResponse data model.
-}
type alias ListIdentityPoolsResponse =
    { identityPools : Maybe IdentityPoolsList, nextToken : Maybe String }


{-| The ListIdentityPoolsInput data model.
-}
type alias ListIdentityPoolsInput =
    { maxResults : Int, nextToken : Maybe String }


{-| The ListIdentitiesResponse data model.
-}
type alias ListIdentitiesResponse =
    { identities : Maybe IdentitiesList, identityPoolId : Maybe String, nextToken : Maybe String }


{-| The ListIdentitiesInput data model.
-}
type alias ListIdentitiesInput =
    { hideDisabled : Maybe Bool, identityPoolId : String, maxResults : Int, nextToken : Maybe String }


{-| The IdentityProviders data model.
-}
type alias IdentityProviders =
    Dict String String


{-| The IdentityPoolsList data model.
-}
type alias IdentityPoolsList =
    List IdentityPoolShortDescription


{-| The IdentityPoolTagsType data model.
-}
type alias IdentityPoolTagsType =
    Dict String String


{-| The IdentityPoolTagsListType data model.
-}
type alias IdentityPoolTagsListType =
    List String


{-| The IdentityPoolShortDescription data model.
-}
type alias IdentityPoolShortDescription =
    { identityPoolId : Maybe String, identityPoolName : Maybe String }


{-| The IdentityPool data model.
-}
type alias IdentityPool =
    { allowUnauthenticatedIdentities : Bool
    , cognitoIdentityProviders : Maybe CognitoIdentityProviderList
    , developerProviderName : Maybe String
    , identityPoolId : String
    , identityPoolName : String
    , identityPoolTags : Maybe IdentityPoolTagsType
    , openIdConnectProviderArns : Maybe OidcproviderList
    , samlProviderArns : Maybe SamlproviderList
    , supportedLoginProviders : Maybe IdentityProviders
    }


{-| The IdentityIdList data model.
-}
type alias IdentityIdList =
    List String


{-| The IdentityDescription data model.
-}
type alias IdentityDescription =
    { creationDate : Maybe String
    , identityId : Maybe String
    , lastModifiedDate : Maybe String
    , logins : Maybe LoginsList
    }


{-| The IdentitiesList data model.
-}
type alias IdentitiesList =
    List IdentityDescription


{-| The GetOpenIdTokenResponse data model.
-}
type alias GetOpenIdTokenResponse =
    { identityId : Maybe String, token : Maybe String }


{-| The GetOpenIdTokenInput data model.
-}
type alias GetOpenIdTokenInput =
    { identityId : String, logins : Maybe LoginsMap }


{-| The GetOpenIdTokenForDeveloperIdentityResponse data model.
-}
type alias GetOpenIdTokenForDeveloperIdentityResponse =
    { identityId : Maybe String, token : Maybe String }


{-| The GetOpenIdTokenForDeveloperIdentityInput data model.
-}
type alias GetOpenIdTokenForDeveloperIdentityInput =
    { identityId : Maybe String, identityPoolId : String, logins : LoginsMap, tokenDuration : Maybe Int }


{-| The GetIdentityPoolRolesResponse data model.
-}
type alias GetIdentityPoolRolesResponse =
    { identityPoolId : Maybe String, roleMappings : Maybe RoleMappingMap, roles : Maybe RolesMap }


{-| The GetIdentityPoolRolesInput data model.
-}
type alias GetIdentityPoolRolesInput =
    { identityPoolId : String }


{-| The GetIdResponse data model.
-}
type alias GetIdResponse =
    { identityId : Maybe String }


{-| The GetIdInput data model.
-}
type alias GetIdInput =
    { accountId : Maybe String, identityPoolId : String, logins : Maybe LoginsMap }


{-| The GetCredentialsForIdentityResponse data model.
-}
type alias GetCredentialsForIdentityResponse =
    { credentials : Maybe Credentials, identityId : Maybe String }


{-| The GetCredentialsForIdentityInput data model.
-}
type alias GetCredentialsForIdentityInput =
    { customRoleArn : Maybe String, identityId : String, logins : Maybe LoginsMap }


{-| The ErrorCode data model.
-}
type ErrorCode
    = ErrorCodeAccessDenied
    | ErrorCodeInternalServerError


{-| The ErrorCode data model.
-}
errorCode : Enum ErrorCode
errorCode =
    Enum.define
        [ ErrorCodeAccessDenied, ErrorCodeInternalServerError ]
        (\val ->
            case val of
                ErrorCodeAccessDenied ->
                    "AccessDenied"

                ErrorCodeInternalServerError ->
                    "InternalServerError"
        )


{-| The DeveloperUserIdentifierList data model.
-}
type alias DeveloperUserIdentifierList =
    List String


{-| The DescribeIdentityPoolInput data model.
-}
type alias DescribeIdentityPoolInput =
    { identityPoolId : String }


{-| The DescribeIdentityInput data model.
-}
type alias DescribeIdentityInput =
    { identityId : String }


{-| The DeleteIdentityPoolInput data model.
-}
type alias DeleteIdentityPoolInput =
    { identityPoolId : String }


{-| The DeleteIdentitiesResponse data model.
-}
type alias DeleteIdentitiesResponse =
    { unprocessedIdentityIds : Maybe UnprocessedIdentityIdList }


{-| The DeleteIdentitiesInput data model.
-}
type alias DeleteIdentitiesInput =
    { identityIdsToDelete : IdentityIdList }


{-| The Credentials data model.
-}
type alias Credentials =
    { accessKeyId : Maybe String, expiration : Maybe String, secretKey : Maybe String, sessionToken : Maybe String }


{-| The CreateIdentityPoolInput data model.
-}
type alias CreateIdentityPoolInput =
    { allowUnauthenticatedIdentities : Bool
    , cognitoIdentityProviders : Maybe CognitoIdentityProviderList
    , developerProviderName : Maybe String
    , identityPoolName : String
    , identityPoolTags : Maybe IdentityPoolTagsType
    , openIdConnectProviderArns : Maybe OidcproviderList
    , samlProviderArns : Maybe SamlproviderList
    , supportedLoginProviders : Maybe IdentityProviders
    }


{-| The CognitoIdentityProviderList data model.
-}
type alias CognitoIdentityProviderList =
    List CognitoIdentityProvider


{-| The CognitoIdentityProvider data model.
-}
type alias CognitoIdentityProvider =
    { clientId : Maybe String, providerName : Maybe String, serverSideTokenCheck : Maybe Bool }


{-| The AmbiguousRoleResolutionType data model.
-}
type AmbiguousRoleResolutionType
    = AmbiguousRoleResolutionTypeAuthenticatedRole
    | AmbiguousRoleResolutionTypeDeny


{-| The AmbiguousRoleResolutionType data model.
-}
ambiguousRoleResolutionType : Enum AmbiguousRoleResolutionType
ambiguousRoleResolutionType =
    Enum.define
        [ AmbiguousRoleResolutionTypeAuthenticatedRole, AmbiguousRoleResolutionTypeDeny ]
        (\val ->
            case val of
                AmbiguousRoleResolutionTypeAuthenticatedRole ->
                    "AuthenticatedRole"

                AmbiguousRoleResolutionTypeDeny ->
                    "Deny"
        )


{-| Codec for AmbiguousRoleResolutionType.
-}
ambiguousRoleResolutionTypeCodec : Codec AmbiguousRoleResolutionType
ambiguousRoleResolutionTypeCodec =
    Codec.build (Enum.encoder ambiguousRoleResolutionType) (Enum.decoder ambiguousRoleResolutionType)


{-| Codec for CognitoIdentityProvider.
-}
cognitoIdentityProviderCodec : Codec CognitoIdentityProvider
cognitoIdentityProviderCodec =
    Codec.object CognitoIdentityProvider
        |> Codec.optionalField "ClientId" .clientId Codec.string
        |> Codec.optionalField "ProviderName" .providerName Codec.string
        |> Codec.optionalField "ServerSideTokenCheck" .serverSideTokenCheck Codec.bool
        |> Codec.buildObject


{-| Codec for CognitoIdentityProviderList.
-}
cognitoIdentityProviderListCodec : Codec CognitoIdentityProviderList
cognitoIdentityProviderListCodec =
    Codec.list cognitoIdentityProviderCodec


{-| Decoder for Credentials.
-}
credentialsDecoder : Decoder Credentials
credentialsDecoder =
    Json.Decode.succeed Credentials
        |> Pipeline.optional "AccessKeyId" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "Expiration" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "SecretKey" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "SessionToken" (Json.Decode.maybe Json.Decode.string) Nothing


{-| Decoder for DeveloperUserIdentifierList.
-}
developerUserIdentifierListDecoder : Decoder DeveloperUserIdentifierList
developerUserIdentifierListDecoder =
    Json.Decode.list Json.Decode.string


{-| Decoder for ErrorCode.
-}
errorCodeDecoder : Decoder ErrorCode
errorCodeDecoder =
    Enum.decoder errorCode


{-| Decoder for IdentitiesList.
-}
identitiesListDecoder : Decoder IdentitiesList
identitiesListDecoder =
    Json.Decode.list identityDescriptionDecoder


{-| Decoder for IdentityDescription.
-}
identityDescriptionDecoder : Decoder IdentityDescription
identityDescriptionDecoder =
    Json.Decode.succeed IdentityDescription
        |> Pipeline.optional "CreationDate" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "IdentityId" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "LastModifiedDate" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "Logins" (Json.Decode.maybe (Codec.decoder loginsListCodec)) Nothing


{-| Encoder for IdentityIdList.
-}
identityIdListEncoder : IdentityIdList -> Value
identityIdListEncoder val =
    Json.Encode.list Json.Encode.string val


{-| Decoder for IdentityPoolShortDescription.
-}
identityPoolShortDescriptionDecoder : Decoder IdentityPoolShortDescription
identityPoolShortDescriptionDecoder =
    Json.Decode.succeed IdentityPoolShortDescription
        |> Pipeline.optional "IdentityPoolId" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "IdentityPoolName" (Json.Decode.maybe Json.Decode.string) Nothing


{-| Encoder for IdentityPoolTagsListType.
-}
identityPoolTagsListTypeEncoder : IdentityPoolTagsListType -> Value
identityPoolTagsListTypeEncoder val =
    Json.Encode.list Json.Encode.string val


{-| Codec for IdentityPoolTagsType.
-}
identityPoolTagsTypeCodec : Codec IdentityPoolTagsType
identityPoolTagsTypeCodec =
    Codec.dict Codec.string


{-| Decoder for IdentityPoolsList.
-}
identityPoolsListDecoder : Decoder IdentityPoolsList
identityPoolsListDecoder =
    Json.Decode.list identityPoolShortDescriptionDecoder


{-| Codec for IdentityProviders.
-}
identityProvidersCodec : Codec IdentityProviders
identityProvidersCodec =
    Codec.dict Codec.string


{-| Codec for LoginsList.
-}
loginsListCodec : Codec LoginsList
loginsListCodec =
    Codec.list Codec.string


{-| Encoder for LoginsMap.
-}
loginsMapEncoder : LoginsMap -> Value
loginsMapEncoder val =
    Json.Encode.dict identity Json.Encode.string val


{-| Codec for MappingRule.
-}
mappingRuleCodec : Codec MappingRule
mappingRuleCodec =
    Codec.object MappingRule
        |> Codec.field "Claim" .claim Codec.string
        |> Codec.field "MatchType" .matchType mappingRuleMatchTypeCodec
        |> Codec.field "RoleARN" .roleArn Codec.string
        |> Codec.field "Value" .value Codec.string
        |> Codec.buildObject


{-| Codec for MappingRuleMatchType.
-}
mappingRuleMatchTypeCodec : Codec MappingRuleMatchType
mappingRuleMatchTypeCodec =
    Codec.build (Enum.encoder mappingRuleMatchType) (Enum.decoder mappingRuleMatchType)


{-| Codec for MappingRulesList.
-}
mappingRulesListCodec : Codec MappingRulesList
mappingRulesListCodec =
    Codec.list mappingRuleCodec


{-| Codec for OidcproviderList.
-}
oidcproviderListCodec : Codec OidcproviderList
oidcproviderListCodec =
    Codec.list Codec.string


{-| Codec for RoleMapping.
-}
roleMappingCodec : Codec RoleMapping
roleMappingCodec =
    Codec.object RoleMapping
        |> Codec.optionalField "AmbiguousRoleResolution" .ambiguousRoleResolution ambiguousRoleResolutionTypeCodec
        |> Codec.optionalField "RulesConfiguration" .rulesConfiguration rulesConfigurationTypeCodec
        |> Codec.field "Type" .type_ roleMappingTypeCodec
        |> Codec.buildObject


{-| Codec for RoleMappingMap.
-}
roleMappingMapCodec : Codec RoleMappingMap
roleMappingMapCodec =
    Codec.dict roleMappingCodec


{-| Codec for RoleMappingType.
-}
roleMappingTypeCodec : Codec RoleMappingType
roleMappingTypeCodec =
    Codec.build (Enum.encoder roleMappingType) (Enum.decoder roleMappingType)


{-| Codec for RolesMap.
-}
rolesMapCodec : Codec RolesMap
rolesMapCodec =
    Codec.dict Codec.string


{-| Codec for RulesConfigurationType.
-}
rulesConfigurationTypeCodec : Codec RulesConfigurationType
rulesConfigurationTypeCodec =
    Codec.object RulesConfigurationType |> Codec.field "Rules" .rules mappingRulesListCodec |> Codec.buildObject


{-| Codec for SamlproviderList.
-}
samlproviderListCodec : Codec SamlproviderList
samlproviderListCodec =
    Codec.list Codec.string


{-| Decoder for UnprocessedIdentityId.
-}
unprocessedIdentityIdDecoder : Decoder UnprocessedIdentityId
unprocessedIdentityIdDecoder =
    Json.Decode.succeed UnprocessedIdentityId
        |> Pipeline.optional "ErrorCode" (Json.Decode.maybe errorCodeDecoder) Nothing
        |> Pipeline.optional "IdentityId" (Json.Decode.maybe Json.Decode.string) Nothing


{-| Decoder for UnprocessedIdentityIdList.
-}
unprocessedIdentityIdListDecoder : Decoder UnprocessedIdentityIdList
unprocessedIdentityIdListDecoder =
    Json.Decode.list unprocessedIdentityIdDecoder
