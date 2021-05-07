module AWS.CognitoIdentity exposing
    ( service
    , createIdentityPool, deleteIdentities, deleteIdentityPool, describeIdentity, describeIdentityPool, getCredentialsForIdentity, getId
    , getIdentityPoolRoles, getOpenIdToken, getOpenIdTokenForDeveloperIdentity, listIdentities, listIdentityPools, listTagsForResource
    , lookupDeveloperIdentity, mergeDeveloperIdentities, setIdentityPoolRoles, tagResource, unlinkDeveloperIdentity, unlinkIdentity
    , untagResource, updateIdentityPool
    , AccessKeyString, AccountId, AmbiguousRoleResolutionType(..), Arnstring, ClaimName, ClaimValue, CognitoIdentityProvider
    , CognitoIdentityProviderClientId, CognitoIdentityProviderList, CognitoIdentityProviderName, CognitoIdentityProviderTokenCheck
    , CreateIdentityPoolInput, Credentials, DateType, DeleteIdentitiesInput, DeleteIdentitiesResponse, DeleteIdentityPoolInput
    , DescribeIdentityInput, DescribeIdentityPoolInput, DeveloperProviderName, DeveloperUserIdentifier, DeveloperUserIdentifierList
    , ErrorCode(..), GetCredentialsForIdentityInput, GetCredentialsForIdentityResponse, GetIdInput, GetIdResponse, GetIdentityPoolRolesInput
    , GetIdentityPoolRolesResponse, GetOpenIdTokenForDeveloperIdentityInput, GetOpenIdTokenForDeveloperIdentityResponse
    , GetOpenIdTokenInput, GetOpenIdTokenResponse, HideDisabled, IdentitiesList, IdentityDescription, IdentityId, IdentityIdList
    , IdentityPool, IdentityPoolId, IdentityPoolName, IdentityPoolShortDescription, IdentityPoolTagsListType, IdentityPoolTagsType
    , IdentityPoolUnauthenticated, IdentityPoolsList, IdentityProviderId, IdentityProviderName, IdentityProviderToken, IdentityProviders
    , ListIdentitiesInput, ListIdentitiesResponse, ListIdentityPoolsInput, ListIdentityPoolsResponse, ListTagsForResourceInput
    , ListTagsForResourceResponse, LoginsList, LoginsMap, LookupDeveloperIdentityInput, LookupDeveloperIdentityResponse, MappingRule
    , MappingRuleMatchType(..), MappingRulesList, MergeDeveloperIdentitiesInput, MergeDeveloperIdentitiesResponse, OidcproviderList
    , Oidctoken, PaginationKey, QueryLimit, RoleMapping, RoleMappingMap, RoleMappingType(..), RoleType, RolesMap, RulesConfigurationType
    , SamlproviderList, SecretKeyString, SessionTokenString, SetIdentityPoolRolesInput, TagKeysType, TagResourceInput, TagResourceResponse
    , TagValueType, TokenDuration, UnlinkDeveloperIdentityInput, UnlinkIdentityInput, UnprocessedIdentityId, UnprocessedIdentityIdList
    , UntagResourceInput, UntagResourceResponse, accountId, ambiguousRoleResolutionType, arnstring, claimName, claimValue
    , cognitoIdentityProviderClientId, cognitoIdentityProviderName, developerProviderName, developerUserIdentifier, errorCode
    , identityId, identityPoolId, identityPoolName, identityProviderId, identityProviderName, identityProviderToken, mappingRuleMatchType
    , paginationKey, queryLimit, roleMappingType, roleType, tagKeysType, tagValueType
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

@docs AccessKeyString, AccountId, AmbiguousRoleResolutionType, Arnstring, ClaimName, ClaimValue, CognitoIdentityProvider
@docs CognitoIdentityProviderClientId, CognitoIdentityProviderList, CognitoIdentityProviderName, CognitoIdentityProviderTokenCheck
@docs CreateIdentityPoolInput, Credentials, DateType, DeleteIdentitiesInput, DeleteIdentitiesResponse, DeleteIdentityPoolInput
@docs DescribeIdentityInput, DescribeIdentityPoolInput, DeveloperProviderName, DeveloperUserIdentifier, DeveloperUserIdentifierList
@docs ErrorCode, GetCredentialsForIdentityInput, GetCredentialsForIdentityResponse, GetIdInput, GetIdResponse, GetIdentityPoolRolesInput
@docs GetIdentityPoolRolesResponse, GetOpenIdTokenForDeveloperIdentityInput, GetOpenIdTokenForDeveloperIdentityResponse
@docs GetOpenIdTokenInput, GetOpenIdTokenResponse, HideDisabled, IdentitiesList, IdentityDescription, IdentityId, IdentityIdList
@docs IdentityPool, IdentityPoolId, IdentityPoolName, IdentityPoolShortDescription, IdentityPoolTagsListType, IdentityPoolTagsType
@docs IdentityPoolUnauthenticated, IdentityPoolsList, IdentityProviderId, IdentityProviderName, IdentityProviderToken, IdentityProviders
@docs ListIdentitiesInput, ListIdentitiesResponse, ListIdentityPoolsInput, ListIdentityPoolsResponse, ListTagsForResourceInput
@docs ListTagsForResourceResponse, LoginsList, LoginsMap, LookupDeveloperIdentityInput, LookupDeveloperIdentityResponse, MappingRule
@docs MappingRuleMatchType, MappingRulesList, MergeDeveloperIdentitiesInput, MergeDeveloperIdentitiesResponse, OidcproviderList
@docs Oidctoken, PaginationKey, QueryLimit, RoleMapping, RoleMappingMap, RoleMappingType, RoleType, RolesMap, RulesConfigurationType
@docs SamlproviderList, SecretKeyString, SessionTokenString, SetIdentityPoolRolesInput, TagKeysType, TagResourceInput, TagResourceResponse
@docs TagValueType, TokenDuration, UnlinkDeveloperIdentityInput, UnlinkIdentityInput, UnprocessedIdentityId, UnprocessedIdentityIdList
@docs UntagResourceInput, UntagResourceResponse, accountId, ambiguousRoleResolutionType, arnstring, claimName, claimValue
@docs cognitoIdentityProviderClientId, cognitoIdentityProviderName, developerProviderName, developerUserIdentifier, errorCode
@docs identityId, identityPoolId, identityPoolName, identityProviderId, identityProviderName, identityProviderToken, mappingRuleMatchType
@docs paginationKey, queryLimit, roleMappingType, roleType, tagKeysType, tagValueType

-}

import AWS.Config
import AWS.Http
import AWS.KVDecode exposing (KVDecoder)
import AWS.Service
import Codec exposing (Codec)
import Dict.Refined
import Enum exposing (Enum)
import Json.Decode exposing (Decoder, Value)
import Json.Decode.Pipeline as Pipeline
import Json.Encode exposing (Value)
import Json.Encode.Optional as EncodeOpt
import Refined exposing (IntError, Refined, StringError)


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
            , ( "IdentityPoolName", val.identityPoolName ) |> EncodeOpt.field (Codec.encoder identityPoolNameCodec)
            , ( "IdentityPoolId", val.identityPoolId ) |> EncodeOpt.field (Codec.encoder identityPoolIdCodec)
            , ( "DeveloperProviderName", val.developerProviderName )
                |> EncodeOpt.optionalField (Codec.encoder developerProviderNameCodec)
            , ( "CognitoIdentityProviders", val.cognitoIdentityProviders )
                |> EncodeOpt.optionalField (Codec.encoder cognitoIdentityProviderListCodec)
            , ( "AllowUnauthenticatedIdentities", val.allowUnauthenticatedIdentities )
                |> EncodeOpt.field (Codec.encoder identityPoolUnauthenticatedCodec)
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
                |> Pipeline.required "IdentityPoolName" (Codec.decoder identityPoolNameCodec)
                |> Pipeline.required "IdentityPoolId" (Codec.decoder identityPoolIdCodec)
                |> Pipeline.optional
                    "DeveloperProviderName"
                    (Json.Decode.maybe (Codec.decoder developerProviderNameCodec))
                    Nothing
                |> Pipeline.optional
                    "CognitoIdentityProviders"
                    (Json.Decode.maybe (Codec.decoder cognitoIdentityProviderListCodec))
                    Nothing
                |> Pipeline.required "AllowUnauthenticatedIdentities" (Codec.decoder identityPoolUnauthenticatedCodec)
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
            , ( "ResourceArn", val.resourceArn ) |> EncodeOpt.field (Codec.encoder arnstringCodec)
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
            , ( "IdentityId", val.identityId ) |> EncodeOpt.field (Codec.encoder identityIdCodec)
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
            [ ( "IdentityPoolId", val.identityPoolId ) |> EncodeOpt.field (Codec.encoder identityPoolIdCodec)
            , ( "IdentityId", val.identityId ) |> EncodeOpt.field (Codec.encoder identityIdCodec)
            , ( "DeveloperUserIdentifier", val.developerUserIdentifier )
                |> EncodeOpt.field (Codec.encoder developerUserIdentifierCodec)
            , ( "DeveloperProviderName", val.developerProviderName )
                |> EncodeOpt.field (Codec.encoder developerProviderNameCodec)
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
            , ( "ResourceArn", val.resourceArn ) |> EncodeOpt.field (Codec.encoder arnstringCodec)
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
            , ( "IdentityPoolId", val.identityPoolId ) |> EncodeOpt.field (Codec.encoder identityPoolIdCodec)
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
            [ ( "SourceUserIdentifier", val.sourceUserIdentifier )
                |> EncodeOpt.field (Codec.encoder developerUserIdentifierCodec)
            , ( "IdentityPoolId", val.identityPoolId ) |> EncodeOpt.field (Codec.encoder identityPoolIdCodec)
            , ( "DeveloperProviderName", val.developerProviderName )
                |> EncodeOpt.field (Codec.encoder developerProviderNameCodec)
            , ( "DestinationUserIdentifier", val.destinationUserIdentifier )
                |> EncodeOpt.field (Codec.encoder developerUserIdentifierCodec)
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\identityIdFld -> { identityId = identityIdFld }) |> Json.Decode.succeed)
                |> Pipeline.optional "IdentityId" (Json.Decode.maybe (Codec.decoder identityIdCodec)) Nothing
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
            [ ( "NextToken", val.nextToken ) |> EncodeOpt.optionalField (Codec.encoder paginationKeyCodec)
            , ( "MaxResults", val.maxResults ) |> EncodeOpt.optionalField queryLimitEncoder
            , ( "IdentityPoolId", val.identityPoolId ) |> EncodeOpt.field (Codec.encoder identityPoolIdCodec)
            , ( "IdentityId", val.identityId ) |> EncodeOpt.optionalField (Codec.encoder identityIdCodec)
            , ( "DeveloperUserIdentifier", val.developerUserIdentifier )
                |> EncodeOpt.optionalField (Codec.encoder developerUserIdentifierCodec)
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
                |> Pipeline.optional "NextToken" (Json.Decode.maybe (Codec.decoder paginationKeyCodec)) Nothing
                |> Pipeline.optional "IdentityId" (Json.Decode.maybe (Codec.decoder identityIdCodec)) Nothing
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
            [ ( "ResourceArn", val.resourceArn ) |> EncodeOpt.field (Codec.encoder arnstringCodec) ]
                |> EncodeOpt.objectMaySkip

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
            [ ( "NextToken", val.nextToken ) |> EncodeOpt.optionalField (Codec.encoder paginationKeyCodec)
            , ( "MaxResults", val.maxResults ) |> EncodeOpt.field queryLimitEncoder
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
                |> Pipeline.optional "NextToken" (Json.Decode.maybe (Codec.decoder paginationKeyCodec)) Nothing
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
            [ ( "NextToken", val.nextToken ) |> EncodeOpt.optionalField (Codec.encoder paginationKeyCodec)
            , ( "MaxResults", val.maxResults ) |> EncodeOpt.field queryLimitEncoder
            , ( "IdentityPoolId", val.identityPoolId ) |> EncodeOpt.field (Codec.encoder identityPoolIdCodec)
            , ( "HideDisabled", val.hideDisabled ) |> EncodeOpt.optionalField hideDisabledEncoder
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
                |> Pipeline.optional "NextToken" (Json.Decode.maybe (Codec.decoder paginationKeyCodec)) Nothing
                |> Pipeline.optional "IdentityPoolId" (Json.Decode.maybe (Codec.decoder identityPoolIdCodec)) Nothing
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
            [ ( "TokenDuration", val.tokenDuration ) |> EncodeOpt.optionalField tokenDurationEncoder
            , ( "Logins", val.logins ) |> EncodeOpt.field loginsMapEncoder
            , ( "IdentityPoolId", val.identityPoolId ) |> EncodeOpt.field (Codec.encoder identityPoolIdCodec)
            , ( "IdentityId", val.identityId ) |> EncodeOpt.optionalField (Codec.encoder identityIdCodec)
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\tokenFld identityIdFld -> { identityId = identityIdFld, token = tokenFld }) |> Json.Decode.succeed)
                |> Pipeline.optional "Token" (Json.Decode.maybe oidctokenDecoder) Nothing
                |> Pipeline.optional "IdentityId" (Json.Decode.maybe (Codec.decoder identityIdCodec)) Nothing
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
            , ( "IdentityId", val.identityId ) |> EncodeOpt.field (Codec.encoder identityIdCodec)
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\tokenFld identityIdFld -> { identityId = identityIdFld, token = tokenFld }) |> Json.Decode.succeed)
                |> Pipeline.optional "Token" (Json.Decode.maybe oidctokenDecoder) Nothing
                |> Pipeline.optional "IdentityId" (Json.Decode.maybe (Codec.decoder identityIdCodec)) Nothing
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
            [ ( "IdentityPoolId", val.identityPoolId ) |> EncodeOpt.field (Codec.encoder identityPoolIdCodec) ]
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
                |> Pipeline.optional "IdentityPoolId" (Json.Decode.maybe (Codec.decoder identityPoolIdCodec)) Nothing
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
            , ( "IdentityPoolId", val.identityPoolId ) |> EncodeOpt.field (Codec.encoder identityPoolIdCodec)
            , ( "AccountId", val.accountId ) |> EncodeOpt.optionalField accountIdEncoder
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\identityIdFld -> { identityId = identityIdFld }) |> Json.Decode.succeed)
                |> Pipeline.optional "IdentityId" (Json.Decode.maybe (Codec.decoder identityIdCodec)) Nothing
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
            , ( "IdentityId", val.identityId ) |> EncodeOpt.field (Codec.encoder identityIdCodec)
            , ( "CustomRoleArn", val.customRoleArn ) |> EncodeOpt.optionalField (Codec.encoder arnstringCodec)
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
                |> Pipeline.optional "IdentityId" (Json.Decode.maybe (Codec.decoder identityIdCodec)) Nothing
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
            [ ( "IdentityPoolId", val.identityPoolId ) |> EncodeOpt.field (Codec.encoder identityPoolIdCodec) ]
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
                |> Pipeline.required "IdentityPoolName" (Codec.decoder identityPoolNameCodec)
                |> Pipeline.required "IdentityPoolId" (Codec.decoder identityPoolIdCodec)
                |> Pipeline.optional
                    "DeveloperProviderName"
                    (Json.Decode.maybe (Codec.decoder developerProviderNameCodec))
                    Nothing
                |> Pipeline.optional
                    "CognitoIdentityProviders"
                    (Json.Decode.maybe (Codec.decoder cognitoIdentityProviderListCodec))
                    Nothing
                |> Pipeline.required "AllowUnauthenticatedIdentities" (Codec.decoder identityPoolUnauthenticatedCodec)
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
            [ ( "IdentityId", val.identityId ) |> EncodeOpt.field (Codec.encoder identityIdCodec) ]
                |> EncodeOpt.objectMaySkip

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
                |> Pipeline.optional "LastModifiedDate" (Json.Decode.maybe dateTypeDecoder) Nothing
                |> Pipeline.optional "IdentityId" (Json.Decode.maybe (Codec.decoder identityIdCodec)) Nothing
                |> Pipeline.optional "CreationDate" (Json.Decode.maybe dateTypeDecoder) Nothing
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
            [ ( "IdentityPoolId", val.identityPoolId ) |> EncodeOpt.field (Codec.encoder identityPoolIdCodec) ]
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
            , ( "IdentityPoolName", val.identityPoolName ) |> EncodeOpt.field (Codec.encoder identityPoolNameCodec)
            , ( "DeveloperProviderName", val.developerProviderName )
                |> EncodeOpt.optionalField (Codec.encoder developerProviderNameCodec)
            , ( "CognitoIdentityProviders", val.cognitoIdentityProviders )
                |> EncodeOpt.optionalField (Codec.encoder cognitoIdentityProviderListCodec)
            , ( "AllowUnauthenticatedIdentities", val.allowUnauthenticatedIdentities )
                |> EncodeOpt.field (Codec.encoder identityPoolUnauthenticatedCodec)
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
                |> Pipeline.required "IdentityPoolName" (Codec.decoder identityPoolNameCodec)
                |> Pipeline.required "IdentityPoolId" (Codec.decoder identityPoolIdCodec)
                |> Pipeline.optional
                    "DeveloperProviderName"
                    (Json.Decode.maybe (Codec.decoder developerProviderNameCodec))
                    Nothing
                |> Pipeline.optional
                    "CognitoIdentityProviders"
                    (Json.Decode.maybe (Codec.decoder cognitoIdentityProviderListCodec))
                    Nothing
                |> Pipeline.required "AllowUnauthenticatedIdentities" (Codec.decoder identityPoolUnauthenticatedCodec)
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
    { resourceArn : Arnstring, tagKeys : Maybe IdentityPoolTagsListType }


{-| The UnprocessedIdentityIdList data model.
-}
type alias UnprocessedIdentityIdList =
    List UnprocessedIdentityId


{-| The UnprocessedIdentityId data model.
-}
type alias UnprocessedIdentityId =
    { errorCode : Maybe ErrorCode, identityId : Maybe IdentityId }


{-| The UnlinkIdentityInput data model.
-}
type alias UnlinkIdentityInput =
    { identityId : IdentityId, logins : LoginsMap, loginsToRemove : LoginsList }


{-| The UnlinkDeveloperIdentityInput data model.
-}
type alias UnlinkDeveloperIdentityInput =
    { developerProviderName : DeveloperProviderName
    , developerUserIdentifier : DeveloperUserIdentifier
    , identityId : IdentityId
    , identityPoolId : IdentityPoolId
    }


{-| The TokenDuration data model.
-}
type alias TokenDuration =
    Int


{-| The TagValueType data model.
-}
type TagValueType
    = TagValueType String


{-| The TagValueType data model.
-}
tagValueType : Refined String TagValueType StringError
tagValueType =
    let
        guardFn val =
            Refined.minLength 0 val |> Result.andThen (Refined.maxLength 256) |> Result.map TagValueType

        unboxFn (TagValueType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The TagResourceResponse data model.
-}
type alias TagResourceResponse =
    {}


{-| The TagResourceInput data model.
-}
type alias TagResourceInput =
    { resourceArn : Arnstring, tags : Maybe IdentityPoolTagsType }


{-| The TagKeysType data model.
-}
type TagKeysType
    = TagKeysType String


{-| The TagKeysType data model.
-}
tagKeysType : Refined String TagKeysType StringError
tagKeysType =
    let
        guardFn val =
            Refined.minLength 1 val |> Result.andThen (Refined.maxLength 128) |> Result.map TagKeysType

        unboxFn (TagKeysType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The SetIdentityPoolRolesInput data model.
-}
type alias SetIdentityPoolRolesInput =
    { identityPoolId : IdentityPoolId, roleMappings : Maybe RoleMappingMap, roles : RolesMap }


{-| The SessionTokenString data model.
-}
type alias SessionTokenString =
    String


{-| The SecretKeyString data model.
-}
type alias SecretKeyString =
    String


{-| The SamlproviderList data model.
-}
type alias SamlproviderList =
    List Arnstring


{-| The RulesConfigurationType data model.
-}
type alias RulesConfigurationType =
    { rules : MappingRulesList }


{-| The RolesMap data model.
-}
type alias RolesMap =
    Dict.Refined.Dict String RoleType Arnstring


{-| The RoleType data model.
-}
type RoleType
    = RoleType String


{-| The RoleType data model.
-}
roleType : Refined String RoleType StringError
roleType =
    let
        guardFn val =
            Refined.regexMatch "(un)?authenticated" val |> Result.map RoleType

        unboxFn (RoleType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


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
    Dict.Refined.Dict String IdentityProviderName RoleMapping


{-| The RoleMapping data model.
-}
type alias RoleMapping =
    { ambiguousRoleResolution : Maybe AmbiguousRoleResolutionType
    , rulesConfiguration : Maybe RulesConfigurationType
    , type_ : RoleMappingType
    }


{-| The QueryLimit data model.
-}
type QueryLimit
    = QueryLimit Int


{-| The QueryLimit data model.
-}
queryLimit : Refined Int QueryLimit IntError
queryLimit =
    let
        guardFn val =
            Refined.gte 1 val |> Result.andThen (Refined.lte 60) |> Result.map QueryLimit

        unboxFn (QueryLimit val) =
            val
    in
    Refined.define guardFn Json.Decode.int Json.Encode.int Refined.intErrorToString unboxFn


{-| The PaginationKey data model.
-}
type PaginationKey
    = PaginationKey String


{-| The PaginationKey data model.
-}
paginationKey : Refined String PaginationKey StringError
paginationKey =
    let
        guardFn val =
            Refined.minLength 1 val |> Result.andThen (Refined.regexMatch "[\\S]+") |> Result.map PaginationKey

        unboxFn (PaginationKey val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The Oidctoken data model.
-}
type alias Oidctoken =
    String


{-| The OidcproviderList data model.
-}
type alias OidcproviderList =
    List Arnstring


{-| The MergeDeveloperIdentitiesResponse data model.
-}
type alias MergeDeveloperIdentitiesResponse =
    { identityId : Maybe IdentityId }


{-| The MergeDeveloperIdentitiesInput data model.
-}
type alias MergeDeveloperIdentitiesInput =
    { destinationUserIdentifier : DeveloperUserIdentifier
    , developerProviderName : DeveloperProviderName
    , identityPoolId : IdentityPoolId
    , sourceUserIdentifier : DeveloperUserIdentifier
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
    { claim : ClaimName, matchType : MappingRuleMatchType, roleArn : Arnstring, value : ClaimValue }


{-| The LookupDeveloperIdentityResponse data model.
-}
type alias LookupDeveloperIdentityResponse =
    { developerUserIdentifierList : Maybe DeveloperUserIdentifierList
    , identityId : Maybe IdentityId
    , nextToken : Maybe PaginationKey
    }


{-| The LookupDeveloperIdentityInput data model.
-}
type alias LookupDeveloperIdentityInput =
    { developerUserIdentifier : Maybe DeveloperUserIdentifier
    , identityId : Maybe IdentityId
    , identityPoolId : IdentityPoolId
    , maxResults : Maybe QueryLimit
    , nextToken : Maybe PaginationKey
    }


{-| The LoginsMap data model.
-}
type alias LoginsMap =
    Dict.Refined.Dict String IdentityProviderName IdentityProviderToken


{-| The LoginsList data model.
-}
type alias LoginsList =
    List IdentityProviderName


{-| The ListTagsForResourceResponse data model.
-}
type alias ListTagsForResourceResponse =
    { tags : Maybe IdentityPoolTagsType }


{-| The ListTagsForResourceInput data model.
-}
type alias ListTagsForResourceInput =
    { resourceArn : Arnstring }


{-| The ListIdentityPoolsResponse data model.
-}
type alias ListIdentityPoolsResponse =
    { identityPools : Maybe IdentityPoolsList, nextToken : Maybe PaginationKey }


{-| The ListIdentityPoolsInput data model.
-}
type alias ListIdentityPoolsInput =
    { maxResults : QueryLimit, nextToken : Maybe PaginationKey }


{-| The ListIdentitiesResponse data model.
-}
type alias ListIdentitiesResponse =
    { identities : Maybe IdentitiesList, identityPoolId : Maybe IdentityPoolId, nextToken : Maybe PaginationKey }


{-| The ListIdentitiesInput data model.
-}
type alias ListIdentitiesInput =
    { hideDisabled : Maybe HideDisabled
    , identityPoolId : IdentityPoolId
    , maxResults : QueryLimit
    , nextToken : Maybe PaginationKey
    }


{-| The IdentityProviders data model.
-}
type alias IdentityProviders =
    Dict.Refined.Dict String IdentityProviderName IdentityProviderId


{-| The IdentityProviderToken data model.
-}
type IdentityProviderToken
    = IdentityProviderToken String


{-| The IdentityProviderToken data model.
-}
identityProviderToken : Refined String IdentityProviderToken StringError
identityProviderToken =
    let
        guardFn val =
            Refined.minLength 1 val |> Result.andThen (Refined.maxLength 50000) |> Result.map IdentityProviderToken

        unboxFn (IdentityProviderToken val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The IdentityProviderName data model.
-}
type IdentityProviderName
    = IdentityProviderName String


{-| The IdentityProviderName data model.
-}
identityProviderName : Refined String IdentityProviderName StringError
identityProviderName =
    let
        guardFn val =
            Refined.minLength 1 val |> Result.andThen (Refined.maxLength 128) |> Result.map IdentityProviderName

        unboxFn (IdentityProviderName val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The IdentityProviderId data model.
-}
type IdentityProviderId
    = IdentityProviderId String


{-| The IdentityProviderId data model.
-}
identityProviderId : Refined String IdentityProviderId StringError
identityProviderId =
    let
        guardFn val =
            Refined.minLength 1 val
                |> Result.andThen (Refined.maxLength 128)
                |> Result.andThen (Refined.regexMatch "[\\w.;_/-]+")
                |> Result.map IdentityProviderId

        unboxFn (IdentityProviderId val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The IdentityPoolsList data model.
-}
type alias IdentityPoolsList =
    List IdentityPoolShortDescription


{-| The IdentityPoolUnauthenticated data model.
-}
type alias IdentityPoolUnauthenticated =
    Bool


{-| The IdentityPoolTagsType data model.
-}
type alias IdentityPoolTagsType =
    Dict.Refined.Dict String TagKeysType TagValueType


{-| The IdentityPoolTagsListType data model.
-}
type alias IdentityPoolTagsListType =
    List TagKeysType


{-| The IdentityPoolShortDescription data model.
-}
type alias IdentityPoolShortDescription =
    { identityPoolId : Maybe IdentityPoolId, identityPoolName : Maybe IdentityPoolName }


{-| The IdentityPoolName data model.
-}
type IdentityPoolName
    = IdentityPoolName String


{-| The IdentityPoolName data model.
-}
identityPoolName : Refined String IdentityPoolName StringError
identityPoolName =
    let
        guardFn val =
            Refined.minLength 1 val
                |> Result.andThen (Refined.maxLength 128)
                |> Result.andThen (Refined.regexMatch "[\\w ]+")
                |> Result.map IdentityPoolName

        unboxFn (IdentityPoolName val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The IdentityPoolId data model.
-}
type IdentityPoolId
    = IdentityPoolId String


{-| The IdentityPoolId data model.
-}
identityPoolId : Refined String IdentityPoolId StringError
identityPoolId =
    let
        guardFn val =
            Refined.minLength 1 val
                |> Result.andThen (Refined.maxLength 55)
                |> Result.andThen (Refined.regexMatch "[\\w-]+:[0-9a-f-]+")
                |> Result.map IdentityPoolId

        unboxFn (IdentityPoolId val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The IdentityPool data model.
-}
type alias IdentityPool =
    { allowUnauthenticatedIdentities : IdentityPoolUnauthenticated
    , cognitoIdentityProviders : Maybe CognitoIdentityProviderList
    , developerProviderName : Maybe DeveloperProviderName
    , identityPoolId : IdentityPoolId
    , identityPoolName : IdentityPoolName
    , identityPoolTags : Maybe IdentityPoolTagsType
    , openIdConnectProviderArns : Maybe OidcproviderList
    , samlProviderArns : Maybe SamlproviderList
    , supportedLoginProviders : Maybe IdentityProviders
    }


{-| The IdentityIdList data model.
-}
type alias IdentityIdList =
    List IdentityId


{-| The IdentityId data model.
-}
type IdentityId
    = IdentityId String


{-| The IdentityId data model.
-}
identityId : Refined String IdentityId StringError
identityId =
    let
        guardFn val =
            Refined.minLength 1 val
                |> Result.andThen (Refined.maxLength 55)
                |> Result.andThen (Refined.regexMatch "[\\w-]+:[0-9a-f-]+")
                |> Result.map IdentityId

        unboxFn (IdentityId val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The IdentityDescription data model.
-}
type alias IdentityDescription =
    { creationDate : Maybe DateType
    , identityId : Maybe IdentityId
    , lastModifiedDate : Maybe DateType
    , logins : Maybe LoginsList
    }


{-| The IdentitiesList data model.
-}
type alias IdentitiesList =
    List IdentityDescription


{-| The HideDisabled data model.
-}
type alias HideDisabled =
    Bool


{-| The GetOpenIdTokenResponse data model.
-}
type alias GetOpenIdTokenResponse =
    { identityId : Maybe IdentityId, token : Maybe Oidctoken }


{-| The GetOpenIdTokenInput data model.
-}
type alias GetOpenIdTokenInput =
    { identityId : IdentityId, logins : Maybe LoginsMap }


{-| The GetOpenIdTokenForDeveloperIdentityResponse data model.
-}
type alias GetOpenIdTokenForDeveloperIdentityResponse =
    { identityId : Maybe IdentityId, token : Maybe Oidctoken }


{-| The GetOpenIdTokenForDeveloperIdentityInput data model.
-}
type alias GetOpenIdTokenForDeveloperIdentityInput =
    { identityId : Maybe IdentityId
    , identityPoolId : IdentityPoolId
    , logins : LoginsMap
    , tokenDuration : Maybe TokenDuration
    }


{-| The GetIdentityPoolRolesResponse data model.
-}
type alias GetIdentityPoolRolesResponse =
    { identityPoolId : Maybe IdentityPoolId, roleMappings : Maybe RoleMappingMap, roles : Maybe RolesMap }


{-| The GetIdentityPoolRolesInput data model.
-}
type alias GetIdentityPoolRolesInput =
    { identityPoolId : IdentityPoolId }


{-| The GetIdResponse data model.
-}
type alias GetIdResponse =
    { identityId : Maybe IdentityId }


{-| The GetIdInput data model.
-}
type alias GetIdInput =
    { accountId : Maybe AccountId, identityPoolId : IdentityPoolId, logins : Maybe LoginsMap }


{-| The GetCredentialsForIdentityResponse data model.
-}
type alias GetCredentialsForIdentityResponse =
    { credentials : Maybe Credentials, identityId : Maybe IdentityId }


{-| The GetCredentialsForIdentityInput data model.
-}
type alias GetCredentialsForIdentityInput =
    { customRoleArn : Maybe Arnstring, identityId : IdentityId, logins : Maybe LoginsMap }


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
    List DeveloperUserIdentifier


{-| The DeveloperUserIdentifier data model.
-}
type DeveloperUserIdentifier
    = DeveloperUserIdentifier String


{-| The DeveloperUserIdentifier data model.
-}
developerUserIdentifier : Refined String DeveloperUserIdentifier StringError
developerUserIdentifier =
    let
        guardFn val =
            Refined.minLength 1 val |> Result.andThen (Refined.maxLength 1024) |> Result.map DeveloperUserIdentifier

        unboxFn (DeveloperUserIdentifier val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The DeveloperProviderName data model.
-}
type DeveloperProviderName
    = DeveloperProviderName String


{-| The DeveloperProviderName data model.
-}
developerProviderName : Refined String DeveloperProviderName StringError
developerProviderName =
    let
        guardFn val =
            Refined.minLength 1 val
                |> Result.andThen (Refined.maxLength 128)
                |> Result.andThen (Refined.regexMatch "[\\w._-]+")
                |> Result.map DeveloperProviderName

        unboxFn (DeveloperProviderName val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The DescribeIdentityPoolInput data model.
-}
type alias DescribeIdentityPoolInput =
    { identityPoolId : IdentityPoolId }


{-| The DescribeIdentityInput data model.
-}
type alias DescribeIdentityInput =
    { identityId : IdentityId }


{-| The DeleteIdentityPoolInput data model.
-}
type alias DeleteIdentityPoolInput =
    { identityPoolId : IdentityPoolId }


{-| The DeleteIdentitiesResponse data model.
-}
type alias DeleteIdentitiesResponse =
    { unprocessedIdentityIds : Maybe UnprocessedIdentityIdList }


{-| The DeleteIdentitiesInput data model.
-}
type alias DeleteIdentitiesInput =
    { identityIdsToDelete : IdentityIdList }


{-| The DateType data model.
-}
type alias DateType =
    Int


{-| The Credentials data model.
-}
type alias Credentials =
    { accessKeyId : Maybe AccessKeyString
    , expiration : Maybe DateType
    , secretKey : Maybe SecretKeyString
    , sessionToken : Maybe SessionTokenString
    }


{-| The CreateIdentityPoolInput data model.
-}
type alias CreateIdentityPoolInput =
    { allowUnauthenticatedIdentities : IdentityPoolUnauthenticated
    , cognitoIdentityProviders : Maybe CognitoIdentityProviderList
    , developerProviderName : Maybe DeveloperProviderName
    , identityPoolName : IdentityPoolName
    , identityPoolTags : Maybe IdentityPoolTagsType
    , openIdConnectProviderArns : Maybe OidcproviderList
    , samlProviderArns : Maybe SamlproviderList
    , supportedLoginProviders : Maybe IdentityProviders
    }


{-| The CognitoIdentityProviderTokenCheck data model.
-}
type alias CognitoIdentityProviderTokenCheck =
    Bool


{-| The CognitoIdentityProviderName data model.
-}
type CognitoIdentityProviderName
    = CognitoIdentityProviderName String


{-| The CognitoIdentityProviderName data model.
-}
cognitoIdentityProviderName : Refined String CognitoIdentityProviderName StringError
cognitoIdentityProviderName =
    let
        guardFn val =
            Refined.minLength 1 val
                |> Result.andThen (Refined.maxLength 128)
                |> Result.andThen (Refined.regexMatch "[\\w._:/-]+")
                |> Result.map CognitoIdentityProviderName

        unboxFn (CognitoIdentityProviderName val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The CognitoIdentityProviderList data model.
-}
type alias CognitoIdentityProviderList =
    List CognitoIdentityProvider


{-| The CognitoIdentityProviderClientId data model.
-}
type CognitoIdentityProviderClientId
    = CognitoIdentityProviderClientId String


{-| The CognitoIdentityProviderClientId data model.
-}
cognitoIdentityProviderClientId : Refined String CognitoIdentityProviderClientId StringError
cognitoIdentityProviderClientId =
    let
        guardFn val =
            Refined.minLength 1 val
                |> Result.andThen (Refined.maxLength 128)
                |> Result.andThen (Refined.regexMatch "[\\w_]+")
                |> Result.map CognitoIdentityProviderClientId

        unboxFn (CognitoIdentityProviderClientId val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The CognitoIdentityProvider data model.
-}
type alias CognitoIdentityProvider =
    { clientId : Maybe CognitoIdentityProviderClientId
    , providerName : Maybe CognitoIdentityProviderName
    , serverSideTokenCheck : Maybe CognitoIdentityProviderTokenCheck
    }


{-| The ClaimValue data model.
-}
type ClaimValue
    = ClaimValue String


{-| The ClaimValue data model.
-}
claimValue : Refined String ClaimValue StringError
claimValue =
    let
        guardFn val =
            Refined.minLength 1 val |> Result.andThen (Refined.maxLength 128) |> Result.map ClaimValue

        unboxFn (ClaimValue val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The ClaimName data model.
-}
type ClaimName
    = ClaimName String


{-| The ClaimName data model.
-}
claimName : Refined String ClaimName StringError
claimName =
    let
        guardFn val =
            Refined.minLength 1 val
                |> Result.andThen (Refined.maxLength 64)
                |> Result.andThen (Refined.regexMatch "[\\p{L}\\p{M}\\p{S}\\p{N}\\p{P}]+")
                |> Result.map ClaimName

        unboxFn (ClaimName val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


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


{-| The AccountId data model.
-}
type AccountId
    = AccountId String


{-| The AccountId data model.
-}
accountId : Refined String AccountId StringError
accountId =
    let
        guardFn val =
            Refined.minLength 1 val
                |> Result.andThen (Refined.maxLength 15)
                |> Result.andThen (Refined.regexMatch "\\d+")
                |> Result.map AccountId

        unboxFn (AccountId val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The AccessKeyString data model.
-}
type alias AccessKeyString =
    String


{-| The Arnstring data model.
-}
type Arnstring
    = Arnstring String


{-| The Arnstring data model.
-}
arnstring : Refined String Arnstring StringError
arnstring =
    let
        guardFn val =
            Refined.minLength 20 val |> Result.andThen (Refined.maxLength 2048) |> Result.map Arnstring

        unboxFn (Arnstring val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| Codec for Arnstring.
-}
arnstringCodec : Codec Arnstring
arnstringCodec =
    Codec.build (Refined.encoder arnstring) (Refined.decoder arnstring)


{-| Decoder for AccessKeyString.
-}
accessKeyStringDecoder : Decoder AccessKeyString
accessKeyStringDecoder =
    Json.Decode.string


{-| Encoder for AccountId.
-}
accountIdEncoder : AccountId -> Value
accountIdEncoder =
    Refined.encoder accountId


{-| Codec for AmbiguousRoleResolutionType.
-}
ambiguousRoleResolutionTypeCodec : Codec AmbiguousRoleResolutionType
ambiguousRoleResolutionTypeCodec =
    Codec.build (Enum.encoder ambiguousRoleResolutionType) (Enum.decoder ambiguousRoleResolutionType)


{-| Codec for ClaimName.
-}
claimNameCodec : Codec ClaimName
claimNameCodec =
    Codec.build (Refined.encoder claimName) (Refined.decoder claimName)


{-| Codec for ClaimValue.
-}
claimValueCodec : Codec ClaimValue
claimValueCodec =
    Codec.build (Refined.encoder claimValue) (Refined.decoder claimValue)


{-| Codec for CognitoIdentityProvider.
-}
cognitoIdentityProviderCodec : Codec CognitoIdentityProvider
cognitoIdentityProviderCodec =
    Codec.object CognitoIdentityProvider
        |> Codec.optionalField "ClientId" .clientId cognitoIdentityProviderClientIdCodec
        |> Codec.optionalField "ProviderName" .providerName cognitoIdentityProviderNameCodec
        |> Codec.optionalField "ServerSideTokenCheck" .serverSideTokenCheck cognitoIdentityProviderTokenCheckCodec
        |> Codec.buildObject


{-| Codec for CognitoIdentityProviderClientId.
-}
cognitoIdentityProviderClientIdCodec : Codec CognitoIdentityProviderClientId
cognitoIdentityProviderClientIdCodec =
    Codec.build (Refined.encoder cognitoIdentityProviderClientId) (Refined.decoder cognitoIdentityProviderClientId)


{-| Codec for CognitoIdentityProviderList.
-}
cognitoIdentityProviderListCodec : Codec CognitoIdentityProviderList
cognitoIdentityProviderListCodec =
    Codec.list cognitoIdentityProviderCodec


{-| Codec for CognitoIdentityProviderName.
-}
cognitoIdentityProviderNameCodec : Codec CognitoIdentityProviderName
cognitoIdentityProviderNameCodec =
    Codec.build (Refined.encoder cognitoIdentityProviderName) (Refined.decoder cognitoIdentityProviderName)


{-| Codec for CognitoIdentityProviderTokenCheck.
-}
cognitoIdentityProviderTokenCheckCodec : Codec CognitoIdentityProviderTokenCheck
cognitoIdentityProviderTokenCheckCodec =
    Codec.bool


{-| Decoder for Credentials.
-}
credentialsDecoder : Decoder Credentials
credentialsDecoder =
    Json.Decode.succeed Credentials
        |> Pipeline.optional "AccessKeyId" (Json.Decode.maybe accessKeyStringDecoder) Nothing
        |> Pipeline.optional "Expiration" (Json.Decode.maybe dateTypeDecoder) Nothing
        |> Pipeline.optional "SecretKey" (Json.Decode.maybe secretKeyStringDecoder) Nothing
        |> Pipeline.optional "SessionToken" (Json.Decode.maybe sessionTokenStringDecoder) Nothing


{-| Decoder for DateType.
-}
dateTypeDecoder : Decoder DateType
dateTypeDecoder =
    Json.Decode.int


{-| Codec for DeveloperProviderName.
-}
developerProviderNameCodec : Codec DeveloperProviderName
developerProviderNameCodec =
    Codec.build (Refined.encoder developerProviderName) (Refined.decoder developerProviderName)


{-| Codec for DeveloperUserIdentifier.
-}
developerUserIdentifierCodec : Codec DeveloperUserIdentifier
developerUserIdentifierCodec =
    Codec.build (Refined.encoder developerUserIdentifier) (Refined.decoder developerUserIdentifier)


{-| Decoder for DeveloperUserIdentifierList.
-}
developerUserIdentifierListDecoder : Decoder DeveloperUserIdentifierList
developerUserIdentifierListDecoder =
    Json.Decode.list (Codec.decoder developerUserIdentifierCodec)


{-| Decoder for ErrorCode.
-}
errorCodeDecoder : Decoder ErrorCode
errorCodeDecoder =
    Enum.decoder errorCode


{-| Encoder for HideDisabled.
-}
hideDisabledEncoder : HideDisabled -> Value
hideDisabledEncoder val =
    Json.Encode.bool val


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
        |> Pipeline.optional "CreationDate" (Json.Decode.maybe dateTypeDecoder) Nothing
        |> Pipeline.optional "IdentityId" (Json.Decode.maybe (Codec.decoder identityIdCodec)) Nothing
        |> Pipeline.optional "LastModifiedDate" (Json.Decode.maybe dateTypeDecoder) Nothing
        |> Pipeline.optional "Logins" (Json.Decode.maybe (Codec.decoder loginsListCodec)) Nothing


{-| Codec for IdentityId.
-}
identityIdCodec : Codec IdentityId
identityIdCodec =
    Codec.build (Refined.encoder identityId) (Refined.decoder identityId)


{-| Encoder for IdentityIdList.
-}
identityIdListEncoder : IdentityIdList -> Value
identityIdListEncoder val =
    Json.Encode.list (Codec.encoder identityIdCodec) val


{-| Codec for IdentityPoolId.
-}
identityPoolIdCodec : Codec IdentityPoolId
identityPoolIdCodec =
    Codec.build (Refined.encoder identityPoolId) (Refined.decoder identityPoolId)


{-| Codec for IdentityPoolName.
-}
identityPoolNameCodec : Codec IdentityPoolName
identityPoolNameCodec =
    Codec.build (Refined.encoder identityPoolName) (Refined.decoder identityPoolName)


{-| Decoder for IdentityPoolShortDescription.
-}
identityPoolShortDescriptionDecoder : Decoder IdentityPoolShortDescription
identityPoolShortDescriptionDecoder =
    Json.Decode.succeed IdentityPoolShortDescription
        |> Pipeline.optional "IdentityPoolId" (Json.Decode.maybe (Codec.decoder identityPoolIdCodec)) Nothing
        |> Pipeline.optional "IdentityPoolName" (Json.Decode.maybe (Codec.decoder identityPoolNameCodec)) Nothing


{-| Encoder for IdentityPoolTagsListType.
-}
identityPoolTagsListTypeEncoder : IdentityPoolTagsListType -> Value
identityPoolTagsListTypeEncoder val =
    Json.Encode.list (Codec.encoder tagKeysTypeCodec) val


{-| Codec for IdentityPoolTagsType.
-}
identityPoolTagsTypeCodec : Codec IdentityPoolTagsType
identityPoolTagsTypeCodec =
    Codec.build
        (Refined.dictEncoder tagKeysType (Codec.encoder tagValueTypeCodec))
        (Refined.dictDecoder tagKeysType (Codec.decoder tagValueTypeCodec))


{-| Codec for IdentityPoolUnauthenticated.
-}
identityPoolUnauthenticatedCodec : Codec IdentityPoolUnauthenticated
identityPoolUnauthenticatedCodec =
    Codec.bool


{-| Decoder for IdentityPoolsList.
-}
identityPoolsListDecoder : Decoder IdentityPoolsList
identityPoolsListDecoder =
    Json.Decode.list identityPoolShortDescriptionDecoder


{-| Codec for IdentityProviderId.
-}
identityProviderIdCodec : Codec IdentityProviderId
identityProviderIdCodec =
    Codec.build (Refined.encoder identityProviderId) (Refined.decoder identityProviderId)


{-| Codec for IdentityProviderName.
-}
identityProviderNameCodec : Codec IdentityProviderName
identityProviderNameCodec =
    Codec.build (Refined.encoder identityProviderName) (Refined.decoder identityProviderName)


{-| Encoder for IdentityProviderToken.
-}
identityProviderTokenEncoder : IdentityProviderToken -> Value
identityProviderTokenEncoder =
    Refined.encoder identityProviderToken


{-| Codec for IdentityProviders.
-}
identityProvidersCodec : Codec IdentityProviders
identityProvidersCodec =
    Codec.build
        (Refined.dictEncoder identityProviderName (Codec.encoder identityProviderIdCodec))
        (Refined.dictDecoder identityProviderName (Codec.decoder identityProviderIdCodec))


{-| Codec for LoginsList.
-}
loginsListCodec : Codec LoginsList
loginsListCodec =
    Codec.list identityProviderNameCodec


{-| Encoder for LoginsMap.
-}
loginsMapEncoder : LoginsMap -> Value
loginsMapEncoder val =
    Refined.dictEncoder identityProviderName identityProviderTokenEncoder val


{-| Codec for MappingRule.
-}
mappingRuleCodec : Codec MappingRule
mappingRuleCodec =
    Codec.object MappingRule
        |> Codec.field "Claim" .claim claimNameCodec
        |> Codec.field "MatchType" .matchType mappingRuleMatchTypeCodec
        |> Codec.field "RoleARN" .roleArn arnstringCodec
        |> Codec.field "Value" .value claimValueCodec
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
    Codec.list arnstringCodec


{-| Decoder for Oidctoken.
-}
oidctokenDecoder : Decoder Oidctoken
oidctokenDecoder =
    Json.Decode.string


{-| Codec for PaginationKey.
-}
paginationKeyCodec : Codec PaginationKey
paginationKeyCodec =
    Codec.build (Refined.encoder paginationKey) (Refined.decoder paginationKey)


{-| Encoder for QueryLimit.
-}
queryLimitEncoder : QueryLimit -> Value
queryLimitEncoder =
    Refined.encoder queryLimit


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
    Codec.build
        (Refined.dictEncoder identityProviderName (Codec.encoder roleMappingCodec))
        (Refined.dictDecoder identityProviderName (Codec.decoder roleMappingCodec))


{-| Codec for RoleMappingType.
-}
roleMappingTypeCodec : Codec RoleMappingType
roleMappingTypeCodec =
    Codec.build (Enum.encoder roleMappingType) (Enum.decoder roleMappingType)


{-| Codec for RoleType.
-}
roleTypeCodec : Codec RoleType
roleTypeCodec =
    Codec.build (Refined.encoder roleType) (Refined.decoder roleType)


{-| Codec for RolesMap.
-}
rolesMapCodec : Codec RolesMap
rolesMapCodec =
    Codec.build
        (Refined.dictEncoder roleType (Codec.encoder arnstringCodec))
        (Refined.dictDecoder roleType (Codec.decoder arnstringCodec))


{-| Codec for RulesConfigurationType.
-}
rulesConfigurationTypeCodec : Codec RulesConfigurationType
rulesConfigurationTypeCodec =
    Codec.object RulesConfigurationType |> Codec.field "Rules" .rules mappingRulesListCodec |> Codec.buildObject


{-| Codec for SamlproviderList.
-}
samlproviderListCodec : Codec SamlproviderList
samlproviderListCodec =
    Codec.list arnstringCodec


{-| Decoder for SecretKeyString.
-}
secretKeyStringDecoder : Decoder SecretKeyString
secretKeyStringDecoder =
    Json.Decode.string


{-| Decoder for SessionTokenString.
-}
sessionTokenStringDecoder : Decoder SessionTokenString
sessionTokenStringDecoder =
    Json.Decode.string


{-| Codec for TagKeysType.
-}
tagKeysTypeCodec : Codec TagKeysType
tagKeysTypeCodec =
    Codec.build (Refined.encoder tagKeysType) (Refined.decoder tagKeysType)


{-| Codec for TagValueType.
-}
tagValueTypeCodec : Codec TagValueType
tagValueTypeCodec =
    Codec.build (Refined.encoder tagValueType) (Refined.decoder tagValueType)


{-| Encoder for TokenDuration.
-}
tokenDurationEncoder : TokenDuration -> Value
tokenDurationEncoder val =
    Json.Encode.int val


{-| Decoder for UnprocessedIdentityId.
-}
unprocessedIdentityIdDecoder : Decoder UnprocessedIdentityId
unprocessedIdentityIdDecoder =
    Json.Decode.succeed UnprocessedIdentityId
        |> Pipeline.optional "ErrorCode" (Json.Decode.maybe errorCodeDecoder) Nothing
        |> Pipeline.optional "IdentityId" (Json.Decode.maybe (Codec.decoder identityIdCodec)) Nothing


{-| Decoder for UnprocessedIdentityIdList.
-}
unprocessedIdentityIdListDecoder : Decoder UnprocessedIdentityIdList
unprocessedIdentityIdListDecoder =
    Json.Decode.list unprocessedIdentityIdDecoder
