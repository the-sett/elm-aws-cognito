module AWS.CognitoIdentity exposing
    ( service
    , createIdentityPool, deleteIdentities, deleteIdentityPool, describeIdentity, describeIdentityPool, getCredentialsForIdentity, getId
    , getIdentityPoolRoles, getOpenIdToken, getOpenIdTokenForDeveloperIdentity, listIdentities, listIdentityPools, listTagsForResource
    , lookupDeveloperIdentity, mergeDeveloperIdentities, setIdentityPoolRoles, tagResource, unlinkDeveloperIdentity, unlinkIdentity
    , untagResource, updateIdentityPool
    , AccessKeyString, AmbiguousRoleResolutionType(..), CognitoIdentityProvider, CognitoIdentityProviderList
    , CognitoIdentityProviderTokenCheck, CreateIdentityPoolInput, Credentials, DateType, DeleteIdentitiesInput, DeleteIdentitiesResponse
    , DeleteIdentityPoolInput, DescribeIdentityInput, DescribeIdentityPoolInput, DeveloperUserIdentifierList, ErrorCode(..)
    , GetCredentialsForIdentityInput, GetCredentialsForIdentityResponse, GetIdInput, GetIdResponse, GetIdentityPoolRolesInput
    , GetIdentityPoolRolesResponse, GetOpenIdTokenForDeveloperIdentityInput, GetOpenIdTokenForDeveloperIdentityResponse
    , GetOpenIdTokenInput, GetOpenIdTokenResponse, HideDisabled, IdentitiesList, IdentityDescription, IdentityIdList, IdentityPool
    , IdentityPoolShortDescription, IdentityPoolTagsListType, IdentityPoolTagsType, IdentityPoolUnauthenticated, IdentityPoolsList
    , IdentityProviders, ListIdentitiesInput, ListIdentitiesResponse, ListIdentityPoolsInput, ListIdentityPoolsResponse
    , ListTagsForResourceInput, ListTagsForResourceResponse, LoginsList, LoginsMap, LookupDeveloperIdentityInput
    , LookupDeveloperIdentityResponse, MappingRule, MappingRuleMatchType(..), MappingRulesList, MergeDeveloperIdentitiesInput
    , MergeDeveloperIdentitiesResponse, OidcproviderList, Oidctoken, RoleMapping, RoleMappingMap, RoleMappingType(..), RolesMap
    , RulesConfigurationType, SamlproviderList, SecretKeyString, SessionTokenString, SetIdentityPoolRolesInput, TagResourceInput
    , TagResourceResponse, TokenDuration, UnlinkDeveloperIdentityInput, UnlinkIdentityInput, UnprocessedIdentityId
    , UnprocessedIdentityIdList, UntagResourceInput, UntagResourceResponse, accountId, ambiguousRoleResolutionType, arnstring, claimName
    , claimValue, cognitoIdentityProviderClientId, cognitoIdentityProviderName, developerProviderName, developerUserIdentifier
    , errorCode, identityId, identityPoolId, identityPoolName, identityProviderId, identityProviderName, identityProviderToken
    , mappingRuleMatchType, paginationKey, queryLimit, roleMappingType, roleType, tagKeysType, tagValueType
    , accessKeyStringCodec, accountIdCodec, ambiguousRoleResolutionTypeCodec, arnstringCodec, claimNameCodec, claimValueCodec
    , cognitoIdentityProviderClientIdCodec, cognitoIdentityProviderCodec, cognitoIdentityProviderListCodec
    , cognitoIdentityProviderNameCodec, cognitoIdentityProviderTokenCheckCodec, createIdentityPoolInputCodec, credentialsCodec
    , dateTypeCodec, deleteIdentitiesInputCodec, deleteIdentitiesResponseCodec, deleteIdentityPoolInputCodec
    , describeIdentityInputCodec, describeIdentityPoolInputCodec, developerProviderNameCodec, developerUserIdentifierCodec
    , developerUserIdentifierListCodec, errorCodeCodec, getCredentialsForIdentityInputCodec, getCredentialsForIdentityResponseCodec
    , getIdInputCodec, getIdResponseCodec, getIdentityPoolRolesInputCodec, getIdentityPoolRolesResponseCodec
    , getOpenIdTokenForDeveloperIdentityInputCodec, getOpenIdTokenForDeveloperIdentityResponseCodec, getOpenIdTokenInputCodec
    , getOpenIdTokenResponseCodec, hideDisabledCodec, identitiesListCodec, identityDescriptionCodec, identityIdCodec
    , identityIdListCodec, identityPoolCodec, identityPoolIdCodec, identityPoolNameCodec, identityPoolShortDescriptionCodec
    , identityPoolTagsListTypeCodec, identityPoolTagsTypeCodec, identityPoolUnauthenticatedCodec, identityPoolsListCodec
    , identityProviderIdCodec, identityProviderNameCodec, identityProviderTokenCodec, identityProvidersCodec, listIdentitiesInputCodec
    , listIdentitiesResponseCodec, listIdentityPoolsInputCodec, listIdentityPoolsResponseCodec, listTagsForResourceInputCodec
    , listTagsForResourceResponseCodec, loginsListCodec, loginsMapCodec, lookupDeveloperIdentityInputCodec
    , lookupDeveloperIdentityResponseCodec, mappingRuleCodec, mappingRuleMatchTypeCodec, mappingRulesListCodec
    , mergeDeveloperIdentitiesInputCodec, mergeDeveloperIdentitiesResponseCodec, oidcproviderListCodec, oidctokenCodec
    , paginationKeyCodec, queryLimitCodec, roleMappingCodec, roleMappingMapCodec, roleMappingTypeCodec, roleTypeCodec, rolesMapCodec
    , rulesConfigurationTypeCodec, samlproviderListCodec, secretKeyStringCodec, sessionTokenStringCodec
    , setIdentityPoolRolesInputCodec, tagKeysTypeCodec, tagResourceInputCodec, tagResourceResponseCodec, tagValueTypeCodec
    , tokenDurationCodec, unlinkDeveloperIdentityInputCodec, unlinkIdentityInputCodec, unprocessedIdentityIdCodec
    , unprocessedIdentityIdListCodec, untagResourceInputCodec, untagResourceResponseCodec
    )

{-| Amazon Cognito Federated Identities

Amazon Cognito Federated Identities is a web service that delivers scoped temporary credentials to mobile devices and other untrusted environments. It uniquely identifies a device and supplies the user with a consistent identity over the lifetime of an application.

Using Amazon Cognito Federated Identities, you can enable authentication with one or more third-party identity providers (Facebook, Google, or Login with Amazon) or an Amazon Cognito user pool, and you can also choose to support unauthenticated access from your app. Cognito delivers a unique identifier for each user and acts as an OpenID token provider trusted by AWS Security Token Service (STS) to access temporary, limited-privilege AWS credentials.

For a description of the authentication flow from the Amazon Cognito Developer Guide see
Authentication Flow
.

For more information see
Amazon Cognito Federated Identities
.


# Service definition.

@docs service


# Service endpoints.

@docs createIdentityPool, deleteIdentities, deleteIdentityPool, describeIdentity, describeIdentityPool, getCredentialsForIdentity, getId
@docs getIdentityPoolRoles, getOpenIdToken, getOpenIdTokenForDeveloperIdentity, listIdentities, listIdentityPools, listTagsForResource
@docs lookupDeveloperIdentity, mergeDeveloperIdentities, setIdentityPoolRoles, tagResource, unlinkDeveloperIdentity, unlinkIdentity
@docs untagResource, updateIdentityPool


# API data model.

@docs AccessKeyString, AmbiguousRoleResolutionType, CognitoIdentityProvider, CognitoIdentityProviderList
@docs CognitoIdentityProviderTokenCheck, CreateIdentityPoolInput, Credentials, DateType, DeleteIdentitiesInput, DeleteIdentitiesResponse
@docs DeleteIdentityPoolInput, DescribeIdentityInput, DescribeIdentityPoolInput, DeveloperUserIdentifierList, ErrorCode
@docs GetCredentialsForIdentityInput, GetCredentialsForIdentityResponse, GetIdInput, GetIdResponse, GetIdentityPoolRolesInput
@docs GetIdentityPoolRolesResponse, GetOpenIdTokenForDeveloperIdentityInput, GetOpenIdTokenForDeveloperIdentityResponse
@docs GetOpenIdTokenInput, GetOpenIdTokenResponse, HideDisabled, IdentitiesList, IdentityDescription, IdentityIdList, IdentityPool
@docs IdentityPoolShortDescription, IdentityPoolTagsListType, IdentityPoolTagsType, IdentityPoolUnauthenticated, IdentityPoolsList
@docs IdentityProviders, ListIdentitiesInput, ListIdentitiesResponse, ListIdentityPoolsInput, ListIdentityPoolsResponse
@docs ListTagsForResourceInput, ListTagsForResourceResponse, LoginsList, LoginsMap, LookupDeveloperIdentityInput
@docs LookupDeveloperIdentityResponse, MappingRule, MappingRuleMatchType, MappingRulesList, MergeDeveloperIdentitiesInput
@docs MergeDeveloperIdentitiesResponse, OidcproviderList, Oidctoken, RoleMapping, RoleMappingMap, RoleMappingType, RolesMap
@docs RulesConfigurationType, SamlproviderList, SecretKeyString, SessionTokenString, SetIdentityPoolRolesInput, TagResourceInput
@docs TagResourceResponse, TokenDuration, UnlinkDeveloperIdentityInput, UnlinkIdentityInput, UnprocessedIdentityId
@docs UnprocessedIdentityIdList, UntagResourceInput, UntagResourceResponse, accountId, ambiguousRoleResolutionType, arnstring, claimName
@docs claimValue, cognitoIdentityProviderClientId, cognitoIdentityProviderName, developerProviderName, developerUserIdentifier
@docs errorCode, identityId, identityPoolId, identityPoolName, identityProviderId, identityProviderName, identityProviderToken
@docs mappingRuleMatchType, paginationKey, queryLimit, roleMappingType, roleType, tagKeysType, tagValueType


# Codecs for the data model.

@docs accessKeyStringCodec, accountIdCodec, ambiguousRoleResolutionTypeCodec, arnstringCodec, claimNameCodec, claimValueCodec
@docs cognitoIdentityProviderClientIdCodec, cognitoIdentityProviderCodec, cognitoIdentityProviderListCodec
@docs cognitoIdentityProviderNameCodec, cognitoIdentityProviderTokenCheckCodec, createIdentityPoolInputCodec, credentialsCodec
@docs dateTypeCodec, deleteIdentitiesInputCodec, deleteIdentitiesResponseCodec, deleteIdentityPoolInputCodec
@docs describeIdentityInputCodec, describeIdentityPoolInputCodec, developerProviderNameCodec, developerUserIdentifierCodec
@docs developerUserIdentifierListCodec, errorCodeCodec, getCredentialsForIdentityInputCodec, getCredentialsForIdentityResponseCodec
@docs getIdInputCodec, getIdResponseCodec, getIdentityPoolRolesInputCodec, getIdentityPoolRolesResponseCodec
@docs getOpenIdTokenForDeveloperIdentityInputCodec, getOpenIdTokenForDeveloperIdentityResponseCodec, getOpenIdTokenInputCodec
@docs getOpenIdTokenResponseCodec, hideDisabledCodec, identitiesListCodec, identityDescriptionCodec, identityIdCodec
@docs identityIdListCodec, identityPoolCodec, identityPoolIdCodec, identityPoolNameCodec, identityPoolShortDescriptionCodec
@docs identityPoolTagsListTypeCodec, identityPoolTagsTypeCodec, identityPoolUnauthenticatedCodec, identityPoolsListCodec
@docs identityProviderIdCodec, identityProviderNameCodec, identityProviderTokenCodec, identityProvidersCodec, listIdentitiesInputCodec
@docs listIdentitiesResponseCodec, listIdentityPoolsInputCodec, listIdentityPoolsResponseCodec, listTagsForResourceInputCodec
@docs listTagsForResourceResponseCodec, loginsListCodec, loginsMapCodec, lookupDeveloperIdentityInputCodec
@docs lookupDeveloperIdentityResponseCodec, mappingRuleCodec, mappingRuleMatchTypeCodec, mappingRulesListCodec
@docs mergeDeveloperIdentitiesInputCodec, mergeDeveloperIdentitiesResponseCodec, oidcproviderListCodec, oidctokenCodec
@docs paginationKeyCodec, queryLimitCodec, roleMappingCodec, roleMappingMapCodec, roleMappingTypeCodec, roleTypeCodec, rolesMapCodec
@docs rulesConfigurationTypeCodec, samlproviderListCodec, secretKeyStringCodec, sessionTokenStringCodec
@docs setIdentityPoolRolesInputCodec, tagKeysTypeCodec, tagResourceInputCodec, tagResourceResponseCodec, tagValueTypeCodec
@docs tokenDurationCodec, unlinkDeveloperIdentityInputCodec, unlinkIdentityInputCodec, unprocessedIdentityIdCodec
@docs unprocessedIdentityIdListCodec, untagResourceInputCodec, untagResourceResponseCodec

-}

import AWS.Core.Decode
import AWS.Core.Http
import AWS.Core.Service
import Codec exposing (Codec)
import Dict.Refined
import Enum exposing (Enum)
import Json.Decode exposing (Decoder)
import Json.Encode exposing (Value)
import Refined exposing (IntError, Refined, StringError)


{-| Configuration for this service.
-}
service : AWS.Core.Service.Region -> AWS.Core.Service.Service
service =
    let
        optionsFn =
            AWS.Core.Service.setJsonVersion "1.1" >> AWS.Core.Service.setTargetPrefix "AWSCognitoIdentityService"
    in
    AWS.Core.Service.defineRegional
        "cognito-identity"
        "2014-06-30"
        AWS.Core.Service.JSON
        AWS.Core.Service.SignV4
        optionsFn


{-| Updates an identity pool.

You must use AWS Developer credentials to call this API.

-}
updateIdentityPool : IdentityPool -> AWS.Core.Http.Request IdentityPool
updateIdentityPool req =
    let
        jsonBody =
            req |> Codec.encoder identityPoolCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder identityPoolCodec
    in
    AWS.Core.Http.request "UpdateIdentityPool" AWS.Core.Http.POST "/" jsonBody decoder


{-| Removes the specified tags from an Amazon Cognito identity pool. You can use this action up to 5 times per second, per account
-}
untagResource : UntagResourceInput -> AWS.Core.Http.Request UntagResourceResponse
untagResource req =
    let
        jsonBody =
            req |> Codec.encoder untagResourceInputCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder untagResourceResponseCodec
    in
    AWS.Core.Http.request "UntagResource" AWS.Core.Http.POST "/" jsonBody decoder


{-| Unlinks a federated identity from an existing account. Unlinked logins will be considered new identities next time they are seen. Removing the last linked login will make this identity inaccessible.

This is a public API. You do not need any credentials to call this API.

-}
unlinkIdentity : UnlinkIdentityInput -> AWS.Core.Http.Request ()
unlinkIdentity req =
    let
        jsonBody =
            req |> Codec.encoder unlinkIdentityInputCodec |> AWS.Core.Http.jsonBody

        decoder =
            Json.Decode.succeed ()
    in
    AWS.Core.Http.request "UnlinkIdentity" AWS.Core.Http.POST "/" jsonBody decoder


{-| Unlinks a
DeveloperUserIdentifier
from an existing identity. Unlinked developer users will be considered new identities next time they are seen. If, for a given Cognito identity, you remove all federated identities as well as the developer user identifier, the Cognito identity becomes inaccessible.

You must use AWS Developer credentials to call this API.

-}
unlinkDeveloperIdentity : UnlinkDeveloperIdentityInput -> AWS.Core.Http.Request ()
unlinkDeveloperIdentity req =
    let
        jsonBody =
            req |> Codec.encoder unlinkDeveloperIdentityInputCodec |> AWS.Core.Http.jsonBody

        decoder =
            Json.Decode.succeed ()
    in
    AWS.Core.Http.request "UnlinkDeveloperIdentity" AWS.Core.Http.POST "/" jsonBody decoder


{-| Assigns a set of tags to an Amazon Cognito identity pool. A tag is a label that you can use to categorize and manage identity pools in different ways, such as by purpose, owner, environment, or other criteria.

Each tag consists of a key and value, both of which you define. A key is a general category for more specific values. For example, if you have two versions of an identity pool, one for testing and another for production, you might assign an
Environment
tag key to both identity pools. The value of this key might be
Test
for one identity pool and
Production
for the other.

Tags are useful for cost tracking and access control. You can activate your tags so that they appear on the Billing and Cost Management console, where you can track the costs associated with your identity pools. In an IAM policy, you can constrain permissions for identity pools based on specific tags or tag values.

You can use this action up to 5 times per second, per account. An identity pool can have as many as 50 tags.

-}
tagResource : TagResourceInput -> AWS.Core.Http.Request TagResourceResponse
tagResource req =
    let
        jsonBody =
            req |> Codec.encoder tagResourceInputCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder tagResourceResponseCodec
    in
    AWS.Core.Http.request "TagResource" AWS.Core.Http.POST "/" jsonBody decoder


{-| Sets the roles for an identity pool. These roles are used when making calls to
GetCredentialsForIdentity
action.

You must use AWS Developer credentials to call this API.

-}
setIdentityPoolRoles : SetIdentityPoolRolesInput -> AWS.Core.Http.Request ()
setIdentityPoolRoles req =
    let
        jsonBody =
            req |> Codec.encoder setIdentityPoolRolesInputCodec |> AWS.Core.Http.jsonBody

        decoder =
            Json.Decode.succeed ()
    in
    AWS.Core.Http.request "SetIdentityPoolRoles" AWS.Core.Http.POST "/" jsonBody decoder


{-| Merges two users having different
IdentityId
s, existing in the same identity pool, and identified by the same developer provider. You can use this action to request that discrete users be merged and identified as a single user in the Cognito environment. Cognito associates the given source user (
SourceUserIdentifier
) with the
IdentityId
of the
DestinationUserIdentifier
. Only developer-authenticated users can be merged. If the users to be merged are associated with the same public provider, but as two different users, an exception will be thrown.

The number of linked logins is limited to 20. So, the number of linked logins for the source user,
SourceUserIdentifier
, and the destination user,
DestinationUserIdentifier
, together should not be larger than 20. Otherwise, an exception will be thrown.

You must use AWS Developer credentials to call this API.

-}
mergeDeveloperIdentities : MergeDeveloperIdentitiesInput -> AWS.Core.Http.Request MergeDeveloperIdentitiesResponse
mergeDeveloperIdentities req =
    let
        jsonBody =
            req |> Codec.encoder mergeDeveloperIdentitiesInputCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder mergeDeveloperIdentitiesResponseCodec
    in
    AWS.Core.Http.request "MergeDeveloperIdentities" AWS.Core.Http.POST "/" jsonBody decoder


{-| Retrieves the
IdentityID
associated with a
DeveloperUserIdentifier
or the list of
DeveloperUserIdentifier
values associated with an
IdentityId
for an existing identity. Either
IdentityID
or
DeveloperUserIdentifier
must not be null. If you supply only one of these values, the other value will be searched in the database and returned as a part of the response. If you supply both,
DeveloperUserIdentifier
will be matched against
IdentityID
. If the values are verified against the database, the response returns both values and is the same as the request. Otherwise a
ResourceConflictException
is thrown.

LookupDeveloperIdentity
is intended for low-throughput control plane operations: for example, to enable customer service to locate an identity ID by username. If you are using it for higher-volume operations such as user authentication, your requests are likely to be throttled.
GetOpenIdTokenForDeveloperIdentity
is a better option for higher-volume operations for user authentication.

You must use AWS Developer credentials to call this API.

-}
lookupDeveloperIdentity : LookupDeveloperIdentityInput -> AWS.Core.Http.Request LookupDeveloperIdentityResponse
lookupDeveloperIdentity req =
    let
        jsonBody =
            req |> Codec.encoder lookupDeveloperIdentityInputCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder lookupDeveloperIdentityResponseCodec
    in
    AWS.Core.Http.request "LookupDeveloperIdentity" AWS.Core.Http.POST "/" jsonBody decoder


{-| Lists the tags that are assigned to an Amazon Cognito identity pool.

A tag is a label that you can apply to identity pools to categorize and manage them in different ways, such as by purpose, owner, environment, or other criteria.

You can use this action up to 10 times per second, per account.

-}
listTagsForResource : ListTagsForResourceInput -> AWS.Core.Http.Request ListTagsForResourceResponse
listTagsForResource req =
    let
        jsonBody =
            req |> Codec.encoder listTagsForResourceInputCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder listTagsForResourceResponseCodec
    in
    AWS.Core.Http.request "ListTagsForResource" AWS.Core.Http.POST "/" jsonBody decoder


{-| Lists all of the Cognito identity pools registered for your account.

You must use AWS Developer credentials to call this API.

-}
listIdentityPools : ListIdentityPoolsInput -> AWS.Core.Http.Request ListIdentityPoolsResponse
listIdentityPools req =
    let
        jsonBody =
            req |> Codec.encoder listIdentityPoolsInputCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder listIdentityPoolsResponseCodec
    in
    AWS.Core.Http.request "ListIdentityPools" AWS.Core.Http.POST "/" jsonBody decoder


{-| Lists the identities in an identity pool.

You must use AWS Developer credentials to call this API.

-}
listIdentities : ListIdentitiesInput -> AWS.Core.Http.Request ListIdentitiesResponse
listIdentities req =
    let
        jsonBody =
            req |> Codec.encoder listIdentitiesInputCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder listIdentitiesResponseCodec
    in
    AWS.Core.Http.request "ListIdentities" AWS.Core.Http.POST "/" jsonBody decoder


{-| Registers (or retrieves) a Cognito
IdentityId
and an OpenID Connect token for a user authenticated by your backend authentication process. Supplying multiple logins will create an implicit linked account. You can only specify one developer provider as part of the
Logins
map, which is linked to the identity pool. The developer provider is the "domain" by which Cognito will refer to your users.

You can use
GetOpenIdTokenForDeveloperIdentity
to create a new identity and to link new logins (that is, user credentials issued by a public provider or developer provider) to an existing identity. When you want to create a new identity, the
IdentityId
should be null. When you want to associate a new login with an existing authenticated/unauthenticated identity, you can do so by providing the existing
IdentityId
. This API will create the identity in the specified
IdentityPoolId
.

You must use AWS Developer credentials to call this API.

-}
getOpenIdTokenForDeveloperIdentity : GetOpenIdTokenForDeveloperIdentityInput -> AWS.Core.Http.Request GetOpenIdTokenForDeveloperIdentityResponse
getOpenIdTokenForDeveloperIdentity req =
    let
        jsonBody =
            req |> Codec.encoder getOpenIdTokenForDeveloperIdentityInputCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder getOpenIdTokenForDeveloperIdentityResponseCodec
    in
    AWS.Core.Http.request "GetOpenIdTokenForDeveloperIdentity" AWS.Core.Http.POST "/" jsonBody decoder


{-| Gets an OpenID token, using a known Cognito ID. This known Cognito ID is returned by
GetId
. You can optionally add additional logins for the identity. Supplying multiple logins creates an implicit link.

The OpenId token is valid for 10 minutes.

This is a public API. You do not need any credentials to call this API.

-}
getOpenIdToken : GetOpenIdTokenInput -> AWS.Core.Http.Request GetOpenIdTokenResponse
getOpenIdToken req =
    let
        jsonBody =
            req |> Codec.encoder getOpenIdTokenInputCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder getOpenIdTokenResponseCodec
    in
    AWS.Core.Http.request "GetOpenIdToken" AWS.Core.Http.POST "/" jsonBody decoder


{-| Gets the roles for an identity pool.

You must use AWS Developer credentials to call this API.

-}
getIdentityPoolRoles : GetIdentityPoolRolesInput -> AWS.Core.Http.Request GetIdentityPoolRolesResponse
getIdentityPoolRoles req =
    let
        jsonBody =
            req |> Codec.encoder getIdentityPoolRolesInputCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder getIdentityPoolRolesResponseCodec
    in
    AWS.Core.Http.request "GetIdentityPoolRoles" AWS.Core.Http.POST "/" jsonBody decoder


{-| Generates (or retrieves) a Cognito ID. Supplying multiple logins will create an implicit linked account.

This is a public API. You do not need any credentials to call this API.

-}
getId : GetIdInput -> AWS.Core.Http.Request GetIdResponse
getId req =
    let
        jsonBody =
            req |> Codec.encoder getIdInputCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder getIdResponseCodec
    in
    AWS.Core.Http.request "GetId" AWS.Core.Http.POST "/" jsonBody decoder


{-| Returns credentials for the provided identity ID. Any provided logins will be validated against supported login providers. If the token is for cognito-identity.amazonaws.com, it will be passed through to AWS Security Token Service with the appropriate role for the token.

This is a public API. You do not need any credentials to call this API.

-}
getCredentialsForIdentity : GetCredentialsForIdentityInput -> AWS.Core.Http.Request GetCredentialsForIdentityResponse
getCredentialsForIdentity req =
    let
        jsonBody =
            req |> Codec.encoder getCredentialsForIdentityInputCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder getCredentialsForIdentityResponseCodec
    in
    AWS.Core.Http.request "GetCredentialsForIdentity" AWS.Core.Http.POST "/" jsonBody decoder


{-| Gets details about a particular identity pool, including the pool name, ID description, creation date, and current number of users.

You must use AWS Developer credentials to call this API.

-}
describeIdentityPool : DescribeIdentityPoolInput -> AWS.Core.Http.Request IdentityPool
describeIdentityPool req =
    let
        jsonBody =
            req |> Codec.encoder describeIdentityPoolInputCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder identityPoolCodec
    in
    AWS.Core.Http.request "DescribeIdentityPool" AWS.Core.Http.POST "/" jsonBody decoder


{-| Returns metadata related to the given identity, including when the identity was created and any associated linked logins.

You must use AWS Developer credentials to call this API.

-}
describeIdentity : DescribeIdentityInput -> AWS.Core.Http.Request IdentityDescription
describeIdentity req =
    let
        jsonBody =
            req |> Codec.encoder describeIdentityInputCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder identityDescriptionCodec
    in
    AWS.Core.Http.request "DescribeIdentity" AWS.Core.Http.POST "/" jsonBody decoder


{-| Deletes an identity pool. Once a pool is deleted, users will not be able to authenticate with the pool.

You must use AWS Developer credentials to call this API.

-}
deleteIdentityPool : DeleteIdentityPoolInput -> AWS.Core.Http.Request ()
deleteIdentityPool req =
    let
        jsonBody =
            req |> Codec.encoder deleteIdentityPoolInputCodec |> AWS.Core.Http.jsonBody

        decoder =
            Json.Decode.succeed ()
    in
    AWS.Core.Http.request "DeleteIdentityPool" AWS.Core.Http.POST "/" jsonBody decoder


{-| Deletes identities from an identity pool. You can specify a list of 1-60 identities that you want to delete.

You must use AWS Developer credentials to call this API.

-}
deleteIdentities : DeleteIdentitiesInput -> AWS.Core.Http.Request DeleteIdentitiesResponse
deleteIdentities req =
    let
        jsonBody =
            req |> Codec.encoder deleteIdentitiesInputCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder deleteIdentitiesResponseCodec
    in
    AWS.Core.Http.request "DeleteIdentities" AWS.Core.Http.POST "/" jsonBody decoder


{-| Creates a new identity pool. The identity pool is a store of user identity information that is specific to your AWS account. The limit on identity pools is 60 per account. The keys for
SupportedLoginProviders
are as follows:

Facebook:
graph.facebook.com

Google:
accounts.google.com

Amazon:
www.amazon.com

Twitter:
api.twitter.com

Digits:
www.digits.com

You must use AWS Developer credentials to call this API.

-}
createIdentityPool : CreateIdentityPoolInput -> AWS.Core.Http.Request IdentityPool
createIdentityPool req =
    let
        jsonBody =
            req |> Codec.encoder createIdentityPoolInputCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder identityPoolCodec
    in
    AWS.Core.Http.request "CreateIdentityPool" AWS.Core.Http.POST "/" jsonBody decoder


type Arnstring
    = Arnstring String


{-| Some type - blah blah blah.
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


{-| Some type - blah blah blah.
-}
type alias AccessKeyString =
    String


type AccountId
    = AccountId String


{-| Some type - blah blah blah.
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


{-| Some type - blah blah blah.
-}
type AmbiguousRoleResolutionType
    = AmbiguousRoleResolutionTypeAuthenticatedRole
    | AmbiguousRoleResolutionTypeDeny


{-| Some type - blah blah blah.
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


type ClaimName
    = ClaimName String


{-| Some type - blah blah blah.
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


type ClaimValue
    = ClaimValue String


{-| Some type - blah blah blah.
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


{-| Some type - blah blah blah.
-}
type alias CognitoIdentityProvider =
    { serverSideTokenCheck : Maybe Bool
    , providerName : Maybe CognitoIdentityProviderName
    , clientId : Maybe CognitoIdentityProviderClientId
    }


type CognitoIdentityProviderClientId
    = CognitoIdentityProviderClientId String


{-| Some type - blah blah blah.
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


{-| Some type - blah blah blah.
-}
type alias CognitoIdentityProviderList =
    List CognitoIdentityProvider


type CognitoIdentityProviderName
    = CognitoIdentityProviderName String


{-| Some type - blah blah blah.
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


{-| Some type - blah blah blah.
-}
type alias CognitoIdentityProviderTokenCheck =
    Bool


{-| Some type - blah blah blah.
-}
type alias CreateIdentityPoolInput =
    { supportedLoginProviders : Maybe IdentityProviders
    , samlProviderArns : Maybe SamlproviderList
    , openIdConnectProviderArns : Maybe OidcproviderList
    , identityPoolTags : Maybe IdentityPoolTagsType
    , identityPoolName : IdentityPoolName
    , developerProviderName : Maybe DeveloperProviderName
    , cognitoIdentityProviders : Maybe CognitoIdentityProviderList
    , allowUnauthenticatedIdentities : Bool
    }


{-| Some type - blah blah blah.
-}
type alias Credentials =
    { sessionToken : Maybe String, secretKey : Maybe String, expiration : Maybe DateType, accessKeyId : Maybe String }


{-| Some type - blah blah blah.
-}
type alias DateType =
    String


{-| Some type - blah blah blah.
-}
type alias DeleteIdentitiesInput =
    { identityIdsToDelete : IdentityIdList }


{-| Some type - blah blah blah.
-}
type alias DeleteIdentitiesResponse =
    { unprocessedIdentityIds : Maybe UnprocessedIdentityIdList }


{-| Some type - blah blah blah.
-}
type alias DeleteIdentityPoolInput =
    { identityPoolId : IdentityPoolId }


{-| Some type - blah blah blah.
-}
type alias DescribeIdentityInput =
    { identityId : IdentityId }


{-| Some type - blah blah blah.
-}
type alias DescribeIdentityPoolInput =
    { identityPoolId : IdentityPoolId }


type DeveloperProviderName
    = DeveloperProviderName String


{-| Some type - blah blah blah.
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


type DeveloperUserIdentifier
    = DeveloperUserIdentifier String


{-| Some type - blah blah blah.
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


{-| Some type - blah blah blah.
-}
type alias DeveloperUserIdentifierList =
    List DeveloperUserIdentifier


{-| Some type - blah blah blah.
-}
type ErrorCode
    = ErrorCodeAccessDenied
    | ErrorCodeInternalServerError


{-| Some type - blah blah blah.
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


{-| Some type - blah blah blah.
-}
type alias GetCredentialsForIdentityInput =
    { logins : Maybe LoginsMap, identityId : IdentityId, customRoleArn : Maybe Arnstring }


{-| Some type - blah blah blah.
-}
type alias GetCredentialsForIdentityResponse =
    { identityId : Maybe IdentityId, credentials : Maybe Credentials }


{-| Some type - blah blah blah.
-}
type alias GetIdInput =
    { logins : Maybe LoginsMap, identityPoolId : IdentityPoolId, accountId : Maybe AccountId }


{-| Some type - blah blah blah.
-}
type alias GetIdResponse =
    { identityId : Maybe IdentityId }


{-| Some type - blah blah blah.
-}
type alias GetIdentityPoolRolesInput =
    { identityPoolId : IdentityPoolId }


{-| Some type - blah blah blah.
-}
type alias GetIdentityPoolRolesResponse =
    { roles : Maybe RolesMap, roleMappings : Maybe RoleMappingMap, identityPoolId : Maybe IdentityPoolId }


{-| Some type - blah blah blah.
-}
type alias GetOpenIdTokenForDeveloperIdentityInput =
    { tokenDuration : Maybe Int, logins : LoginsMap, identityPoolId : IdentityPoolId, identityId : Maybe IdentityId }


{-| Some type - blah blah blah.
-}
type alias GetOpenIdTokenForDeveloperIdentityResponse =
    { token : Maybe String, identityId : Maybe IdentityId }


{-| Some type - blah blah blah.
-}
type alias GetOpenIdTokenInput =
    { logins : Maybe LoginsMap, identityId : IdentityId }


{-| Some type - blah blah blah.
-}
type alias GetOpenIdTokenResponse =
    { token : Maybe String, identityId : Maybe IdentityId }


{-| Some type - blah blah blah.
-}
type alias HideDisabled =
    Bool


{-| Some type - blah blah blah.
-}
type alias IdentitiesList =
    List IdentityDescription


{-| Some type - blah blah blah.
-}
type alias IdentityDescription =
    { logins : Maybe LoginsList
    , lastModifiedDate : Maybe DateType
    , identityId : Maybe IdentityId
    , creationDate : Maybe DateType
    }


type IdentityId
    = IdentityId String


{-| Some type - blah blah blah.
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


{-| Some type - blah blah blah.
-}
type alias IdentityIdList =
    List IdentityId


{-| Some type - blah blah blah.
-}
type alias IdentityPool =
    { supportedLoginProviders : Maybe IdentityProviders
    , samlProviderArns : Maybe SamlproviderList
    , openIdConnectProviderArns : Maybe OidcproviderList
    , identityPoolTags : Maybe IdentityPoolTagsType
    , identityPoolName : IdentityPoolName
    , identityPoolId : IdentityPoolId
    , developerProviderName : Maybe DeveloperProviderName
    , cognitoIdentityProviders : Maybe CognitoIdentityProviderList
    , allowUnauthenticatedIdentities : Bool
    }


type IdentityPoolId
    = IdentityPoolId String


{-| Some type - blah blah blah.
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


type IdentityPoolName
    = IdentityPoolName String


{-| Some type - blah blah blah.
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


{-| Some type - blah blah blah.
-}
type alias IdentityPoolShortDescription =
    { identityPoolName : Maybe IdentityPoolName, identityPoolId : Maybe IdentityPoolId }


{-| Some type - blah blah blah.
-}
type alias IdentityPoolTagsListType =
    List TagKeysType


{-| Some type - blah blah blah.
-}
type alias IdentityPoolTagsType =
    Dict.Refined.Dict String TagKeysType TagValueType


{-| Some type - blah blah blah.
-}
type alias IdentityPoolUnauthenticated =
    Bool


{-| Some type - blah blah blah.
-}
type alias IdentityPoolsList =
    List IdentityPoolShortDescription


type IdentityProviderId
    = IdentityProviderId String


{-| Some type - blah blah blah.
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


type IdentityProviderName
    = IdentityProviderName String


{-| Some type - blah blah blah.
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


type IdentityProviderToken
    = IdentityProviderToken String


{-| Some type - blah blah blah.
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


{-| Some type - blah blah blah.
-}
type alias IdentityProviders =
    Dict.Refined.Dict String IdentityProviderName IdentityProviderId


{-| Some type - blah blah blah.
-}
type alias ListIdentitiesInput =
    { nextToken : Maybe PaginationKey
    , maxResults : QueryLimit
    , identityPoolId : IdentityPoolId
    , hideDisabled : Maybe Bool
    }


{-| Some type - blah blah blah.
-}
type alias ListIdentitiesResponse =
    { nextToken : Maybe PaginationKey, identityPoolId : Maybe IdentityPoolId, identities : Maybe IdentitiesList }


{-| Some type - blah blah blah.
-}
type alias ListIdentityPoolsInput =
    { nextToken : Maybe PaginationKey, maxResults : QueryLimit }


{-| Some type - blah blah blah.
-}
type alias ListIdentityPoolsResponse =
    { nextToken : Maybe PaginationKey, identityPools : Maybe IdentityPoolsList }


{-| Some type - blah blah blah.
-}
type alias ListTagsForResourceInput =
    { resourceArn : Arnstring }


{-| Some type - blah blah blah.
-}
type alias ListTagsForResourceResponse =
    { tags : Maybe IdentityPoolTagsType }


{-| Some type - blah blah blah.
-}
type alias LoginsList =
    List IdentityProviderName


{-| Some type - blah blah blah.
-}
type alias LoginsMap =
    Dict.Refined.Dict String IdentityProviderName IdentityProviderToken


{-| Some type - blah blah blah.
-}
type alias LookupDeveloperIdentityInput =
    { nextToken : Maybe PaginationKey
    , maxResults : Maybe QueryLimit
    , identityPoolId : IdentityPoolId
    , identityId : Maybe IdentityId
    , developerUserIdentifier : Maybe DeveloperUserIdentifier
    }


{-| Some type - blah blah blah.
-}
type alias LookupDeveloperIdentityResponse =
    { nextToken : Maybe PaginationKey
    , identityId : Maybe IdentityId
    , developerUserIdentifierList : Maybe DeveloperUserIdentifierList
    }


{-| Some type - blah blah blah.
-}
type alias MappingRule =
    { value : ClaimValue, roleArn : Arnstring, matchType : MappingRuleMatchType, claim : ClaimName }


{-| Some type - blah blah blah.
-}
type MappingRuleMatchType
    = MappingRuleMatchTypeEquals
    | MappingRuleMatchTypeContains
    | MappingRuleMatchTypeStartsWith
    | MappingRuleMatchTypeNotEqual


{-| Some type - blah blah blah.
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


{-| Some type - blah blah blah.
-}
type alias MappingRulesList =
    List MappingRule


{-| Some type - blah blah blah.
-}
type alias MergeDeveloperIdentitiesInput =
    { sourceUserIdentifier : DeveloperUserIdentifier
    , identityPoolId : IdentityPoolId
    , developerProviderName : DeveloperProviderName
    , destinationUserIdentifier : DeveloperUserIdentifier
    }


{-| Some type - blah blah blah.
-}
type alias MergeDeveloperIdentitiesResponse =
    { identityId : Maybe IdentityId }


{-| Some type - blah blah blah.
-}
type alias OidcproviderList =
    List Arnstring


{-| Some type - blah blah blah.
-}
type alias Oidctoken =
    String


type PaginationKey
    = PaginationKey String


{-| Some type - blah blah blah.
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


type QueryLimit
    = QueryLimit Int


{-| Some type - blah blah blah.
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


{-| Some type - blah blah blah.
-}
type alias RoleMapping =
    { type_ : RoleMappingType
    , rulesConfiguration : Maybe RulesConfigurationType
    , ambiguousRoleResolution : Maybe AmbiguousRoleResolutionType
    }


{-| Some type - blah blah blah.
-}
type alias RoleMappingMap =
    Dict.Refined.Dict String IdentityProviderName RoleMapping


{-| Some type - blah blah blah.
-}
type RoleMappingType
    = RoleMappingTypeToken
    | RoleMappingTypeRules


{-| Some type - blah blah blah.
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


type RoleType
    = RoleType String


{-| Some type - blah blah blah.
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


{-| Some type - blah blah blah.
-}
type alias RolesMap =
    Dict.Refined.Dict String RoleType Arnstring


{-| Some type - blah blah blah.
-}
type alias RulesConfigurationType =
    { rules : MappingRulesList }


{-| Some type - blah blah blah.
-}
type alias SamlproviderList =
    List Arnstring


{-| Some type - blah blah blah.
-}
type alias SecretKeyString =
    String


{-| Some type - blah blah blah.
-}
type alias SessionTokenString =
    String


{-| Some type - blah blah blah.
-}
type alias SetIdentityPoolRolesInput =
    { roles : RolesMap, roleMappings : Maybe RoleMappingMap, identityPoolId : IdentityPoolId }


type TagKeysType
    = TagKeysType String


{-| Some type - blah blah blah.
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


{-| Some type - blah blah blah.
-}
type alias TagResourceInput =
    { tags : Maybe IdentityPoolTagsType, resourceArn : Arnstring }


{-| Some type - blah blah blah.
-}
type alias TagResourceResponse =
    {}


type TagValueType
    = TagValueType String


{-| Some type - blah blah blah.
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


{-| Some type - blah blah blah.
-}
type alias TokenDuration =
    Int


{-| Some type - blah blah blah.
-}
type alias UnlinkDeveloperIdentityInput =
    { identityPoolId : IdentityPoolId
    , identityId : IdentityId
    , developerUserIdentifier : DeveloperUserIdentifier
    , developerProviderName : DeveloperProviderName
    }


{-| Some type - blah blah blah.
-}
type alias UnlinkIdentityInput =
    { loginsToRemove : LoginsList, logins : LoginsMap, identityId : IdentityId }


{-| Some type - blah blah blah.
-}
type alias UnprocessedIdentityId =
    { identityId : Maybe IdentityId, errorCode : Maybe ErrorCode }


{-| Some type - blah blah blah.
-}
type alias UnprocessedIdentityIdList =
    List UnprocessedIdentityId


{-| Some type - blah blah blah.
-}
type alias UntagResourceInput =
    { tagKeys : Maybe IdentityPoolTagsListType, resourceArn : Arnstring }


{-| Some type - blah blah blah.
-}
type alias UntagResourceResponse =
    {}


{-| Codec for UntagResourceResponse.
-}
untagResourceResponseCodec : Codec UntagResourceResponse
untagResourceResponseCodec =
    Codec.object UntagResourceResponse |> Codec.buildObject


{-| Codec for UntagResourceInput.
-}
untagResourceInputCodec : Codec UntagResourceInput
untagResourceInputCodec =
    Codec.object UntagResourceInput
        |> Codec.optionalField "TagKeys" .tagKeys identityPoolTagsListTypeCodec
        |> Codec.field "ResourceArn" .resourceArn arnstringCodec
        |> Codec.buildObject


{-| Codec for UnprocessedIdentityIdList.
-}
unprocessedIdentityIdListCodec : Codec UnprocessedIdentityIdList
unprocessedIdentityIdListCodec =
    Codec.list unprocessedIdentityIdCodec


{-| Codec for UnprocessedIdentityId.
-}
unprocessedIdentityIdCodec : Codec UnprocessedIdentityId
unprocessedIdentityIdCodec =
    Codec.object UnprocessedIdentityId
        |> Codec.optionalField "IdentityId" .identityId identityIdCodec
        |> Codec.optionalField "ErrorCode" .errorCode errorCodeCodec
        |> Codec.buildObject


{-| Codec for UnlinkIdentityInput.
-}
unlinkIdentityInputCodec : Codec UnlinkIdentityInput
unlinkIdentityInputCodec =
    Codec.object UnlinkIdentityInput
        |> Codec.field "LoginsToRemove" .loginsToRemove loginsListCodec
        |> Codec.field "Logins" .logins loginsMapCodec
        |> Codec.field "IdentityId" .identityId identityIdCodec
        |> Codec.buildObject


{-| Codec for UnlinkDeveloperIdentityInput.
-}
unlinkDeveloperIdentityInputCodec : Codec UnlinkDeveloperIdentityInput
unlinkDeveloperIdentityInputCodec =
    Codec.object UnlinkDeveloperIdentityInput
        |> Codec.field "IdentityPoolId" .identityPoolId identityPoolIdCodec
        |> Codec.field "IdentityId" .identityId identityIdCodec
        |> Codec.field "DeveloperUserIdentifier" .developerUserIdentifier developerUserIdentifierCodec
        |> Codec.field "DeveloperProviderName" .developerProviderName developerProviderNameCodec
        |> Codec.buildObject


{-| Codec for TokenDuration.
-}
tokenDurationCodec : Codec TokenDuration
tokenDurationCodec =
    Codec.int


{-| Codec for TagValueType.
-}
tagValueTypeCodec : Codec TagValueType
tagValueTypeCodec =
    Codec.build (Refined.encoder tagValueType) (Refined.decoder tagValueType)


{-| Codec for TagResourceResponse.
-}
tagResourceResponseCodec : Codec TagResourceResponse
tagResourceResponseCodec =
    Codec.object TagResourceResponse |> Codec.buildObject


{-| Codec for TagResourceInput.
-}
tagResourceInputCodec : Codec TagResourceInput
tagResourceInputCodec =
    Codec.object TagResourceInput
        |> Codec.optionalField "Tags" .tags identityPoolTagsTypeCodec
        |> Codec.field "ResourceArn" .resourceArn arnstringCodec
        |> Codec.buildObject


{-| Codec for TagKeysType.
-}
tagKeysTypeCodec : Codec TagKeysType
tagKeysTypeCodec =
    Codec.build (Refined.encoder tagKeysType) (Refined.decoder tagKeysType)


{-| Codec for SetIdentityPoolRolesInput.
-}
setIdentityPoolRolesInputCodec : Codec SetIdentityPoolRolesInput
setIdentityPoolRolesInputCodec =
    Codec.object SetIdentityPoolRolesInput
        |> Codec.field "Roles" .roles rolesMapCodec
        |> Codec.optionalField "RoleMappings" .roleMappings roleMappingMapCodec
        |> Codec.field "IdentityPoolId" .identityPoolId identityPoolIdCodec
        |> Codec.buildObject


{-| Codec for SessionTokenString.
-}
sessionTokenStringCodec : Codec SessionTokenString
sessionTokenStringCodec =
    Codec.string


{-| Codec for SecretKeyString.
-}
secretKeyStringCodec : Codec SecretKeyString
secretKeyStringCodec =
    Codec.string


{-| Codec for SamlproviderList.
-}
samlproviderListCodec : Codec SamlproviderList
samlproviderListCodec =
    Codec.list arnstringCodec


{-| Codec for RulesConfigurationType.
-}
rulesConfigurationTypeCodec : Codec RulesConfigurationType
rulesConfigurationTypeCodec =
    Codec.object RulesConfigurationType |> Codec.field "Rules" .rules mappingRulesListCodec |> Codec.buildObject


{-| Codec for RolesMap.
-}
rolesMapCodec : Codec RolesMap
rolesMapCodec =
    Codec.build
        (Refined.dictEncoder roleType (Codec.encoder arnstringCodec))
        (Refined.dictDecoder roleType (Codec.decoder arnstringCodec))


{-| Codec for RoleType.
-}
roleTypeCodec : Codec RoleType
roleTypeCodec =
    Codec.build (Refined.encoder roleType) (Refined.decoder roleType)


{-| Codec for RoleMappingType.
-}
roleMappingTypeCodec : Codec RoleMappingType
roleMappingTypeCodec =
    Codec.build (Enum.encoder roleMappingType) (Enum.decoder roleMappingType)


{-| Codec for RoleMappingMap.
-}
roleMappingMapCodec : Codec RoleMappingMap
roleMappingMapCodec =
    Codec.build
        (Refined.dictEncoder identityProviderName (Codec.encoder roleMappingCodec))
        (Refined.dictDecoder identityProviderName (Codec.decoder roleMappingCodec))


{-| Codec for RoleMapping.
-}
roleMappingCodec : Codec RoleMapping
roleMappingCodec =
    Codec.object RoleMapping
        |> Codec.field "Type" .type_ roleMappingTypeCodec
        |> Codec.optionalField "RulesConfiguration" .rulesConfiguration rulesConfigurationTypeCodec
        |> Codec.optionalField "AmbiguousRoleResolution" .ambiguousRoleResolution ambiguousRoleResolutionTypeCodec
        |> Codec.buildObject


{-| Codec for QueryLimit.
-}
queryLimitCodec : Codec QueryLimit
queryLimitCodec =
    Codec.build (Refined.encoder queryLimit) (Refined.decoder queryLimit)


{-| Codec for PaginationKey.
-}
paginationKeyCodec : Codec PaginationKey
paginationKeyCodec =
    Codec.build (Refined.encoder paginationKey) (Refined.decoder paginationKey)


{-| Codec for Oidctoken.
-}
oidctokenCodec : Codec Oidctoken
oidctokenCodec =
    Codec.string


{-| Codec for OidcproviderList.
-}
oidcproviderListCodec : Codec OidcproviderList
oidcproviderListCodec =
    Codec.list arnstringCodec


{-| Codec for MergeDeveloperIdentitiesResponse.
-}
mergeDeveloperIdentitiesResponseCodec : Codec MergeDeveloperIdentitiesResponse
mergeDeveloperIdentitiesResponseCodec =
    Codec.object MergeDeveloperIdentitiesResponse
        |> Codec.optionalField "IdentityId" .identityId identityIdCodec
        |> Codec.buildObject


{-| Codec for MergeDeveloperIdentitiesInput.
-}
mergeDeveloperIdentitiesInputCodec : Codec MergeDeveloperIdentitiesInput
mergeDeveloperIdentitiesInputCodec =
    Codec.object MergeDeveloperIdentitiesInput
        |> Codec.field "SourceUserIdentifier" .sourceUserIdentifier developerUserIdentifierCodec
        |> Codec.field "IdentityPoolId" .identityPoolId identityPoolIdCodec
        |> Codec.field "DeveloperProviderName" .developerProviderName developerProviderNameCodec
        |> Codec.field "DestinationUserIdentifier" .destinationUserIdentifier developerUserIdentifierCodec
        |> Codec.buildObject


{-| Codec for MappingRulesList.
-}
mappingRulesListCodec : Codec MappingRulesList
mappingRulesListCodec =
    Codec.list mappingRuleCodec


{-| Codec for MappingRuleMatchType.
-}
mappingRuleMatchTypeCodec : Codec MappingRuleMatchType
mappingRuleMatchTypeCodec =
    Codec.build (Enum.encoder mappingRuleMatchType) (Enum.decoder mappingRuleMatchType)


{-| Codec for MappingRule.
-}
mappingRuleCodec : Codec MappingRule
mappingRuleCodec =
    Codec.object MappingRule
        |> Codec.field "Value" .value claimValueCodec
        |> Codec.field "RoleARN" .roleArn arnstringCodec
        |> Codec.field "MatchType" .matchType mappingRuleMatchTypeCodec
        |> Codec.field "Claim" .claim claimNameCodec
        |> Codec.buildObject


{-| Codec for LookupDeveloperIdentityResponse.
-}
lookupDeveloperIdentityResponseCodec : Codec LookupDeveloperIdentityResponse
lookupDeveloperIdentityResponseCodec =
    Codec.object LookupDeveloperIdentityResponse
        |> Codec.optionalField "NextToken" .nextToken paginationKeyCodec
        |> Codec.optionalField "IdentityId" .identityId identityIdCodec
        |> Codec.optionalField
            "DeveloperUserIdentifierList"
            .developerUserIdentifierList
            developerUserIdentifierListCodec
        |> Codec.buildObject


{-| Codec for LookupDeveloperIdentityInput.
-}
lookupDeveloperIdentityInputCodec : Codec LookupDeveloperIdentityInput
lookupDeveloperIdentityInputCodec =
    Codec.object LookupDeveloperIdentityInput
        |> Codec.optionalField "NextToken" .nextToken paginationKeyCodec
        |> Codec.optionalField "MaxResults" .maxResults queryLimitCodec
        |> Codec.field "IdentityPoolId" .identityPoolId identityPoolIdCodec
        |> Codec.optionalField "IdentityId" .identityId identityIdCodec
        |> Codec.optionalField "DeveloperUserIdentifier" .developerUserIdentifier developerUserIdentifierCodec
        |> Codec.buildObject


{-| Codec for LoginsMap.
-}
loginsMapCodec : Codec LoginsMap
loginsMapCodec =
    Codec.build
        (Refined.dictEncoder identityProviderName (Codec.encoder identityProviderTokenCodec))
        (Refined.dictDecoder identityProviderName (Codec.decoder identityProviderTokenCodec))


{-| Codec for LoginsList.
-}
loginsListCodec : Codec LoginsList
loginsListCodec =
    Codec.list identityProviderNameCodec


{-| Codec for ListTagsForResourceResponse.
-}
listTagsForResourceResponseCodec : Codec ListTagsForResourceResponse
listTagsForResourceResponseCodec =
    Codec.object ListTagsForResourceResponse
        |> Codec.optionalField "Tags" .tags identityPoolTagsTypeCodec
        |> Codec.buildObject


{-| Codec for ListTagsForResourceInput.
-}
listTagsForResourceInputCodec : Codec ListTagsForResourceInput
listTagsForResourceInputCodec =
    Codec.object ListTagsForResourceInput |> Codec.field "ResourceArn" .resourceArn arnstringCodec |> Codec.buildObject


{-| Codec for ListIdentityPoolsResponse.
-}
listIdentityPoolsResponseCodec : Codec ListIdentityPoolsResponse
listIdentityPoolsResponseCodec =
    Codec.object ListIdentityPoolsResponse
        |> Codec.optionalField "NextToken" .nextToken paginationKeyCodec
        |> Codec.optionalField "IdentityPools" .identityPools identityPoolsListCodec
        |> Codec.buildObject


{-| Codec for ListIdentityPoolsInput.
-}
listIdentityPoolsInputCodec : Codec ListIdentityPoolsInput
listIdentityPoolsInputCodec =
    Codec.object ListIdentityPoolsInput
        |> Codec.optionalField "NextToken" .nextToken paginationKeyCodec
        |> Codec.field "MaxResults" .maxResults queryLimitCodec
        |> Codec.buildObject


{-| Codec for ListIdentitiesResponse.
-}
listIdentitiesResponseCodec : Codec ListIdentitiesResponse
listIdentitiesResponseCodec =
    Codec.object ListIdentitiesResponse
        |> Codec.optionalField "NextToken" .nextToken paginationKeyCodec
        |> Codec.optionalField "IdentityPoolId" .identityPoolId identityPoolIdCodec
        |> Codec.optionalField "Identities" .identities identitiesListCodec
        |> Codec.buildObject


{-| Codec for ListIdentitiesInput.
-}
listIdentitiesInputCodec : Codec ListIdentitiesInput
listIdentitiesInputCodec =
    Codec.object ListIdentitiesInput
        |> Codec.optionalField "NextToken" .nextToken paginationKeyCodec
        |> Codec.field "MaxResults" .maxResults queryLimitCodec
        |> Codec.field "IdentityPoolId" .identityPoolId identityPoolIdCodec
        |> Codec.optionalField "HideDisabled" .hideDisabled Codec.bool
        |> Codec.buildObject


{-| Codec for IdentityProviders.
-}
identityProvidersCodec : Codec IdentityProviders
identityProvidersCodec =
    Codec.build
        (Refined.dictEncoder identityProviderName (Codec.encoder identityProviderIdCodec))
        (Refined.dictDecoder identityProviderName (Codec.decoder identityProviderIdCodec))


{-| Codec for IdentityProviderToken.
-}
identityProviderTokenCodec : Codec IdentityProviderToken
identityProviderTokenCodec =
    Codec.build (Refined.encoder identityProviderToken) (Refined.decoder identityProviderToken)


{-| Codec for IdentityProviderName.
-}
identityProviderNameCodec : Codec IdentityProviderName
identityProviderNameCodec =
    Codec.build (Refined.encoder identityProviderName) (Refined.decoder identityProviderName)


{-| Codec for IdentityProviderId.
-}
identityProviderIdCodec : Codec IdentityProviderId
identityProviderIdCodec =
    Codec.build (Refined.encoder identityProviderId) (Refined.decoder identityProviderId)


{-| Codec for IdentityPoolsList.
-}
identityPoolsListCodec : Codec IdentityPoolsList
identityPoolsListCodec =
    Codec.list identityPoolShortDescriptionCodec


{-| Codec for IdentityPoolUnauthenticated.
-}
identityPoolUnauthenticatedCodec : Codec IdentityPoolUnauthenticated
identityPoolUnauthenticatedCodec =
    Codec.bool


{-| Codec for IdentityPoolTagsType.
-}
identityPoolTagsTypeCodec : Codec IdentityPoolTagsType
identityPoolTagsTypeCodec =
    Codec.build
        (Refined.dictEncoder tagKeysType (Codec.encoder tagValueTypeCodec))
        (Refined.dictDecoder tagKeysType (Codec.decoder tagValueTypeCodec))


{-| Codec for IdentityPoolTagsListType.
-}
identityPoolTagsListTypeCodec : Codec IdentityPoolTagsListType
identityPoolTagsListTypeCodec =
    Codec.list tagKeysTypeCodec


{-| Codec for IdentityPoolShortDescription.
-}
identityPoolShortDescriptionCodec : Codec IdentityPoolShortDescription
identityPoolShortDescriptionCodec =
    Codec.object IdentityPoolShortDescription
        |> Codec.optionalField "IdentityPoolName" .identityPoolName identityPoolNameCodec
        |> Codec.optionalField "IdentityPoolId" .identityPoolId identityPoolIdCodec
        |> Codec.buildObject


{-| Codec for IdentityPoolName.
-}
identityPoolNameCodec : Codec IdentityPoolName
identityPoolNameCodec =
    Codec.build (Refined.encoder identityPoolName) (Refined.decoder identityPoolName)


{-| Codec for IdentityPoolId.
-}
identityPoolIdCodec : Codec IdentityPoolId
identityPoolIdCodec =
    Codec.build (Refined.encoder identityPoolId) (Refined.decoder identityPoolId)


{-| Codec for IdentityPool.
-}
identityPoolCodec : Codec IdentityPool
identityPoolCodec =
    Codec.object IdentityPool
        |> Codec.optionalField "SupportedLoginProviders" .supportedLoginProviders identityProvidersCodec
        |> Codec.optionalField "SamlProviderARNs" .samlProviderArns samlproviderListCodec
        |> Codec.optionalField "OpenIdConnectProviderARNs" .openIdConnectProviderArns oidcproviderListCodec
        |> Codec.optionalField "IdentityPoolTags" .identityPoolTags identityPoolTagsTypeCodec
        |> Codec.field "IdentityPoolName" .identityPoolName identityPoolNameCodec
        |> Codec.field "IdentityPoolId" .identityPoolId identityPoolIdCodec
        |> Codec.optionalField "DeveloperProviderName" .developerProviderName developerProviderNameCodec
        |> Codec.optionalField "CognitoIdentityProviders" .cognitoIdentityProviders cognitoIdentityProviderListCodec
        |> Codec.field "AllowUnauthenticatedIdentities" .allowUnauthenticatedIdentities Codec.bool
        |> Codec.buildObject


{-| Codec for IdentityIdList.
-}
identityIdListCodec : Codec IdentityIdList
identityIdListCodec =
    Codec.list identityIdCodec


{-| Codec for IdentityId.
-}
identityIdCodec : Codec IdentityId
identityIdCodec =
    Codec.build (Refined.encoder identityId) (Refined.decoder identityId)


{-| Codec for IdentityDescription.
-}
identityDescriptionCodec : Codec IdentityDescription
identityDescriptionCodec =
    Codec.object IdentityDescription
        |> Codec.optionalField "Logins" .logins loginsListCodec
        |> Codec.optionalField "LastModifiedDate" .lastModifiedDate dateTypeCodec
        |> Codec.optionalField "IdentityId" .identityId identityIdCodec
        |> Codec.optionalField "CreationDate" .creationDate dateTypeCodec
        |> Codec.buildObject


{-| Codec for IdentitiesList.
-}
identitiesListCodec : Codec IdentitiesList
identitiesListCodec =
    Codec.list identityDescriptionCodec


{-| Codec for HideDisabled.
-}
hideDisabledCodec : Codec HideDisabled
hideDisabledCodec =
    Codec.bool


{-| Codec for GetOpenIdTokenResponse.
-}
getOpenIdTokenResponseCodec : Codec GetOpenIdTokenResponse
getOpenIdTokenResponseCodec =
    Codec.object GetOpenIdTokenResponse
        |> Codec.optionalField "Token" .token Codec.string
        |> Codec.optionalField "IdentityId" .identityId identityIdCodec
        |> Codec.buildObject


{-| Codec for GetOpenIdTokenInput.
-}
getOpenIdTokenInputCodec : Codec GetOpenIdTokenInput
getOpenIdTokenInputCodec =
    Codec.object GetOpenIdTokenInput
        |> Codec.optionalField "Logins" .logins loginsMapCodec
        |> Codec.field "IdentityId" .identityId identityIdCodec
        |> Codec.buildObject


{-| Codec for GetOpenIdTokenForDeveloperIdentityResponse.
-}
getOpenIdTokenForDeveloperIdentityResponseCodec : Codec GetOpenIdTokenForDeveloperIdentityResponse
getOpenIdTokenForDeveloperIdentityResponseCodec =
    Codec.object GetOpenIdTokenForDeveloperIdentityResponse
        |> Codec.optionalField "Token" .token Codec.string
        |> Codec.optionalField "IdentityId" .identityId identityIdCodec
        |> Codec.buildObject


{-| Codec for GetOpenIdTokenForDeveloperIdentityInput.
-}
getOpenIdTokenForDeveloperIdentityInputCodec : Codec GetOpenIdTokenForDeveloperIdentityInput
getOpenIdTokenForDeveloperIdentityInputCodec =
    Codec.object GetOpenIdTokenForDeveloperIdentityInput
        |> Codec.optionalField "TokenDuration" .tokenDuration Codec.int
        |> Codec.field "Logins" .logins loginsMapCodec
        |> Codec.field "IdentityPoolId" .identityPoolId identityPoolIdCodec
        |> Codec.optionalField "IdentityId" .identityId identityIdCodec
        |> Codec.buildObject


{-| Codec for GetIdentityPoolRolesResponse.
-}
getIdentityPoolRolesResponseCodec : Codec GetIdentityPoolRolesResponse
getIdentityPoolRolesResponseCodec =
    Codec.object GetIdentityPoolRolesResponse
        |> Codec.optionalField "Roles" .roles rolesMapCodec
        |> Codec.optionalField "RoleMappings" .roleMappings roleMappingMapCodec
        |> Codec.optionalField "IdentityPoolId" .identityPoolId identityPoolIdCodec
        |> Codec.buildObject


{-| Codec for GetIdentityPoolRolesInput.
-}
getIdentityPoolRolesInputCodec : Codec GetIdentityPoolRolesInput
getIdentityPoolRolesInputCodec =
    Codec.object GetIdentityPoolRolesInput
        |> Codec.field "IdentityPoolId" .identityPoolId identityPoolIdCodec
        |> Codec.buildObject


{-| Codec for GetIdResponse.
-}
getIdResponseCodec : Codec GetIdResponse
getIdResponseCodec =
    Codec.object GetIdResponse |> Codec.optionalField "IdentityId" .identityId identityIdCodec |> Codec.buildObject


{-| Codec for GetIdInput.
-}
getIdInputCodec : Codec GetIdInput
getIdInputCodec =
    Codec.object GetIdInput
        |> Codec.optionalField "Logins" .logins loginsMapCodec
        |> Codec.field "IdentityPoolId" .identityPoolId identityPoolIdCodec
        |> Codec.optionalField "AccountId" .accountId accountIdCodec
        |> Codec.buildObject


{-| Codec for GetCredentialsForIdentityResponse.
-}
getCredentialsForIdentityResponseCodec : Codec GetCredentialsForIdentityResponse
getCredentialsForIdentityResponseCodec =
    Codec.object GetCredentialsForIdentityResponse
        |> Codec.optionalField "IdentityId" .identityId identityIdCodec
        |> Codec.optionalField "Credentials" .credentials credentialsCodec
        |> Codec.buildObject


{-| Codec for GetCredentialsForIdentityInput.
-}
getCredentialsForIdentityInputCodec : Codec GetCredentialsForIdentityInput
getCredentialsForIdentityInputCodec =
    Codec.object GetCredentialsForIdentityInput
        |> Codec.optionalField "Logins" .logins loginsMapCodec
        |> Codec.field "IdentityId" .identityId identityIdCodec
        |> Codec.optionalField "CustomRoleArn" .customRoleArn arnstringCodec
        |> Codec.buildObject


{-| Codec for ErrorCode.
-}
errorCodeCodec : Codec ErrorCode
errorCodeCodec =
    Codec.build (Enum.encoder errorCode) (Enum.decoder errorCode)


{-| Codec for DeveloperUserIdentifierList.
-}
developerUserIdentifierListCodec : Codec DeveloperUserIdentifierList
developerUserIdentifierListCodec =
    Codec.list developerUserIdentifierCodec


{-| Codec for DeveloperUserIdentifier.
-}
developerUserIdentifierCodec : Codec DeveloperUserIdentifier
developerUserIdentifierCodec =
    Codec.build (Refined.encoder developerUserIdentifier) (Refined.decoder developerUserIdentifier)


{-| Codec for DeveloperProviderName.
-}
developerProviderNameCodec : Codec DeveloperProviderName
developerProviderNameCodec =
    Codec.build (Refined.encoder developerProviderName) (Refined.decoder developerProviderName)


{-| Codec for DescribeIdentityPoolInput.
-}
describeIdentityPoolInputCodec : Codec DescribeIdentityPoolInput
describeIdentityPoolInputCodec =
    Codec.object DescribeIdentityPoolInput
        |> Codec.field "IdentityPoolId" .identityPoolId identityPoolIdCodec
        |> Codec.buildObject


{-| Codec for DescribeIdentityInput.
-}
describeIdentityInputCodec : Codec DescribeIdentityInput
describeIdentityInputCodec =
    Codec.object DescribeIdentityInput |> Codec.field "IdentityId" .identityId identityIdCodec |> Codec.buildObject


{-| Codec for DeleteIdentityPoolInput.
-}
deleteIdentityPoolInputCodec : Codec DeleteIdentityPoolInput
deleteIdentityPoolInputCodec =
    Codec.object DeleteIdentityPoolInput
        |> Codec.field "IdentityPoolId" .identityPoolId identityPoolIdCodec
        |> Codec.buildObject


{-| Codec for DeleteIdentitiesResponse.
-}
deleteIdentitiesResponseCodec : Codec DeleteIdentitiesResponse
deleteIdentitiesResponseCodec =
    Codec.object DeleteIdentitiesResponse
        |> Codec.optionalField "UnprocessedIdentityIds" .unprocessedIdentityIds unprocessedIdentityIdListCodec
        |> Codec.buildObject


{-| Codec for DeleteIdentitiesInput.
-}
deleteIdentitiesInputCodec : Codec DeleteIdentitiesInput
deleteIdentitiesInputCodec =
    Codec.object DeleteIdentitiesInput
        |> Codec.field "IdentityIdsToDelete" .identityIdsToDelete identityIdListCodec
        |> Codec.buildObject


{-| Codec for DateType.
-}
dateTypeCodec : Codec DateType
dateTypeCodec =
    Codec.string


{-| Codec for Credentials.
-}
credentialsCodec : Codec Credentials
credentialsCodec =
    Codec.object Credentials
        |> Codec.optionalField "SessionToken" .sessionToken Codec.string
        |> Codec.optionalField "SecretKey" .secretKey Codec.string
        |> Codec.optionalField "Expiration" .expiration dateTypeCodec
        |> Codec.optionalField "AccessKeyId" .accessKeyId Codec.string
        |> Codec.buildObject


{-| Codec for CreateIdentityPoolInput.
-}
createIdentityPoolInputCodec : Codec CreateIdentityPoolInput
createIdentityPoolInputCodec =
    Codec.object CreateIdentityPoolInput
        |> Codec.optionalField "SupportedLoginProviders" .supportedLoginProviders identityProvidersCodec
        |> Codec.optionalField "SamlProviderARNs" .samlProviderArns samlproviderListCodec
        |> Codec.optionalField "OpenIdConnectProviderARNs" .openIdConnectProviderArns oidcproviderListCodec
        |> Codec.optionalField "IdentityPoolTags" .identityPoolTags identityPoolTagsTypeCodec
        |> Codec.field "IdentityPoolName" .identityPoolName identityPoolNameCodec
        |> Codec.optionalField "DeveloperProviderName" .developerProviderName developerProviderNameCodec
        |> Codec.optionalField "CognitoIdentityProviders" .cognitoIdentityProviders cognitoIdentityProviderListCodec
        |> Codec.field "AllowUnauthenticatedIdentities" .allowUnauthenticatedIdentities Codec.bool
        |> Codec.buildObject


{-| Codec for CognitoIdentityProviderTokenCheck.
-}
cognitoIdentityProviderTokenCheckCodec : Codec CognitoIdentityProviderTokenCheck
cognitoIdentityProviderTokenCheckCodec =
    Codec.bool


{-| Codec for CognitoIdentityProviderName.
-}
cognitoIdentityProviderNameCodec : Codec CognitoIdentityProviderName
cognitoIdentityProviderNameCodec =
    Codec.build (Refined.encoder cognitoIdentityProviderName) (Refined.decoder cognitoIdentityProviderName)


{-| Codec for CognitoIdentityProviderList.
-}
cognitoIdentityProviderListCodec : Codec CognitoIdentityProviderList
cognitoIdentityProviderListCodec =
    Codec.list cognitoIdentityProviderCodec


{-| Codec for CognitoIdentityProviderClientId.
-}
cognitoIdentityProviderClientIdCodec : Codec CognitoIdentityProviderClientId
cognitoIdentityProviderClientIdCodec =
    Codec.build (Refined.encoder cognitoIdentityProviderClientId) (Refined.decoder cognitoIdentityProviderClientId)


{-| Codec for CognitoIdentityProvider.
-}
cognitoIdentityProviderCodec : Codec CognitoIdentityProvider
cognitoIdentityProviderCodec =
    Codec.object CognitoIdentityProvider
        |> Codec.optionalField "ServerSideTokenCheck" .serverSideTokenCheck Codec.bool
        |> Codec.optionalField "ProviderName" .providerName cognitoIdentityProviderNameCodec
        |> Codec.optionalField "ClientId" .clientId cognitoIdentityProviderClientIdCodec
        |> Codec.buildObject


{-| Codec for ClaimValue.
-}
claimValueCodec : Codec ClaimValue
claimValueCodec =
    Codec.build (Refined.encoder claimValue) (Refined.decoder claimValue)


{-| Codec for ClaimName.
-}
claimNameCodec : Codec ClaimName
claimNameCodec =
    Codec.build (Refined.encoder claimName) (Refined.decoder claimName)


{-| Codec for AmbiguousRoleResolutionType.
-}
ambiguousRoleResolutionTypeCodec : Codec AmbiguousRoleResolutionType
ambiguousRoleResolutionTypeCodec =
    Codec.build (Enum.encoder ambiguousRoleResolutionType) (Enum.decoder ambiguousRoleResolutionType)


{-| Codec for AccountId.
-}
accountIdCodec : Codec AccountId
accountIdCodec =
    Codec.build (Refined.encoder accountId) (Refined.decoder accountId)


{-| Codec for AccessKeyString.
-}
accessKeyStringCodec : Codec AccessKeyString
accessKeyStringCodec =
    Codec.string


{-| Codec for Arnstring.
-}
arnstringCodec : Codec Arnstring
arnstringCodec =
    Codec.build (Refined.encoder arnstring) (Refined.decoder arnstring)
