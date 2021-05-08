module AWS.CognitoIdentityProvider exposing
    ( service
    , addCustomAttributes, adminAddUserToGroup, adminConfirmSignUp, adminCreateUser, adminDeleteUser, adminDeleteUserAttributes
    , adminDisableProviderForUser, adminDisableUser, adminEnableUser, adminForgetDevice, adminGetDevice, adminGetUser, adminInitiateAuth
    , adminLinkProviderForUser, adminListDevices, adminListGroupsForUser, adminListUserAuthEvents, adminRemoveUserFromGroup
    , adminResetUserPassword, adminRespondToAuthChallenge, adminSetUserMfapreference, adminSetUserPassword, adminSetUserSettings
    , adminUpdateAuthEventFeedback, adminUpdateDeviceStatus, adminUpdateUserAttributes, adminUserGlobalSignOut, associateSoftwareToken
    , changePassword, confirmDevice, confirmForgotPassword, confirmSignUp, createGroup, createIdentityProvider, createResourceServer
    , createUserImportJob, createUserPool, createUserPoolClient, createUserPoolDomain, deleteGroup, deleteIdentityProvider
    , deleteResourceServer, deleteUser, deleteUserAttributes, deleteUserPool, deleteUserPoolClient, deleteUserPoolDomain
    , describeIdentityProvider, describeResourceServer, describeRiskConfiguration, describeUserImportJob, describeUserPool
    , describeUserPoolClient, describeUserPoolDomain, forgetDevice, forgotPassword, getCsvheader, getDevice, getGroup
    , getIdentityProviderByIdentifier, getSigningCertificate, getUicustomization, getUser, getUserAttributeVerificationCode
    , getUserPoolMfaConfig, globalSignOut, initiateAuth, listDevices, listGroups, listIdentityProviders, listResourceServers
    , listTagsForResource, listUserImportJobs, listUserPoolClients, listUserPools, listUsers, listUsersInGroup, resendConfirmationCode
    , respondToAuthChallenge, setRiskConfiguration, setUicustomization, setUserMfapreference, setUserPoolMfaConfig, setUserSettings
    , signUp, startUserImportJob, stopUserImportJob, tagResource, untagResource, updateAuthEventFeedback, updateDeviceStatus, updateGroup
    , updateIdentityProvider, updateResourceServer, updateUserAttributes, updateUserPool, updateUserPoolClient, updateUserPoolDomain
    , verifySoftwareToken, verifyUserAttribute
    , AccountTakeoverActionType, AccountTakeoverActionsType, AccountTakeoverEventActionType(..), AccountTakeoverRiskConfigurationType
    , AddCustomAttributesRequest, AddCustomAttributesResponse, AdminAddUserToGroupRequest, AdminConfirmSignUpRequest
    , AdminConfirmSignUpResponse, AdminCreateUserConfigType, AdminCreateUserRequest, AdminCreateUserResponse
    , AdminDeleteUserAttributesRequest, AdminDeleteUserAttributesResponse, AdminDeleteUserRequest
    , AdminDisableProviderForUserRequest, AdminDisableProviderForUserResponse, AdminDisableUserRequest, AdminDisableUserResponse
    , AdminEnableUserRequest, AdminEnableUserResponse, AdminForgetDeviceRequest, AdminGetDeviceRequest, AdminGetDeviceResponse
    , AdminGetUserRequest, AdminGetUserResponse, AdminInitiateAuthRequest, AdminInitiateAuthResponse, AdminLinkProviderForUserRequest
    , AdminLinkProviderForUserResponse, AdminListDevicesRequest, AdminListDevicesResponse, AdminListGroupsForUserRequest
    , AdminListGroupsForUserResponse, AdminListUserAuthEventsRequest, AdminListUserAuthEventsResponse
    , AdminRemoveUserFromGroupRequest, AdminResetUserPasswordRequest, AdminResetUserPasswordResponse
    , AdminRespondToAuthChallengeRequest, AdminRespondToAuthChallengeResponse, AdminSetUserMfapreferenceRequest
    , AdminSetUserMfapreferenceResponse, AdminSetUserPasswordRequest, AdminSetUserPasswordResponse, AdminSetUserSettingsRequest
    , AdminSetUserSettingsResponse, AdminUpdateAuthEventFeedbackRequest, AdminUpdateAuthEventFeedbackResponse
    , AdminUpdateDeviceStatusRequest, AdminUpdateDeviceStatusResponse, AdminUpdateUserAttributesRequest
    , AdminUpdateUserAttributesResponse, AdminUserGlobalSignOutRequest, AdminUserGlobalSignOutResponse, AdvancedSecurityModeType(..)
    , AliasAttributeType(..), AliasAttributesListType, AnalyticsConfigurationType, AnalyticsMetadataType, AssociateSoftwareTokenRequest
    , AssociateSoftwareTokenResponse, AttributeDataType(..), AttributeListType, AttributeMappingType, AttributeNameListType, AttributeType
    , AuthEventType, AuthEventsType, AuthFlowType(..), AuthParametersType, AuthenticationResultType, BlockedIprangeListType
    , CallbackUrlsListType, ChallengeName(..), ChallengeNameType(..), ChallengeParametersType, ChallengeResponse(..), ChallengeResponseListType
    , ChallengeResponseType, ChallengeResponsesType, ChangePasswordRequest, ChangePasswordResponse, ClientMetadataType
    , ClientPermissionListType, CodeDeliveryDetailsListType, CodeDeliveryDetailsType, CompromisedCredentialsActionsType
    , CompromisedCredentialsEventActionType(..), CompromisedCredentialsRiskConfigurationType, ConfirmDeviceRequest
    , ConfirmDeviceResponse, ConfirmForgotPasswordRequest, ConfirmForgotPasswordResponse, ConfirmSignUpRequest, ConfirmSignUpResponse
    , ContextDataType, CreateGroupRequest, CreateGroupResponse, CreateIdentityProviderRequest, CreateIdentityProviderResponse
    , CreateResourceServerRequest, CreateResourceServerResponse, CreateUserImportJobRequest, CreateUserImportJobResponse
    , CreateUserPoolClientRequest, CreateUserPoolClientResponse, CreateUserPoolDomainRequest, CreateUserPoolDomainResponse
    , CreateUserPoolRequest, CreateUserPoolResponse, CustomAttributesListType, CustomDomainConfigType, DefaultEmailOptionType(..)
    , DeleteGroupRequest, DeleteIdentityProviderRequest, DeleteResourceServerRequest, DeleteUserAttributesRequest
    , DeleteUserAttributesResponse, DeleteUserPoolClientRequest, DeleteUserPoolDomainRequest, DeleteUserPoolDomainResponse
    , DeleteUserPoolRequest, DeleteUserRequest, DeliveryMediumListType, DeliveryMediumType(..), DescribeIdentityProviderRequest
    , DescribeIdentityProviderResponse, DescribeResourceServerRequest, DescribeResourceServerResponse
    , DescribeRiskConfigurationRequest, DescribeRiskConfigurationResponse, DescribeUserImportJobRequest
    , DescribeUserImportJobResponse, DescribeUserPoolClientRequest, DescribeUserPoolClientResponse, DescribeUserPoolDomainRequest
    , DescribeUserPoolDomainResponse, DescribeUserPoolRequest, DescribeUserPoolResponse, DeviceConfigurationType, DeviceListType
    , DeviceRememberedStatusType(..), DeviceSecretVerifierConfigType, DeviceType, DomainDescriptionType, DomainStatusType(..)
    , EmailConfigurationType, EmailSendingAccountType(..), EventContextDataType, EventFeedbackType, EventFilterType(..), EventFiltersType
    , EventResponseType(..), EventRiskType, EventType(..), ExplicitAuthFlowsListType, ExplicitAuthFlowsType(..), FeedbackValueType(..)
    , ForgetDeviceRequest, ForgotPasswordRequest, ForgotPasswordResponse, GetCsvheaderRequest, GetCsvheaderResponse, GetDeviceRequest
    , GetDeviceResponse, GetGroupRequest, GetGroupResponse, GetIdentityProviderByIdentifierRequest
    , GetIdentityProviderByIdentifierResponse, GetSigningCertificateRequest, GetSigningCertificateResponse
    , GetUicustomizationRequest, GetUicustomizationResponse, GetUserAttributeVerificationCodeRequest
    , GetUserAttributeVerificationCodeResponse, GetUserPoolMfaConfigRequest, GetUserPoolMfaConfigResponse, GetUserRequest
    , GetUserResponse, GlobalSignOutRequest, GlobalSignOutResponse, GroupListType, GroupType, HttpHeader, HttpHeaderList
    , IdentityProviderType, IdentityProviderTypeType(..), IdpIdentifiersListType, InitiateAuthRequest, InitiateAuthResponse
    , LambdaConfigType, ListDevicesRequest, ListDevicesResponse, ListGroupsRequest, ListGroupsResponse, ListIdentityProvidersRequest
    , ListIdentityProvidersResponse, ListOfStringTypes, ListResourceServersRequest, ListResourceServersResponse
    , ListTagsForResourceRequest, ListTagsForResourceResponse, ListUserImportJobsRequest, ListUserImportJobsResponse
    , ListUserPoolClientsRequest, ListUserPoolClientsResponse, ListUserPoolsRequest, ListUserPoolsResponse, ListUsersInGroupRequest
    , ListUsersInGroupResponse, ListUsersRequest, ListUsersResponse, LogoutUrlsListType, MessageActionType(..), MessageTemplateType
    , MfaoptionListType, MfaoptionType, NewDeviceMetadataType, NotifyConfigurationType, NotifyEmailType, NumberAttributeConstraintsType
    , OauthFlowType(..), OauthFlowsType, PasswordPolicyType, ProviderDescription, ProviderDetailsType, ProviderUserIdentifierType
    , ProvidersListType, ResendConfirmationCodeRequest, ResendConfirmationCodeResponse, ResourceServerScopeListType
    , ResourceServerScopeType, ResourceServerType, ResourceServersListType, RespondToAuthChallengeRequest
    , RespondToAuthChallengeResponse, RiskConfigurationType, RiskDecisionType(..), RiskExceptionConfigurationType, RiskLevelType(..)
    , SchemaAttributeType, SchemaAttributesListType, ScopeListType, SearchedAttributeNamesListType, SetRiskConfigurationRequest
    , SetRiskConfigurationResponse, SetUicustomizationRequest, SetUicustomizationResponse, SetUserMfapreferenceRequest
    , SetUserMfapreferenceResponse, SetUserPoolMfaConfigRequest, SetUserPoolMfaConfigResponse, SetUserSettingsRequest
    , SetUserSettingsResponse, SignUpRequest, SignUpResponse, SkippedIprangeListType, SmsConfigurationType, SmsMfaConfigType
    , SmsmfaSettingsType, SoftwareTokenMfaConfigType, SoftwareTokenMfaSettingsType, StartUserImportJobRequest
    , StartUserImportJobResponse, StatusType(..), StopUserImportJobRequest, StopUserImportJobResponse, StringAttributeConstraintsType
    , SupportedIdentityProvidersListType, TagResourceRequest, TagResourceResponse, UicustomizationType, UntagResourceRequest
    , UntagResourceResponse, UpdateAuthEventFeedbackRequest, UpdateAuthEventFeedbackResponse, UpdateDeviceStatusRequest
    , UpdateDeviceStatusResponse, UpdateGroupRequest, UpdateGroupResponse, UpdateIdentityProviderRequest
    , UpdateIdentityProviderResponse, UpdateResourceServerRequest, UpdateResourceServerResponse, UpdateUserAttributesRequest
    , UpdateUserAttributesResponse, UpdateUserPoolClientRequest, UpdateUserPoolClientResponse, UpdateUserPoolDomainRequest
    , UpdateUserPoolDomainResponse, UpdateUserPoolRequest, UpdateUserPoolResponse, UserContextDataType, UserImportJobStatusType(..)
    , UserImportJobType, UserImportJobsListType, UserMfasettingListType, UserPoolAddOnsType, UserPoolClientDescription
    , UserPoolClientListType, UserPoolClientType, UserPoolDescriptionType, UserPoolListType, UserPoolMfaType(..), UserPoolPolicyType
    , UserPoolTagsListType, UserPoolTagsType, UserPoolType, UserStatusType(..), UserType, UsernameAttributeType(..), UsernameAttributesListType
    , UsersListType, VerificationMessageTemplateType, VerifiedAttributeType(..), VerifiedAttributesListType, VerifySoftwareTokenRequest
    , VerifySoftwareTokenResponse, VerifySoftwareTokenResponseType(..), VerifyUserAttributeRequest, VerifyUserAttributeResponse
    , accountTakeoverEventActionType, advancedSecurityModeType, aliasAttributeType, attributeDataType, authFlowType, challengeName
    , challengeNameType, challengeResponse, compromisedCredentialsEventActionType, defaultEmailOptionType, deliveryMediumType
    , deviceRememberedStatusType, domainStatusType, emailSendingAccountType, eventFilterType, eventResponseType, eventType
    , explicitAuthFlowsType, feedbackValueType, identityProviderTypeType, messageActionType, oauthFlowType, riskDecisionType
    , riskLevelType, statusType, userImportJobStatusType, userPoolMfaType, userStatusType, usernameAttributeType, verifiedAttributeType
    , verifySoftwareTokenResponseType
    )

{-| Using the Amazon Cognito User Pools API, you can create a user pool to manage directories and users. You can authenticate a user to obtain tokens related to user identity and access policies.

This API reference provides information about user pools in Amazon Cognito User Pools.

For more information, see the Amazon Cognito Documentation.


# Service definition.

@docs service


# Service endpoints.

@docs addCustomAttributes, adminAddUserToGroup, adminConfirmSignUp, adminCreateUser, adminDeleteUser, adminDeleteUserAttributes
@docs adminDisableProviderForUser, adminDisableUser, adminEnableUser, adminForgetDevice, adminGetDevice, adminGetUser, adminInitiateAuth
@docs adminLinkProviderForUser, adminListDevices, adminListGroupsForUser, adminListUserAuthEvents, adminRemoveUserFromGroup
@docs adminResetUserPassword, adminRespondToAuthChallenge, adminSetUserMfapreference, adminSetUserPassword, adminSetUserSettings
@docs adminUpdateAuthEventFeedback, adminUpdateDeviceStatus, adminUpdateUserAttributes, adminUserGlobalSignOut, associateSoftwareToken
@docs changePassword, confirmDevice, confirmForgotPassword, confirmSignUp, createGroup, createIdentityProvider, createResourceServer
@docs createUserImportJob, createUserPool, createUserPoolClient, createUserPoolDomain, deleteGroup, deleteIdentityProvider
@docs deleteResourceServer, deleteUser, deleteUserAttributes, deleteUserPool, deleteUserPoolClient, deleteUserPoolDomain
@docs describeIdentityProvider, describeResourceServer, describeRiskConfiguration, describeUserImportJob, describeUserPool
@docs describeUserPoolClient, describeUserPoolDomain, forgetDevice, forgotPassword, getCsvheader, getDevice, getGroup
@docs getIdentityProviderByIdentifier, getSigningCertificate, getUicustomization, getUser, getUserAttributeVerificationCode
@docs getUserPoolMfaConfig, globalSignOut, initiateAuth, listDevices, listGroups, listIdentityProviders, listResourceServers
@docs listTagsForResource, listUserImportJobs, listUserPoolClients, listUserPools, listUsers, listUsersInGroup, resendConfirmationCode
@docs respondToAuthChallenge, setRiskConfiguration, setUicustomization, setUserMfapreference, setUserPoolMfaConfig, setUserSettings
@docs signUp, startUserImportJob, stopUserImportJob, tagResource, untagResource, updateAuthEventFeedback, updateDeviceStatus, updateGroup
@docs updateIdentityProvider, updateResourceServer, updateUserAttributes, updateUserPool, updateUserPoolClient, updateUserPoolDomain
@docs verifySoftwareToken, verifyUserAttribute


# API data model.

@docs AccountTakeoverActionType, AccountTakeoverActionsType, AccountTakeoverEventActionType, AccountTakeoverRiskConfigurationType
@docs AddCustomAttributesRequest, AddCustomAttributesResponse, AdminAddUserToGroupRequest, AdminConfirmSignUpRequest
@docs AdminConfirmSignUpResponse, AdminCreateUserConfigType, AdminCreateUserRequest, AdminCreateUserResponse
@docs AdminDeleteUserAttributesRequest, AdminDeleteUserAttributesResponse, AdminDeleteUserRequest
@docs AdminDisableProviderForUserRequest, AdminDisableProviderForUserResponse, AdminDisableUserRequest, AdminDisableUserResponse
@docs AdminEnableUserRequest, AdminEnableUserResponse, AdminForgetDeviceRequest, AdminGetDeviceRequest, AdminGetDeviceResponse
@docs AdminGetUserRequest, AdminGetUserResponse, AdminInitiateAuthRequest, AdminInitiateAuthResponse, AdminLinkProviderForUserRequest
@docs AdminLinkProviderForUserResponse, AdminListDevicesRequest, AdminListDevicesResponse, AdminListGroupsForUserRequest
@docs AdminListGroupsForUserResponse, AdminListUserAuthEventsRequest, AdminListUserAuthEventsResponse
@docs AdminRemoveUserFromGroupRequest, AdminResetUserPasswordRequest, AdminResetUserPasswordResponse
@docs AdminRespondToAuthChallengeRequest, AdminRespondToAuthChallengeResponse, AdminSetUserMfapreferenceRequest
@docs AdminSetUserMfapreferenceResponse, AdminSetUserPasswordRequest, AdminSetUserPasswordResponse, AdminSetUserSettingsRequest
@docs AdminSetUserSettingsResponse, AdminUpdateAuthEventFeedbackRequest, AdminUpdateAuthEventFeedbackResponse
@docs AdminUpdateDeviceStatusRequest, AdminUpdateDeviceStatusResponse, AdminUpdateUserAttributesRequest
@docs AdminUpdateUserAttributesResponse, AdminUserGlobalSignOutRequest, AdminUserGlobalSignOutResponse, AdvancedSecurityModeType
@docs AliasAttributeType, AliasAttributesListType, AnalyticsConfigurationType, AnalyticsMetadataType, AssociateSoftwareTokenRequest
@docs AssociateSoftwareTokenResponse, AttributeDataType, AttributeListType, AttributeMappingType, AttributeNameListType, AttributeType
@docs AuthEventType, AuthEventsType, AuthFlowType, AuthParametersType, AuthenticationResultType, BlockedIprangeListType
@docs CallbackUrlsListType, ChallengeName, ChallengeNameType, ChallengeParametersType, ChallengeResponse, ChallengeResponseListType
@docs ChallengeResponseType, ChallengeResponsesType, ChangePasswordRequest, ChangePasswordResponse, ClientMetadataType
@docs ClientPermissionListType, CodeDeliveryDetailsListType, CodeDeliveryDetailsType, CompromisedCredentialsActionsType
@docs CompromisedCredentialsEventActionType, CompromisedCredentialsRiskConfigurationType, ConfirmDeviceRequest
@docs ConfirmDeviceResponse, ConfirmForgotPasswordRequest, ConfirmForgotPasswordResponse, ConfirmSignUpRequest, ConfirmSignUpResponse
@docs ContextDataType, CreateGroupRequest, CreateGroupResponse, CreateIdentityProviderRequest, CreateIdentityProviderResponse
@docs CreateResourceServerRequest, CreateResourceServerResponse, CreateUserImportJobRequest, CreateUserImportJobResponse
@docs CreateUserPoolClientRequest, CreateUserPoolClientResponse, CreateUserPoolDomainRequest, CreateUserPoolDomainResponse
@docs CreateUserPoolRequest, CreateUserPoolResponse, CustomAttributesListType, CustomDomainConfigType, DefaultEmailOptionType
@docs DeleteGroupRequest, DeleteIdentityProviderRequest, DeleteResourceServerRequest, DeleteUserAttributesRequest
@docs DeleteUserAttributesResponse, DeleteUserPoolClientRequest, DeleteUserPoolDomainRequest, DeleteUserPoolDomainResponse
@docs DeleteUserPoolRequest, DeleteUserRequest, DeliveryMediumListType, DeliveryMediumType, DescribeIdentityProviderRequest
@docs DescribeIdentityProviderResponse, DescribeResourceServerRequest, DescribeResourceServerResponse
@docs DescribeRiskConfigurationRequest, DescribeRiskConfigurationResponse, DescribeUserImportJobRequest
@docs DescribeUserImportJobResponse, DescribeUserPoolClientRequest, DescribeUserPoolClientResponse, DescribeUserPoolDomainRequest
@docs DescribeUserPoolDomainResponse, DescribeUserPoolRequest, DescribeUserPoolResponse, DeviceConfigurationType, DeviceListType
@docs DeviceRememberedStatusType, DeviceSecretVerifierConfigType, DeviceType, DomainDescriptionType, DomainStatusType
@docs EmailConfigurationType, EmailSendingAccountType, EventContextDataType, EventFeedbackType, EventFilterType, EventFiltersType
@docs EventResponseType, EventRiskType, EventType, ExplicitAuthFlowsListType, ExplicitAuthFlowsType, FeedbackValueType
@docs ForgetDeviceRequest, ForgotPasswordRequest, ForgotPasswordResponse, GetCsvheaderRequest, GetCsvheaderResponse, GetDeviceRequest
@docs GetDeviceResponse, GetGroupRequest, GetGroupResponse, GetIdentityProviderByIdentifierRequest
@docs GetIdentityProviderByIdentifierResponse, GetSigningCertificateRequest, GetSigningCertificateResponse
@docs GetUicustomizationRequest, GetUicustomizationResponse, GetUserAttributeVerificationCodeRequest
@docs GetUserAttributeVerificationCodeResponse, GetUserPoolMfaConfigRequest, GetUserPoolMfaConfigResponse, GetUserRequest
@docs GetUserResponse, GlobalSignOutRequest, GlobalSignOutResponse, GroupListType, GroupType, HttpHeader, HttpHeaderList
@docs IdentityProviderType, IdentityProviderTypeType, IdpIdentifiersListType, InitiateAuthRequest, InitiateAuthResponse
@docs LambdaConfigType, ListDevicesRequest, ListDevicesResponse, ListGroupsRequest, ListGroupsResponse, ListIdentityProvidersRequest
@docs ListIdentityProvidersResponse, ListOfStringTypes, ListResourceServersRequest, ListResourceServersResponse
@docs ListTagsForResourceRequest, ListTagsForResourceResponse, ListUserImportJobsRequest, ListUserImportJobsResponse
@docs ListUserPoolClientsRequest, ListUserPoolClientsResponse, ListUserPoolsRequest, ListUserPoolsResponse, ListUsersInGroupRequest
@docs ListUsersInGroupResponse, ListUsersRequest, ListUsersResponse, LogoutUrlsListType, MessageActionType, MessageTemplateType
@docs MfaoptionListType, MfaoptionType, NewDeviceMetadataType, NotifyConfigurationType, NotifyEmailType, NumberAttributeConstraintsType
@docs OauthFlowType, OauthFlowsType, PasswordPolicyType, ProviderDescription, ProviderDetailsType, ProviderUserIdentifierType
@docs ProvidersListType, ResendConfirmationCodeRequest, ResendConfirmationCodeResponse, ResourceServerScopeListType
@docs ResourceServerScopeType, ResourceServerType, ResourceServersListType, RespondToAuthChallengeRequest
@docs RespondToAuthChallengeResponse, RiskConfigurationType, RiskDecisionType, RiskExceptionConfigurationType, RiskLevelType
@docs SchemaAttributeType, SchemaAttributesListType, ScopeListType, SearchedAttributeNamesListType, SetRiskConfigurationRequest
@docs SetRiskConfigurationResponse, SetUicustomizationRequest, SetUicustomizationResponse, SetUserMfapreferenceRequest
@docs SetUserMfapreferenceResponse, SetUserPoolMfaConfigRequest, SetUserPoolMfaConfigResponse, SetUserSettingsRequest
@docs SetUserSettingsResponse, SignUpRequest, SignUpResponse, SkippedIprangeListType, SmsConfigurationType, SmsMfaConfigType
@docs SmsmfaSettingsType, SoftwareTokenMfaConfigType, SoftwareTokenMfaSettingsType, StartUserImportJobRequest
@docs StartUserImportJobResponse, StatusType, StopUserImportJobRequest, StopUserImportJobResponse, StringAttributeConstraintsType
@docs SupportedIdentityProvidersListType, TagResourceRequest, TagResourceResponse, UicustomizationType, UntagResourceRequest
@docs UntagResourceResponse, UpdateAuthEventFeedbackRequest, UpdateAuthEventFeedbackResponse, UpdateDeviceStatusRequest
@docs UpdateDeviceStatusResponse, UpdateGroupRequest, UpdateGroupResponse, UpdateIdentityProviderRequest
@docs UpdateIdentityProviderResponse, UpdateResourceServerRequest, UpdateResourceServerResponse, UpdateUserAttributesRequest
@docs UpdateUserAttributesResponse, UpdateUserPoolClientRequest, UpdateUserPoolClientResponse, UpdateUserPoolDomainRequest
@docs UpdateUserPoolDomainResponse, UpdateUserPoolRequest, UpdateUserPoolResponse, UserContextDataType, UserImportJobStatusType
@docs UserImportJobType, UserImportJobsListType, UserMfasettingListType, UserPoolAddOnsType, UserPoolClientDescription
@docs UserPoolClientListType, UserPoolClientType, UserPoolDescriptionType, UserPoolListType, UserPoolMfaType, UserPoolPolicyType
@docs UserPoolTagsListType, UserPoolTagsType, UserPoolType, UserStatusType, UserType, UsernameAttributeType, UsernameAttributesListType
@docs UsersListType, VerificationMessageTemplateType, VerifiedAttributeType, VerifiedAttributesListType, VerifySoftwareTokenRequest
@docs VerifySoftwareTokenResponse, VerifySoftwareTokenResponseType, VerifyUserAttributeRequest, VerifyUserAttributeResponse
@docs accountTakeoverEventActionType, advancedSecurityModeType, aliasAttributeType, attributeDataType, authFlowType, challengeName
@docs challengeNameType, challengeResponse, compromisedCredentialsEventActionType, defaultEmailOptionType, deliveryMediumType
@docs deviceRememberedStatusType, domainStatusType, emailSendingAccountType, eventFilterType, eventResponseType, eventType
@docs explicitAuthFlowsType, feedbackValueType, identityProviderTypeType, messageActionType, oauthFlowType, riskDecisionType
@docs riskLevelType, statusType, userImportJobStatusType, userPoolMfaType, userStatusType, usernameAttributeType, verifiedAttributeType
@docs verifySoftwareTokenResponseType

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
    AWS.Config.defineRegional "cognito-idp" "2016-04-18" AWS.Config.JSON AWS.Config.SignV4 region
        |> AWS.Config.withJsonVersion "1.1"
        |> AWS.Config.withTargetPrefix "AWSCognitoIdentityProviderService"
        |> AWS.Service.service


{-| Verifies the specified user attributes in the user pool.
-}
verifyUserAttribute : VerifyUserAttributeRequest -> AWS.Http.Request AWS.Http.AWSAppError ()
verifyUserAttribute req =
    let
        encoder val =
            [ ( "Code", val.code ) |> EncodeOpt.field Json.Encode.string
            , ( "AttributeName", val.attributeName ) |> EncodeOpt.field Json.Encode.string
            , ( "AccessToken", val.accessToken ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "VerifyUserAttribute" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Use this API to register a user's entered TOTP code and mark the user's software token MFA status as "verified" if successful. The request takes an access token or a session string, but not both.
-}
verifySoftwareToken : VerifySoftwareTokenRequest -> AWS.Http.Request AWS.Http.AWSAppError VerifySoftwareTokenResponse
verifySoftwareToken req =
    let
        encoder val =
            [ ( "UserCode", val.userCode ) |> EncodeOpt.field Json.Encode.string
            , ( "Session", val.session ) |> EncodeOpt.optionalField Json.Encode.string
            , ( "FriendlyDeviceName", val.friendlyDeviceName ) |> EncodeOpt.optionalField Json.Encode.string
            , ( "AccessToken", val.accessToken ) |> EncodeOpt.optionalField Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\statusFld sessionFld -> { session = sessionFld, status = statusFld }) |> Json.Decode.succeed)
                |> Pipeline.optional "Status" (Json.Decode.maybe verifySoftwareTokenResponseTypeDecoder) Nothing
                |> Pipeline.optional "Session" (Json.Decode.maybe Json.Decode.string) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "VerifySoftwareToken" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Updates the Secure Sockets Layer (SSL) certificate for the custom domain for your user pool.

You can use this operation to provide the Amazon Resource Name (ARN) of a new certificate to Amazon Cognito. You cannot use it to change the domain for a user pool.

A custom domain is used to host the Amazon Cognito hosted UI, which provides sign-up and sign-in pages for your application. When you set up a custom domain, you provide a certificate that you manage with AWS Certificate Manager (ACM). When necessary, you can use this operation to change the certificate that you applied to your custom domain.

Usually, this is unnecessary following routine certificate renewal with ACM. When you renew your existing certificate in ACM, the ARN for your certificate remains the same, and your custom domain uses the new certificate automatically.

However, if you replace your existing certificate with a new one, ACM gives the new certificate a new ARN. To apply the new certificate to your custom domain, you must provide this ARN to Amazon Cognito.

When you add your new certificate in ACM, you must choose US East (N. Virginia) as the AWS Region.

After you submit your request, Amazon Cognito requires up to 1 hour to distribute your new certificate to your custom domain.

For more information about adding a custom domain to your user pool, see `Using Your Own Domain for the Hosted UI`.

-}
updateUserPoolDomain : UpdateUserPoolDomainRequest -> AWS.Http.Request AWS.Http.AWSAppError UpdateUserPoolDomainResponse
updateUserPoolDomain req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "Domain", val.domain ) |> EncodeOpt.field Json.Encode.string
            , ( "CustomDomainConfig", val.customDomainConfig )
                |> EncodeOpt.field (Codec.encoder customDomainConfigTypeCodec)
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\cloudFrontDomainFld -> { cloudFrontDomain = cloudFrontDomainFld }) |> Json.Decode.succeed)
                |> Pipeline.optional "CloudFrontDomain" (Json.Decode.maybe Json.Decode.string) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "UpdateUserPoolDomain" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Updates the specified user pool app client with the specified attributes. If you don't provide a value for an attribute, it will be set to the default value. You can get a list of the current user pool app client settings with .
-}
updateUserPoolClient : UpdateUserPoolClientRequest -> AWS.Http.Request AWS.Http.AWSAppError UpdateUserPoolClientResponse
updateUserPoolClient req =
    let
        encoder val =
            [ ( "WriteAttributes", val.writeAttributes )
                |> EncodeOpt.optionalField (Codec.encoder clientPermissionListTypeCodec)
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "SupportedIdentityProviders", val.supportedIdentityProviders )
                |> EncodeOpt.optionalField (Codec.encoder supportedIdentityProvidersListTypeCodec)
            , ( "RefreshTokenValidity", val.refreshTokenValidity ) |> EncodeOpt.optionalField Json.Encode.int
            , ( "ReadAttributes", val.readAttributes )
                |> EncodeOpt.optionalField (Codec.encoder clientPermissionListTypeCodec)
            , ( "LogoutURLs", val.logoutUrls ) |> EncodeOpt.optionalField (Codec.encoder logoutUrlsListTypeCodec)
            , ( "ExplicitAuthFlows", val.explicitAuthFlows )
                |> EncodeOpt.optionalField (Codec.encoder explicitAuthFlowsListTypeCodec)
            , ( "DefaultRedirectURI", val.defaultRedirectUri ) |> EncodeOpt.optionalField Json.Encode.string
            , ( "ClientName", val.clientName ) |> EncodeOpt.optionalField Json.Encode.string
            , ( "ClientId", val.clientId ) |> EncodeOpt.field Json.Encode.string
            , ( "CallbackURLs", val.callbackUrls ) |> EncodeOpt.optionalField (Codec.encoder callbackUrlsListTypeCodec)
            , ( "AnalyticsConfiguration", val.analyticsConfiguration )
                |> EncodeOpt.optionalField (Codec.encoder analyticsConfigurationTypeCodec)
            , ( "AllowedOAuthScopes", val.allowedOauthScopes )
                |> EncodeOpt.optionalField (Codec.encoder scopeListTypeCodec)
            , ( "AllowedOAuthFlowsUserPoolClient", val.allowedOauthFlowsUserPoolClient )
                |> EncodeOpt.optionalField Json.Encode.bool
            , ( "AllowedOAuthFlows", val.allowedOauthFlows )
                |> EncodeOpt.optionalField (Codec.encoder oauthFlowsTypeCodec)
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\userPoolClientFld -> { userPoolClient = userPoolClientFld }) |> Json.Decode.succeed)
                |> Pipeline.optional "UserPoolClient" (Json.Decode.maybe userPoolClientTypeDecoder) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "UpdateUserPoolClient" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Updates the specified user pool with the specified attributes. If you don't provide a value for an attribute, it will be set to the default value. You can get a list of the current user pool settings with .
-}
updateUserPool : UpdateUserPoolRequest -> AWS.Http.Request AWS.Http.AWSAppError ()
updateUserPool req =
    let
        encoder val =
            [ ( "VerificationMessageTemplate", val.verificationMessageTemplate )
                |> EncodeOpt.optionalField (Codec.encoder verificationMessageTemplateTypeCodec)
            , ( "UserPoolTags", val.userPoolTags ) |> EncodeOpt.optionalField (Codec.encoder userPoolTagsTypeCodec)
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "UserPoolAddOns", val.userPoolAddOns )
                |> EncodeOpt.optionalField (Codec.encoder userPoolAddOnsTypeCodec)
            , ( "SmsVerificationMessage", val.smsVerificationMessage ) |> EncodeOpt.optionalField Json.Encode.string
            , ( "SmsConfiguration", val.smsConfiguration )
                |> EncodeOpt.optionalField (Codec.encoder smsConfigurationTypeCodec)
            , ( "SmsAuthenticationMessage", val.smsAuthenticationMessage ) |> EncodeOpt.optionalField Json.Encode.string
            , ( "Policies", val.policies ) |> EncodeOpt.optionalField (Codec.encoder userPoolPolicyTypeCodec)
            , ( "MfaConfiguration", val.mfaConfiguration )
                |> EncodeOpt.optionalField (Codec.encoder userPoolMfaTypeCodec)
            , ( "LambdaConfig", val.lambdaConfig ) |> EncodeOpt.optionalField (Codec.encoder lambdaConfigTypeCodec)
            , ( "EmailVerificationSubject", val.emailVerificationSubject ) |> EncodeOpt.optionalField Json.Encode.string
            , ( "EmailVerificationMessage", val.emailVerificationMessage ) |> EncodeOpt.optionalField Json.Encode.string
            , ( "EmailConfiguration", val.emailConfiguration )
                |> EncodeOpt.optionalField (Codec.encoder emailConfigurationTypeCodec)
            , ( "DeviceConfiguration", val.deviceConfiguration )
                |> EncodeOpt.optionalField (Codec.encoder deviceConfigurationTypeCodec)
            , ( "AutoVerifiedAttributes", val.autoVerifiedAttributes )
                |> EncodeOpt.optionalField (Codec.encoder verifiedAttributesListTypeCodec)
            , ( "AdminCreateUserConfig", val.adminCreateUserConfig )
                |> EncodeOpt.optionalField (Codec.encoder adminCreateUserConfigTypeCodec)
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "UpdateUserPool" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Allows a user to update a specific attribute (one at a time).
-}
updateUserAttributes : UpdateUserAttributesRequest -> AWS.Http.Request AWS.Http.AWSAppError UpdateUserAttributesResponse
updateUserAttributes req =
    let
        encoder val =
            [ ( "UserAttributes", val.userAttributes ) |> EncodeOpt.field (Codec.encoder attributeListTypeCodec)
            , ( "AccessToken", val.accessToken ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\codeDeliveryDetailsListFld -> { codeDeliveryDetailsList = codeDeliveryDetailsListFld })
                |> Json.Decode.succeed
            )
                |> Pipeline.optional
                    "CodeDeliveryDetailsList"
                    (Json.Decode.maybe codeDeliveryDetailsListTypeDecoder)
                    Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "UpdateUserAttributes" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Updates the name and scopes of resource server. All other fields are read-only.
-}
updateResourceServer : UpdateResourceServerRequest -> AWS.Http.Request AWS.Http.AWSAppError UpdateResourceServerResponse
updateResourceServer req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "Scopes", val.scopes ) |> EncodeOpt.optionalField (Codec.encoder resourceServerScopeListTypeCodec)
            , ( "Name", val.name ) |> EncodeOpt.field Json.Encode.string
            , ( "Identifier", val.identifier ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\resourceServerFld -> { resourceServer = resourceServerFld }) |> Json.Decode.succeed)
                |> Pipeline.required "ResourceServer" resourceServerTypeDecoder
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "UpdateResourceServer" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Updates identity provider information for a user pool.
-}
updateIdentityProvider : UpdateIdentityProviderRequest -> AWS.Http.Request AWS.Http.AWSAppError UpdateIdentityProviderResponse
updateIdentityProvider req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "ProviderName", val.providerName ) |> EncodeOpt.field Json.Encode.string
            , ( "ProviderDetails", val.providerDetails )
                |> EncodeOpt.optionalField (Codec.encoder providerDetailsTypeCodec)
            , ( "IdpIdentifiers", val.idpIdentifiers )
                |> EncodeOpt.optionalField (Codec.encoder idpIdentifiersListTypeCodec)
            , ( "AttributeMapping", val.attributeMapping )
                |> EncodeOpt.optionalField (Codec.encoder attributeMappingTypeCodec)
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\identityProviderFld -> { identityProvider = identityProviderFld }) |> Json.Decode.succeed)
                |> Pipeline.required "IdentityProvider" identityProviderTypeDecoder
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "UpdateIdentityProvider" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Updates the specified group with the specified attributes.

Requires developer credentials.

-}
updateGroup : UpdateGroupRequest -> AWS.Http.Request AWS.Http.AWSAppError UpdateGroupResponse
updateGroup req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "RoleArn", val.roleArn ) |> EncodeOpt.optionalField Json.Encode.string
            , ( "Precedence", val.precedence ) |> EncodeOpt.optionalField Json.Encode.int
            , ( "GroupName", val.groupName ) |> EncodeOpt.field Json.Encode.string
            , ( "Description", val.description ) |> EncodeOpt.optionalField Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\groupFld -> { group = groupFld }) |> Json.Decode.succeed)
                |> Pipeline.optional "Group" (Json.Decode.maybe groupTypeDecoder) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "UpdateGroup" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Updates the device status.
-}
updateDeviceStatus : UpdateDeviceStatusRequest -> AWS.Http.Request AWS.Http.AWSAppError ()
updateDeviceStatus req =
    let
        encoder val =
            [ ( "DeviceRememberedStatus", val.deviceRememberedStatus )
                |> EncodeOpt.optionalField deviceRememberedStatusTypeEncoder
            , ( "DeviceKey", val.deviceKey ) |> EncodeOpt.field Json.Encode.string
            , ( "AccessToken", val.accessToken ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "UpdateDeviceStatus" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Provides the feedback for an authentication event whether it was from a valid user or not. This feedback is used for improving the risk evaluation decision for the user pool as part of Amazon Cognito advanced security.
-}
updateAuthEventFeedback : UpdateAuthEventFeedbackRequest -> AWS.Http.Request AWS.Http.AWSAppError ()
updateAuthEventFeedback req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field Json.Encode.string
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "FeedbackValue", val.feedbackValue ) |> EncodeOpt.field (Codec.encoder feedbackValueTypeCodec)
            , ( "FeedbackToken", val.feedbackToken ) |> EncodeOpt.field Json.Encode.string
            , ( "EventId", val.eventId ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "UpdateAuthEventFeedback" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Removes the specified tags from an Amazon Cognito user pool. You can use this action up to 5 times per second, per account
-}
untagResource : UntagResourceRequest -> AWS.Http.Request AWS.Http.AWSAppError ()
untagResource req =
    let
        encoder val =
            [ ( "TagKeys", val.tagKeys ) |> EncodeOpt.optionalField userPoolTagsListTypeEncoder
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


{-| Assigns a set of tags to an Amazon Cognito user pool. A tag is a label that you can use to categorize and manage user pools in different ways, such as by purpose, owner, environment, or other criteria.

Each tag consists of a key and value, both of which you define. A key is a general category for more specific values. For example, if you have two versions of a user pool, one for testing and another for production, you might assign an `Environment` tag key to both user pools. The value of this key might be `Test` for one user pool and `Production` for the other.

Tags are useful for cost tracking and access control. You can activate your tags so that they appear on the Billing and Cost Management console, where you can track the costs associated with your user pools. In an IAM policy, you can constrain permissions for user pools based on specific tags or tag values.

You can use this action up to 5 times per second, per account. A user pool can have as many as 50 tags.

-}
tagResource : TagResourceRequest -> AWS.Http.Request AWS.Http.AWSAppError ()
tagResource req =
    let
        encoder val =
            [ ( "Tags", val.tags ) |> EncodeOpt.optionalField (Codec.encoder userPoolTagsTypeCodec)
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


{-| Stops the user import job.
-}
stopUserImportJob : StopUserImportJobRequest -> AWS.Http.Request AWS.Http.AWSAppError StopUserImportJobResponse
stopUserImportJob req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "JobId", val.jobId ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\userImportJobFld -> { userImportJob = userImportJobFld }) |> Json.Decode.succeed)
                |> Pipeline.optional "UserImportJob" (Json.Decode.maybe userImportJobTypeDecoder) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "StopUserImportJob" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Starts the user import.
-}
startUserImportJob : StartUserImportJobRequest -> AWS.Http.Request AWS.Http.AWSAppError StartUserImportJobResponse
startUserImportJob req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "JobId", val.jobId ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\userImportJobFld -> { userImportJob = userImportJobFld }) |> Json.Decode.succeed)
                |> Pipeline.optional "UserImportJob" (Json.Decode.maybe userImportJobTypeDecoder) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "StartUserImportJob" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Registers the user in the specified user pool and creates a user name, password, and user attributes.
-}
signUp : SignUpRequest -> AWS.Http.Request AWS.Http.AWSAppError SignUpResponse
signUp req =
    let
        encoder val =
            [ ( "ValidationData", val.validationData ) |> EncodeOpt.optionalField (Codec.encoder attributeListTypeCodec)
            , ( "Username", val.username ) |> EncodeOpt.field Json.Encode.string
            , ( "UserContextData", val.userContextData ) |> EncodeOpt.optionalField userContextDataTypeEncoder
            , ( "UserAttributes", val.userAttributes ) |> EncodeOpt.optionalField (Codec.encoder attributeListTypeCodec)
            , ( "SecretHash", val.secretHash ) |> EncodeOpt.optionalField Json.Encode.string
            , ( "Password", val.password ) |> EncodeOpt.field Json.Encode.string
            , ( "ClientId", val.clientId ) |> EncodeOpt.field Json.Encode.string
            , ( "AnalyticsMetadata", val.analyticsMetadata ) |> EncodeOpt.optionalField analyticsMetadataTypeEncoder
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\userSubFld userConfirmedFld codeDeliveryDetailsFld ->
                { codeDeliveryDetails = codeDeliveryDetailsFld
                , userConfirmed = userConfirmedFld
                , userSub = userSubFld
                }
             )
                |> Json.Decode.succeed
            )
                |> Pipeline.required "UserSub" Json.Decode.string
                |> Pipeline.required "UserConfirmed" Json.Decode.bool
                |> Pipeline.optional "CodeDeliveryDetails" (Json.Decode.maybe codeDeliveryDetailsTypeDecoder) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "SignUp" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Sets the user settings like multi-factor authentication (MFA). If MFA is to be removed for a particular attribute pass the attribute with code delivery as null. If null list is passed, all MFA options are removed.
-}
setUserSettings : SetUserSettingsRequest -> AWS.Http.Request AWS.Http.AWSAppError ()
setUserSettings req =
    let
        encoder val =
            [ ( "MFAOptions", val.mfaoptions ) |> EncodeOpt.field (Codec.encoder mfaoptionListTypeCodec)
            , ( "AccessToken", val.accessToken ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "SetUserSettings" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Set the user pool MFA configuration.
-}
setUserPoolMfaConfig : SetUserPoolMfaConfigRequest -> AWS.Http.Request AWS.Http.AWSAppError SetUserPoolMfaConfigResponse
setUserPoolMfaConfig req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "SoftwareTokenMfaConfiguration", val.softwareTokenMfaConfiguration )
                |> EncodeOpt.optionalField (Codec.encoder softwareTokenMfaConfigTypeCodec)
            , ( "SmsMfaConfiguration", val.smsMfaConfiguration )
                |> EncodeOpt.optionalField (Codec.encoder smsMfaConfigTypeCodec)
            , ( "MfaConfiguration", val.mfaConfiguration )
                |> EncodeOpt.optionalField (Codec.encoder userPoolMfaTypeCodec)
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\softwareTokenMfaConfigurationFld smsMfaConfigurationFld mfaConfigurationFld ->
                { mfaConfiguration = mfaConfigurationFld
                , smsMfaConfiguration = smsMfaConfigurationFld
                , softwareTokenMfaConfiguration = softwareTokenMfaConfigurationFld
                }
             )
                |> Json.Decode.succeed
            )
                |> Pipeline.optional
                    "SoftwareTokenMfaConfiguration"
                    (Json.Decode.maybe (Codec.decoder softwareTokenMfaConfigTypeCodec))
                    Nothing
                |> Pipeline.optional
                    "SmsMfaConfiguration"
                    (Json.Decode.maybe (Codec.decoder smsMfaConfigTypeCodec))
                    Nothing
                |> Pipeline.optional "MfaConfiguration" (Json.Decode.maybe (Codec.decoder userPoolMfaTypeCodec)) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "SetUserPoolMfaConfig" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Set the user's multi-factor authentication (MFA) method preference.
-}
setUserMfapreference : SetUserMfapreferenceRequest -> AWS.Http.Request AWS.Http.AWSAppError ()
setUserMfapreference req =
    let
        encoder val =
            [ ( "SoftwareTokenMfaSettings", val.softwareTokenMfaSettings )
                |> EncodeOpt.optionalField softwareTokenMfaSettingsTypeEncoder
            , ( "SMSMfaSettings", val.smsmfaSettings ) |> EncodeOpt.optionalField smsmfaSettingsTypeEncoder
            , ( "AccessToken", val.accessToken ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "SetUserMfapreference" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Sets the UI customization information for a user pool's built-in app UI.

You can specify app UI customization settings for a single client (with a specific `clientId`) or for all clients (by setting the `clientId` to `ALL`). If you specify `ALL`, the default configuration will be used for every client that has no UI customization set previously. If you specify UI customization settings for a particular client, it will no longer fall back to the `ALL` configuration.

To use this API, your user pool must have a domain associated with it. Otherwise, there is no place to host the app's pages, and the service will throw an error.

-}
setUicustomization : SetUicustomizationRequest -> AWS.Http.Request AWS.Http.AWSAppError SetUicustomizationResponse
setUicustomization req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "ImageFile", val.imageFile ) |> EncodeOpt.optionalField Json.Encode.string
            , ( "ClientId", val.clientId ) |> EncodeOpt.optionalField Json.Encode.string
            , ( "CSS", val.css ) |> EncodeOpt.optionalField Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\uicustomizationFld -> { uicustomization = uicustomizationFld }) |> Json.Decode.succeed)
                |> Pipeline.required "UICustomization" uicustomizationTypeDecoder
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "SetUicustomization" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Configures actions on detected risks. To delete the risk configuration for `UserPoolId` or `ClientId`, pass null values for all four configuration types.

To enable Amazon Cognito advanced security features, update the user pool to include the `UserPoolAddOns` key`AdvancedSecurityMode`.

See .

-}
setRiskConfiguration : SetRiskConfigurationRequest -> AWS.Http.Request AWS.Http.AWSAppError SetRiskConfigurationResponse
setRiskConfiguration req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "RiskExceptionConfiguration", val.riskExceptionConfiguration )
                |> EncodeOpt.optionalField (Codec.encoder riskExceptionConfigurationTypeCodec)
            , ( "CompromisedCredentialsRiskConfiguration", val.compromisedCredentialsRiskConfiguration )
                |> EncodeOpt.optionalField (Codec.encoder compromisedCredentialsRiskConfigurationTypeCodec)
            , ( "ClientId", val.clientId ) |> EncodeOpt.optionalField Json.Encode.string
            , ( "AccountTakeoverRiskConfiguration", val.accountTakeoverRiskConfiguration )
                |> EncodeOpt.optionalField (Codec.encoder accountTakeoverRiskConfigurationTypeCodec)
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\riskConfigurationFld -> { riskConfiguration = riskConfigurationFld }) |> Json.Decode.succeed)
                |> Pipeline.required "RiskConfiguration" riskConfigurationTypeDecoder
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "SetRiskConfiguration" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Responds to the authentication challenge.
-}
respondToAuthChallenge : RespondToAuthChallengeRequest -> AWS.Http.Request AWS.Http.AWSAppError RespondToAuthChallengeResponse
respondToAuthChallenge req =
    let
        encoder val =
            [ ( "UserContextData", val.userContextData ) |> EncodeOpt.optionalField userContextDataTypeEncoder
            , ( "Session", val.session ) |> EncodeOpt.optionalField Json.Encode.string
            , ( "ClientId", val.clientId ) |> EncodeOpt.field Json.Encode.string
            , ( "ChallengeResponses", val.challengeResponses ) |> EncodeOpt.optionalField challengeResponsesTypeEncoder
            , ( "ChallengeName", val.challengeName ) |> EncodeOpt.field (Codec.encoder challengeNameTypeCodec)
            , ( "AnalyticsMetadata", val.analyticsMetadata ) |> EncodeOpt.optionalField analyticsMetadataTypeEncoder
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\sessionFld challengeParametersFld challengeNameFld authenticationResultFld ->
                { authenticationResult = authenticationResultFld
                , challengeName = challengeNameFld
                , challengeParameters = challengeParametersFld
                , session = sessionFld
                }
             )
                |> Json.Decode.succeed
            )
                |> Pipeline.optional "Session" (Json.Decode.maybe Json.Decode.string) Nothing
                |> Pipeline.optional "ChallengeParameters" (Json.Decode.maybe challengeParametersTypeDecoder) Nothing
                |> Pipeline.optional "ChallengeName" (Json.Decode.maybe (Codec.decoder challengeNameTypeCodec)) Nothing
                |> Pipeline.optional "AuthenticationResult" (Json.Decode.maybe authenticationResultTypeDecoder) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "RespondToAuthChallenge" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Resends the confirmation (for confirmation of registration) to a specific user in the user pool.
-}
resendConfirmationCode : ResendConfirmationCodeRequest -> AWS.Http.Request AWS.Http.AWSAppError ResendConfirmationCodeResponse
resendConfirmationCode req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field Json.Encode.string
            , ( "UserContextData", val.userContextData ) |> EncodeOpt.optionalField userContextDataTypeEncoder
            , ( "SecretHash", val.secretHash ) |> EncodeOpt.optionalField Json.Encode.string
            , ( "ClientId", val.clientId ) |> EncodeOpt.field Json.Encode.string
            , ( "AnalyticsMetadata", val.analyticsMetadata ) |> EncodeOpt.optionalField analyticsMetadataTypeEncoder
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\codeDeliveryDetailsFld -> { codeDeliveryDetails = codeDeliveryDetailsFld }) |> Json.Decode.succeed)
                |> Pipeline.optional "CodeDeliveryDetails" (Json.Decode.maybe codeDeliveryDetailsTypeDecoder) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "ResendConfirmationCode" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Lists the users in the specified group.

Requires developer credentials.

-}
listUsersInGroup : ListUsersInGroupRequest -> AWS.Http.Request AWS.Http.AWSAppError ListUsersInGroupResponse
listUsersInGroup req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "NextToken", val.nextToken ) |> EncodeOpt.optionalField Json.Encode.string
            , ( "Limit", val.limit ) |> EncodeOpt.optionalField Json.Encode.int
            , ( "GroupName", val.groupName ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\usersFld nextTokenFld -> { nextToken = nextTokenFld, users = usersFld }) |> Json.Decode.succeed)
                |> Pipeline.optional "Users" (Json.Decode.maybe usersListTypeDecoder) Nothing
                |> Pipeline.optional "NextToken" (Json.Decode.maybe Json.Decode.string) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "ListUsersInGroup" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Lists the users in the Amazon Cognito user pool.
-}
listUsers : ListUsersRequest -> AWS.Http.Request AWS.Http.AWSAppError ListUsersResponse
listUsers req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "PaginationToken", val.paginationToken ) |> EncodeOpt.optionalField Json.Encode.string
            , ( "Limit", val.limit ) |> EncodeOpt.optionalField Json.Encode.int
            , ( "Filter", val.filter ) |> EncodeOpt.optionalField Json.Encode.string
            , ( "AttributesToGet", val.attributesToGet )
                |> EncodeOpt.optionalField searchedAttributeNamesListTypeEncoder
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\usersFld paginationTokenFld -> { paginationToken = paginationTokenFld, users = usersFld })
                |> Json.Decode.succeed
            )
                |> Pipeline.optional "Users" (Json.Decode.maybe usersListTypeDecoder) Nothing
                |> Pipeline.optional "PaginationToken" (Json.Decode.maybe Json.Decode.string) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "ListUsers" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Lists the user pools associated with an AWS account.
-}
listUserPools : ListUserPoolsRequest -> AWS.Http.Request AWS.Http.AWSAppError ListUserPoolsResponse
listUserPools req =
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
            ((\userPoolsFld nextTokenFld -> { nextToken = nextTokenFld, userPools = userPoolsFld })
                |> Json.Decode.succeed
            )
                |> Pipeline.optional "UserPools" (Json.Decode.maybe userPoolListTypeDecoder) Nothing
                |> Pipeline.optional "NextToken" (Json.Decode.maybe Json.Decode.string) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "ListUserPools" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Lists the clients that have been created for the specified user pool.
-}
listUserPoolClients : ListUserPoolClientsRequest -> AWS.Http.Request AWS.Http.AWSAppError ListUserPoolClientsResponse
listUserPoolClients req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "NextToken", val.nextToken ) |> EncodeOpt.optionalField Json.Encode.string
            , ( "MaxResults", val.maxResults ) |> EncodeOpt.optionalField Json.Encode.int
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\userPoolClientsFld nextTokenFld -> { nextToken = nextTokenFld, userPoolClients = userPoolClientsFld })
                |> Json.Decode.succeed
            )
                |> Pipeline.optional "UserPoolClients" (Json.Decode.maybe userPoolClientListTypeDecoder) Nothing
                |> Pipeline.optional "NextToken" (Json.Decode.maybe Json.Decode.string) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "ListUserPoolClients" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Lists the user import jobs.
-}
listUserImportJobs : ListUserImportJobsRequest -> AWS.Http.Request AWS.Http.AWSAppError ListUserImportJobsResponse
listUserImportJobs req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "PaginationToken", val.paginationToken ) |> EncodeOpt.optionalField Json.Encode.string
            , ( "MaxResults", val.maxResults ) |> EncodeOpt.field Json.Encode.int
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\userImportJobsFld paginationTokenFld ->
                { paginationToken = paginationTokenFld, userImportJobs = userImportJobsFld }
             )
                |> Json.Decode.succeed
            )
                |> Pipeline.optional "UserImportJobs" (Json.Decode.maybe userImportJobsListTypeDecoder) Nothing
                |> Pipeline.optional "PaginationToken" (Json.Decode.maybe Json.Decode.string) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "ListUserImportJobs" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Lists the tags that are assigned to an Amazon Cognito user pool.

A tag is a label that you can apply to user pools to categorize and manage them in different ways, such as by purpose, owner, environment, or other criteria.

You can use this action up to 10 times per second, per account.

-}
listTagsForResource : ListTagsForResourceRequest -> AWS.Http.Request AWS.Http.AWSAppError ListTagsForResourceResponse
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
                |> Pipeline.optional "Tags" (Json.Decode.maybe (Codec.decoder userPoolTagsTypeCodec)) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "ListTagsForResource" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Lists the resource servers for a user pool.
-}
listResourceServers : ListResourceServersRequest -> AWS.Http.Request AWS.Http.AWSAppError ListResourceServersResponse
listResourceServers req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "NextToken", val.nextToken ) |> EncodeOpt.optionalField Json.Encode.string
            , ( "MaxResults", val.maxResults ) |> EncodeOpt.optionalField Json.Encode.int
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\resourceServersFld nextTokenFld -> { nextToken = nextTokenFld, resourceServers = resourceServersFld })
                |> Json.Decode.succeed
            )
                |> Pipeline.required "ResourceServers" resourceServersListTypeDecoder
                |> Pipeline.optional "NextToken" (Json.Decode.maybe Json.Decode.string) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "ListResourceServers" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Lists information about all identity providers for a user pool.
-}
listIdentityProviders : ListIdentityProvidersRequest -> AWS.Http.Request AWS.Http.AWSAppError ListIdentityProvidersResponse
listIdentityProviders req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "NextToken", val.nextToken ) |> EncodeOpt.optionalField Json.Encode.string
            , ( "MaxResults", val.maxResults ) |> EncodeOpt.optionalField Json.Encode.int
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\providersFld nextTokenFld -> { nextToken = nextTokenFld, providers = providersFld })
                |> Json.Decode.succeed
            )
                |> Pipeline.required "Providers" providersListTypeDecoder
                |> Pipeline.optional "NextToken" (Json.Decode.maybe Json.Decode.string) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "ListIdentityProviders" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Lists the groups associated with a user pool.

Requires developer credentials.

-}
listGroups : ListGroupsRequest -> AWS.Http.Request AWS.Http.AWSAppError ListGroupsResponse
listGroups req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "NextToken", val.nextToken ) |> EncodeOpt.optionalField Json.Encode.string
            , ( "Limit", val.limit ) |> EncodeOpt.optionalField Json.Encode.int
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\nextTokenFld groupsFld -> { groups = groupsFld, nextToken = nextTokenFld }) |> Json.Decode.succeed)
                |> Pipeline.optional "NextToken" (Json.Decode.maybe Json.Decode.string) Nothing
                |> Pipeline.optional "Groups" (Json.Decode.maybe groupListTypeDecoder) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "ListGroups" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Lists the devices.
-}
listDevices : ListDevicesRequest -> AWS.Http.Request AWS.Http.AWSAppError ListDevicesResponse
listDevices req =
    let
        encoder val =
            [ ( "PaginationToken", val.paginationToken ) |> EncodeOpt.optionalField Json.Encode.string
            , ( "Limit", val.limit ) |> EncodeOpt.optionalField Json.Encode.int
            , ( "AccessToken", val.accessToken ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\paginationTokenFld devicesFld -> { devices = devicesFld, paginationToken = paginationTokenFld })
                |> Json.Decode.succeed
            )
                |> Pipeline.optional "PaginationToken" (Json.Decode.maybe Json.Decode.string) Nothing
                |> Pipeline.optional "Devices" (Json.Decode.maybe deviceListTypeDecoder) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "ListDevices" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Initiates the authentication flow.
-}
initiateAuth : InitiateAuthRequest -> AWS.Http.Request AWS.Http.AWSAppError InitiateAuthResponse
initiateAuth req =
    let
        encoder val =
            [ ( "UserContextData", val.userContextData ) |> EncodeOpt.optionalField userContextDataTypeEncoder
            , ( "ClientMetadata", val.clientMetadata ) |> EncodeOpt.optionalField clientMetadataTypeEncoder
            , ( "ClientId", val.clientId ) |> EncodeOpt.field Json.Encode.string
            , ( "AuthParameters", val.authParameters ) |> EncodeOpt.optionalField authParametersTypeEncoder
            , ( "AuthFlow", val.authFlow ) |> EncodeOpt.field authFlowTypeEncoder
            , ( "AnalyticsMetadata", val.analyticsMetadata ) |> EncodeOpt.optionalField analyticsMetadataTypeEncoder
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\sessionFld challengeParametersFld challengeNameFld authenticationResultFld ->
                { authenticationResult = authenticationResultFld
                , challengeName = challengeNameFld
                , challengeParameters = challengeParametersFld
                , session = sessionFld
                }
             )
                |> Json.Decode.succeed
            )
                |> Pipeline.optional "Session" (Json.Decode.maybe Json.Decode.string) Nothing
                |> Pipeline.optional "ChallengeParameters" (Json.Decode.maybe challengeParametersTypeDecoder) Nothing
                |> Pipeline.optional "ChallengeName" (Json.Decode.maybe (Codec.decoder challengeNameTypeCodec)) Nothing
                |> Pipeline.optional "AuthenticationResult" (Json.Decode.maybe authenticationResultTypeDecoder) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "InitiateAuth" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Signs out users from all devices.
-}
globalSignOut : GlobalSignOutRequest -> AWS.Http.Request AWS.Http.AWSAppError ()
globalSignOut req =
    let
        encoder val =
            [ ( "AccessToken", val.accessToken ) |> EncodeOpt.field Json.Encode.string ] |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "GlobalSignOut" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Gets the user pool multi-factor authentication (MFA) configuration.
-}
getUserPoolMfaConfig : GetUserPoolMfaConfigRequest -> AWS.Http.Request AWS.Http.AWSAppError GetUserPoolMfaConfigResponse
getUserPoolMfaConfig req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string ] |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\softwareTokenMfaConfigurationFld smsMfaConfigurationFld mfaConfigurationFld ->
                { mfaConfiguration = mfaConfigurationFld
                , smsMfaConfiguration = smsMfaConfigurationFld
                , softwareTokenMfaConfiguration = softwareTokenMfaConfigurationFld
                }
             )
                |> Json.Decode.succeed
            )
                |> Pipeline.optional
                    "SoftwareTokenMfaConfiguration"
                    (Json.Decode.maybe (Codec.decoder softwareTokenMfaConfigTypeCodec))
                    Nothing
                |> Pipeline.optional
                    "SmsMfaConfiguration"
                    (Json.Decode.maybe (Codec.decoder smsMfaConfigTypeCodec))
                    Nothing
                |> Pipeline.optional "MfaConfiguration" (Json.Decode.maybe (Codec.decoder userPoolMfaTypeCodec)) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "GetUserPoolMfaConfig" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Gets the user attribute verification code for the specified attribute name.
-}
getUserAttributeVerificationCode :
    GetUserAttributeVerificationCodeRequest
    -> AWS.Http.Request AWS.Http.AWSAppError GetUserAttributeVerificationCodeResponse
getUserAttributeVerificationCode req =
    let
        encoder val =
            [ ( "AttributeName", val.attributeName ) |> EncodeOpt.field Json.Encode.string
            , ( "AccessToken", val.accessToken ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\codeDeliveryDetailsFld -> { codeDeliveryDetails = codeDeliveryDetailsFld }) |> Json.Decode.succeed)
                |> Pipeline.optional "CodeDeliveryDetails" (Json.Decode.maybe codeDeliveryDetailsTypeDecoder) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "GetUserAttributeVerificationCode" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Gets the user attributes and metadata for a user.
-}
getUser : GetUserRequest -> AWS.Http.Request AWS.Http.AWSAppError GetUserResponse
getUser req =
    let
        encoder val =
            [ ( "AccessToken", val.accessToken ) |> EncodeOpt.field Json.Encode.string ] |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\usernameFld userMfasettingListFld userAttributesFld preferredMfaSettingFld mfaoptionsFld ->
                { mfaoptions = mfaoptionsFld
                , preferredMfaSetting = preferredMfaSettingFld
                , userAttributes = userAttributesFld
                , userMfasettingList = userMfasettingListFld
                , username = usernameFld
                }
             )
                |> Json.Decode.succeed
            )
                |> Pipeline.required "Username" Json.Decode.string
                |> Pipeline.optional "UserMFASettingList" (Json.Decode.maybe userMfasettingListTypeDecoder) Nothing
                |> Pipeline.required "UserAttributes" (Codec.decoder attributeListTypeCodec)
                |> Pipeline.optional "PreferredMfaSetting" (Json.Decode.maybe Json.Decode.string) Nothing
                |> Pipeline.optional "MFAOptions" (Json.Decode.maybe (Codec.decoder mfaoptionListTypeCodec)) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "GetUser" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Gets the UI Customization information for a particular app client's app UI, if there is something set. If nothing is set for the particular client, but there is an existing pool level customization (app `clientId` will be `ALL`), then that is returned. If nothing is present, then an empty shape is returned.
-}
getUicustomization : GetUicustomizationRequest -> AWS.Http.Request AWS.Http.AWSAppError GetUicustomizationResponse
getUicustomization req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "ClientId", val.clientId ) |> EncodeOpt.optionalField Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\uicustomizationFld -> { uicustomization = uicustomizationFld }) |> Json.Decode.succeed)
                |> Pipeline.required "UICustomization" uicustomizationTypeDecoder
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "GetUicustomization" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| This method takes a user pool ID, and returns the signing certificate.
-}
getSigningCertificate : GetSigningCertificateRequest -> AWS.Http.Request AWS.Http.AWSAppError GetSigningCertificateResponse
getSigningCertificate req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string ] |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\certificateFld -> { certificate = certificateFld }) |> Json.Decode.succeed)
                |> Pipeline.optional "Certificate" (Json.Decode.maybe Json.Decode.string) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "GetSigningCertificate" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Gets the specified identity provider.
-}
getIdentityProviderByIdentifier :
    GetIdentityProviderByIdentifierRequest
    -> AWS.Http.Request AWS.Http.AWSAppError GetIdentityProviderByIdentifierResponse
getIdentityProviderByIdentifier req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "IdpIdentifier", val.idpIdentifier ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\identityProviderFld -> { identityProvider = identityProviderFld }) |> Json.Decode.succeed)
                |> Pipeline.required "IdentityProvider" identityProviderTypeDecoder
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "GetIdentityProviderByIdentifier" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Gets a group.

Requires developer credentials.

-}
getGroup : GetGroupRequest -> AWS.Http.Request AWS.Http.AWSAppError GetGroupResponse
getGroup req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "GroupName", val.groupName ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\groupFld -> { group = groupFld }) |> Json.Decode.succeed)
                |> Pipeline.optional "Group" (Json.Decode.maybe groupTypeDecoder) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "GetGroup" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Gets the device.
-}
getDevice : GetDeviceRequest -> AWS.Http.Request AWS.Http.AWSAppError GetDeviceResponse
getDevice req =
    let
        encoder val =
            [ ( "DeviceKey", val.deviceKey ) |> EncodeOpt.field Json.Encode.string
            , ( "AccessToken", val.accessToken ) |> EncodeOpt.optionalField Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\deviceFld -> { device = deviceFld }) |> Json.Decode.succeed)
                |> Pipeline.required "Device" deviceTypeDecoder
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "GetDevice" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Gets the header information for the .csv file to be used as input for the user import job.
-}
getCsvheader : GetCsvheaderRequest -> AWS.Http.Request AWS.Http.AWSAppError GetCsvheaderResponse
getCsvheader req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string ] |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\userPoolIdFld csvheaderFld -> { csvheader = csvheaderFld, userPoolId = userPoolIdFld })
                |> Json.Decode.succeed
            )
                |> Pipeline.optional "UserPoolId" (Json.Decode.maybe Json.Decode.string) Nothing
                |> Pipeline.optional "CSVHeader" (Json.Decode.maybe listOfStringTypesDecoder) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "GetCsvheader" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Calling this API causes a message to be sent to the end user with a confirmation code that is required to change the user's password. For the `Username` parameter, you can use the username or user alias. If a verified phone number exists for the user, the confirmation code is sent to the phone number. Otherwise, if a verified email exists, the confirmation code is sent to the email. If neither a verified phone number nor a verified email exists, `InvalidParameterException` is thrown. To use the confirmation code for resetting the password, call .
-}
forgotPassword : ForgotPasswordRequest -> AWS.Http.Request AWS.Http.AWSAppError ForgotPasswordResponse
forgotPassword req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field Json.Encode.string
            , ( "UserContextData", val.userContextData ) |> EncodeOpt.optionalField userContextDataTypeEncoder
            , ( "SecretHash", val.secretHash ) |> EncodeOpt.optionalField Json.Encode.string
            , ( "ClientId", val.clientId ) |> EncodeOpt.field Json.Encode.string
            , ( "AnalyticsMetadata", val.analyticsMetadata ) |> EncodeOpt.optionalField analyticsMetadataTypeEncoder
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\codeDeliveryDetailsFld -> { codeDeliveryDetails = codeDeliveryDetailsFld }) |> Json.Decode.succeed)
                |> Pipeline.optional "CodeDeliveryDetails" (Json.Decode.maybe codeDeliveryDetailsTypeDecoder) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "ForgotPassword" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Forgets the specified device.
-}
forgetDevice : ForgetDeviceRequest -> AWS.Http.Request AWS.Http.AWSAppError ()
forgetDevice req =
    let
        encoder val =
            [ ( "DeviceKey", val.deviceKey ) |> EncodeOpt.field Json.Encode.string
            , ( "AccessToken", val.accessToken ) |> EncodeOpt.optionalField Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "ForgetDevice" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Gets information about a domain.
-}
describeUserPoolDomain : DescribeUserPoolDomainRequest -> AWS.Http.Request AWS.Http.AWSAppError DescribeUserPoolDomainResponse
describeUserPoolDomain req =
    let
        encoder val =
            [ ( "Domain", val.domain ) |> EncodeOpt.field Json.Encode.string ] |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\domainDescriptionFld -> { domainDescription = domainDescriptionFld }) |> Json.Decode.succeed)
                |> Pipeline.optional "DomainDescription" (Json.Decode.maybe domainDescriptionTypeDecoder) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "DescribeUserPoolDomain" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Client method for returning the configuration information and metadata of the specified user pool app client.
-}
describeUserPoolClient : DescribeUserPoolClientRequest -> AWS.Http.Request AWS.Http.AWSAppError DescribeUserPoolClientResponse
describeUserPoolClient req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "ClientId", val.clientId ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\userPoolClientFld -> { userPoolClient = userPoolClientFld }) |> Json.Decode.succeed)
                |> Pipeline.optional "UserPoolClient" (Json.Decode.maybe userPoolClientTypeDecoder) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "DescribeUserPoolClient" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Returns the configuration information and metadata of the specified user pool.
-}
describeUserPool : DescribeUserPoolRequest -> AWS.Http.Request AWS.Http.AWSAppError DescribeUserPoolResponse
describeUserPool req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string ] |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\userPoolFld -> { userPool = userPoolFld }) |> Json.Decode.succeed)
                |> Pipeline.optional "UserPool" (Json.Decode.maybe userPoolTypeDecoder) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "DescribeUserPool" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Describes the user import job.
-}
describeUserImportJob : DescribeUserImportJobRequest -> AWS.Http.Request AWS.Http.AWSAppError DescribeUserImportJobResponse
describeUserImportJob req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "JobId", val.jobId ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\userImportJobFld -> { userImportJob = userImportJobFld }) |> Json.Decode.succeed)
                |> Pipeline.optional "UserImportJob" (Json.Decode.maybe userImportJobTypeDecoder) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "DescribeUserImportJob" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Describes the risk configuration.
-}
describeRiskConfiguration : DescribeRiskConfigurationRequest -> AWS.Http.Request AWS.Http.AWSAppError DescribeRiskConfigurationResponse
describeRiskConfiguration req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "ClientId", val.clientId ) |> EncodeOpt.optionalField Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\riskConfigurationFld -> { riskConfiguration = riskConfigurationFld }) |> Json.Decode.succeed)
                |> Pipeline.required "RiskConfiguration" riskConfigurationTypeDecoder
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "DescribeRiskConfiguration" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Describes a resource server.
-}
describeResourceServer : DescribeResourceServerRequest -> AWS.Http.Request AWS.Http.AWSAppError DescribeResourceServerResponse
describeResourceServer req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "Identifier", val.identifier ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\resourceServerFld -> { resourceServer = resourceServerFld }) |> Json.Decode.succeed)
                |> Pipeline.required "ResourceServer" resourceServerTypeDecoder
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "DescribeResourceServer" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Gets information about a specific identity provider.
-}
describeIdentityProvider : DescribeIdentityProviderRequest -> AWS.Http.Request AWS.Http.AWSAppError DescribeIdentityProviderResponse
describeIdentityProvider req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "ProviderName", val.providerName ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\identityProviderFld -> { identityProvider = identityProviderFld }) |> Json.Decode.succeed)
                |> Pipeline.required "IdentityProvider" identityProviderTypeDecoder
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "DescribeIdentityProvider" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Deletes a domain for a user pool.
-}
deleteUserPoolDomain : DeleteUserPoolDomainRequest -> AWS.Http.Request AWS.Http.AWSAppError ()
deleteUserPoolDomain req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "Domain", val.domain ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "DeleteUserPoolDomain" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Allows the developer to delete the user pool client.
-}
deleteUserPoolClient : DeleteUserPoolClientRequest -> AWS.Http.Request AWS.Http.AWSAppError ()
deleteUserPoolClient req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "ClientId", val.clientId ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "DeleteUserPoolClient" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Deletes the specified Amazon Cognito user pool.
-}
deleteUserPool : DeleteUserPoolRequest -> AWS.Http.Request AWS.Http.AWSAppError ()
deleteUserPool req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string ] |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "DeleteUserPool" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Deletes the attributes for a user.
-}
deleteUserAttributes : DeleteUserAttributesRequest -> AWS.Http.Request AWS.Http.AWSAppError ()
deleteUserAttributes req =
    let
        encoder val =
            [ ( "UserAttributeNames", val.userAttributeNames ) |> EncodeOpt.field attributeNameListTypeEncoder
            , ( "AccessToken", val.accessToken ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "DeleteUserAttributes" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Allows a user to delete himself or herself.
-}
deleteUser : DeleteUserRequest -> AWS.Http.Request AWS.Http.AWSAppError ()
deleteUser req =
    let
        encoder val =
            [ ( "AccessToken", val.accessToken ) |> EncodeOpt.field Json.Encode.string ] |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "DeleteUser" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Deletes a resource server.
-}
deleteResourceServer : DeleteResourceServerRequest -> AWS.Http.Request AWS.Http.AWSAppError ()
deleteResourceServer req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "Identifier", val.identifier ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "DeleteResourceServer" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Deletes an identity provider for a user pool.
-}
deleteIdentityProvider : DeleteIdentityProviderRequest -> AWS.Http.Request AWS.Http.AWSAppError ()
deleteIdentityProvider req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "ProviderName", val.providerName ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "DeleteIdentityProvider" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Deletes a group. Currently only groups with no members can be deleted.

Requires developer credentials.

-}
deleteGroup : DeleteGroupRequest -> AWS.Http.Request AWS.Http.AWSAppError ()
deleteGroup req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "GroupName", val.groupName ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "DeleteGroup" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Creates a new domain for a user pool.
-}
createUserPoolDomain : CreateUserPoolDomainRequest -> AWS.Http.Request AWS.Http.AWSAppError CreateUserPoolDomainResponse
createUserPoolDomain req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "Domain", val.domain ) |> EncodeOpt.field Json.Encode.string
            , ( "CustomDomainConfig", val.customDomainConfig )
                |> EncodeOpt.optionalField (Codec.encoder customDomainConfigTypeCodec)
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\cloudFrontDomainFld -> { cloudFrontDomain = cloudFrontDomainFld }) |> Json.Decode.succeed)
                |> Pipeline.optional "CloudFrontDomain" (Json.Decode.maybe Json.Decode.string) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "CreateUserPoolDomain" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Creates the user pool client.
-}
createUserPoolClient : CreateUserPoolClientRequest -> AWS.Http.Request AWS.Http.AWSAppError CreateUserPoolClientResponse
createUserPoolClient req =
    let
        encoder val =
            [ ( "WriteAttributes", val.writeAttributes )
                |> EncodeOpt.optionalField (Codec.encoder clientPermissionListTypeCodec)
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "SupportedIdentityProviders", val.supportedIdentityProviders )
                |> EncodeOpt.optionalField (Codec.encoder supportedIdentityProvidersListTypeCodec)
            , ( "RefreshTokenValidity", val.refreshTokenValidity ) |> EncodeOpt.optionalField Json.Encode.int
            , ( "ReadAttributes", val.readAttributes )
                |> EncodeOpt.optionalField (Codec.encoder clientPermissionListTypeCodec)
            , ( "LogoutURLs", val.logoutUrls ) |> EncodeOpt.optionalField (Codec.encoder logoutUrlsListTypeCodec)
            , ( "GenerateSecret", val.generateSecret ) |> EncodeOpt.optionalField Json.Encode.bool
            , ( "ExplicitAuthFlows", val.explicitAuthFlows )
                |> EncodeOpt.optionalField (Codec.encoder explicitAuthFlowsListTypeCodec)
            , ( "DefaultRedirectURI", val.defaultRedirectUri ) |> EncodeOpt.optionalField Json.Encode.string
            , ( "ClientName", val.clientName ) |> EncodeOpt.field Json.Encode.string
            , ( "CallbackURLs", val.callbackUrls ) |> EncodeOpt.optionalField (Codec.encoder callbackUrlsListTypeCodec)
            , ( "AnalyticsConfiguration", val.analyticsConfiguration )
                |> EncodeOpt.optionalField (Codec.encoder analyticsConfigurationTypeCodec)
            , ( "AllowedOAuthScopes", val.allowedOauthScopes )
                |> EncodeOpt.optionalField (Codec.encoder scopeListTypeCodec)
            , ( "AllowedOAuthFlowsUserPoolClient", val.allowedOauthFlowsUserPoolClient )
                |> EncodeOpt.optionalField Json.Encode.bool
            , ( "AllowedOAuthFlows", val.allowedOauthFlows )
                |> EncodeOpt.optionalField (Codec.encoder oauthFlowsTypeCodec)
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\userPoolClientFld -> { userPoolClient = userPoolClientFld }) |> Json.Decode.succeed)
                |> Pipeline.optional "UserPoolClient" (Json.Decode.maybe userPoolClientTypeDecoder) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "CreateUserPoolClient" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Creates a new Amazon Cognito user pool and sets the password policy for the pool.
-}
createUserPool : CreateUserPoolRequest -> AWS.Http.Request AWS.Http.AWSAppError CreateUserPoolResponse
createUserPool req =
    let
        encoder val =
            [ ( "VerificationMessageTemplate", val.verificationMessageTemplate )
                |> EncodeOpt.optionalField (Codec.encoder verificationMessageTemplateTypeCodec)
            , ( "UsernameAttributes", val.usernameAttributes )
                |> EncodeOpt.optionalField (Codec.encoder usernameAttributesListTypeCodec)
            , ( "UserPoolTags", val.userPoolTags ) |> EncodeOpt.optionalField (Codec.encoder userPoolTagsTypeCodec)
            , ( "UserPoolAddOns", val.userPoolAddOns )
                |> EncodeOpt.optionalField (Codec.encoder userPoolAddOnsTypeCodec)
            , ( "SmsVerificationMessage", val.smsVerificationMessage ) |> EncodeOpt.optionalField Json.Encode.string
            , ( "SmsConfiguration", val.smsConfiguration )
                |> EncodeOpt.optionalField (Codec.encoder smsConfigurationTypeCodec)
            , ( "SmsAuthenticationMessage", val.smsAuthenticationMessage ) |> EncodeOpt.optionalField Json.Encode.string
            , ( "Schema", val.schema ) |> EncodeOpt.optionalField (Codec.encoder schemaAttributesListTypeCodec)
            , ( "PoolName", val.poolName ) |> EncodeOpt.field Json.Encode.string
            , ( "Policies", val.policies ) |> EncodeOpt.optionalField (Codec.encoder userPoolPolicyTypeCodec)
            , ( "MfaConfiguration", val.mfaConfiguration )
                |> EncodeOpt.optionalField (Codec.encoder userPoolMfaTypeCodec)
            , ( "LambdaConfig", val.lambdaConfig ) |> EncodeOpt.optionalField (Codec.encoder lambdaConfigTypeCodec)
            , ( "EmailVerificationSubject", val.emailVerificationSubject ) |> EncodeOpt.optionalField Json.Encode.string
            , ( "EmailVerificationMessage", val.emailVerificationMessage ) |> EncodeOpt.optionalField Json.Encode.string
            , ( "EmailConfiguration", val.emailConfiguration )
                |> EncodeOpt.optionalField (Codec.encoder emailConfigurationTypeCodec)
            , ( "DeviceConfiguration", val.deviceConfiguration )
                |> EncodeOpt.optionalField (Codec.encoder deviceConfigurationTypeCodec)
            , ( "AutoVerifiedAttributes", val.autoVerifiedAttributes )
                |> EncodeOpt.optionalField (Codec.encoder verifiedAttributesListTypeCodec)
            , ( "AliasAttributes", val.aliasAttributes )
                |> EncodeOpt.optionalField (Codec.encoder aliasAttributesListTypeCodec)
            , ( "AdminCreateUserConfig", val.adminCreateUserConfig )
                |> EncodeOpt.optionalField (Codec.encoder adminCreateUserConfigTypeCodec)
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\userPoolFld -> { userPool = userPoolFld }) |> Json.Decode.succeed)
                |> Pipeline.optional "UserPool" (Json.Decode.maybe userPoolTypeDecoder) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "CreateUserPool" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Creates the user import job.
-}
createUserImportJob : CreateUserImportJobRequest -> AWS.Http.Request AWS.Http.AWSAppError CreateUserImportJobResponse
createUserImportJob req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "JobName", val.jobName ) |> EncodeOpt.field Json.Encode.string
            , ( "CloudWatchLogsRoleArn", val.cloudWatchLogsRoleArn ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\userImportJobFld -> { userImportJob = userImportJobFld }) |> Json.Decode.succeed)
                |> Pipeline.optional "UserImportJob" (Json.Decode.maybe userImportJobTypeDecoder) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "CreateUserImportJob" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Creates a new OAuth2.0 resource server and defines custom scopes in it.
-}
createResourceServer : CreateResourceServerRequest -> AWS.Http.Request AWS.Http.AWSAppError CreateResourceServerResponse
createResourceServer req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "Scopes", val.scopes ) |> EncodeOpt.optionalField (Codec.encoder resourceServerScopeListTypeCodec)
            , ( "Name", val.name ) |> EncodeOpt.field Json.Encode.string
            , ( "Identifier", val.identifier ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\resourceServerFld -> { resourceServer = resourceServerFld }) |> Json.Decode.succeed)
                |> Pipeline.required "ResourceServer" resourceServerTypeDecoder
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "CreateResourceServer" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Creates an identity provider for a user pool.
-}
createIdentityProvider : CreateIdentityProviderRequest -> AWS.Http.Request AWS.Http.AWSAppError CreateIdentityProviderResponse
createIdentityProvider req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "ProviderType", val.providerType ) |> EncodeOpt.field (Codec.encoder identityProviderTypeTypeCodec)
            , ( "ProviderName", val.providerName ) |> EncodeOpt.field Json.Encode.string
            , ( "ProviderDetails", val.providerDetails ) |> EncodeOpt.field (Codec.encoder providerDetailsTypeCodec)
            , ( "IdpIdentifiers", val.idpIdentifiers )
                |> EncodeOpt.optionalField (Codec.encoder idpIdentifiersListTypeCodec)
            , ( "AttributeMapping", val.attributeMapping )
                |> EncodeOpt.optionalField (Codec.encoder attributeMappingTypeCodec)
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\identityProviderFld -> { identityProvider = identityProviderFld }) |> Json.Decode.succeed)
                |> Pipeline.required "IdentityProvider" identityProviderTypeDecoder
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "CreateIdentityProvider" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Creates a new group in the specified user pool.

Requires developer credentials.

-}
createGroup : CreateGroupRequest -> AWS.Http.Request AWS.Http.AWSAppError CreateGroupResponse
createGroup req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "RoleArn", val.roleArn ) |> EncodeOpt.optionalField Json.Encode.string
            , ( "Precedence", val.precedence ) |> EncodeOpt.optionalField Json.Encode.int
            , ( "GroupName", val.groupName ) |> EncodeOpt.field Json.Encode.string
            , ( "Description", val.description ) |> EncodeOpt.optionalField Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\groupFld -> { group = groupFld }) |> Json.Decode.succeed)
                |> Pipeline.optional "Group" (Json.Decode.maybe groupTypeDecoder) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "CreateGroup" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Confirms registration of a user and handles the existing alias from a previous user.
-}
confirmSignUp : ConfirmSignUpRequest -> AWS.Http.Request AWS.Http.AWSAppError ()
confirmSignUp req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field Json.Encode.string
            , ( "UserContextData", val.userContextData ) |> EncodeOpt.optionalField userContextDataTypeEncoder
            , ( "SecretHash", val.secretHash ) |> EncodeOpt.optionalField Json.Encode.string
            , ( "ForceAliasCreation", val.forceAliasCreation ) |> EncodeOpt.optionalField Json.Encode.bool
            , ( "ConfirmationCode", val.confirmationCode ) |> EncodeOpt.field Json.Encode.string
            , ( "ClientId", val.clientId ) |> EncodeOpt.field Json.Encode.string
            , ( "AnalyticsMetadata", val.analyticsMetadata ) |> EncodeOpt.optionalField analyticsMetadataTypeEncoder
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "ConfirmSignUp" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Allows a user to enter a confirmation code to reset a forgotten password.
-}
confirmForgotPassword : ConfirmForgotPasswordRequest -> AWS.Http.Request AWS.Http.AWSAppError ()
confirmForgotPassword req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field Json.Encode.string
            , ( "UserContextData", val.userContextData ) |> EncodeOpt.optionalField userContextDataTypeEncoder
            , ( "SecretHash", val.secretHash ) |> EncodeOpt.optionalField Json.Encode.string
            , ( "Password", val.password ) |> EncodeOpt.field Json.Encode.string
            , ( "ConfirmationCode", val.confirmationCode ) |> EncodeOpt.field Json.Encode.string
            , ( "ClientId", val.clientId ) |> EncodeOpt.field Json.Encode.string
            , ( "AnalyticsMetadata", val.analyticsMetadata ) |> EncodeOpt.optionalField analyticsMetadataTypeEncoder
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "ConfirmForgotPassword" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Confirms tracking of the device. This API call is the call that begins device tracking.
-}
confirmDevice : ConfirmDeviceRequest -> AWS.Http.Request AWS.Http.AWSAppError ConfirmDeviceResponse
confirmDevice req =
    let
        encoder val =
            [ ( "DeviceSecretVerifierConfig", val.deviceSecretVerifierConfig )
                |> EncodeOpt.optionalField deviceSecretVerifierConfigTypeEncoder
            , ( "DeviceName", val.deviceName ) |> EncodeOpt.optionalField Json.Encode.string
            , ( "DeviceKey", val.deviceKey ) |> EncodeOpt.field Json.Encode.string
            , ( "AccessToken", val.accessToken ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\userConfirmationNecessaryFld -> { userConfirmationNecessary = userConfirmationNecessaryFld })
                |> Json.Decode.succeed
            )
                |> Pipeline.optional "UserConfirmationNecessary" (Json.Decode.maybe Json.Decode.bool) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "ConfirmDevice" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Changes the password for a specified user in a user pool.
-}
changePassword : ChangePasswordRequest -> AWS.Http.Request AWS.Http.AWSAppError ()
changePassword req =
    let
        encoder val =
            [ ( "ProposedPassword", val.proposedPassword ) |> EncodeOpt.field Json.Encode.string
            , ( "PreviousPassword", val.previousPassword ) |> EncodeOpt.field Json.Encode.string
            , ( "AccessToken", val.accessToken ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "ChangePassword" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Returns a unique generated shared secret key code for the user account. The request takes an access token or a session string, but not both.
-}
associateSoftwareToken : AssociateSoftwareTokenRequest -> AWS.Http.Request AWS.Http.AWSAppError AssociateSoftwareTokenResponse
associateSoftwareToken req =
    let
        encoder val =
            [ ( "Session", val.session ) |> EncodeOpt.optionalField Json.Encode.string
            , ( "AccessToken", val.accessToken ) |> EncodeOpt.optionalField Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\sessionFld secretCodeFld -> { secretCode = secretCodeFld, session = sessionFld }) |> Json.Decode.succeed)
                |> Pipeline.optional "Session" (Json.Decode.maybe Json.Decode.string) Nothing
                |> Pipeline.optional "SecretCode" (Json.Decode.maybe Json.Decode.string) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "AssociateSoftwareToken" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Signs out users from all devices, as an administrator.

Requires developer credentials.

-}
adminUserGlobalSignOut : AdminUserGlobalSignOutRequest -> AWS.Http.Request AWS.Http.AWSAppError ()
adminUserGlobalSignOut req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field Json.Encode.string
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "AdminUserGlobalSignOut" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Updates the specified user's attributes, including developer attributes, as an administrator. Works on any user.

For custom attributes, you must prepend the `custom:` prefix to the attribute name.

In addition to updating user attributes, this API can also be used to mark phone and email as verified.

Requires developer credentials.

-}
adminUpdateUserAttributes : AdminUpdateUserAttributesRequest -> AWS.Http.Request AWS.Http.AWSAppError ()
adminUpdateUserAttributes req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field Json.Encode.string
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "UserAttributes", val.userAttributes ) |> EncodeOpt.field (Codec.encoder attributeListTypeCodec)
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "AdminUpdateUserAttributes" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Updates the device status as an administrator.

Requires developer credentials.

-}
adminUpdateDeviceStatus : AdminUpdateDeviceStatusRequest -> AWS.Http.Request AWS.Http.AWSAppError ()
adminUpdateDeviceStatus req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field Json.Encode.string
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "DeviceRememberedStatus", val.deviceRememberedStatus )
                |> EncodeOpt.optionalField deviceRememberedStatusTypeEncoder
            , ( "DeviceKey", val.deviceKey ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "AdminUpdateDeviceStatus" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Provides feedback for an authentication event as to whether it was from a valid user. This feedback is used for improving the risk evaluation decision for the user pool as part of Amazon Cognito advanced security.
-}
adminUpdateAuthEventFeedback : AdminUpdateAuthEventFeedbackRequest -> AWS.Http.Request AWS.Http.AWSAppError ()
adminUpdateAuthEventFeedback req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field Json.Encode.string
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "FeedbackValue", val.feedbackValue ) |> EncodeOpt.field (Codec.encoder feedbackValueTypeCodec)
            , ( "EventId", val.eventId ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "AdminUpdateAuthEventFeedback" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Sets all the user settings for a specified user name. Works on any user.

Requires developer credentials.

-}
adminSetUserSettings : AdminSetUserSettingsRequest -> AWS.Http.Request AWS.Http.AWSAppError ()
adminSetUserSettings req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field Json.Encode.string
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "MFAOptions", val.mfaoptions ) |> EncodeOpt.field (Codec.encoder mfaoptionListTypeCodec)
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "AdminSetUserSettings" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| -}
adminSetUserPassword : AdminSetUserPasswordRequest -> AWS.Http.Request AWS.Http.AWSAppError ()
adminSetUserPassword req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field Json.Encode.string
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "Permanent", val.permanent ) |> EncodeOpt.optionalField Json.Encode.bool
            , ( "Password", val.password ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "AdminSetUserPassword" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Sets the user's multi-factor authentication (MFA) preference.
-}
adminSetUserMfapreference : AdminSetUserMfapreferenceRequest -> AWS.Http.Request AWS.Http.AWSAppError ()
adminSetUserMfapreference req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field Json.Encode.string
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "SoftwareTokenMfaSettings", val.softwareTokenMfaSettings )
                |> EncodeOpt.optionalField softwareTokenMfaSettingsTypeEncoder
            , ( "SMSMfaSettings", val.smsmfaSettings ) |> EncodeOpt.optionalField smsmfaSettingsTypeEncoder
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "AdminSetUserMfapreference" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Responds to an authentication challenge, as an administrator.

Requires developer credentials.

-}
adminRespondToAuthChallenge : AdminRespondToAuthChallengeRequest -> AWS.Http.Request AWS.Http.AWSAppError AdminRespondToAuthChallengeResponse
adminRespondToAuthChallenge req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "Session", val.session ) |> EncodeOpt.optionalField Json.Encode.string
            , ( "ContextData", val.contextData ) |> EncodeOpt.optionalField contextDataTypeEncoder
            , ( "ClientId", val.clientId ) |> EncodeOpt.field Json.Encode.string
            , ( "ChallengeResponses", val.challengeResponses ) |> EncodeOpt.optionalField challengeResponsesTypeEncoder
            , ( "ChallengeName", val.challengeName ) |> EncodeOpt.field (Codec.encoder challengeNameTypeCodec)
            , ( "AnalyticsMetadata", val.analyticsMetadata ) |> EncodeOpt.optionalField analyticsMetadataTypeEncoder
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\sessionFld challengeParametersFld challengeNameFld authenticationResultFld ->
                { authenticationResult = authenticationResultFld
                , challengeName = challengeNameFld
                , challengeParameters = challengeParametersFld
                , session = sessionFld
                }
             )
                |> Json.Decode.succeed
            )
                |> Pipeline.optional "Session" (Json.Decode.maybe Json.Decode.string) Nothing
                |> Pipeline.optional "ChallengeParameters" (Json.Decode.maybe challengeParametersTypeDecoder) Nothing
                |> Pipeline.optional "ChallengeName" (Json.Decode.maybe (Codec.decoder challengeNameTypeCodec)) Nothing
                |> Pipeline.optional "AuthenticationResult" (Json.Decode.maybe authenticationResultTypeDecoder) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "AdminRespondToAuthChallenge" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Resets the specified user's password in a user pool as an administrator. Works on any user.

When a developer calls this API, the current password is invalidated, so it must be changed. If a user tries to sign in after the API is called, the app will get a PasswordResetRequiredException exception back and should direct the user down the flow to reset the password, which is the same as the forgot password flow. In addition, if the user pool has phone verification selected and a verified phone number exists for the user, or if email verification is selected and a verified email exists for the user, calling this API will also result in sending a message to the end user with the code to change their password.

Requires developer credentials.

-}
adminResetUserPassword : AdminResetUserPasswordRequest -> AWS.Http.Request AWS.Http.AWSAppError ()
adminResetUserPassword req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field Json.Encode.string
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "AdminResetUserPassword" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Removes the specified user from the specified group.

Requires developer credentials.

-}
adminRemoveUserFromGroup : AdminRemoveUserFromGroupRequest -> AWS.Http.Request AWS.Http.AWSAppError ()
adminRemoveUserFromGroup req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field Json.Encode.string
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "GroupName", val.groupName ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "AdminRemoveUserFromGroup" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Lists a history of user activity and any risks detected as part of Amazon Cognito advanced security.
-}
adminListUserAuthEvents : AdminListUserAuthEventsRequest -> AWS.Http.Request AWS.Http.AWSAppError AdminListUserAuthEventsResponse
adminListUserAuthEvents req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field Json.Encode.string
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "NextToken", val.nextToken ) |> EncodeOpt.optionalField Json.Encode.string
            , ( "MaxResults", val.maxResults ) |> EncodeOpt.optionalField Json.Encode.int
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\nextTokenFld authEventsFld -> { authEvents = authEventsFld, nextToken = nextTokenFld })
                |> Json.Decode.succeed
            )
                |> Pipeline.optional "NextToken" (Json.Decode.maybe Json.Decode.string) Nothing
                |> Pipeline.optional "AuthEvents" (Json.Decode.maybe authEventsTypeDecoder) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "AdminListUserAuthEvents" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Lists the groups that the user belongs to.

Requires developer credentials.

-}
adminListGroupsForUser : AdminListGroupsForUserRequest -> AWS.Http.Request AWS.Http.AWSAppError AdminListGroupsForUserResponse
adminListGroupsForUser req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field Json.Encode.string
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "NextToken", val.nextToken ) |> EncodeOpt.optionalField Json.Encode.string
            , ( "Limit", val.limit ) |> EncodeOpt.optionalField Json.Encode.int
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\nextTokenFld groupsFld -> { groups = groupsFld, nextToken = nextTokenFld }) |> Json.Decode.succeed)
                |> Pipeline.optional "NextToken" (Json.Decode.maybe Json.Decode.string) Nothing
                |> Pipeline.optional "Groups" (Json.Decode.maybe groupListTypeDecoder) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "AdminListGroupsForUser" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Lists devices, as an administrator.

Requires developer credentials.

-}
adminListDevices : AdminListDevicesRequest -> AWS.Http.Request AWS.Http.AWSAppError AdminListDevicesResponse
adminListDevices req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field Json.Encode.string
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "PaginationToken", val.paginationToken ) |> EncodeOpt.optionalField Json.Encode.string
            , ( "Limit", val.limit ) |> EncodeOpt.optionalField Json.Encode.int
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\paginationTokenFld devicesFld -> { devices = devicesFld, paginationToken = paginationTokenFld })
                |> Json.Decode.succeed
            )
                |> Pipeline.optional "PaginationToken" (Json.Decode.maybe Json.Decode.string) Nothing
                |> Pipeline.optional "Devices" (Json.Decode.maybe deviceListTypeDecoder) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "AdminListDevices" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Links an existing user account in a user pool (`DestinationUser`) to an identity from an external identity provider (`SourceUser`) based on a specified attribute name and value from the external identity provider. This allows you to create a link from the existing user account to an external federated user identity that has not yet been used to sign in, so that the federated user identity can be used to sign in as the existing user account.

For example, if there is an existing user with a username and password, this API links that user to a federated user identity, so that when the federated user identity is used, the user signs in as the existing user account.

Because this API allows a user with an external federated identity to sign in as an existing user in the user pool, it is critical that it only be used with external identity providers and provider attributes that have been trusted by the application owner.

See also .

This action is enabled only for admin access and requires developer credentials.

-}
adminLinkProviderForUser : AdminLinkProviderForUserRequest -> AWS.Http.Request AWS.Http.AWSAppError ()
adminLinkProviderForUser req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "SourceUser", val.sourceUser ) |> EncodeOpt.field providerUserIdentifierTypeEncoder
            , ( "DestinationUser", val.destinationUser ) |> EncodeOpt.field providerUserIdentifierTypeEncoder
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "AdminLinkProviderForUser" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Initiates the authentication flow, as an administrator.

Requires developer credentials.

-}
adminInitiateAuth : AdminInitiateAuthRequest -> AWS.Http.Request AWS.Http.AWSAppError AdminInitiateAuthResponse
adminInitiateAuth req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "ContextData", val.contextData ) |> EncodeOpt.optionalField contextDataTypeEncoder
            , ( "ClientMetadata", val.clientMetadata ) |> EncodeOpt.optionalField clientMetadataTypeEncoder
            , ( "ClientId", val.clientId ) |> EncodeOpt.field Json.Encode.string
            , ( "AuthParameters", val.authParameters ) |> EncodeOpt.optionalField authParametersTypeEncoder
            , ( "AuthFlow", val.authFlow ) |> EncodeOpt.field authFlowTypeEncoder
            , ( "AnalyticsMetadata", val.analyticsMetadata ) |> EncodeOpt.optionalField analyticsMetadataTypeEncoder
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\sessionFld challengeParametersFld challengeNameFld authenticationResultFld ->
                { authenticationResult = authenticationResultFld
                , challengeName = challengeNameFld
                , challengeParameters = challengeParametersFld
                , session = sessionFld
                }
             )
                |> Json.Decode.succeed
            )
                |> Pipeline.optional "Session" (Json.Decode.maybe Json.Decode.string) Nothing
                |> Pipeline.optional "ChallengeParameters" (Json.Decode.maybe challengeParametersTypeDecoder) Nothing
                |> Pipeline.optional "ChallengeName" (Json.Decode.maybe (Codec.decoder challengeNameTypeCodec)) Nothing
                |> Pipeline.optional "AuthenticationResult" (Json.Decode.maybe authenticationResultTypeDecoder) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "AdminInitiateAuth" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Gets the specified user by user name in a user pool as an administrator. Works on any user.

Requires developer credentials.

-}
adminGetUser : AdminGetUserRequest -> AWS.Http.Request AWS.Http.AWSAppError AdminGetUserResponse
adminGetUser req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field Json.Encode.string
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\usernameFld userStatusFld userMfasettingListFld userLastModifiedDateFld userCreateDateFld userAttributesFld preferredMfaSettingFld mfaoptionsFld enabledFld ->
                { enabled = enabledFld
                , mfaoptions = mfaoptionsFld
                , preferredMfaSetting = preferredMfaSettingFld
                , userAttributes = userAttributesFld
                , userCreateDate = userCreateDateFld
                , userLastModifiedDate = userLastModifiedDateFld
                , userMfasettingList = userMfasettingListFld
                , userStatus = userStatusFld
                , username = usernameFld
                }
             )
                |> Json.Decode.succeed
            )
                |> Pipeline.required "Username" Json.Decode.string
                |> Pipeline.optional "UserStatus" (Json.Decode.maybe userStatusTypeDecoder) Nothing
                |> Pipeline.optional "UserMFASettingList" (Json.Decode.maybe userMfasettingListTypeDecoder) Nothing
                |> Pipeline.optional "UserLastModifiedDate" (Json.Decode.maybe Json.Decode.string) Nothing
                |> Pipeline.optional "UserCreateDate" (Json.Decode.maybe Json.Decode.string) Nothing
                |> Pipeline.optional "UserAttributes" (Json.Decode.maybe (Codec.decoder attributeListTypeCodec)) Nothing
                |> Pipeline.optional "PreferredMfaSetting" (Json.Decode.maybe Json.Decode.string) Nothing
                |> Pipeline.optional "MFAOptions" (Json.Decode.maybe (Codec.decoder mfaoptionListTypeCodec)) Nothing
                |> Pipeline.optional "Enabled" (Json.Decode.maybe Json.Decode.bool) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "AdminGetUser" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Gets the device, as an administrator.

Requires developer credentials.

-}
adminGetDevice : AdminGetDeviceRequest -> AWS.Http.Request AWS.Http.AWSAppError AdminGetDeviceResponse
adminGetDevice req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field Json.Encode.string
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "DeviceKey", val.deviceKey ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\deviceFld -> { device = deviceFld }) |> Json.Decode.succeed)
                |> Pipeline.required "Device" deviceTypeDecoder
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "AdminGetDevice" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Forgets the device, as an administrator.

Requires developer credentials.

-}
adminForgetDevice : AdminForgetDeviceRequest -> AWS.Http.Request AWS.Http.AWSAppError ()
adminForgetDevice req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field Json.Encode.string
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "DeviceKey", val.deviceKey ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "AdminForgetDevice" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Enables the specified user as an administrator. Works on any user.

Requires developer credentials.

-}
adminEnableUser : AdminEnableUserRequest -> AWS.Http.Request AWS.Http.AWSAppError ()
adminEnableUser req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field Json.Encode.string
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "AdminEnableUser" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Disables the specified user as an administrator. Works on any user.

Requires developer credentials.

-}
adminDisableUser : AdminDisableUserRequest -> AWS.Http.Request AWS.Http.AWSAppError ()
adminDisableUser req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field Json.Encode.string
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "AdminDisableUser" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Disables the user from signing in with the specified external (SAML or social) identity provider. If the user to disable is a Cognito User Pools native username + password user, they are not permitted to use their password to sign-in. If the user to disable is a linked external IdP user, any link between that user and an existing user is removed. The next time the external user (no longer attached to the previously linked `DestinationUser`) signs in, they must create a new user account. See .

This action is enabled only for admin access and requires developer credentials.

The `ProviderName` must match the value specified when creating an IdP for the pool.

To disable a native username + password user, the `ProviderName` value must be `Cognito` and the `ProviderAttributeName` must be `Cognito_Subject`, with the `ProviderAttributeValue` being the name that is used in the user pool for the user.

The `ProviderAttributeName` must always be `Cognito_Subject` for social identity providers. The `ProviderAttributeValue` must always be the exact subject that was used when the user was originally linked as a source user.

For de-linking a SAML identity, there are two scenarios. If the linked identity has not yet been used to sign-in, the `ProviderAttributeName` and `ProviderAttributeValue` must be the same values that were used for the `SourceUser` when the identities were originally linked in the call. (If the linking was done with `ProviderAttributeName` set to `Cognito_Subject`, the same applies here). However, if the user has already signed in, the `ProviderAttributeName` must be `Cognito_Subject` and `ProviderAttributeValue` must be the subject of the SAML assertion.

-}
adminDisableProviderForUser : AdminDisableProviderForUserRequest -> AWS.Http.Request AWS.Http.AWSAppError ()
adminDisableProviderForUser req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "User", val.user ) |> EncodeOpt.field providerUserIdentifierTypeEncoder
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "AdminDisableProviderForUser" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Deletes the user attributes in a user pool as an administrator. Works on any user.

Requires developer credentials.

-}
adminDeleteUserAttributes : AdminDeleteUserAttributesRequest -> AWS.Http.Request AWS.Http.AWSAppError ()
adminDeleteUserAttributes req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field Json.Encode.string
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "UserAttributeNames", val.userAttributeNames ) |> EncodeOpt.field attributeNameListTypeEncoder
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "AdminDeleteUserAttributes" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Deletes a user as an administrator. Works on any user.

Requires developer credentials.

-}
adminDeleteUser : AdminDeleteUserRequest -> AWS.Http.Request AWS.Http.AWSAppError ()
adminDeleteUser req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field Json.Encode.string
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "AdminDeleteUser" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Creates a new user in the specified user pool.

If `MessageAction` is not set, the default is to send a welcome message via email or phone (SMS).

This message is based on a template that you configured in your call to or . This template includes your custom sign-up instructions and placeholders for user name and temporary password.

Alternatively, you can call AdminCreateUser with “SUPPRESS” for the `MessageAction` parameter, and Amazon Cognito will not send any email.

In either case, the user will be in the `FORCE_CHANGE_PASSWORD` state until they sign in and change their password.

AdminCreateUser requires developer credentials.

-}
adminCreateUser : AdminCreateUserRequest -> AWS.Http.Request AWS.Http.AWSAppError AdminCreateUserResponse
adminCreateUser req =
    let
        encoder val =
            [ ( "ValidationData", val.validationData ) |> EncodeOpt.optionalField (Codec.encoder attributeListTypeCodec)
            , ( "Username", val.username ) |> EncodeOpt.field Json.Encode.string
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "UserAttributes", val.userAttributes ) |> EncodeOpt.optionalField (Codec.encoder attributeListTypeCodec)
            , ( "TemporaryPassword", val.temporaryPassword ) |> EncodeOpt.optionalField Json.Encode.string
            , ( "MessageAction", val.messageAction ) |> EncodeOpt.optionalField messageActionTypeEncoder
            , ( "ForceAliasCreation", val.forceAliasCreation ) |> EncodeOpt.optionalField Json.Encode.bool
            , ( "DesiredDeliveryMediums", val.desiredDeliveryMediums )
                |> EncodeOpt.optionalField deliveryMediumListTypeEncoder
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\userFld -> { user = userFld }) |> Json.Decode.succeed)
                |> Pipeline.optional "User" (Json.Decode.maybe userTypeDecoder) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "AdminCreateUser" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Confirms user registration as an admin without using a confirmation code. Works on any user.

Requires developer credentials.

-}
adminConfirmSignUp : AdminConfirmSignUpRequest -> AWS.Http.Request AWS.Http.AWSAppError ()
adminConfirmSignUp req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field Json.Encode.string
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "AdminConfirmSignUp" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Adds the specified user to the specified group.

Requires developer credentials.

-}
adminAddUserToGroup : AdminAddUserToGroupRequest -> AWS.Http.Request AWS.Http.AWSAppError ()
adminAddUserToGroup req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field Json.Encode.string
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "GroupName", val.groupName ) |> EncodeOpt.field Json.Encode.string
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "AdminAddUserToGroup" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| Adds additional user attributes to the user pool schema.
-}
addCustomAttributes : AddCustomAttributesRequest -> AWS.Http.Request AWS.Http.AWSAppError ()
addCustomAttributes req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field Json.Encode.string
            , ( "CustomAttributes", val.customAttributes ) |> EncodeOpt.field customAttributesListTypeEncoder
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "AddCustomAttributes" AWS.Http.POST url jsonBody decoder AWS.Http.awsAppErrDecoder


{-| The VerifyUserAttributeResponse data model.
-}
type alias VerifyUserAttributeResponse =
    {}


{-| The VerifyUserAttributeRequest data model.
-}
type alias VerifyUserAttributeRequest =
    { accessToken : String, attributeName : String, code : String }


{-| The VerifySoftwareTokenResponseType data model.
-}
type VerifySoftwareTokenResponseType
    = VerifySoftwareTokenResponseTypeSuccess
    | VerifySoftwareTokenResponseTypeError


{-| The VerifySoftwareTokenResponseType data model.
-}
verifySoftwareTokenResponseType : Enum VerifySoftwareTokenResponseType
verifySoftwareTokenResponseType =
    Enum.define
        [ VerifySoftwareTokenResponseTypeSuccess, VerifySoftwareTokenResponseTypeError ]
        (\val ->
            case val of
                VerifySoftwareTokenResponseTypeSuccess ->
                    "SUCCESS"

                VerifySoftwareTokenResponseTypeError ->
                    "ERROR"
        )


{-| The VerifySoftwareTokenResponse data model.
-}
type alias VerifySoftwareTokenResponse =
    { session : Maybe String, status : Maybe VerifySoftwareTokenResponseType }


{-| The VerifySoftwareTokenRequest data model.
-}
type alias VerifySoftwareTokenRequest =
    { accessToken : Maybe String, friendlyDeviceName : Maybe String, session : Maybe String, userCode : String }


{-| The VerifiedAttributesListType data model.
-}
type alias VerifiedAttributesListType =
    List VerifiedAttributeType


{-| The VerifiedAttributeType data model.
-}
type VerifiedAttributeType
    = VerifiedAttributeTypePhoneNumber
    | VerifiedAttributeTypeEmail


{-| The VerifiedAttributeType data model.
-}
verifiedAttributeType : Enum VerifiedAttributeType
verifiedAttributeType =
    Enum.define
        [ VerifiedAttributeTypePhoneNumber, VerifiedAttributeTypeEmail ]
        (\val ->
            case val of
                VerifiedAttributeTypePhoneNumber ->
                    "phone_number"

                VerifiedAttributeTypeEmail ->
                    "email"
        )


{-| The VerificationMessageTemplateType data model.
-}
type alias VerificationMessageTemplateType =
    { defaultEmailOption : Maybe DefaultEmailOptionType
    , emailMessage : Maybe String
    , emailMessageByLink : Maybe String
    , emailSubject : Maybe String
    , emailSubjectByLink : Maybe String
    , smsMessage : Maybe String
    }


{-| The UsersListType data model.
-}
type alias UsersListType =
    List UserType


{-| The UsernameAttributesListType data model.
-}
type alias UsernameAttributesListType =
    List UsernameAttributeType


{-| The UsernameAttributeType data model.
-}
type UsernameAttributeType
    = UsernameAttributeTypePhoneNumber
    | UsernameAttributeTypeEmail


{-| The UsernameAttributeType data model.
-}
usernameAttributeType : Enum UsernameAttributeType
usernameAttributeType =
    Enum.define
        [ UsernameAttributeTypePhoneNumber, UsernameAttributeTypeEmail ]
        (\val ->
            case val of
                UsernameAttributeTypePhoneNumber ->
                    "phone_number"

                UsernameAttributeTypeEmail ->
                    "email"
        )


{-| The UserType data model.
-}
type alias UserType =
    { attributes : Maybe AttributeListType
    , enabled : Maybe Bool
    , mfaoptions : Maybe MfaoptionListType
    , userCreateDate : Maybe String
    , userLastModifiedDate : Maybe String
    , userStatus : Maybe UserStatusType
    , username : Maybe String
    }


{-| The UserStatusType data model.
-}
type UserStatusType
    = UserStatusTypeUnconfirmed
    | UserStatusTypeConfirmed
    | UserStatusTypeArchived
    | UserStatusTypeCompromised
    | UserStatusTypeUnknown
    | UserStatusTypeResetRequired
    | UserStatusTypeForceChangePassword


{-| The UserStatusType data model.
-}
userStatusType : Enum UserStatusType
userStatusType =
    Enum.define
        [ UserStatusTypeUnconfirmed
        , UserStatusTypeConfirmed
        , UserStatusTypeArchived
        , UserStatusTypeCompromised
        , UserStatusTypeUnknown
        , UserStatusTypeResetRequired
        , UserStatusTypeForceChangePassword
        ]
        (\val ->
            case val of
                UserStatusTypeUnconfirmed ->
                    "UNCONFIRMED"

                UserStatusTypeConfirmed ->
                    "CONFIRMED"

                UserStatusTypeArchived ->
                    "ARCHIVED"

                UserStatusTypeCompromised ->
                    "COMPROMISED"

                UserStatusTypeUnknown ->
                    "UNKNOWN"

                UserStatusTypeResetRequired ->
                    "RESET_REQUIRED"

                UserStatusTypeForceChangePassword ->
                    "FORCE_CHANGE_PASSWORD"
        )


{-| The UserPoolType data model.
-}
type alias UserPoolType =
    { adminCreateUserConfig : Maybe AdminCreateUserConfigType
    , aliasAttributes : Maybe AliasAttributesListType
    , arn : Maybe String
    , autoVerifiedAttributes : Maybe VerifiedAttributesListType
    , creationDate : Maybe String
    , customDomain : Maybe String
    , deviceConfiguration : Maybe DeviceConfigurationType
    , domain : Maybe String
    , emailConfiguration : Maybe EmailConfigurationType
    , emailConfigurationFailure : Maybe String
    , emailVerificationMessage : Maybe String
    , emailVerificationSubject : Maybe String
    , estimatedNumberOfUsers : Maybe Int
    , id : Maybe String
    , lambdaConfig : Maybe LambdaConfigType
    , lastModifiedDate : Maybe String
    , mfaConfiguration : Maybe UserPoolMfaType
    , name : Maybe String
    , policies : Maybe UserPoolPolicyType
    , schemaAttributes : Maybe SchemaAttributesListType
    , smsAuthenticationMessage : Maybe String
    , smsConfiguration : Maybe SmsConfigurationType
    , smsConfigurationFailure : Maybe String
    , smsVerificationMessage : Maybe String
    , status : Maybe StatusType
    , userPoolAddOns : Maybe UserPoolAddOnsType
    , userPoolTags : Maybe UserPoolTagsType
    , usernameAttributes : Maybe UsernameAttributesListType
    , verificationMessageTemplate : Maybe VerificationMessageTemplateType
    }


{-| The UserPoolTagsType data model.
-}
type alias UserPoolTagsType =
    Dict String String


{-| The UserPoolTagsListType data model.
-}
type alias UserPoolTagsListType =
    List String


{-| The UserPoolPolicyType data model.
-}
type alias UserPoolPolicyType =
    { passwordPolicy : Maybe PasswordPolicyType }


{-| The UserPoolMfaType data model.
-}
type UserPoolMfaType
    = UserPoolMfaTypeOff
    | UserPoolMfaTypeOn
    | UserPoolMfaTypeOptional


{-| The UserPoolMfaType data model.
-}
userPoolMfaType : Enum UserPoolMfaType
userPoolMfaType =
    Enum.define
        [ UserPoolMfaTypeOff, UserPoolMfaTypeOn, UserPoolMfaTypeOptional ]
        (\val ->
            case val of
                UserPoolMfaTypeOff ->
                    "OFF"

                UserPoolMfaTypeOn ->
                    "ON"

                UserPoolMfaTypeOptional ->
                    "OPTIONAL"
        )


{-| The UserPoolListType data model.
-}
type alias UserPoolListType =
    List UserPoolDescriptionType


{-| The UserPoolDescriptionType data model.
-}
type alias UserPoolDescriptionType =
    { creationDate : Maybe String
    , id : Maybe String
    , lambdaConfig : Maybe LambdaConfigType
    , lastModifiedDate : Maybe String
    , name : Maybe String
    , status : Maybe StatusType
    }


{-| The UserPoolClientType data model.
-}
type alias UserPoolClientType =
    { allowedOauthFlows : Maybe OauthFlowsType
    , allowedOauthFlowsUserPoolClient : Maybe Bool
    , allowedOauthScopes : Maybe ScopeListType
    , analyticsConfiguration : Maybe AnalyticsConfigurationType
    , callbackUrls : Maybe CallbackUrlsListType
    , clientId : Maybe String
    , clientName : Maybe String
    , clientSecret : Maybe String
    , creationDate : Maybe String
    , defaultRedirectUri : Maybe String
    , explicitAuthFlows : Maybe ExplicitAuthFlowsListType
    , lastModifiedDate : Maybe String
    , logoutUrls : Maybe LogoutUrlsListType
    , readAttributes : Maybe ClientPermissionListType
    , refreshTokenValidity : Maybe Int
    , supportedIdentityProviders : Maybe SupportedIdentityProvidersListType
    , userPoolId : Maybe String
    , writeAttributes : Maybe ClientPermissionListType
    }


{-| The UserPoolClientListType data model.
-}
type alias UserPoolClientListType =
    List UserPoolClientDescription


{-| The UserPoolClientDescription data model.
-}
type alias UserPoolClientDescription =
    { clientId : Maybe String, clientName : Maybe String, userPoolId : Maybe String }


{-| The UserPoolAddOnsType data model.
-}
type alias UserPoolAddOnsType =
    { advancedSecurityMode : AdvancedSecurityModeType }


{-| The UserMfasettingListType data model.
-}
type alias UserMfasettingListType =
    List String


{-| The UserImportJobsListType data model.
-}
type alias UserImportJobsListType =
    List UserImportJobType


{-| The UserImportJobType data model.
-}
type alias UserImportJobType =
    { cloudWatchLogsRoleArn : Maybe String
    , completionDate : Maybe String
    , completionMessage : Maybe String
    , creationDate : Maybe String
    , failedUsers : Maybe Int
    , importedUsers : Maybe Int
    , jobId : Maybe String
    , jobName : Maybe String
    , preSignedUrl : Maybe String
    , skippedUsers : Maybe Int
    , startDate : Maybe String
    , status : Maybe UserImportJobStatusType
    , userPoolId : Maybe String
    }


{-| The UserImportJobStatusType data model.
-}
type UserImportJobStatusType
    = UserImportJobStatusTypeCreated
    | UserImportJobStatusTypePending
    | UserImportJobStatusTypeInProgress
    | UserImportJobStatusTypeStopping
    | UserImportJobStatusTypeExpired
    | UserImportJobStatusTypeStopped
    | UserImportJobStatusTypeFailed
    | UserImportJobStatusTypeSucceeded


{-| The UserImportJobStatusType data model.
-}
userImportJobStatusType : Enum UserImportJobStatusType
userImportJobStatusType =
    Enum.define
        [ UserImportJobStatusTypeCreated
        , UserImportJobStatusTypePending
        , UserImportJobStatusTypeInProgress
        , UserImportJobStatusTypeStopping
        , UserImportJobStatusTypeExpired
        , UserImportJobStatusTypeStopped
        , UserImportJobStatusTypeFailed
        , UserImportJobStatusTypeSucceeded
        ]
        (\val ->
            case val of
                UserImportJobStatusTypeCreated ->
                    "Created"

                UserImportJobStatusTypePending ->
                    "Pending"

                UserImportJobStatusTypeInProgress ->
                    "InProgress"

                UserImportJobStatusTypeStopping ->
                    "Stopping"

                UserImportJobStatusTypeExpired ->
                    "Expired"

                UserImportJobStatusTypeStopped ->
                    "Stopped"

                UserImportJobStatusTypeFailed ->
                    "Failed"

                UserImportJobStatusTypeSucceeded ->
                    "Succeeded"
        )


{-| The UserContextDataType data model.
-}
type alias UserContextDataType =
    { encodedData : Maybe String }


{-| The UpdateUserPoolResponse data model.
-}
type alias UpdateUserPoolResponse =
    {}


{-| The UpdateUserPoolRequest data model.
-}
type alias UpdateUserPoolRequest =
    { adminCreateUserConfig : Maybe AdminCreateUserConfigType
    , autoVerifiedAttributes : Maybe VerifiedAttributesListType
    , deviceConfiguration : Maybe DeviceConfigurationType
    , emailConfiguration : Maybe EmailConfigurationType
    , emailVerificationMessage : Maybe String
    , emailVerificationSubject : Maybe String
    , lambdaConfig : Maybe LambdaConfigType
    , mfaConfiguration : Maybe UserPoolMfaType
    , policies : Maybe UserPoolPolicyType
    , smsAuthenticationMessage : Maybe String
    , smsConfiguration : Maybe SmsConfigurationType
    , smsVerificationMessage : Maybe String
    , userPoolAddOns : Maybe UserPoolAddOnsType
    , userPoolId : String
    , userPoolTags : Maybe UserPoolTagsType
    , verificationMessageTemplate : Maybe VerificationMessageTemplateType
    }


{-| The UpdateUserPoolDomainResponse data model.
-}
type alias UpdateUserPoolDomainResponse =
    { cloudFrontDomain : Maybe String }


{-| The UpdateUserPoolDomainRequest data model.
-}
type alias UpdateUserPoolDomainRequest =
    { customDomainConfig : CustomDomainConfigType, domain : String, userPoolId : String }


{-| The UpdateUserPoolClientResponse data model.
-}
type alias UpdateUserPoolClientResponse =
    { userPoolClient : Maybe UserPoolClientType }


{-| The UpdateUserPoolClientRequest data model.
-}
type alias UpdateUserPoolClientRequest =
    { allowedOauthFlows : Maybe OauthFlowsType
    , allowedOauthFlowsUserPoolClient : Maybe Bool
    , allowedOauthScopes : Maybe ScopeListType
    , analyticsConfiguration : Maybe AnalyticsConfigurationType
    , callbackUrls : Maybe CallbackUrlsListType
    , clientId : String
    , clientName : Maybe String
    , defaultRedirectUri : Maybe String
    , explicitAuthFlows : Maybe ExplicitAuthFlowsListType
    , logoutUrls : Maybe LogoutUrlsListType
    , readAttributes : Maybe ClientPermissionListType
    , refreshTokenValidity : Maybe Int
    , supportedIdentityProviders : Maybe SupportedIdentityProvidersListType
    , userPoolId : String
    , writeAttributes : Maybe ClientPermissionListType
    }


{-| The UpdateUserAttributesResponse data model.
-}
type alias UpdateUserAttributesResponse =
    { codeDeliveryDetailsList : Maybe CodeDeliveryDetailsListType }


{-| The UpdateUserAttributesRequest data model.
-}
type alias UpdateUserAttributesRequest =
    { accessToken : String, userAttributes : AttributeListType }


{-| The UpdateResourceServerResponse data model.
-}
type alias UpdateResourceServerResponse =
    { resourceServer : ResourceServerType }


{-| The UpdateResourceServerRequest data model.
-}
type alias UpdateResourceServerRequest =
    { identifier : String, name : String, scopes : Maybe ResourceServerScopeListType, userPoolId : String }


{-| The UpdateIdentityProviderResponse data model.
-}
type alias UpdateIdentityProviderResponse =
    { identityProvider : IdentityProviderType }


{-| The UpdateIdentityProviderRequest data model.
-}
type alias UpdateIdentityProviderRequest =
    { attributeMapping : Maybe AttributeMappingType
    , idpIdentifiers : Maybe IdpIdentifiersListType
    , providerDetails : Maybe ProviderDetailsType
    , providerName : String
    , userPoolId : String
    }


{-| The UpdateGroupResponse data model.
-}
type alias UpdateGroupResponse =
    { group : Maybe GroupType }


{-| The UpdateGroupRequest data model.
-}
type alias UpdateGroupRequest =
    { description : Maybe String
    , groupName : String
    , precedence : Maybe Int
    , roleArn : Maybe String
    , userPoolId : String
    }


{-| The UpdateDeviceStatusResponse data model.
-}
type alias UpdateDeviceStatusResponse =
    {}


{-| The UpdateDeviceStatusRequest data model.
-}
type alias UpdateDeviceStatusRequest =
    { accessToken : String, deviceKey : String, deviceRememberedStatus : Maybe DeviceRememberedStatusType }


{-| The UpdateAuthEventFeedbackResponse data model.
-}
type alias UpdateAuthEventFeedbackResponse =
    {}


{-| The UpdateAuthEventFeedbackRequest data model.
-}
type alias UpdateAuthEventFeedbackRequest =
    { eventId : String
    , feedbackToken : String
    , feedbackValue : FeedbackValueType
    , userPoolId : String
    , username : String
    }


{-| The UntagResourceResponse data model.
-}
type alias UntagResourceResponse =
    {}


{-| The UntagResourceRequest data model.
-}
type alias UntagResourceRequest =
    { resourceArn : String, tagKeys : Maybe UserPoolTagsListType }


{-| The UicustomizationType data model.
-}
type alias UicustomizationType =
    { css : Maybe String
    , cssversion : Maybe String
    , clientId : Maybe String
    , creationDate : Maybe String
    , imageUrl : Maybe String
    , lastModifiedDate : Maybe String
    , userPoolId : Maybe String
    }


{-| The TagResourceResponse data model.
-}
type alias TagResourceResponse =
    {}


{-| The TagResourceRequest data model.
-}
type alias TagResourceRequest =
    { resourceArn : String, tags : Maybe UserPoolTagsType }


{-| The SupportedIdentityProvidersListType data model.
-}
type alias SupportedIdentityProvidersListType =
    List String


{-| The StringAttributeConstraintsType data model.
-}
type alias StringAttributeConstraintsType =
    { maxLength : Maybe String, minLength : Maybe String }


{-| The StopUserImportJobResponse data model.
-}
type alias StopUserImportJobResponse =
    { userImportJob : Maybe UserImportJobType }


{-| The StopUserImportJobRequest data model.
-}
type alias StopUserImportJobRequest =
    { jobId : String, userPoolId : String }


{-| The StatusType data model.
-}
type StatusType
    = StatusTypeEnabled
    | StatusTypeDisabled


{-| The StatusType data model.
-}
statusType : Enum StatusType
statusType =
    Enum.define
        [ StatusTypeEnabled, StatusTypeDisabled ]
        (\val ->
            case val of
                StatusTypeEnabled ->
                    "Enabled"

                StatusTypeDisabled ->
                    "Disabled"
        )


{-| The StartUserImportJobResponse data model.
-}
type alias StartUserImportJobResponse =
    { userImportJob : Maybe UserImportJobType }


{-| The StartUserImportJobRequest data model.
-}
type alias StartUserImportJobRequest =
    { jobId : String, userPoolId : String }


{-| The SoftwareTokenMfaSettingsType data model.
-}
type alias SoftwareTokenMfaSettingsType =
    { enabled : Maybe Bool, preferredMfa : Maybe Bool }


{-| The SoftwareTokenMfaConfigType data model.
-}
type alias SoftwareTokenMfaConfigType =
    { enabled : Maybe Bool }


{-| The SmsMfaConfigType data model.
-}
type alias SmsMfaConfigType =
    { smsAuthenticationMessage : Maybe String, smsConfiguration : Maybe SmsConfigurationType }


{-| The SmsConfigurationType data model.
-}
type alias SmsConfigurationType =
    { externalId : Maybe String, snsCallerArn : String }


{-| The SkippedIprangeListType data model.
-}
type alias SkippedIprangeListType =
    List String


{-| The SignUpResponse data model.
-}
type alias SignUpResponse =
    { codeDeliveryDetails : Maybe CodeDeliveryDetailsType, userConfirmed : Bool, userSub : String }


{-| The SignUpRequest data model.
-}
type alias SignUpRequest =
    { analyticsMetadata : Maybe AnalyticsMetadataType
    , clientId : String
    , password : String
    , secretHash : Maybe String
    , userAttributes : Maybe AttributeListType
    , userContextData : Maybe UserContextDataType
    , username : String
    , validationData : Maybe AttributeListType
    }


{-| The SetUserSettingsResponse data model.
-}
type alias SetUserSettingsResponse =
    {}


{-| The SetUserSettingsRequest data model.
-}
type alias SetUserSettingsRequest =
    { accessToken : String, mfaoptions : MfaoptionListType }


{-| The SetUserPoolMfaConfigResponse data model.
-}
type alias SetUserPoolMfaConfigResponse =
    { mfaConfiguration : Maybe UserPoolMfaType
    , smsMfaConfiguration : Maybe SmsMfaConfigType
    , softwareTokenMfaConfiguration : Maybe SoftwareTokenMfaConfigType
    }


{-| The SetUserPoolMfaConfigRequest data model.
-}
type alias SetUserPoolMfaConfigRequest =
    { mfaConfiguration : Maybe UserPoolMfaType
    , smsMfaConfiguration : Maybe SmsMfaConfigType
    , softwareTokenMfaConfiguration : Maybe SoftwareTokenMfaConfigType
    , userPoolId : String
    }


{-| The SetUserMfapreferenceResponse data model.
-}
type alias SetUserMfapreferenceResponse =
    {}


{-| The SetUserMfapreferenceRequest data model.
-}
type alias SetUserMfapreferenceRequest =
    { accessToken : String
    , smsmfaSettings : Maybe SmsmfaSettingsType
    , softwareTokenMfaSettings : Maybe SoftwareTokenMfaSettingsType
    }


{-| The SetUicustomizationResponse data model.
-}
type alias SetUicustomizationResponse =
    { uicustomization : UicustomizationType }


{-| The SetUicustomizationRequest data model.
-}
type alias SetUicustomizationRequest =
    { css : Maybe String, clientId : Maybe String, imageFile : Maybe String, userPoolId : String }


{-| The SetRiskConfigurationResponse data model.
-}
type alias SetRiskConfigurationResponse =
    { riskConfiguration : RiskConfigurationType }


{-| The SetRiskConfigurationRequest data model.
-}
type alias SetRiskConfigurationRequest =
    { accountTakeoverRiskConfiguration : Maybe AccountTakeoverRiskConfigurationType
    , clientId : Maybe String
    , compromisedCredentialsRiskConfiguration : Maybe CompromisedCredentialsRiskConfigurationType
    , riskExceptionConfiguration : Maybe RiskExceptionConfigurationType
    , userPoolId : String
    }


{-| The SearchedAttributeNamesListType data model.
-}
type alias SearchedAttributeNamesListType =
    List String


{-| The ScopeListType data model.
-}
type alias ScopeListType =
    List String


{-| The SchemaAttributesListType data model.
-}
type alias SchemaAttributesListType =
    List SchemaAttributeType


{-| The SchemaAttributeType data model.
-}
type alias SchemaAttributeType =
    { attributeDataType : Maybe AttributeDataType
    , developerOnlyAttribute : Maybe Bool
    , mutable : Maybe Bool
    , name : Maybe String
    , numberAttributeConstraints : Maybe NumberAttributeConstraintsType
    , required : Maybe Bool
    , stringAttributeConstraints : Maybe StringAttributeConstraintsType
    }


{-| The SmsmfaSettingsType data model.
-}
type alias SmsmfaSettingsType =
    { enabled : Maybe Bool, preferredMfa : Maybe Bool }


{-| The RiskLevelType data model.
-}
type RiskLevelType
    = RiskLevelTypeLow
    | RiskLevelTypeMedium
    | RiskLevelTypeHigh


{-| The RiskLevelType data model.
-}
riskLevelType : Enum RiskLevelType
riskLevelType =
    Enum.define
        [ RiskLevelTypeLow, RiskLevelTypeMedium, RiskLevelTypeHigh ]
        (\val ->
            case val of
                RiskLevelTypeLow ->
                    "Low"

                RiskLevelTypeMedium ->
                    "Medium"

                RiskLevelTypeHigh ->
                    "High"
        )


{-| The RiskExceptionConfigurationType data model.
-}
type alias RiskExceptionConfigurationType =
    { blockedIprangeList : Maybe BlockedIprangeListType, skippedIprangeList : Maybe SkippedIprangeListType }


{-| The RiskDecisionType data model.
-}
type RiskDecisionType
    = RiskDecisionTypeNoRisk
    | RiskDecisionTypeAccountTakeover
    | RiskDecisionTypeBlock


{-| The RiskDecisionType data model.
-}
riskDecisionType : Enum RiskDecisionType
riskDecisionType =
    Enum.define
        [ RiskDecisionTypeNoRisk, RiskDecisionTypeAccountTakeover, RiskDecisionTypeBlock ]
        (\val ->
            case val of
                RiskDecisionTypeNoRisk ->
                    "NoRisk"

                RiskDecisionTypeAccountTakeover ->
                    "AccountTakeover"

                RiskDecisionTypeBlock ->
                    "Block"
        )


{-| The RiskConfigurationType data model.
-}
type alias RiskConfigurationType =
    { accountTakeoverRiskConfiguration : Maybe AccountTakeoverRiskConfigurationType
    , clientId : Maybe String
    , compromisedCredentialsRiskConfiguration : Maybe CompromisedCredentialsRiskConfigurationType
    , lastModifiedDate : Maybe String
    , riskExceptionConfiguration : Maybe RiskExceptionConfigurationType
    , userPoolId : Maybe String
    }


{-| The RespondToAuthChallengeResponse data model.
-}
type alias RespondToAuthChallengeResponse =
    { authenticationResult : Maybe AuthenticationResultType
    , challengeName : Maybe ChallengeNameType
    , challengeParameters : Maybe ChallengeParametersType
    , session : Maybe String
    }


{-| The RespondToAuthChallengeRequest data model.
-}
type alias RespondToAuthChallengeRequest =
    { analyticsMetadata : Maybe AnalyticsMetadataType
    , challengeName : ChallengeNameType
    , challengeResponses : Maybe ChallengeResponsesType
    , clientId : String
    , session : Maybe String
    , userContextData : Maybe UserContextDataType
    }


{-| The ResourceServersListType data model.
-}
type alias ResourceServersListType =
    List ResourceServerType


{-| The ResourceServerType data model.
-}
type alias ResourceServerType =
    { identifier : Maybe String
    , name : Maybe String
    , scopes : Maybe ResourceServerScopeListType
    , userPoolId : Maybe String
    }


{-| The ResourceServerScopeType data model.
-}
type alias ResourceServerScopeType =
    { scopeDescription : String, scopeName : String }


{-| The ResourceServerScopeListType data model.
-}
type alias ResourceServerScopeListType =
    List ResourceServerScopeType


{-| The ResendConfirmationCodeResponse data model.
-}
type alias ResendConfirmationCodeResponse =
    { codeDeliveryDetails : Maybe CodeDeliveryDetailsType }


{-| The ResendConfirmationCodeRequest data model.
-}
type alias ResendConfirmationCodeRequest =
    { analyticsMetadata : Maybe AnalyticsMetadataType
    , clientId : String
    , secretHash : Maybe String
    , userContextData : Maybe UserContextDataType
    , username : String
    }


{-| The ProvidersListType data model.
-}
type alias ProvidersListType =
    List ProviderDescription


{-| The ProviderUserIdentifierType data model.
-}
type alias ProviderUserIdentifierType =
    { providerAttributeName : Maybe String, providerAttributeValue : Maybe String, providerName : Maybe String }


{-| The ProviderDetailsType data model.
-}
type alias ProviderDetailsType =
    Dict String String


{-| The ProviderDescription data model.
-}
type alias ProviderDescription =
    { creationDate : Maybe String
    , lastModifiedDate : Maybe String
    , providerName : Maybe String
    , providerType : Maybe IdentityProviderTypeType
    }


{-| The PasswordPolicyType data model.
-}
type alias PasswordPolicyType =
    { minimumLength : Maybe Int
    , requireLowercase : Maybe Bool
    , requireNumbers : Maybe Bool
    , requireSymbols : Maybe Bool
    , requireUppercase : Maybe Bool
    , temporaryPasswordValidityDays : Maybe Int
    }


{-| The OauthFlowsType data model.
-}
type alias OauthFlowsType =
    List OauthFlowType


{-| The OauthFlowType data model.
-}
type OauthFlowType
    = OauthFlowTypeCode
    | OauthFlowTypeImplicit
    | OauthFlowTypeClientCredentials


{-| The OauthFlowType data model.
-}
oauthFlowType : Enum OauthFlowType
oauthFlowType =
    Enum.define
        [ OauthFlowTypeCode, OauthFlowTypeImplicit, OauthFlowTypeClientCredentials ]
        (\val ->
            case val of
                OauthFlowTypeCode ->
                    "code"

                OauthFlowTypeImplicit ->
                    "implicit"

                OauthFlowTypeClientCredentials ->
                    "client_credentials"
        )


{-| The NumberAttributeConstraintsType data model.
-}
type alias NumberAttributeConstraintsType =
    { maxValue : Maybe String, minValue : Maybe String }


{-| The NotifyEmailType data model.
-}
type alias NotifyEmailType =
    { htmlBody : Maybe String, subject : String, textBody : Maybe String }


{-| The NotifyConfigurationType data model.
-}
type alias NotifyConfigurationType =
    { blockEmail : Maybe NotifyEmailType
    , from : Maybe String
    , mfaEmail : Maybe NotifyEmailType
    , noActionEmail : Maybe NotifyEmailType
    , replyTo : Maybe String
    , sourceArn : String
    }


{-| The NewDeviceMetadataType data model.
-}
type alias NewDeviceMetadataType =
    { deviceGroupKey : Maybe String, deviceKey : Maybe String }


{-| The MessageTemplateType data model.
-}
type alias MessageTemplateType =
    { emailMessage : Maybe String, emailSubject : Maybe String, smsmessage : Maybe String }


{-| The MessageActionType data model.
-}
type MessageActionType
    = MessageActionTypeResend
    | MessageActionTypeSuppress


{-| The MessageActionType data model.
-}
messageActionType : Enum MessageActionType
messageActionType =
    Enum.define
        [ MessageActionTypeResend, MessageActionTypeSuppress ]
        (\val ->
            case val of
                MessageActionTypeResend ->
                    "RESEND"

                MessageActionTypeSuppress ->
                    "SUPPRESS"
        )


{-| The MfaoptionType data model.
-}
type alias MfaoptionType =
    { attributeName : Maybe String, deliveryMedium : Maybe DeliveryMediumType }


{-| The MfaoptionListType data model.
-}
type alias MfaoptionListType =
    List MfaoptionType


{-| The LogoutUrlsListType data model.
-}
type alias LogoutUrlsListType =
    List String


{-| The ListUsersResponse data model.
-}
type alias ListUsersResponse =
    { paginationToken : Maybe String, users : Maybe UsersListType }


{-| The ListUsersRequest data model.
-}
type alias ListUsersRequest =
    { attributesToGet : Maybe SearchedAttributeNamesListType
    , filter : Maybe String
    , limit : Maybe Int
    , paginationToken : Maybe String
    , userPoolId : String
    }


{-| The ListUsersInGroupResponse data model.
-}
type alias ListUsersInGroupResponse =
    { nextToken : Maybe String, users : Maybe UsersListType }


{-| The ListUsersInGroupRequest data model.
-}
type alias ListUsersInGroupRequest =
    { groupName : String, limit : Maybe Int, nextToken : Maybe String, userPoolId : String }


{-| The ListUserPoolsResponse data model.
-}
type alias ListUserPoolsResponse =
    { nextToken : Maybe String, userPools : Maybe UserPoolListType }


{-| The ListUserPoolsRequest data model.
-}
type alias ListUserPoolsRequest =
    { maxResults : Int, nextToken : Maybe String }


{-| The ListUserPoolClientsResponse data model.
-}
type alias ListUserPoolClientsResponse =
    { nextToken : Maybe String, userPoolClients : Maybe UserPoolClientListType }


{-| The ListUserPoolClientsRequest data model.
-}
type alias ListUserPoolClientsRequest =
    { maxResults : Maybe Int, nextToken : Maybe String, userPoolId : String }


{-| The ListUserImportJobsResponse data model.
-}
type alias ListUserImportJobsResponse =
    { paginationToken : Maybe String, userImportJobs : Maybe UserImportJobsListType }


{-| The ListUserImportJobsRequest data model.
-}
type alias ListUserImportJobsRequest =
    { maxResults : Int, paginationToken : Maybe String, userPoolId : String }


{-| The ListTagsForResourceResponse data model.
-}
type alias ListTagsForResourceResponse =
    { tags : Maybe UserPoolTagsType }


{-| The ListTagsForResourceRequest data model.
-}
type alias ListTagsForResourceRequest =
    { resourceArn : String }


{-| The ListResourceServersResponse data model.
-}
type alias ListResourceServersResponse =
    { nextToken : Maybe String, resourceServers : ResourceServersListType }


{-| The ListResourceServersRequest data model.
-}
type alias ListResourceServersRequest =
    { maxResults : Maybe Int, nextToken : Maybe String, userPoolId : String }


{-| The ListOfStringTypes data model.
-}
type alias ListOfStringTypes =
    List String


{-| The ListIdentityProvidersResponse data model.
-}
type alias ListIdentityProvidersResponse =
    { nextToken : Maybe String, providers : ProvidersListType }


{-| The ListIdentityProvidersRequest data model.
-}
type alias ListIdentityProvidersRequest =
    { maxResults : Maybe Int, nextToken : Maybe String, userPoolId : String }


{-| The ListGroupsResponse data model.
-}
type alias ListGroupsResponse =
    { groups : Maybe GroupListType, nextToken : Maybe String }


{-| The ListGroupsRequest data model.
-}
type alias ListGroupsRequest =
    { limit : Maybe Int, nextToken : Maybe String, userPoolId : String }


{-| The ListDevicesResponse data model.
-}
type alias ListDevicesResponse =
    { devices : Maybe DeviceListType, paginationToken : Maybe String }


{-| The ListDevicesRequest data model.
-}
type alias ListDevicesRequest =
    { accessToken : String, limit : Maybe Int, paginationToken : Maybe String }


{-| The LambdaConfigType data model.
-}
type alias LambdaConfigType =
    { createAuthChallenge : Maybe String
    , customMessage : Maybe String
    , defineAuthChallenge : Maybe String
    , postAuthentication : Maybe String
    , postConfirmation : Maybe String
    , preAuthentication : Maybe String
    , preSignUp : Maybe String
    , preTokenGeneration : Maybe String
    , userMigration : Maybe String
    , verifyAuthChallengeResponse : Maybe String
    }


{-| The InitiateAuthResponse data model.
-}
type alias InitiateAuthResponse =
    { authenticationResult : Maybe AuthenticationResultType
    , challengeName : Maybe ChallengeNameType
    , challengeParameters : Maybe ChallengeParametersType
    , session : Maybe String
    }


{-| The InitiateAuthRequest data model.
-}
type alias InitiateAuthRequest =
    { analyticsMetadata : Maybe AnalyticsMetadataType
    , authFlow : AuthFlowType
    , authParameters : Maybe AuthParametersType
    , clientId : String
    , clientMetadata : Maybe ClientMetadataType
    , userContextData : Maybe UserContextDataType
    }


{-| The IdpIdentifiersListType data model.
-}
type alias IdpIdentifiersListType =
    List String


{-| The IdentityProviderTypeType data model.
-}
type IdentityProviderTypeType
    = IdentityProviderTypeTypeSaml
    | IdentityProviderTypeTypeFacebook
    | IdentityProviderTypeTypeGoogle
    | IdentityProviderTypeTypeLoginWithAmazon
    | IdentityProviderTypeTypeOidc


{-| The IdentityProviderTypeType data model.
-}
identityProviderTypeType : Enum IdentityProviderTypeType
identityProviderTypeType =
    Enum.define
        [ IdentityProviderTypeTypeSaml
        , IdentityProviderTypeTypeFacebook
        , IdentityProviderTypeTypeGoogle
        , IdentityProviderTypeTypeLoginWithAmazon
        , IdentityProviderTypeTypeOidc
        ]
        (\val ->
            case val of
                IdentityProviderTypeTypeSaml ->
                    "SAML"

                IdentityProviderTypeTypeFacebook ->
                    "Facebook"

                IdentityProviderTypeTypeGoogle ->
                    "Google"

                IdentityProviderTypeTypeLoginWithAmazon ->
                    "LoginWithAmazon"

                IdentityProviderTypeTypeOidc ->
                    "OIDC"
        )


{-| The IdentityProviderType data model.
-}
type alias IdentityProviderType =
    { attributeMapping : Maybe AttributeMappingType
    , creationDate : Maybe String
    , idpIdentifiers : Maybe IdpIdentifiersListType
    , lastModifiedDate : Maybe String
    , providerDetails : Maybe ProviderDetailsType
    , providerName : Maybe String
    , providerType : Maybe IdentityProviderTypeType
    , userPoolId : Maybe String
    }


{-| The HttpHeaderList data model.
-}
type alias HttpHeaderList =
    List HttpHeader


{-| The HttpHeader data model.
-}
type alias HttpHeader =
    { headerName : Maybe String, headerValue : Maybe String }


{-| The GroupType data model.
-}
type alias GroupType =
    { creationDate : Maybe String
    , description : Maybe String
    , groupName : Maybe String
    , lastModifiedDate : Maybe String
    , precedence : Maybe Int
    , roleArn : Maybe String
    , userPoolId : Maybe String
    }


{-| The GroupListType data model.
-}
type alias GroupListType =
    List GroupType


{-| The GlobalSignOutResponse data model.
-}
type alias GlobalSignOutResponse =
    {}


{-| The GlobalSignOutRequest data model.
-}
type alias GlobalSignOutRequest =
    { accessToken : String }


{-| The GetUserResponse data model.
-}
type alias GetUserResponse =
    { mfaoptions : Maybe MfaoptionListType
    , preferredMfaSetting : Maybe String
    , userAttributes : AttributeListType
    , userMfasettingList : Maybe UserMfasettingListType
    , username : String
    }


{-| The GetUserRequest data model.
-}
type alias GetUserRequest =
    { accessToken : String }


{-| The GetUserPoolMfaConfigResponse data model.
-}
type alias GetUserPoolMfaConfigResponse =
    { mfaConfiguration : Maybe UserPoolMfaType
    , smsMfaConfiguration : Maybe SmsMfaConfigType
    , softwareTokenMfaConfiguration : Maybe SoftwareTokenMfaConfigType
    }


{-| The GetUserPoolMfaConfigRequest data model.
-}
type alias GetUserPoolMfaConfigRequest =
    { userPoolId : String }


{-| The GetUserAttributeVerificationCodeResponse data model.
-}
type alias GetUserAttributeVerificationCodeResponse =
    { codeDeliveryDetails : Maybe CodeDeliveryDetailsType }


{-| The GetUserAttributeVerificationCodeRequest data model.
-}
type alias GetUserAttributeVerificationCodeRequest =
    { accessToken : String, attributeName : String }


{-| The GetUicustomizationResponse data model.
-}
type alias GetUicustomizationResponse =
    { uicustomization : UicustomizationType }


{-| The GetUicustomizationRequest data model.
-}
type alias GetUicustomizationRequest =
    { clientId : Maybe String, userPoolId : String }


{-| The GetSigningCertificateResponse data model.
-}
type alias GetSigningCertificateResponse =
    { certificate : Maybe String }


{-| The GetSigningCertificateRequest data model.
-}
type alias GetSigningCertificateRequest =
    { userPoolId : String }


{-| The GetIdentityProviderByIdentifierResponse data model.
-}
type alias GetIdentityProviderByIdentifierResponse =
    { identityProvider : IdentityProviderType }


{-| The GetIdentityProviderByIdentifierRequest data model.
-}
type alias GetIdentityProviderByIdentifierRequest =
    { idpIdentifier : String, userPoolId : String }


{-| The GetGroupResponse data model.
-}
type alias GetGroupResponse =
    { group : Maybe GroupType }


{-| The GetGroupRequest data model.
-}
type alias GetGroupRequest =
    { groupName : String, userPoolId : String }


{-| The GetDeviceResponse data model.
-}
type alias GetDeviceResponse =
    { device : DeviceType }


{-| The GetDeviceRequest data model.
-}
type alias GetDeviceRequest =
    { accessToken : Maybe String, deviceKey : String }


{-| The GetCsvheaderResponse data model.
-}
type alias GetCsvheaderResponse =
    { csvheader : Maybe ListOfStringTypes, userPoolId : Maybe String }


{-| The GetCsvheaderRequest data model.
-}
type alias GetCsvheaderRequest =
    { userPoolId : String }


{-| The ForgotPasswordResponse data model.
-}
type alias ForgotPasswordResponse =
    { codeDeliveryDetails : Maybe CodeDeliveryDetailsType }


{-| The ForgotPasswordRequest data model.
-}
type alias ForgotPasswordRequest =
    { analyticsMetadata : Maybe AnalyticsMetadataType
    , clientId : String
    , secretHash : Maybe String
    , userContextData : Maybe UserContextDataType
    , username : String
    }


{-| The ForgetDeviceRequest data model.
-}
type alias ForgetDeviceRequest =
    { accessToken : Maybe String, deviceKey : String }


{-| The FeedbackValueType data model.
-}
type FeedbackValueType
    = FeedbackValueTypeValid
    | FeedbackValueTypeInvalid


{-| The FeedbackValueType data model.
-}
feedbackValueType : Enum FeedbackValueType
feedbackValueType =
    Enum.define
        [ FeedbackValueTypeValid, FeedbackValueTypeInvalid ]
        (\val ->
            case val of
                FeedbackValueTypeValid ->
                    "Valid"

                FeedbackValueTypeInvalid ->
                    "Invalid"
        )


{-| The ExplicitAuthFlowsType data model.
-}
type ExplicitAuthFlowsType
    = ExplicitAuthFlowsTypeAdminNoSrpAuth
    | ExplicitAuthFlowsTypeCustomAuthFlowOnly
    | ExplicitAuthFlowsTypeUserPasswordAuth


{-| The ExplicitAuthFlowsType data model.
-}
explicitAuthFlowsType : Enum ExplicitAuthFlowsType
explicitAuthFlowsType =
    Enum.define
        [ ExplicitAuthFlowsTypeAdminNoSrpAuth
        , ExplicitAuthFlowsTypeCustomAuthFlowOnly
        , ExplicitAuthFlowsTypeUserPasswordAuth
        ]
        (\val ->
            case val of
                ExplicitAuthFlowsTypeAdminNoSrpAuth ->
                    "ADMIN_NO_SRP_AUTH"

                ExplicitAuthFlowsTypeCustomAuthFlowOnly ->
                    "CUSTOM_AUTH_FLOW_ONLY"

                ExplicitAuthFlowsTypeUserPasswordAuth ->
                    "USER_PASSWORD_AUTH"
        )


{-| The ExplicitAuthFlowsListType data model.
-}
type alias ExplicitAuthFlowsListType =
    List ExplicitAuthFlowsType


{-| The EventType data model.
-}
type EventType
    = EventTypeSignIn
    | EventTypeSignUp
    | EventTypeForgotPassword


{-| The EventType data model.
-}
eventType : Enum EventType
eventType =
    Enum.define
        [ EventTypeSignIn, EventTypeSignUp, EventTypeForgotPassword ]
        (\val ->
            case val of
                EventTypeSignIn ->
                    "SignIn"

                EventTypeSignUp ->
                    "SignUp"

                EventTypeForgotPassword ->
                    "ForgotPassword"
        )


{-| The EventRiskType data model.
-}
type alias EventRiskType =
    { riskDecision : Maybe RiskDecisionType, riskLevel : Maybe RiskLevelType }


{-| The EventResponseType data model.
-}
type EventResponseType
    = EventResponseTypeSuccess
    | EventResponseTypeFailure


{-| The EventResponseType data model.
-}
eventResponseType : Enum EventResponseType
eventResponseType =
    Enum.define
        [ EventResponseTypeSuccess, EventResponseTypeFailure ]
        (\val ->
            case val of
                EventResponseTypeSuccess ->
                    "Success"

                EventResponseTypeFailure ->
                    "Failure"
        )


{-| The EventFiltersType data model.
-}
type alias EventFiltersType =
    List EventFilterType


{-| The EventFilterType data model.
-}
type EventFilterType
    = EventFilterTypeSignIn
    | EventFilterTypePasswordChange
    | EventFilterTypeSignUp


{-| The EventFilterType data model.
-}
eventFilterType : Enum EventFilterType
eventFilterType =
    Enum.define
        [ EventFilterTypeSignIn, EventFilterTypePasswordChange, EventFilterTypeSignUp ]
        (\val ->
            case val of
                EventFilterTypeSignIn ->
                    "SIGN_IN"

                EventFilterTypePasswordChange ->
                    "PASSWORD_CHANGE"

                EventFilterTypeSignUp ->
                    "SIGN_UP"
        )


{-| The EventFeedbackType data model.
-}
type alias EventFeedbackType =
    { feedbackDate : Maybe String, feedbackValue : FeedbackValueType, provider : String }


{-| The EventContextDataType data model.
-}
type alias EventContextDataType =
    { city : Maybe String
    , country : Maybe String
    , deviceName : Maybe String
    , ipAddress : Maybe String
    , timezone : Maybe String
    }


{-| The EmailSendingAccountType data model.
-}
type EmailSendingAccountType
    = EmailSendingAccountTypeCognitoDefault
    | EmailSendingAccountTypeDeveloper


{-| The EmailSendingAccountType data model.
-}
emailSendingAccountType : Enum EmailSendingAccountType
emailSendingAccountType =
    Enum.define
        [ EmailSendingAccountTypeCognitoDefault, EmailSendingAccountTypeDeveloper ]
        (\val ->
            case val of
                EmailSendingAccountTypeCognitoDefault ->
                    "COGNITO_DEFAULT"

                EmailSendingAccountTypeDeveloper ->
                    "DEVELOPER"
        )


{-| The EmailConfigurationType data model.
-}
type alias EmailConfigurationType =
    { emailSendingAccount : Maybe EmailSendingAccountType
    , replyToEmailAddress : Maybe String
    , sourceArn : Maybe String
    }


{-| The DomainStatusType data model.
-}
type DomainStatusType
    = DomainStatusTypeCreating
    | DomainStatusTypeDeleting
    | DomainStatusTypeUpdating
    | DomainStatusTypeActive
    | DomainStatusTypeFailed


{-| The DomainStatusType data model.
-}
domainStatusType : Enum DomainStatusType
domainStatusType =
    Enum.define
        [ DomainStatusTypeCreating
        , DomainStatusTypeDeleting
        , DomainStatusTypeUpdating
        , DomainStatusTypeActive
        , DomainStatusTypeFailed
        ]
        (\val ->
            case val of
                DomainStatusTypeCreating ->
                    "CREATING"

                DomainStatusTypeDeleting ->
                    "DELETING"

                DomainStatusTypeUpdating ->
                    "UPDATING"

                DomainStatusTypeActive ->
                    "ACTIVE"

                DomainStatusTypeFailed ->
                    "FAILED"
        )


{-| The DomainDescriptionType data model.
-}
type alias DomainDescriptionType =
    { awsaccountId : Maybe String
    , cloudFrontDistribution : Maybe String
    , customDomainConfig : Maybe CustomDomainConfigType
    , domain : Maybe String
    , s3Bucket : Maybe String
    , status : Maybe DomainStatusType
    , userPoolId : Maybe String
    , version : Maybe String
    }


{-| The DeviceType data model.
-}
type alias DeviceType =
    { deviceAttributes : Maybe AttributeListType
    , deviceCreateDate : Maybe String
    , deviceKey : Maybe String
    , deviceLastAuthenticatedDate : Maybe String
    , deviceLastModifiedDate : Maybe String
    }


{-| The DeviceSecretVerifierConfigType data model.
-}
type alias DeviceSecretVerifierConfigType =
    { passwordVerifier : Maybe String, salt : Maybe String }


{-| The DeviceRememberedStatusType data model.
-}
type DeviceRememberedStatusType
    = DeviceRememberedStatusTypeRemembered
    | DeviceRememberedStatusTypeNotRemembered


{-| The DeviceRememberedStatusType data model.
-}
deviceRememberedStatusType : Enum DeviceRememberedStatusType
deviceRememberedStatusType =
    Enum.define
        [ DeviceRememberedStatusTypeRemembered, DeviceRememberedStatusTypeNotRemembered ]
        (\val ->
            case val of
                DeviceRememberedStatusTypeRemembered ->
                    "remembered"

                DeviceRememberedStatusTypeNotRemembered ->
                    "not_remembered"
        )


{-| The DeviceListType data model.
-}
type alias DeviceListType =
    List DeviceType


{-| The DeviceConfigurationType data model.
-}
type alias DeviceConfigurationType =
    { challengeRequiredOnNewDevice : Maybe Bool, deviceOnlyRememberedOnUserPrompt : Maybe Bool }


{-| The DescribeUserPoolResponse data model.
-}
type alias DescribeUserPoolResponse =
    { userPool : Maybe UserPoolType }


{-| The DescribeUserPoolRequest data model.
-}
type alias DescribeUserPoolRequest =
    { userPoolId : String }


{-| The DescribeUserPoolDomainResponse data model.
-}
type alias DescribeUserPoolDomainResponse =
    { domainDescription : Maybe DomainDescriptionType }


{-| The DescribeUserPoolDomainRequest data model.
-}
type alias DescribeUserPoolDomainRequest =
    { domain : String }


{-| The DescribeUserPoolClientResponse data model.
-}
type alias DescribeUserPoolClientResponse =
    { userPoolClient : Maybe UserPoolClientType }


{-| The DescribeUserPoolClientRequest data model.
-}
type alias DescribeUserPoolClientRequest =
    { clientId : String, userPoolId : String }


{-| The DescribeUserImportJobResponse data model.
-}
type alias DescribeUserImportJobResponse =
    { userImportJob : Maybe UserImportJobType }


{-| The DescribeUserImportJobRequest data model.
-}
type alias DescribeUserImportJobRequest =
    { jobId : String, userPoolId : String }


{-| The DescribeRiskConfigurationResponse data model.
-}
type alias DescribeRiskConfigurationResponse =
    { riskConfiguration : RiskConfigurationType }


{-| The DescribeRiskConfigurationRequest data model.
-}
type alias DescribeRiskConfigurationRequest =
    { clientId : Maybe String, userPoolId : String }


{-| The DescribeResourceServerResponse data model.
-}
type alias DescribeResourceServerResponse =
    { resourceServer : ResourceServerType }


{-| The DescribeResourceServerRequest data model.
-}
type alias DescribeResourceServerRequest =
    { identifier : String, userPoolId : String }


{-| The DescribeIdentityProviderResponse data model.
-}
type alias DescribeIdentityProviderResponse =
    { identityProvider : IdentityProviderType }


{-| The DescribeIdentityProviderRequest data model.
-}
type alias DescribeIdentityProviderRequest =
    { providerName : String, userPoolId : String }


{-| The DeliveryMediumType data model.
-}
type DeliveryMediumType
    = DeliveryMediumTypeSms
    | DeliveryMediumTypeEmail


{-| The DeliveryMediumType data model.
-}
deliveryMediumType : Enum DeliveryMediumType
deliveryMediumType =
    Enum.define
        [ DeliveryMediumTypeSms, DeliveryMediumTypeEmail ]
        (\val ->
            case val of
                DeliveryMediumTypeSms ->
                    "SMS"

                DeliveryMediumTypeEmail ->
                    "EMAIL"
        )


{-| The DeliveryMediumListType data model.
-}
type alias DeliveryMediumListType =
    List DeliveryMediumType


{-| The DeleteUserRequest data model.
-}
type alias DeleteUserRequest =
    { accessToken : String }


{-| The DeleteUserPoolRequest data model.
-}
type alias DeleteUserPoolRequest =
    { userPoolId : String }


{-| The DeleteUserPoolDomainResponse data model.
-}
type alias DeleteUserPoolDomainResponse =
    {}


{-| The DeleteUserPoolDomainRequest data model.
-}
type alias DeleteUserPoolDomainRequest =
    { domain : String, userPoolId : String }


{-| The DeleteUserPoolClientRequest data model.
-}
type alias DeleteUserPoolClientRequest =
    { clientId : String, userPoolId : String }


{-| The DeleteUserAttributesResponse data model.
-}
type alias DeleteUserAttributesResponse =
    {}


{-| The DeleteUserAttributesRequest data model.
-}
type alias DeleteUserAttributesRequest =
    { accessToken : String, userAttributeNames : AttributeNameListType }


{-| The DeleteResourceServerRequest data model.
-}
type alias DeleteResourceServerRequest =
    { identifier : String, userPoolId : String }


{-| The DeleteIdentityProviderRequest data model.
-}
type alias DeleteIdentityProviderRequest =
    { providerName : String, userPoolId : String }


{-| The DeleteGroupRequest data model.
-}
type alias DeleteGroupRequest =
    { groupName : String, userPoolId : String }


{-| The DefaultEmailOptionType data model.
-}
type DefaultEmailOptionType
    = DefaultEmailOptionTypeConfirmWithLink
    | DefaultEmailOptionTypeConfirmWithCode


{-| The DefaultEmailOptionType data model.
-}
defaultEmailOptionType : Enum DefaultEmailOptionType
defaultEmailOptionType =
    Enum.define
        [ DefaultEmailOptionTypeConfirmWithLink, DefaultEmailOptionTypeConfirmWithCode ]
        (\val ->
            case val of
                DefaultEmailOptionTypeConfirmWithLink ->
                    "CONFIRM_WITH_LINK"

                DefaultEmailOptionTypeConfirmWithCode ->
                    "CONFIRM_WITH_CODE"
        )


{-| The CustomDomainConfigType data model.
-}
type alias CustomDomainConfigType =
    { certificateArn : String }


{-| The CustomAttributesListType data model.
-}
type alias CustomAttributesListType =
    List SchemaAttributeType


{-| The CreateUserPoolResponse data model.
-}
type alias CreateUserPoolResponse =
    { userPool : Maybe UserPoolType }


{-| The CreateUserPoolRequest data model.
-}
type alias CreateUserPoolRequest =
    { adminCreateUserConfig : Maybe AdminCreateUserConfigType
    , aliasAttributes : Maybe AliasAttributesListType
    , autoVerifiedAttributes : Maybe VerifiedAttributesListType
    , deviceConfiguration : Maybe DeviceConfigurationType
    , emailConfiguration : Maybe EmailConfigurationType
    , emailVerificationMessage : Maybe String
    , emailVerificationSubject : Maybe String
    , lambdaConfig : Maybe LambdaConfigType
    , mfaConfiguration : Maybe UserPoolMfaType
    , policies : Maybe UserPoolPolicyType
    , poolName : String
    , schema : Maybe SchemaAttributesListType
    , smsAuthenticationMessage : Maybe String
    , smsConfiguration : Maybe SmsConfigurationType
    , smsVerificationMessage : Maybe String
    , userPoolAddOns : Maybe UserPoolAddOnsType
    , userPoolTags : Maybe UserPoolTagsType
    , usernameAttributes : Maybe UsernameAttributesListType
    , verificationMessageTemplate : Maybe VerificationMessageTemplateType
    }


{-| The CreateUserPoolDomainResponse data model.
-}
type alias CreateUserPoolDomainResponse =
    { cloudFrontDomain : Maybe String }


{-| The CreateUserPoolDomainRequest data model.
-}
type alias CreateUserPoolDomainRequest =
    { customDomainConfig : Maybe CustomDomainConfigType, domain : String, userPoolId : String }


{-| The CreateUserPoolClientResponse data model.
-}
type alias CreateUserPoolClientResponse =
    { userPoolClient : Maybe UserPoolClientType }


{-| The CreateUserPoolClientRequest data model.
-}
type alias CreateUserPoolClientRequest =
    { allowedOauthFlows : Maybe OauthFlowsType
    , allowedOauthFlowsUserPoolClient : Maybe Bool
    , allowedOauthScopes : Maybe ScopeListType
    , analyticsConfiguration : Maybe AnalyticsConfigurationType
    , callbackUrls : Maybe CallbackUrlsListType
    , clientName : String
    , defaultRedirectUri : Maybe String
    , explicitAuthFlows : Maybe ExplicitAuthFlowsListType
    , generateSecret : Maybe Bool
    , logoutUrls : Maybe LogoutUrlsListType
    , readAttributes : Maybe ClientPermissionListType
    , refreshTokenValidity : Maybe Int
    , supportedIdentityProviders : Maybe SupportedIdentityProvidersListType
    , userPoolId : String
    , writeAttributes : Maybe ClientPermissionListType
    }


{-| The CreateUserImportJobResponse data model.
-}
type alias CreateUserImportJobResponse =
    { userImportJob : Maybe UserImportJobType }


{-| The CreateUserImportJobRequest data model.
-}
type alias CreateUserImportJobRequest =
    { cloudWatchLogsRoleArn : String, jobName : String, userPoolId : String }


{-| The CreateResourceServerResponse data model.
-}
type alias CreateResourceServerResponse =
    { resourceServer : ResourceServerType }


{-| The CreateResourceServerRequest data model.
-}
type alias CreateResourceServerRequest =
    { identifier : String, name : String, scopes : Maybe ResourceServerScopeListType, userPoolId : String }


{-| The CreateIdentityProviderResponse data model.
-}
type alias CreateIdentityProviderResponse =
    { identityProvider : IdentityProviderType }


{-| The CreateIdentityProviderRequest data model.
-}
type alias CreateIdentityProviderRequest =
    { attributeMapping : Maybe AttributeMappingType
    , idpIdentifiers : Maybe IdpIdentifiersListType
    , providerDetails : ProviderDetailsType
    , providerName : String
    , providerType : IdentityProviderTypeType
    , userPoolId : String
    }


{-| The CreateGroupResponse data model.
-}
type alias CreateGroupResponse =
    { group : Maybe GroupType }


{-| The CreateGroupRequest data model.
-}
type alias CreateGroupRequest =
    { description : Maybe String
    , groupName : String
    , precedence : Maybe Int
    , roleArn : Maybe String
    , userPoolId : String
    }


{-| The ContextDataType data model.
-}
type alias ContextDataType =
    { encodedData : Maybe String
    , httpHeaders : HttpHeaderList
    , ipAddress : String
    , serverName : String
    , serverPath : String
    }


{-| The ConfirmSignUpResponse data model.
-}
type alias ConfirmSignUpResponse =
    {}


{-| The ConfirmSignUpRequest data model.
-}
type alias ConfirmSignUpRequest =
    { analyticsMetadata : Maybe AnalyticsMetadataType
    , clientId : String
    , confirmationCode : String
    , forceAliasCreation : Maybe Bool
    , secretHash : Maybe String
    , userContextData : Maybe UserContextDataType
    , username : String
    }


{-| The ConfirmForgotPasswordResponse data model.
-}
type alias ConfirmForgotPasswordResponse =
    {}


{-| The ConfirmForgotPasswordRequest data model.
-}
type alias ConfirmForgotPasswordRequest =
    { analyticsMetadata : Maybe AnalyticsMetadataType
    , clientId : String
    , confirmationCode : String
    , password : String
    , secretHash : Maybe String
    , userContextData : Maybe UserContextDataType
    , username : String
    }


{-| The ConfirmDeviceResponse data model.
-}
type alias ConfirmDeviceResponse =
    { userConfirmationNecessary : Maybe Bool }


{-| The ConfirmDeviceRequest data model.
-}
type alias ConfirmDeviceRequest =
    { accessToken : String
    , deviceKey : String
    , deviceName : Maybe String
    , deviceSecretVerifierConfig : Maybe DeviceSecretVerifierConfigType
    }


{-| The CompromisedCredentialsRiskConfigurationType data model.
-}
type alias CompromisedCredentialsRiskConfigurationType =
    { actions : CompromisedCredentialsActionsType, eventFilter : Maybe EventFiltersType }


{-| The CompromisedCredentialsEventActionType data model.
-}
type CompromisedCredentialsEventActionType
    = CompromisedCredentialsEventActionTypeBlock
    | CompromisedCredentialsEventActionTypeNoAction


{-| The CompromisedCredentialsEventActionType data model.
-}
compromisedCredentialsEventActionType : Enum CompromisedCredentialsEventActionType
compromisedCredentialsEventActionType =
    Enum.define
        [ CompromisedCredentialsEventActionTypeBlock, CompromisedCredentialsEventActionTypeNoAction ]
        (\val ->
            case val of
                CompromisedCredentialsEventActionTypeBlock ->
                    "BLOCK"

                CompromisedCredentialsEventActionTypeNoAction ->
                    "NO_ACTION"
        )


{-| The CompromisedCredentialsActionsType data model.
-}
type alias CompromisedCredentialsActionsType =
    { eventAction : CompromisedCredentialsEventActionType }


{-| The CodeDeliveryDetailsType data model.
-}
type alias CodeDeliveryDetailsType =
    { attributeName : Maybe String, deliveryMedium : Maybe DeliveryMediumType, destination : Maybe String }


{-| The CodeDeliveryDetailsListType data model.
-}
type alias CodeDeliveryDetailsListType =
    List CodeDeliveryDetailsType


{-| The ClientPermissionListType data model.
-}
type alias ClientPermissionListType =
    List String


{-| The ClientMetadataType data model.
-}
type alias ClientMetadataType =
    Dict String String


{-| The ChangePasswordResponse data model.
-}
type alias ChangePasswordResponse =
    {}


{-| The ChangePasswordRequest data model.
-}
type alias ChangePasswordRequest =
    { accessToken : String, previousPassword : String, proposedPassword : String }


{-| The ChallengeResponsesType data model.
-}
type alias ChallengeResponsesType =
    Dict String String


{-| The ChallengeResponseType data model.
-}
type alias ChallengeResponseType =
    { challengeName : Maybe ChallengeName, challengeResponse : Maybe ChallengeResponse }


{-| The ChallengeResponseListType data model.
-}
type alias ChallengeResponseListType =
    List ChallengeResponseType


{-| The ChallengeResponse data model.
-}
type ChallengeResponse
    = ChallengeResponseSuccess
    | ChallengeResponseFailure


{-| The ChallengeResponse data model.
-}
challengeResponse : Enum ChallengeResponse
challengeResponse =
    Enum.define
        [ ChallengeResponseSuccess, ChallengeResponseFailure ]
        (\val ->
            case val of
                ChallengeResponseSuccess ->
                    "Success"

                ChallengeResponseFailure ->
                    "Failure"
        )


{-| The ChallengeParametersType data model.
-}
type alias ChallengeParametersType =
    Dict String String


{-| The ChallengeNameType data model.
-}
type ChallengeNameType
    = ChallengeNameTypeSmsMfa
    | ChallengeNameTypeSoftwareTokenMfa
    | ChallengeNameTypeSelectMfaType
    | ChallengeNameTypeMfaSetup
    | ChallengeNameTypePasswordVerifier
    | ChallengeNameTypeCustomChallenge
    | ChallengeNameTypeDeviceSrpAuth
    | ChallengeNameTypeDevicePasswordVerifier
    | ChallengeNameTypeAdminNoSrpAuth
    | ChallengeNameTypeNewPasswordRequired


{-| The ChallengeNameType data model.
-}
challengeNameType : Enum ChallengeNameType
challengeNameType =
    Enum.define
        [ ChallengeNameTypeSmsMfa
        , ChallengeNameTypeSoftwareTokenMfa
        , ChallengeNameTypeSelectMfaType
        , ChallengeNameTypeMfaSetup
        , ChallengeNameTypePasswordVerifier
        , ChallengeNameTypeCustomChallenge
        , ChallengeNameTypeDeviceSrpAuth
        , ChallengeNameTypeDevicePasswordVerifier
        , ChallengeNameTypeAdminNoSrpAuth
        , ChallengeNameTypeNewPasswordRequired
        ]
        (\val ->
            case val of
                ChallengeNameTypeSmsMfa ->
                    "SMS_MFA"

                ChallengeNameTypeSoftwareTokenMfa ->
                    "SOFTWARE_TOKEN_MFA"

                ChallengeNameTypeSelectMfaType ->
                    "SELECT_MFA_TYPE"

                ChallengeNameTypeMfaSetup ->
                    "MFA_SETUP"

                ChallengeNameTypePasswordVerifier ->
                    "PASSWORD_VERIFIER"

                ChallengeNameTypeCustomChallenge ->
                    "CUSTOM_CHALLENGE"

                ChallengeNameTypeDeviceSrpAuth ->
                    "DEVICE_SRP_AUTH"

                ChallengeNameTypeDevicePasswordVerifier ->
                    "DEVICE_PASSWORD_VERIFIER"

                ChallengeNameTypeAdminNoSrpAuth ->
                    "ADMIN_NO_SRP_AUTH"

                ChallengeNameTypeNewPasswordRequired ->
                    "NEW_PASSWORD_REQUIRED"
        )


{-| The ChallengeName data model.
-}
type ChallengeName
    = ChallengeNamePassword
    | ChallengeNameMfa


{-| The ChallengeName data model.
-}
challengeName : Enum ChallengeName
challengeName =
    Enum.define
        [ ChallengeNamePassword, ChallengeNameMfa ]
        (\val ->
            case val of
                ChallengeNamePassword ->
                    "Password"

                ChallengeNameMfa ->
                    "Mfa"
        )


{-| The CallbackUrlsListType data model.
-}
type alias CallbackUrlsListType =
    List String


{-| The BlockedIprangeListType data model.
-}
type alias BlockedIprangeListType =
    List String


{-| The AuthenticationResultType data model.
-}
type alias AuthenticationResultType =
    { accessToken : Maybe String
    , expiresIn : Maybe Int
    , idToken : Maybe String
    , newDeviceMetadata : Maybe NewDeviceMetadataType
    , refreshToken : Maybe String
    , tokenType : Maybe String
    }


{-| The AuthParametersType data model.
-}
type alias AuthParametersType =
    Dict String String


{-| The AuthFlowType data model.
-}
type AuthFlowType
    = AuthFlowTypeUserSrpAuth
    | AuthFlowTypeRefreshTokenAuth
    | AuthFlowTypeRefreshToken
    | AuthFlowTypeCustomAuth
    | AuthFlowTypeAdminNoSrpAuth
    | AuthFlowTypeUserPasswordAuth


{-| The AuthFlowType data model.
-}
authFlowType : Enum AuthFlowType
authFlowType =
    Enum.define
        [ AuthFlowTypeUserSrpAuth
        , AuthFlowTypeRefreshTokenAuth
        , AuthFlowTypeRefreshToken
        , AuthFlowTypeCustomAuth
        , AuthFlowTypeAdminNoSrpAuth
        , AuthFlowTypeUserPasswordAuth
        ]
        (\val ->
            case val of
                AuthFlowTypeUserSrpAuth ->
                    "USER_SRP_AUTH"

                AuthFlowTypeRefreshTokenAuth ->
                    "REFRESH_TOKEN_AUTH"

                AuthFlowTypeRefreshToken ->
                    "REFRESH_TOKEN"

                AuthFlowTypeCustomAuth ->
                    "CUSTOM_AUTH"

                AuthFlowTypeAdminNoSrpAuth ->
                    "ADMIN_NO_SRP_AUTH"

                AuthFlowTypeUserPasswordAuth ->
                    "USER_PASSWORD_AUTH"
        )


{-| The AuthEventsType data model.
-}
type alias AuthEventsType =
    List AuthEventType


{-| The AuthEventType data model.
-}
type alias AuthEventType =
    { challengeResponses : Maybe ChallengeResponseListType
    , creationDate : Maybe String
    , eventContextData : Maybe EventContextDataType
    , eventFeedback : Maybe EventFeedbackType
    , eventId : Maybe String
    , eventResponse : Maybe EventResponseType
    , eventRisk : Maybe EventRiskType
    , eventType : Maybe EventType
    }


{-| The AttributeType data model.
-}
type alias AttributeType =
    { name : String, value : Maybe String }


{-| The AttributeNameListType data model.
-}
type alias AttributeNameListType =
    List String


{-| The AttributeMappingType data model.
-}
type alias AttributeMappingType =
    Dict String String


{-| The AttributeListType data model.
-}
type alias AttributeListType =
    List AttributeType


{-| The AttributeDataType data model.
-}
type AttributeDataType
    = AttributeDataTypeString_
    | AttributeDataTypeNumber
    | AttributeDataTypeDateTime
    | AttributeDataTypeBoolean


{-| The AttributeDataType data model.
-}
attributeDataType : Enum AttributeDataType
attributeDataType =
    Enum.define
        [ AttributeDataTypeString_, AttributeDataTypeNumber, AttributeDataTypeDateTime, AttributeDataTypeBoolean ]
        (\val ->
            case val of
                AttributeDataTypeString_ ->
                    "String"

                AttributeDataTypeNumber ->
                    "Number"

                AttributeDataTypeDateTime ->
                    "DateTime"

                AttributeDataTypeBoolean ->
                    "Boolean"
        )


{-| The AssociateSoftwareTokenResponse data model.
-}
type alias AssociateSoftwareTokenResponse =
    { secretCode : Maybe String, session : Maybe String }


{-| The AssociateSoftwareTokenRequest data model.
-}
type alias AssociateSoftwareTokenRequest =
    { accessToken : Maybe String, session : Maybe String }


{-| The AnalyticsMetadataType data model.
-}
type alias AnalyticsMetadataType =
    { analyticsEndpointId : Maybe String }


{-| The AnalyticsConfigurationType data model.
-}
type alias AnalyticsConfigurationType =
    { applicationId : String, externalId : String, roleArn : String, userDataShared : Maybe Bool }


{-| The AliasAttributesListType data model.
-}
type alias AliasAttributesListType =
    List AliasAttributeType


{-| The AliasAttributeType data model.
-}
type AliasAttributeType
    = AliasAttributeTypePhoneNumber
    | AliasAttributeTypeEmail
    | AliasAttributeTypePreferredUsername


{-| The AliasAttributeType data model.
-}
aliasAttributeType : Enum AliasAttributeType
aliasAttributeType =
    Enum.define
        [ AliasAttributeTypePhoneNumber, AliasAttributeTypeEmail, AliasAttributeTypePreferredUsername ]
        (\val ->
            case val of
                AliasAttributeTypePhoneNumber ->
                    "phone_number"

                AliasAttributeTypeEmail ->
                    "email"

                AliasAttributeTypePreferredUsername ->
                    "preferred_username"
        )


{-| The AdvancedSecurityModeType data model.
-}
type AdvancedSecurityModeType
    = AdvancedSecurityModeTypeOff
    | AdvancedSecurityModeTypeAudit
    | AdvancedSecurityModeTypeEnforced


{-| The AdvancedSecurityModeType data model.
-}
advancedSecurityModeType : Enum AdvancedSecurityModeType
advancedSecurityModeType =
    Enum.define
        [ AdvancedSecurityModeTypeOff, AdvancedSecurityModeTypeAudit, AdvancedSecurityModeTypeEnforced ]
        (\val ->
            case val of
                AdvancedSecurityModeTypeOff ->
                    "OFF"

                AdvancedSecurityModeTypeAudit ->
                    "AUDIT"

                AdvancedSecurityModeTypeEnforced ->
                    "ENFORCED"
        )


{-| The AdminUserGlobalSignOutResponse data model.
-}
type alias AdminUserGlobalSignOutResponse =
    {}


{-| The AdminUserGlobalSignOutRequest data model.
-}
type alias AdminUserGlobalSignOutRequest =
    { userPoolId : String, username : String }


{-| The AdminUpdateUserAttributesResponse data model.
-}
type alias AdminUpdateUserAttributesResponse =
    {}


{-| The AdminUpdateUserAttributesRequest data model.
-}
type alias AdminUpdateUserAttributesRequest =
    { userAttributes : AttributeListType, userPoolId : String, username : String }


{-| The AdminUpdateDeviceStatusResponse data model.
-}
type alias AdminUpdateDeviceStatusResponse =
    {}


{-| The AdminUpdateDeviceStatusRequest data model.
-}
type alias AdminUpdateDeviceStatusRequest =
    { deviceKey : String
    , deviceRememberedStatus : Maybe DeviceRememberedStatusType
    , userPoolId : String
    , username : String
    }


{-| The AdminUpdateAuthEventFeedbackResponse data model.
-}
type alias AdminUpdateAuthEventFeedbackResponse =
    {}


{-| The AdminUpdateAuthEventFeedbackRequest data model.
-}
type alias AdminUpdateAuthEventFeedbackRequest =
    { eventId : String, feedbackValue : FeedbackValueType, userPoolId : String, username : String }


{-| The AdminSetUserSettingsResponse data model.
-}
type alias AdminSetUserSettingsResponse =
    {}


{-| The AdminSetUserSettingsRequest data model.
-}
type alias AdminSetUserSettingsRequest =
    { mfaoptions : MfaoptionListType, userPoolId : String, username : String }


{-| The AdminSetUserPasswordResponse data model.
-}
type alias AdminSetUserPasswordResponse =
    {}


{-| The AdminSetUserPasswordRequest data model.
-}
type alias AdminSetUserPasswordRequest =
    { password : String, permanent : Maybe Bool, userPoolId : String, username : String }


{-| The AdminSetUserMfapreferenceResponse data model.
-}
type alias AdminSetUserMfapreferenceResponse =
    {}


{-| The AdminSetUserMfapreferenceRequest data model.
-}
type alias AdminSetUserMfapreferenceRequest =
    { smsmfaSettings : Maybe SmsmfaSettingsType
    , softwareTokenMfaSettings : Maybe SoftwareTokenMfaSettingsType
    , userPoolId : String
    , username : String
    }


{-| The AdminRespondToAuthChallengeResponse data model.
-}
type alias AdminRespondToAuthChallengeResponse =
    { authenticationResult : Maybe AuthenticationResultType
    , challengeName : Maybe ChallengeNameType
    , challengeParameters : Maybe ChallengeParametersType
    , session : Maybe String
    }


{-| The AdminRespondToAuthChallengeRequest data model.
-}
type alias AdminRespondToAuthChallengeRequest =
    { analyticsMetadata : Maybe AnalyticsMetadataType
    , challengeName : ChallengeNameType
    , challengeResponses : Maybe ChallengeResponsesType
    , clientId : String
    , contextData : Maybe ContextDataType
    , session : Maybe String
    , userPoolId : String
    }


{-| The AdminResetUserPasswordResponse data model.
-}
type alias AdminResetUserPasswordResponse =
    {}


{-| The AdminResetUserPasswordRequest data model.
-}
type alias AdminResetUserPasswordRequest =
    { userPoolId : String, username : String }


{-| The AdminRemoveUserFromGroupRequest data model.
-}
type alias AdminRemoveUserFromGroupRequest =
    { groupName : String, userPoolId : String, username : String }


{-| The AdminListUserAuthEventsResponse data model.
-}
type alias AdminListUserAuthEventsResponse =
    { authEvents : Maybe AuthEventsType, nextToken : Maybe String }


{-| The AdminListUserAuthEventsRequest data model.
-}
type alias AdminListUserAuthEventsRequest =
    { maxResults : Maybe Int, nextToken : Maybe String, userPoolId : String, username : String }


{-| The AdminListGroupsForUserResponse data model.
-}
type alias AdminListGroupsForUserResponse =
    { groups : Maybe GroupListType, nextToken : Maybe String }


{-| The AdminListGroupsForUserRequest data model.
-}
type alias AdminListGroupsForUserRequest =
    { limit : Maybe Int, nextToken : Maybe String, userPoolId : String, username : String }


{-| The AdminListDevicesResponse data model.
-}
type alias AdminListDevicesResponse =
    { devices : Maybe DeviceListType, paginationToken : Maybe String }


{-| The AdminListDevicesRequest data model.
-}
type alias AdminListDevicesRequest =
    { limit : Maybe Int, paginationToken : Maybe String, userPoolId : String, username : String }


{-| The AdminLinkProviderForUserResponse data model.
-}
type alias AdminLinkProviderForUserResponse =
    {}


{-| The AdminLinkProviderForUserRequest data model.
-}
type alias AdminLinkProviderForUserRequest =
    { destinationUser : ProviderUserIdentifierType, sourceUser : ProviderUserIdentifierType, userPoolId : String }


{-| The AdminInitiateAuthResponse data model.
-}
type alias AdminInitiateAuthResponse =
    { authenticationResult : Maybe AuthenticationResultType
    , challengeName : Maybe ChallengeNameType
    , challengeParameters : Maybe ChallengeParametersType
    , session : Maybe String
    }


{-| The AdminInitiateAuthRequest data model.
-}
type alias AdminInitiateAuthRequest =
    { analyticsMetadata : Maybe AnalyticsMetadataType
    , authFlow : AuthFlowType
    , authParameters : Maybe AuthParametersType
    , clientId : String
    , clientMetadata : Maybe ClientMetadataType
    , contextData : Maybe ContextDataType
    , userPoolId : String
    }


{-| The AdminGetUserResponse data model.
-}
type alias AdminGetUserResponse =
    { enabled : Maybe Bool
    , mfaoptions : Maybe MfaoptionListType
    , preferredMfaSetting : Maybe String
    , userAttributes : Maybe AttributeListType
    , userCreateDate : Maybe String
    , userLastModifiedDate : Maybe String
    , userMfasettingList : Maybe UserMfasettingListType
    , userStatus : Maybe UserStatusType
    , username : String
    }


{-| The AdminGetUserRequest data model.
-}
type alias AdminGetUserRequest =
    { userPoolId : String, username : String }


{-| The AdminGetDeviceResponse data model.
-}
type alias AdminGetDeviceResponse =
    { device : DeviceType }


{-| The AdminGetDeviceRequest data model.
-}
type alias AdminGetDeviceRequest =
    { deviceKey : String, userPoolId : String, username : String }


{-| The AdminForgetDeviceRequest data model.
-}
type alias AdminForgetDeviceRequest =
    { deviceKey : String, userPoolId : String, username : String }


{-| The AdminEnableUserResponse data model.
-}
type alias AdminEnableUserResponse =
    {}


{-| The AdminEnableUserRequest data model.
-}
type alias AdminEnableUserRequest =
    { userPoolId : String, username : String }


{-| The AdminDisableUserResponse data model.
-}
type alias AdminDisableUserResponse =
    {}


{-| The AdminDisableUserRequest data model.
-}
type alias AdminDisableUserRequest =
    { userPoolId : String, username : String }


{-| The AdminDisableProviderForUserResponse data model.
-}
type alias AdminDisableProviderForUserResponse =
    {}


{-| The AdminDisableProviderForUserRequest data model.
-}
type alias AdminDisableProviderForUserRequest =
    { user : ProviderUserIdentifierType, userPoolId : String }


{-| The AdminDeleteUserRequest data model.
-}
type alias AdminDeleteUserRequest =
    { userPoolId : String, username : String }


{-| The AdminDeleteUserAttributesResponse data model.
-}
type alias AdminDeleteUserAttributesResponse =
    {}


{-| The AdminDeleteUserAttributesRequest data model.
-}
type alias AdminDeleteUserAttributesRequest =
    { userAttributeNames : AttributeNameListType, userPoolId : String, username : String }


{-| The AdminCreateUserResponse data model.
-}
type alias AdminCreateUserResponse =
    { user : Maybe UserType }


{-| The AdminCreateUserRequest data model.
-}
type alias AdminCreateUserRequest =
    { desiredDeliveryMediums : Maybe DeliveryMediumListType
    , forceAliasCreation : Maybe Bool
    , messageAction : Maybe MessageActionType
    , temporaryPassword : Maybe String
    , userAttributes : Maybe AttributeListType
    , userPoolId : String
    , username : String
    , validationData : Maybe AttributeListType
    }


{-| The AdminCreateUserConfigType data model.
-}
type alias AdminCreateUserConfigType =
    { allowAdminCreateUserOnly : Maybe Bool
    , inviteMessageTemplate : Maybe MessageTemplateType
    , unusedAccountValidityDays : Maybe Int
    }


{-| The AdminConfirmSignUpResponse data model.
-}
type alias AdminConfirmSignUpResponse =
    {}


{-| The AdminConfirmSignUpRequest data model.
-}
type alias AdminConfirmSignUpRequest =
    { userPoolId : String, username : String }


{-| The AdminAddUserToGroupRequest data model.
-}
type alias AdminAddUserToGroupRequest =
    { groupName : String, userPoolId : String, username : String }


{-| The AddCustomAttributesResponse data model.
-}
type alias AddCustomAttributesResponse =
    {}


{-| The AddCustomAttributesRequest data model.
-}
type alias AddCustomAttributesRequest =
    { customAttributes : CustomAttributesListType, userPoolId : String }


{-| The AccountTakeoverRiskConfigurationType data model.
-}
type alias AccountTakeoverRiskConfigurationType =
    { actions : AccountTakeoverActionsType, notifyConfiguration : Maybe NotifyConfigurationType }


{-| The AccountTakeoverEventActionType data model.
-}
type AccountTakeoverEventActionType
    = AccountTakeoverEventActionTypeBlock
    | AccountTakeoverEventActionTypeMfaIfConfigured
    | AccountTakeoverEventActionTypeMfaRequired
    | AccountTakeoverEventActionTypeNoAction


{-| The AccountTakeoverEventActionType data model.
-}
accountTakeoverEventActionType : Enum AccountTakeoverEventActionType
accountTakeoverEventActionType =
    Enum.define
        [ AccountTakeoverEventActionTypeBlock
        , AccountTakeoverEventActionTypeMfaIfConfigured
        , AccountTakeoverEventActionTypeMfaRequired
        , AccountTakeoverEventActionTypeNoAction
        ]
        (\val ->
            case val of
                AccountTakeoverEventActionTypeBlock ->
                    "BLOCK"

                AccountTakeoverEventActionTypeMfaIfConfigured ->
                    "MFA_IF_CONFIGURED"

                AccountTakeoverEventActionTypeMfaRequired ->
                    "MFA_REQUIRED"

                AccountTakeoverEventActionTypeNoAction ->
                    "NO_ACTION"
        )


{-| The AccountTakeoverActionsType data model.
-}
type alias AccountTakeoverActionsType =
    { highAction : Maybe AccountTakeoverActionType
    , lowAction : Maybe AccountTakeoverActionType
    , mediumAction : Maybe AccountTakeoverActionType
    }


{-| The AccountTakeoverActionType data model.
-}
type alias AccountTakeoverActionType =
    { eventAction : AccountTakeoverEventActionType, notify : Bool }


{-| Codec for AccountTakeoverActionType.
-}
accountTakeoverActionTypeCodec : Codec AccountTakeoverActionType
accountTakeoverActionTypeCodec =
    Codec.object AccountTakeoverActionType
        |> Codec.field "EventAction" .eventAction accountTakeoverEventActionTypeCodec
        |> Codec.field "Notify" .notify Codec.bool
        |> Codec.buildObject


{-| Codec for AccountTakeoverActionsType.
-}
accountTakeoverActionsTypeCodec : Codec AccountTakeoverActionsType
accountTakeoverActionsTypeCodec =
    Codec.object AccountTakeoverActionsType
        |> Codec.optionalField "HighAction" .highAction accountTakeoverActionTypeCodec
        |> Codec.optionalField "LowAction" .lowAction accountTakeoverActionTypeCodec
        |> Codec.optionalField "MediumAction" .mediumAction accountTakeoverActionTypeCodec
        |> Codec.buildObject


{-| Codec for AccountTakeoverEventActionType.
-}
accountTakeoverEventActionTypeCodec : Codec AccountTakeoverEventActionType
accountTakeoverEventActionTypeCodec =
    Codec.build (Enum.encoder accountTakeoverEventActionType) (Enum.decoder accountTakeoverEventActionType)


{-| Codec for AccountTakeoverRiskConfigurationType.
-}
accountTakeoverRiskConfigurationTypeCodec : Codec AccountTakeoverRiskConfigurationType
accountTakeoverRiskConfigurationTypeCodec =
    Codec.object AccountTakeoverRiskConfigurationType
        |> Codec.field "Actions" .actions accountTakeoverActionsTypeCodec
        |> Codec.optionalField "NotifyConfiguration" .notifyConfiguration notifyConfigurationTypeCodec
        |> Codec.buildObject


{-| Codec for AdminCreateUserConfigType.
-}
adminCreateUserConfigTypeCodec : Codec AdminCreateUserConfigType
adminCreateUserConfigTypeCodec =
    Codec.object AdminCreateUserConfigType
        |> Codec.optionalField "AllowAdminCreateUserOnly" .allowAdminCreateUserOnly Codec.bool
        |> Codec.optionalField "InviteMessageTemplate" .inviteMessageTemplate messageTemplateTypeCodec
        |> Codec.optionalField "UnusedAccountValidityDays" .unusedAccountValidityDays Codec.int
        |> Codec.buildObject


{-| Codec for AdvancedSecurityModeType.
-}
advancedSecurityModeTypeCodec : Codec AdvancedSecurityModeType
advancedSecurityModeTypeCodec =
    Codec.build (Enum.encoder advancedSecurityModeType) (Enum.decoder advancedSecurityModeType)


{-| Codec for AliasAttributeType.
-}
aliasAttributeTypeCodec : Codec AliasAttributeType
aliasAttributeTypeCodec =
    Codec.build (Enum.encoder aliasAttributeType) (Enum.decoder aliasAttributeType)


{-| Codec for AliasAttributesListType.
-}
aliasAttributesListTypeCodec : Codec AliasAttributesListType
aliasAttributesListTypeCodec =
    Codec.list aliasAttributeTypeCodec


{-| Codec for AnalyticsConfigurationType.
-}
analyticsConfigurationTypeCodec : Codec AnalyticsConfigurationType
analyticsConfigurationTypeCodec =
    Codec.object AnalyticsConfigurationType
        |> Codec.field "ApplicationId" .applicationId Codec.string
        |> Codec.field "ExternalId" .externalId Codec.string
        |> Codec.field "RoleArn" .roleArn Codec.string
        |> Codec.optionalField "UserDataShared" .userDataShared Codec.bool
        |> Codec.buildObject


{-| Encoder for AnalyticsMetadataType.
-}
analyticsMetadataTypeEncoder : AnalyticsMetadataType -> Value
analyticsMetadataTypeEncoder val =
    [ ( "AnalyticsEndpointId", val.analyticsEndpointId ) |> EncodeOpt.optionalField Json.Encode.string ]
        |> EncodeOpt.objectMaySkip


{-| Codec for AttributeDataType.
-}
attributeDataTypeCodec : Codec AttributeDataType
attributeDataTypeCodec =
    Codec.build (Enum.encoder attributeDataType) (Enum.decoder attributeDataType)


{-| Codec for AttributeListType.
-}
attributeListTypeCodec : Codec AttributeListType
attributeListTypeCodec =
    Codec.list attributeTypeCodec


{-| Codec for AttributeMappingType.
-}
attributeMappingTypeCodec : Codec AttributeMappingType
attributeMappingTypeCodec =
    Codec.dict Codec.string


{-| Encoder for AttributeNameListType.
-}
attributeNameListTypeEncoder : AttributeNameListType -> Value
attributeNameListTypeEncoder val =
    Json.Encode.list Json.Encode.string val


{-| Codec for AttributeType.
-}
attributeTypeCodec : Codec AttributeType
attributeTypeCodec =
    Codec.object AttributeType
        |> Codec.field "Name" .name Codec.string
        |> Codec.optionalField "Value" .value Codec.string
        |> Codec.buildObject


{-| Decoder for AuthEventType.
-}
authEventTypeDecoder : Decoder AuthEventType
authEventTypeDecoder =
    Json.Decode.succeed AuthEventType
        |> Pipeline.optional "ChallengeResponses" (Json.Decode.maybe challengeResponseListTypeDecoder) Nothing
        |> Pipeline.optional "CreationDate" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "EventContextData" (Json.Decode.maybe eventContextDataTypeDecoder) Nothing
        |> Pipeline.optional "EventFeedback" (Json.Decode.maybe eventFeedbackTypeDecoder) Nothing
        |> Pipeline.optional "EventId" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "EventResponse" (Json.Decode.maybe eventResponseTypeDecoder) Nothing
        |> Pipeline.optional "EventRisk" (Json.Decode.maybe eventRiskTypeDecoder) Nothing
        |> Pipeline.optional "EventType" (Json.Decode.maybe eventTypeDecoder) Nothing


{-| Decoder for AuthEventsType.
-}
authEventsTypeDecoder : Decoder AuthEventsType
authEventsTypeDecoder =
    Json.Decode.list authEventTypeDecoder


{-| Encoder for AuthFlowType.
-}
authFlowTypeEncoder : AuthFlowType -> Value
authFlowTypeEncoder =
    Enum.encoder authFlowType


{-| Encoder for AuthParametersType.
-}
authParametersTypeEncoder : AuthParametersType -> Value
authParametersTypeEncoder val =
    Json.Encode.dict identity Json.Encode.string val


{-| Decoder for AuthenticationResultType.
-}
authenticationResultTypeDecoder : Decoder AuthenticationResultType
authenticationResultTypeDecoder =
    Json.Decode.succeed AuthenticationResultType
        |> Pipeline.optional "AccessToken" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "ExpiresIn" (Json.Decode.maybe Json.Decode.int) Nothing
        |> Pipeline.optional "IdToken" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "NewDeviceMetadata" (Json.Decode.maybe newDeviceMetadataTypeDecoder) Nothing
        |> Pipeline.optional "RefreshToken" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "TokenType" (Json.Decode.maybe Json.Decode.string) Nothing


{-| Codec for BlockedIprangeListType.
-}
blockedIprangeListTypeCodec : Codec BlockedIprangeListType
blockedIprangeListTypeCodec =
    Codec.list Codec.string


{-| Codec for CallbackUrlsListType.
-}
callbackUrlsListTypeCodec : Codec CallbackUrlsListType
callbackUrlsListTypeCodec =
    Codec.list Codec.string


{-| Decoder for ChallengeName.
-}
challengeNameDecoder : Decoder ChallengeName
challengeNameDecoder =
    Enum.decoder challengeName


{-| Codec for ChallengeNameType.
-}
challengeNameTypeCodec : Codec ChallengeNameType
challengeNameTypeCodec =
    Codec.build (Enum.encoder challengeNameType) (Enum.decoder challengeNameType)


{-| Decoder for ChallengeParametersType.
-}
challengeParametersTypeDecoder : Decoder ChallengeParametersType
challengeParametersTypeDecoder =
    Json.Decode.dict Json.Decode.string


{-| Decoder for ChallengeResponse.
-}
challengeResponseDecoder : Decoder ChallengeResponse
challengeResponseDecoder =
    Enum.decoder challengeResponse


{-| Decoder for ChallengeResponseListType.
-}
challengeResponseListTypeDecoder : Decoder ChallengeResponseListType
challengeResponseListTypeDecoder =
    Json.Decode.list challengeResponseTypeDecoder


{-| Decoder for ChallengeResponseType.
-}
challengeResponseTypeDecoder : Decoder ChallengeResponseType
challengeResponseTypeDecoder =
    Json.Decode.succeed ChallengeResponseType
        |> Pipeline.optional "ChallengeName" (Json.Decode.maybe challengeNameDecoder) Nothing
        |> Pipeline.optional "ChallengeResponse" (Json.Decode.maybe challengeResponseDecoder) Nothing


{-| Encoder for ChallengeResponsesType.
-}
challengeResponsesTypeEncoder : ChallengeResponsesType -> Value
challengeResponsesTypeEncoder val =
    Json.Encode.dict identity Json.Encode.string val


{-| Encoder for ClientMetadataType.
-}
clientMetadataTypeEncoder : ClientMetadataType -> Value
clientMetadataTypeEncoder val =
    Json.Encode.dict identity Json.Encode.string val


{-| Codec for ClientPermissionListType.
-}
clientPermissionListTypeCodec : Codec ClientPermissionListType
clientPermissionListTypeCodec =
    Codec.list Codec.string


{-| Decoder for CodeDeliveryDetailsListType.
-}
codeDeliveryDetailsListTypeDecoder : Decoder CodeDeliveryDetailsListType
codeDeliveryDetailsListTypeDecoder =
    Json.Decode.list codeDeliveryDetailsTypeDecoder


{-| Decoder for CodeDeliveryDetailsType.
-}
codeDeliveryDetailsTypeDecoder : Decoder CodeDeliveryDetailsType
codeDeliveryDetailsTypeDecoder =
    Json.Decode.succeed CodeDeliveryDetailsType
        |> Pipeline.optional "AttributeName" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "DeliveryMedium" (Json.Decode.maybe (Codec.decoder deliveryMediumTypeCodec)) Nothing
        |> Pipeline.optional "Destination" (Json.Decode.maybe Json.Decode.string) Nothing


{-| Codec for CompromisedCredentialsActionsType.
-}
compromisedCredentialsActionsTypeCodec : Codec CompromisedCredentialsActionsType
compromisedCredentialsActionsTypeCodec =
    Codec.object CompromisedCredentialsActionsType
        |> Codec.field "EventAction" .eventAction compromisedCredentialsEventActionTypeCodec
        |> Codec.buildObject


{-| Codec for CompromisedCredentialsEventActionType.
-}
compromisedCredentialsEventActionTypeCodec : Codec CompromisedCredentialsEventActionType
compromisedCredentialsEventActionTypeCodec =
    Codec.build
        (Enum.encoder compromisedCredentialsEventActionType)
        (Enum.decoder compromisedCredentialsEventActionType)


{-| Codec for CompromisedCredentialsRiskConfigurationType.
-}
compromisedCredentialsRiskConfigurationTypeCodec : Codec CompromisedCredentialsRiskConfigurationType
compromisedCredentialsRiskConfigurationTypeCodec =
    Codec.object CompromisedCredentialsRiskConfigurationType
        |> Codec.field "Actions" .actions compromisedCredentialsActionsTypeCodec
        |> Codec.optionalField "EventFilter" .eventFilter eventFiltersTypeCodec
        |> Codec.buildObject


{-| Encoder for ContextDataType.
-}
contextDataTypeEncoder : ContextDataType -> Value
contextDataTypeEncoder val =
    [ ( "EncodedData", val.encodedData ) |> EncodeOpt.optionalField Json.Encode.string
    , ( "HttpHeaders", val.httpHeaders ) |> EncodeOpt.field httpHeaderListEncoder
    , ( "IpAddress", val.ipAddress ) |> EncodeOpt.field Json.Encode.string
    , ( "ServerName", val.serverName ) |> EncodeOpt.field Json.Encode.string
    , ( "ServerPath", val.serverPath ) |> EncodeOpt.field Json.Encode.string
    ]
        |> EncodeOpt.objectMaySkip


{-| Encoder for CustomAttributesListType.
-}
customAttributesListTypeEncoder : CustomAttributesListType -> Value
customAttributesListTypeEncoder val =
    Json.Encode.list (Codec.encoder schemaAttributeTypeCodec) val


{-| Codec for CustomDomainConfigType.
-}
customDomainConfigTypeCodec : Codec CustomDomainConfigType
customDomainConfigTypeCodec =
    Codec.object CustomDomainConfigType
        |> Codec.field "CertificateArn" .certificateArn Codec.string
        |> Codec.buildObject


{-| Codec for DefaultEmailOptionType.
-}
defaultEmailOptionTypeCodec : Codec DefaultEmailOptionType
defaultEmailOptionTypeCodec =
    Codec.build (Enum.encoder defaultEmailOptionType) (Enum.decoder defaultEmailOptionType)


{-| Encoder for DeliveryMediumListType.
-}
deliveryMediumListTypeEncoder : DeliveryMediumListType -> Value
deliveryMediumListTypeEncoder val =
    Json.Encode.list (Codec.encoder deliveryMediumTypeCodec) val


{-| Codec for DeliveryMediumType.
-}
deliveryMediumTypeCodec : Codec DeliveryMediumType
deliveryMediumTypeCodec =
    Codec.build (Enum.encoder deliveryMediumType) (Enum.decoder deliveryMediumType)


{-| Codec for DeviceConfigurationType.
-}
deviceConfigurationTypeCodec : Codec DeviceConfigurationType
deviceConfigurationTypeCodec =
    Codec.object DeviceConfigurationType
        |> Codec.optionalField "ChallengeRequiredOnNewDevice" .challengeRequiredOnNewDevice Codec.bool
        |> Codec.optionalField "DeviceOnlyRememberedOnUserPrompt" .deviceOnlyRememberedOnUserPrompt Codec.bool
        |> Codec.buildObject


{-| Decoder for DeviceListType.
-}
deviceListTypeDecoder : Decoder DeviceListType
deviceListTypeDecoder =
    Json.Decode.list deviceTypeDecoder


{-| Encoder for DeviceRememberedStatusType.
-}
deviceRememberedStatusTypeEncoder : DeviceRememberedStatusType -> Value
deviceRememberedStatusTypeEncoder =
    Enum.encoder deviceRememberedStatusType


{-| Encoder for DeviceSecretVerifierConfigType.
-}
deviceSecretVerifierConfigTypeEncoder : DeviceSecretVerifierConfigType -> Value
deviceSecretVerifierConfigTypeEncoder val =
    [ ( "PasswordVerifier", val.passwordVerifier ) |> EncodeOpt.optionalField Json.Encode.string
    , ( "Salt", val.salt ) |> EncodeOpt.optionalField Json.Encode.string
    ]
        |> EncodeOpt.objectMaySkip


{-| Decoder for DeviceType.
-}
deviceTypeDecoder : Decoder DeviceType
deviceTypeDecoder =
    Json.Decode.succeed DeviceType
        |> Pipeline.optional "DeviceAttributes" (Json.Decode.maybe (Codec.decoder attributeListTypeCodec)) Nothing
        |> Pipeline.optional "DeviceCreateDate" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "DeviceKey" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "DeviceLastAuthenticatedDate" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "DeviceLastModifiedDate" (Json.Decode.maybe Json.Decode.string) Nothing


{-| Decoder for DomainDescriptionType.
-}
domainDescriptionTypeDecoder : Decoder DomainDescriptionType
domainDescriptionTypeDecoder =
    Json.Decode.succeed DomainDescriptionType
        |> Pipeline.optional "AWSAccountId" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "CloudFrontDistribution" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional
            "CustomDomainConfig"
            (Json.Decode.maybe (Codec.decoder customDomainConfigTypeCodec))
            Nothing
        |> Pipeline.optional "Domain" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "S3Bucket" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "Status" (Json.Decode.maybe domainStatusTypeDecoder) Nothing
        |> Pipeline.optional "UserPoolId" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "Version" (Json.Decode.maybe Json.Decode.string) Nothing


{-| Decoder for DomainStatusType.
-}
domainStatusTypeDecoder : Decoder DomainStatusType
domainStatusTypeDecoder =
    Enum.decoder domainStatusType


{-| Codec for EmailConfigurationType.
-}
emailConfigurationTypeCodec : Codec EmailConfigurationType
emailConfigurationTypeCodec =
    Codec.object EmailConfigurationType
        |> Codec.optionalField "EmailSendingAccount" .emailSendingAccount emailSendingAccountTypeCodec
        |> Codec.optionalField "ReplyToEmailAddress" .replyToEmailAddress Codec.string
        |> Codec.optionalField "SourceArn" .sourceArn Codec.string
        |> Codec.buildObject


{-| Codec for EmailSendingAccountType.
-}
emailSendingAccountTypeCodec : Codec EmailSendingAccountType
emailSendingAccountTypeCodec =
    Codec.build (Enum.encoder emailSendingAccountType) (Enum.decoder emailSendingAccountType)


{-| Decoder for EventContextDataType.
-}
eventContextDataTypeDecoder : Decoder EventContextDataType
eventContextDataTypeDecoder =
    Json.Decode.succeed EventContextDataType
        |> Pipeline.optional "City" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "Country" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "DeviceName" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "IpAddress" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "Timezone" (Json.Decode.maybe Json.Decode.string) Nothing


{-| Decoder for EventFeedbackType.
-}
eventFeedbackTypeDecoder : Decoder EventFeedbackType
eventFeedbackTypeDecoder =
    Json.Decode.succeed EventFeedbackType
        |> Pipeline.optional "FeedbackDate" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.required "FeedbackValue" (Codec.decoder feedbackValueTypeCodec)
        |> Pipeline.required "Provider" Json.Decode.string


{-| Codec for EventFilterType.
-}
eventFilterTypeCodec : Codec EventFilterType
eventFilterTypeCodec =
    Codec.build (Enum.encoder eventFilterType) (Enum.decoder eventFilterType)


{-| Codec for EventFiltersType.
-}
eventFiltersTypeCodec : Codec EventFiltersType
eventFiltersTypeCodec =
    Codec.list eventFilterTypeCodec


{-| Decoder for EventResponseType.
-}
eventResponseTypeDecoder : Decoder EventResponseType
eventResponseTypeDecoder =
    Enum.decoder eventResponseType


{-| Decoder for EventRiskType.
-}
eventRiskTypeDecoder : Decoder EventRiskType
eventRiskTypeDecoder =
    Json.Decode.succeed EventRiskType
        |> Pipeline.optional "RiskDecision" (Json.Decode.maybe riskDecisionTypeDecoder) Nothing
        |> Pipeline.optional "RiskLevel" (Json.Decode.maybe riskLevelTypeDecoder) Nothing


{-| Decoder for EventType.
-}
eventTypeDecoder : Decoder EventType
eventTypeDecoder =
    Enum.decoder eventType


{-| Codec for ExplicitAuthFlowsListType.
-}
explicitAuthFlowsListTypeCodec : Codec ExplicitAuthFlowsListType
explicitAuthFlowsListTypeCodec =
    Codec.list explicitAuthFlowsTypeCodec


{-| Codec for ExplicitAuthFlowsType.
-}
explicitAuthFlowsTypeCodec : Codec ExplicitAuthFlowsType
explicitAuthFlowsTypeCodec =
    Codec.build (Enum.encoder explicitAuthFlowsType) (Enum.decoder explicitAuthFlowsType)


{-| Codec for FeedbackValueType.
-}
feedbackValueTypeCodec : Codec FeedbackValueType
feedbackValueTypeCodec =
    Codec.build (Enum.encoder feedbackValueType) (Enum.decoder feedbackValueType)


{-| Decoder for GroupListType.
-}
groupListTypeDecoder : Decoder GroupListType
groupListTypeDecoder =
    Json.Decode.list groupTypeDecoder


{-| Decoder for GroupType.
-}
groupTypeDecoder : Decoder GroupType
groupTypeDecoder =
    Json.Decode.succeed GroupType
        |> Pipeline.optional "CreationDate" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "Description" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "GroupName" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "LastModifiedDate" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "Precedence" (Json.Decode.maybe Json.Decode.int) Nothing
        |> Pipeline.optional "RoleArn" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "UserPoolId" (Json.Decode.maybe Json.Decode.string) Nothing


{-| Encoder for HttpHeader.
-}
httpHeaderEncoder : HttpHeader -> Value
httpHeaderEncoder val =
    [ ( "headerName", val.headerName ) |> EncodeOpt.optionalField Json.Encode.string
    , ( "headerValue", val.headerValue ) |> EncodeOpt.optionalField Json.Encode.string
    ]
        |> EncodeOpt.objectMaySkip


{-| Encoder for HttpHeaderList.
-}
httpHeaderListEncoder : HttpHeaderList -> Value
httpHeaderListEncoder val =
    Json.Encode.list httpHeaderEncoder val


{-| Decoder for IdentityProviderType.
-}
identityProviderTypeDecoder : Decoder IdentityProviderType
identityProviderTypeDecoder =
    Json.Decode.succeed IdentityProviderType
        |> Pipeline.optional "AttributeMapping" (Json.Decode.maybe (Codec.decoder attributeMappingTypeCodec)) Nothing
        |> Pipeline.optional "CreationDate" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "IdpIdentifiers" (Json.Decode.maybe (Codec.decoder idpIdentifiersListTypeCodec)) Nothing
        |> Pipeline.optional "LastModifiedDate" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "ProviderDetails" (Json.Decode.maybe (Codec.decoder providerDetailsTypeCodec)) Nothing
        |> Pipeline.optional "ProviderName" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "ProviderType" (Json.Decode.maybe (Codec.decoder identityProviderTypeTypeCodec)) Nothing
        |> Pipeline.optional "UserPoolId" (Json.Decode.maybe Json.Decode.string) Nothing


{-| Codec for IdentityProviderTypeType.
-}
identityProviderTypeTypeCodec : Codec IdentityProviderTypeType
identityProviderTypeTypeCodec =
    Codec.build (Enum.encoder identityProviderTypeType) (Enum.decoder identityProviderTypeType)


{-| Codec for IdpIdentifiersListType.
-}
idpIdentifiersListTypeCodec : Codec IdpIdentifiersListType
idpIdentifiersListTypeCodec =
    Codec.list Codec.string


{-| Codec for LambdaConfigType.
-}
lambdaConfigTypeCodec : Codec LambdaConfigType
lambdaConfigTypeCodec =
    Codec.object LambdaConfigType
        |> Codec.optionalField "CreateAuthChallenge" .createAuthChallenge Codec.string
        |> Codec.optionalField "CustomMessage" .customMessage Codec.string
        |> Codec.optionalField "DefineAuthChallenge" .defineAuthChallenge Codec.string
        |> Codec.optionalField "PostAuthentication" .postAuthentication Codec.string
        |> Codec.optionalField "PostConfirmation" .postConfirmation Codec.string
        |> Codec.optionalField "PreAuthentication" .preAuthentication Codec.string
        |> Codec.optionalField "PreSignUp" .preSignUp Codec.string
        |> Codec.optionalField "PreTokenGeneration" .preTokenGeneration Codec.string
        |> Codec.optionalField "UserMigration" .userMigration Codec.string
        |> Codec.optionalField "VerifyAuthChallengeResponse" .verifyAuthChallengeResponse Codec.string
        |> Codec.buildObject


{-| Decoder for ListOfStringTypes.
-}
listOfStringTypesDecoder : Decoder ListOfStringTypes
listOfStringTypesDecoder =
    Json.Decode.list Json.Decode.string


{-| Codec for LogoutUrlsListType.
-}
logoutUrlsListTypeCodec : Codec LogoutUrlsListType
logoutUrlsListTypeCodec =
    Codec.list Codec.string


{-| Codec for MfaoptionListType.
-}
mfaoptionListTypeCodec : Codec MfaoptionListType
mfaoptionListTypeCodec =
    Codec.list mfaoptionTypeCodec


{-| Codec for MfaoptionType.
-}
mfaoptionTypeCodec : Codec MfaoptionType
mfaoptionTypeCodec =
    Codec.object MfaoptionType
        |> Codec.optionalField "AttributeName" .attributeName Codec.string
        |> Codec.optionalField "DeliveryMedium" .deliveryMedium deliveryMediumTypeCodec
        |> Codec.buildObject


{-| Encoder for MessageActionType.
-}
messageActionTypeEncoder : MessageActionType -> Value
messageActionTypeEncoder =
    Enum.encoder messageActionType


{-| Codec for MessageTemplateType.
-}
messageTemplateTypeCodec : Codec MessageTemplateType
messageTemplateTypeCodec =
    Codec.object MessageTemplateType
        |> Codec.optionalField "EmailMessage" .emailMessage Codec.string
        |> Codec.optionalField "EmailSubject" .emailSubject Codec.string
        |> Codec.optionalField "SMSMessage" .smsmessage Codec.string
        |> Codec.buildObject


{-| Decoder for NewDeviceMetadataType.
-}
newDeviceMetadataTypeDecoder : Decoder NewDeviceMetadataType
newDeviceMetadataTypeDecoder =
    Json.Decode.succeed NewDeviceMetadataType
        |> Pipeline.optional "DeviceGroupKey" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "DeviceKey" (Json.Decode.maybe Json.Decode.string) Nothing


{-| Codec for NotifyConfigurationType.
-}
notifyConfigurationTypeCodec : Codec NotifyConfigurationType
notifyConfigurationTypeCodec =
    Codec.object NotifyConfigurationType
        |> Codec.optionalField "BlockEmail" .blockEmail notifyEmailTypeCodec
        |> Codec.optionalField "From" .from Codec.string
        |> Codec.optionalField "MfaEmail" .mfaEmail notifyEmailTypeCodec
        |> Codec.optionalField "NoActionEmail" .noActionEmail notifyEmailTypeCodec
        |> Codec.optionalField "ReplyTo" .replyTo Codec.string
        |> Codec.field "SourceArn" .sourceArn Codec.string
        |> Codec.buildObject


{-| Codec for NotifyEmailType.
-}
notifyEmailTypeCodec : Codec NotifyEmailType
notifyEmailTypeCodec =
    Codec.object NotifyEmailType
        |> Codec.optionalField "HtmlBody" .htmlBody Codec.string
        |> Codec.field "Subject" .subject Codec.string
        |> Codec.optionalField "TextBody" .textBody Codec.string
        |> Codec.buildObject


{-| Codec for NumberAttributeConstraintsType.
-}
numberAttributeConstraintsTypeCodec : Codec NumberAttributeConstraintsType
numberAttributeConstraintsTypeCodec =
    Codec.object NumberAttributeConstraintsType
        |> Codec.optionalField "MaxValue" .maxValue Codec.string
        |> Codec.optionalField "MinValue" .minValue Codec.string
        |> Codec.buildObject


{-| Codec for OauthFlowType.
-}
oauthFlowTypeCodec : Codec OauthFlowType
oauthFlowTypeCodec =
    Codec.build (Enum.encoder oauthFlowType) (Enum.decoder oauthFlowType)


{-| Codec for OauthFlowsType.
-}
oauthFlowsTypeCodec : Codec OauthFlowsType
oauthFlowsTypeCodec =
    Codec.list oauthFlowTypeCodec


{-| Codec for PasswordPolicyType.
-}
passwordPolicyTypeCodec : Codec PasswordPolicyType
passwordPolicyTypeCodec =
    Codec.object PasswordPolicyType
        |> Codec.optionalField "MinimumLength" .minimumLength Codec.int
        |> Codec.optionalField "RequireLowercase" .requireLowercase Codec.bool
        |> Codec.optionalField "RequireNumbers" .requireNumbers Codec.bool
        |> Codec.optionalField "RequireSymbols" .requireSymbols Codec.bool
        |> Codec.optionalField "RequireUppercase" .requireUppercase Codec.bool
        |> Codec.optionalField "TemporaryPasswordValidityDays" .temporaryPasswordValidityDays Codec.int
        |> Codec.buildObject


{-| Decoder for ProviderDescription.
-}
providerDescriptionDecoder : Decoder ProviderDescription
providerDescriptionDecoder =
    Json.Decode.succeed ProviderDescription
        |> Pipeline.optional "CreationDate" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "LastModifiedDate" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "ProviderName" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "ProviderType" (Json.Decode.maybe (Codec.decoder identityProviderTypeTypeCodec)) Nothing


{-| Codec for ProviderDetailsType.
-}
providerDetailsTypeCodec : Codec ProviderDetailsType
providerDetailsTypeCodec =
    Codec.dict Codec.string


{-| Encoder for ProviderUserIdentifierType.
-}
providerUserIdentifierTypeEncoder : ProviderUserIdentifierType -> Value
providerUserIdentifierTypeEncoder val =
    [ ( "ProviderAttributeName", val.providerAttributeName ) |> EncodeOpt.optionalField Json.Encode.string
    , ( "ProviderAttributeValue", val.providerAttributeValue ) |> EncodeOpt.optionalField Json.Encode.string
    , ( "ProviderName", val.providerName ) |> EncodeOpt.optionalField Json.Encode.string
    ]
        |> EncodeOpt.objectMaySkip


{-| Decoder for ProvidersListType.
-}
providersListTypeDecoder : Decoder ProvidersListType
providersListTypeDecoder =
    Json.Decode.list providerDescriptionDecoder


{-| Codec for ResourceServerScopeListType.
-}
resourceServerScopeListTypeCodec : Codec ResourceServerScopeListType
resourceServerScopeListTypeCodec =
    Codec.list resourceServerScopeTypeCodec


{-| Codec for ResourceServerScopeType.
-}
resourceServerScopeTypeCodec : Codec ResourceServerScopeType
resourceServerScopeTypeCodec =
    Codec.object ResourceServerScopeType
        |> Codec.field "ScopeDescription" .scopeDescription Codec.string
        |> Codec.field "ScopeName" .scopeName Codec.string
        |> Codec.buildObject


{-| Decoder for ResourceServerType.
-}
resourceServerTypeDecoder : Decoder ResourceServerType
resourceServerTypeDecoder =
    Json.Decode.succeed ResourceServerType
        |> Pipeline.optional "Identifier" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "Name" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "Scopes" (Json.Decode.maybe (Codec.decoder resourceServerScopeListTypeCodec)) Nothing
        |> Pipeline.optional "UserPoolId" (Json.Decode.maybe Json.Decode.string) Nothing


{-| Decoder for ResourceServersListType.
-}
resourceServersListTypeDecoder : Decoder ResourceServersListType
resourceServersListTypeDecoder =
    Json.Decode.list resourceServerTypeDecoder


{-| Decoder for RiskConfigurationType.
-}
riskConfigurationTypeDecoder : Decoder RiskConfigurationType
riskConfigurationTypeDecoder =
    Json.Decode.succeed RiskConfigurationType
        |> Pipeline.optional
            "AccountTakeoverRiskConfiguration"
            (Json.Decode.maybe (Codec.decoder accountTakeoverRiskConfigurationTypeCodec))
            Nothing
        |> Pipeline.optional "ClientId" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional
            "CompromisedCredentialsRiskConfiguration"
            (Json.Decode.maybe (Codec.decoder compromisedCredentialsRiskConfigurationTypeCodec))
            Nothing
        |> Pipeline.optional "LastModifiedDate" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional
            "RiskExceptionConfiguration"
            (Json.Decode.maybe (Codec.decoder riskExceptionConfigurationTypeCodec))
            Nothing
        |> Pipeline.optional "UserPoolId" (Json.Decode.maybe Json.Decode.string) Nothing


{-| Decoder for RiskDecisionType.
-}
riskDecisionTypeDecoder : Decoder RiskDecisionType
riskDecisionTypeDecoder =
    Enum.decoder riskDecisionType


{-| Codec for RiskExceptionConfigurationType.
-}
riskExceptionConfigurationTypeCodec : Codec RiskExceptionConfigurationType
riskExceptionConfigurationTypeCodec =
    Codec.object RiskExceptionConfigurationType
        |> Codec.optionalField "BlockedIPRangeList" .blockedIprangeList blockedIprangeListTypeCodec
        |> Codec.optionalField "SkippedIPRangeList" .skippedIprangeList skippedIprangeListTypeCodec
        |> Codec.buildObject


{-| Decoder for RiskLevelType.
-}
riskLevelTypeDecoder : Decoder RiskLevelType
riskLevelTypeDecoder =
    Enum.decoder riskLevelType


{-| Encoder for SmsmfaSettingsType.
-}
smsmfaSettingsTypeEncoder : SmsmfaSettingsType -> Value
smsmfaSettingsTypeEncoder val =
    [ ( "Enabled", val.enabled ) |> EncodeOpt.optionalField Json.Encode.bool
    , ( "PreferredMfa", val.preferredMfa ) |> EncodeOpt.optionalField Json.Encode.bool
    ]
        |> EncodeOpt.objectMaySkip


{-| Codec for SchemaAttributeType.
-}
schemaAttributeTypeCodec : Codec SchemaAttributeType
schemaAttributeTypeCodec =
    Codec.object SchemaAttributeType
        |> Codec.optionalField "AttributeDataType" .attributeDataType attributeDataTypeCodec
        |> Codec.optionalField "DeveloperOnlyAttribute" .developerOnlyAttribute Codec.bool
        |> Codec.optionalField "Mutable" .mutable Codec.bool
        |> Codec.optionalField "Name" .name Codec.string
        |> Codec.optionalField
            "NumberAttributeConstraints"
            .numberAttributeConstraints
            numberAttributeConstraintsTypeCodec
        |> Codec.optionalField "Required" .required Codec.bool
        |> Codec.optionalField
            "StringAttributeConstraints"
            .stringAttributeConstraints
            stringAttributeConstraintsTypeCodec
        |> Codec.buildObject


{-| Codec for SchemaAttributesListType.
-}
schemaAttributesListTypeCodec : Codec SchemaAttributesListType
schemaAttributesListTypeCodec =
    Codec.list schemaAttributeTypeCodec


{-| Codec for ScopeListType.
-}
scopeListTypeCodec : Codec ScopeListType
scopeListTypeCodec =
    Codec.list Codec.string


{-| Encoder for SearchedAttributeNamesListType.
-}
searchedAttributeNamesListTypeEncoder : SearchedAttributeNamesListType -> Value
searchedAttributeNamesListTypeEncoder val =
    Json.Encode.list Json.Encode.string val


{-| Codec for SkippedIprangeListType.
-}
skippedIprangeListTypeCodec : Codec SkippedIprangeListType
skippedIprangeListTypeCodec =
    Codec.list Codec.string


{-| Codec for SmsConfigurationType.
-}
smsConfigurationTypeCodec : Codec SmsConfigurationType
smsConfigurationTypeCodec =
    Codec.object SmsConfigurationType
        |> Codec.optionalField "ExternalId" .externalId Codec.string
        |> Codec.field "SnsCallerArn" .snsCallerArn Codec.string
        |> Codec.buildObject


{-| Codec for SmsMfaConfigType.
-}
smsMfaConfigTypeCodec : Codec SmsMfaConfigType
smsMfaConfigTypeCodec =
    Codec.object SmsMfaConfigType
        |> Codec.optionalField "SmsAuthenticationMessage" .smsAuthenticationMessage Codec.string
        |> Codec.optionalField "SmsConfiguration" .smsConfiguration smsConfigurationTypeCodec
        |> Codec.buildObject


{-| Codec for SoftwareTokenMfaConfigType.
-}
softwareTokenMfaConfigTypeCodec : Codec SoftwareTokenMfaConfigType
softwareTokenMfaConfigTypeCodec =
    Codec.object SoftwareTokenMfaConfigType |> Codec.optionalField "Enabled" .enabled Codec.bool |> Codec.buildObject


{-| Encoder for SoftwareTokenMfaSettingsType.
-}
softwareTokenMfaSettingsTypeEncoder : SoftwareTokenMfaSettingsType -> Value
softwareTokenMfaSettingsTypeEncoder val =
    [ ( "Enabled", val.enabled ) |> EncodeOpt.optionalField Json.Encode.bool
    , ( "PreferredMfa", val.preferredMfa ) |> EncodeOpt.optionalField Json.Encode.bool
    ]
        |> EncodeOpt.objectMaySkip


{-| Decoder for StatusType.
-}
statusTypeDecoder : Decoder StatusType
statusTypeDecoder =
    Enum.decoder statusType


{-| Codec for StringAttributeConstraintsType.
-}
stringAttributeConstraintsTypeCodec : Codec StringAttributeConstraintsType
stringAttributeConstraintsTypeCodec =
    Codec.object StringAttributeConstraintsType
        |> Codec.optionalField "MaxLength" .maxLength Codec.string
        |> Codec.optionalField "MinLength" .minLength Codec.string
        |> Codec.buildObject


{-| Codec for SupportedIdentityProvidersListType.
-}
supportedIdentityProvidersListTypeCodec : Codec SupportedIdentityProvidersListType
supportedIdentityProvidersListTypeCodec =
    Codec.list Codec.string


{-| Decoder for UicustomizationType.
-}
uicustomizationTypeDecoder : Decoder UicustomizationType
uicustomizationTypeDecoder =
    Json.Decode.succeed UicustomizationType
        |> Pipeline.optional "CSS" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "CSSVersion" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "ClientId" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "CreationDate" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "ImageUrl" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "LastModifiedDate" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "UserPoolId" (Json.Decode.maybe Json.Decode.string) Nothing


{-| Encoder for UserContextDataType.
-}
userContextDataTypeEncoder : UserContextDataType -> Value
userContextDataTypeEncoder val =
    [ ( "EncodedData", val.encodedData ) |> EncodeOpt.optionalField Json.Encode.string ] |> EncodeOpt.objectMaySkip


{-| Decoder for UserImportJobStatusType.
-}
userImportJobStatusTypeDecoder : Decoder UserImportJobStatusType
userImportJobStatusTypeDecoder =
    Enum.decoder userImportJobStatusType


{-| Decoder for UserImportJobType.
-}
userImportJobTypeDecoder : Decoder UserImportJobType
userImportJobTypeDecoder =
    Json.Decode.succeed UserImportJobType
        |> Pipeline.optional "CloudWatchLogsRoleArn" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "CompletionDate" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "CompletionMessage" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "CreationDate" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "FailedUsers" (Json.Decode.maybe Json.Decode.int) Nothing
        |> Pipeline.optional "ImportedUsers" (Json.Decode.maybe Json.Decode.int) Nothing
        |> Pipeline.optional "JobId" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "JobName" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "PreSignedUrl" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "SkippedUsers" (Json.Decode.maybe Json.Decode.int) Nothing
        |> Pipeline.optional "StartDate" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "Status" (Json.Decode.maybe userImportJobStatusTypeDecoder) Nothing
        |> Pipeline.optional "UserPoolId" (Json.Decode.maybe Json.Decode.string) Nothing


{-| Decoder for UserImportJobsListType.
-}
userImportJobsListTypeDecoder : Decoder UserImportJobsListType
userImportJobsListTypeDecoder =
    Json.Decode.list userImportJobTypeDecoder


{-| Decoder for UserMfasettingListType.
-}
userMfasettingListTypeDecoder : Decoder UserMfasettingListType
userMfasettingListTypeDecoder =
    Json.Decode.list Json.Decode.string


{-| Codec for UserPoolAddOnsType.
-}
userPoolAddOnsTypeCodec : Codec UserPoolAddOnsType
userPoolAddOnsTypeCodec =
    Codec.object UserPoolAddOnsType
        |> Codec.field "AdvancedSecurityMode" .advancedSecurityMode advancedSecurityModeTypeCodec
        |> Codec.buildObject


{-| Decoder for UserPoolClientDescription.
-}
userPoolClientDescriptionDecoder : Decoder UserPoolClientDescription
userPoolClientDescriptionDecoder =
    Json.Decode.succeed UserPoolClientDescription
        |> Pipeline.optional "ClientId" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "ClientName" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "UserPoolId" (Json.Decode.maybe Json.Decode.string) Nothing


{-| Decoder for UserPoolClientListType.
-}
userPoolClientListTypeDecoder : Decoder UserPoolClientListType
userPoolClientListTypeDecoder =
    Json.Decode.list userPoolClientDescriptionDecoder


{-| Decoder for UserPoolClientType.
-}
userPoolClientTypeDecoder : Decoder UserPoolClientType
userPoolClientTypeDecoder =
    Json.Decode.succeed UserPoolClientType
        |> Pipeline.optional "AllowedOAuthFlows" (Json.Decode.maybe (Codec.decoder oauthFlowsTypeCodec)) Nothing
        |> Pipeline.optional "AllowedOAuthFlowsUserPoolClient" (Json.Decode.maybe Json.Decode.bool) Nothing
        |> Pipeline.optional "AllowedOAuthScopes" (Json.Decode.maybe (Codec.decoder scopeListTypeCodec)) Nothing
        |> Pipeline.optional
            "AnalyticsConfiguration"
            (Json.Decode.maybe (Codec.decoder analyticsConfigurationTypeCodec))
            Nothing
        |> Pipeline.optional "CallbackURLs" (Json.Decode.maybe (Codec.decoder callbackUrlsListTypeCodec)) Nothing
        |> Pipeline.optional "ClientId" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "ClientName" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "ClientSecret" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "CreationDate" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "DefaultRedirectURI" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional
            "ExplicitAuthFlows"
            (Json.Decode.maybe (Codec.decoder explicitAuthFlowsListTypeCodec))
            Nothing
        |> Pipeline.optional "LastModifiedDate" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "LogoutURLs" (Json.Decode.maybe (Codec.decoder logoutUrlsListTypeCodec)) Nothing
        |> Pipeline.optional "ReadAttributes" (Json.Decode.maybe (Codec.decoder clientPermissionListTypeCodec)) Nothing
        |> Pipeline.optional "RefreshTokenValidity" (Json.Decode.maybe Json.Decode.int) Nothing
        |> Pipeline.optional
            "SupportedIdentityProviders"
            (Json.Decode.maybe (Codec.decoder supportedIdentityProvidersListTypeCodec))
            Nothing
        |> Pipeline.optional "UserPoolId" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "WriteAttributes" (Json.Decode.maybe (Codec.decoder clientPermissionListTypeCodec)) Nothing


{-| Decoder for UserPoolDescriptionType.
-}
userPoolDescriptionTypeDecoder : Decoder UserPoolDescriptionType
userPoolDescriptionTypeDecoder =
    Json.Decode.succeed UserPoolDescriptionType
        |> Pipeline.optional "CreationDate" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "Id" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "LambdaConfig" (Json.Decode.maybe (Codec.decoder lambdaConfigTypeCodec)) Nothing
        |> Pipeline.optional "LastModifiedDate" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "Name" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "Status" (Json.Decode.maybe statusTypeDecoder) Nothing


{-| Decoder for UserPoolListType.
-}
userPoolListTypeDecoder : Decoder UserPoolListType
userPoolListTypeDecoder =
    Json.Decode.list userPoolDescriptionTypeDecoder


{-| Codec for UserPoolMfaType.
-}
userPoolMfaTypeCodec : Codec UserPoolMfaType
userPoolMfaTypeCodec =
    Codec.build (Enum.encoder userPoolMfaType) (Enum.decoder userPoolMfaType)


{-| Codec for UserPoolPolicyType.
-}
userPoolPolicyTypeCodec : Codec UserPoolPolicyType
userPoolPolicyTypeCodec =
    Codec.object UserPoolPolicyType
        |> Codec.optionalField "PasswordPolicy" .passwordPolicy passwordPolicyTypeCodec
        |> Codec.buildObject


{-| Encoder for UserPoolTagsListType.
-}
userPoolTagsListTypeEncoder : UserPoolTagsListType -> Value
userPoolTagsListTypeEncoder val =
    Json.Encode.list Json.Encode.string val


{-| Codec for UserPoolTagsType.
-}
userPoolTagsTypeCodec : Codec UserPoolTagsType
userPoolTagsTypeCodec =
    Codec.dict Codec.string


{-| Decoder for UserPoolType.
-}
userPoolTypeDecoder : Decoder UserPoolType
userPoolTypeDecoder =
    Json.Decode.succeed UserPoolType
        |> Pipeline.optional
            "AdminCreateUserConfig"
            (Json.Decode.maybe (Codec.decoder adminCreateUserConfigTypeCodec))
            Nothing
        |> Pipeline.optional "AliasAttributes" (Json.Decode.maybe (Codec.decoder aliasAttributesListTypeCodec)) Nothing
        |> Pipeline.optional "Arn" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional
            "AutoVerifiedAttributes"
            (Json.Decode.maybe (Codec.decoder verifiedAttributesListTypeCodec))
            Nothing
        |> Pipeline.optional "CreationDate" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "CustomDomain" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional
            "DeviceConfiguration"
            (Json.Decode.maybe (Codec.decoder deviceConfigurationTypeCodec))
            Nothing
        |> Pipeline.optional "Domain" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional
            "EmailConfiguration"
            (Json.Decode.maybe (Codec.decoder emailConfigurationTypeCodec))
            Nothing
        |> Pipeline.optional "EmailConfigurationFailure" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "EmailVerificationMessage" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "EmailVerificationSubject" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "EstimatedNumberOfUsers" (Json.Decode.maybe Json.Decode.int) Nothing
        |> Pipeline.optional "Id" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "LambdaConfig" (Json.Decode.maybe (Codec.decoder lambdaConfigTypeCodec)) Nothing
        |> Pipeline.optional "LastModifiedDate" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "MfaConfiguration" (Json.Decode.maybe (Codec.decoder userPoolMfaTypeCodec)) Nothing
        |> Pipeline.optional "Name" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "Policies" (Json.Decode.maybe (Codec.decoder userPoolPolicyTypeCodec)) Nothing
        |> Pipeline.optional
            "SchemaAttributes"
            (Json.Decode.maybe (Codec.decoder schemaAttributesListTypeCodec))
            Nothing
        |> Pipeline.optional "SmsAuthenticationMessage" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "SmsConfiguration" (Json.Decode.maybe (Codec.decoder smsConfigurationTypeCodec)) Nothing
        |> Pipeline.optional "SmsConfigurationFailure" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "SmsVerificationMessage" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "Status" (Json.Decode.maybe statusTypeDecoder) Nothing
        |> Pipeline.optional "UserPoolAddOns" (Json.Decode.maybe (Codec.decoder userPoolAddOnsTypeCodec)) Nothing
        |> Pipeline.optional "UserPoolTags" (Json.Decode.maybe (Codec.decoder userPoolTagsTypeCodec)) Nothing
        |> Pipeline.optional
            "UsernameAttributes"
            (Json.Decode.maybe (Codec.decoder usernameAttributesListTypeCodec))
            Nothing
        |> Pipeline.optional
            "VerificationMessageTemplate"
            (Json.Decode.maybe (Codec.decoder verificationMessageTemplateTypeCodec))
            Nothing


{-| Decoder for UserStatusType.
-}
userStatusTypeDecoder : Decoder UserStatusType
userStatusTypeDecoder =
    Enum.decoder userStatusType


{-| Decoder for UserType.
-}
userTypeDecoder : Decoder UserType
userTypeDecoder =
    Json.Decode.succeed UserType
        |> Pipeline.optional "Attributes" (Json.Decode.maybe (Codec.decoder attributeListTypeCodec)) Nothing
        |> Pipeline.optional "Enabled" (Json.Decode.maybe Json.Decode.bool) Nothing
        |> Pipeline.optional "MFAOptions" (Json.Decode.maybe (Codec.decoder mfaoptionListTypeCodec)) Nothing
        |> Pipeline.optional "UserCreateDate" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "UserLastModifiedDate" (Json.Decode.maybe Json.Decode.string) Nothing
        |> Pipeline.optional "UserStatus" (Json.Decode.maybe userStatusTypeDecoder) Nothing
        |> Pipeline.optional "Username" (Json.Decode.maybe Json.Decode.string) Nothing


{-| Codec for UsernameAttributeType.
-}
usernameAttributeTypeCodec : Codec UsernameAttributeType
usernameAttributeTypeCodec =
    Codec.build (Enum.encoder usernameAttributeType) (Enum.decoder usernameAttributeType)


{-| Codec for UsernameAttributesListType.
-}
usernameAttributesListTypeCodec : Codec UsernameAttributesListType
usernameAttributesListTypeCodec =
    Codec.list usernameAttributeTypeCodec


{-| Decoder for UsersListType.
-}
usersListTypeDecoder : Decoder UsersListType
usersListTypeDecoder =
    Json.Decode.list userTypeDecoder


{-| Codec for VerificationMessageTemplateType.
-}
verificationMessageTemplateTypeCodec : Codec VerificationMessageTemplateType
verificationMessageTemplateTypeCodec =
    Codec.object VerificationMessageTemplateType
        |> Codec.optionalField "DefaultEmailOption" .defaultEmailOption defaultEmailOptionTypeCodec
        |> Codec.optionalField "EmailMessage" .emailMessage Codec.string
        |> Codec.optionalField "EmailMessageByLink" .emailMessageByLink Codec.string
        |> Codec.optionalField "EmailSubject" .emailSubject Codec.string
        |> Codec.optionalField "EmailSubjectByLink" .emailSubjectByLink Codec.string
        |> Codec.optionalField "SmsMessage" .smsMessage Codec.string
        |> Codec.buildObject


{-| Codec for VerifiedAttributeType.
-}
verifiedAttributeTypeCodec : Codec VerifiedAttributeType
verifiedAttributeTypeCodec =
    Codec.build (Enum.encoder verifiedAttributeType) (Enum.decoder verifiedAttributeType)


{-| Codec for VerifiedAttributesListType.
-}
verifiedAttributesListTypeCodec : Codec VerifiedAttributesListType
verifiedAttributesListTypeCodec =
    Codec.list verifiedAttributeTypeCodec


{-| Decoder for VerifySoftwareTokenResponseType.
-}
verifySoftwareTokenResponseTypeDecoder : Decoder VerifySoftwareTokenResponseType
verifySoftwareTokenResponseTypeDecoder =
    Enum.decoder verifySoftwareTokenResponseType
