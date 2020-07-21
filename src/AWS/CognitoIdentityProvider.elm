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
    , AccountTakeoverActionNotifyType, AccountTakeoverActionType, AccountTakeoverActionsType, AccountTakeoverEventActionType(..)
    , AccountTakeoverRiskConfigurationType, AddCustomAttributesRequest, AddCustomAttributesResponse, AdminAddUserToGroupRequest
    , AdminConfirmSignUpRequest, AdminConfirmSignUpResponse, AdminCreateUserConfigType, AdminCreateUserRequest
    , AdminCreateUserResponse, AdminCreateUserUnusedAccountValidityDaysType, AdminDeleteUserAttributesRequest
    , AdminDeleteUserAttributesResponse, AdminDeleteUserRequest, AdminDisableProviderForUserRequest
    , AdminDisableProviderForUserResponse, AdminDisableUserRequest, AdminDisableUserResponse, AdminEnableUserRequest
    , AdminEnableUserResponse, AdminForgetDeviceRequest, AdminGetDeviceRequest, AdminGetDeviceResponse, AdminGetUserRequest
    , AdminGetUserResponse, AdminInitiateAuthRequest, AdminInitiateAuthResponse, AdminLinkProviderForUserRequest
    , AdminLinkProviderForUserResponse, AdminListDevicesRequest, AdminListDevicesResponse, AdminListGroupsForUserRequest
    , AdminListGroupsForUserResponse, AdminListUserAuthEventsRequest, AdminListUserAuthEventsResponse
    , AdminRemoveUserFromGroupRequest, AdminResetUserPasswordRequest, AdminResetUserPasswordResponse
    , AdminRespondToAuthChallengeRequest, AdminRespondToAuthChallengeResponse, AdminSetUserMfapreferenceRequest
    , AdminSetUserMfapreferenceResponse, AdminSetUserPasswordRequest, AdminSetUserPasswordResponse, AdminSetUserSettingsRequest
    , AdminSetUserSettingsResponse, AdminUpdateAuthEventFeedbackRequest, AdminUpdateAuthEventFeedbackResponse
    , AdminUpdateDeviceStatusRequest, AdminUpdateDeviceStatusResponse, AdminUpdateUserAttributesRequest
    , AdminUpdateUserAttributesResponse, AdminUserGlobalSignOutRequest, AdminUserGlobalSignOutResponse, AdvancedSecurityModeType(..)
    , AliasAttributeType(..), AliasAttributesListType, AnalyticsConfigurationType, AnalyticsMetadataType, ArnType
    , AssociateSoftwareTokenRequest, AssociateSoftwareTokenResponse, AttributeDataType(..), AttributeListType, AttributeMappingKeyType
    , AttributeMappingType, AttributeNameListType, AttributeNameType, AttributeType, AttributeValueType, AuthEventType, AuthEventsType
    , AuthFlowType(..), AuthParametersType, AuthenticationResultType, AwsaccountIdType, BlockedIprangeListType, BooleanType
    , CallbackUrlsListType, ChallengeName(..), ChallengeNameType(..), ChallengeParametersType, ChallengeResponse(..), ChallengeResponseListType
    , ChallengeResponseType, ChallengeResponsesType, ChangePasswordRequest, ChangePasswordResponse, ClientIdType, ClientMetadataType
    , ClientNameType, ClientPermissionListType, ClientPermissionType, ClientSecretType, CodeDeliveryDetailsListType
    , CodeDeliveryDetailsType, CompletionMessageType, CompromisedCredentialsActionsType, CompromisedCredentialsEventActionType(..)
    , CompromisedCredentialsRiskConfigurationType, ConfirmDeviceRequest, ConfirmDeviceResponse, ConfirmForgotPasswordRequest
    , ConfirmForgotPasswordResponse, ConfirmSignUpRequest, ConfirmSignUpResponse, ConfirmationCodeType, ContextDataType
    , CreateGroupRequest, CreateGroupResponse, CreateIdentityProviderRequest, CreateIdentityProviderResponse
    , CreateResourceServerRequest, CreateResourceServerResponse, CreateUserImportJobRequest, CreateUserImportJobResponse
    , CreateUserPoolClientRequest, CreateUserPoolClientResponse, CreateUserPoolDomainRequest, CreateUserPoolDomainResponse
    , CreateUserPoolRequest, CreateUserPoolResponse, Csstype, CssversionType, CustomAttributeNameType, CustomAttributesListType
    , CustomDomainConfigType, DateType, DefaultEmailOptionType(..), DeleteGroupRequest, DeleteIdentityProviderRequest
    , DeleteResourceServerRequest, DeleteUserAttributesRequest, DeleteUserAttributesResponse, DeleteUserPoolClientRequest
    , DeleteUserPoolDomainRequest, DeleteUserPoolDomainResponse, DeleteUserPoolRequest, DeleteUserRequest, DeliveryMediumListType
    , DeliveryMediumType(..), DescribeIdentityProviderRequest, DescribeIdentityProviderResponse, DescribeResourceServerRequest
    , DescribeResourceServerResponse, DescribeRiskConfigurationRequest, DescribeRiskConfigurationResponse
    , DescribeUserImportJobRequest, DescribeUserImportJobResponse, DescribeUserPoolClientRequest, DescribeUserPoolClientResponse
    , DescribeUserPoolDomainRequest, DescribeUserPoolDomainResponse, DescribeUserPoolRequest, DescribeUserPoolResponse
    , DescriptionType, DeviceConfigurationType, DeviceKeyType, DeviceListType, DeviceNameType, DeviceRememberedStatusType(..)
    , DeviceSecretVerifierConfigType, DeviceType, DomainDescriptionType, DomainStatusType(..), DomainType, DomainVersionType, EmailAddressType
    , EmailConfigurationType, EmailNotificationBodyType, EmailNotificationSubjectType, EmailSendingAccountType(..)
    , EmailVerificationMessageByLinkType, EmailVerificationMessageType, EmailVerificationSubjectByLinkType
    , EmailVerificationSubjectType, EventContextDataType, EventFeedbackType, EventFilterType(..), EventFiltersType, EventIdType
    , EventResponseType(..), EventRiskType, EventType(..), ExplicitAuthFlowsListType, ExplicitAuthFlowsType(..), FeedbackValueType(..), ForceAliasCreation
    , ForgetDeviceRequest, ForgotPasswordRequest, ForgotPasswordResponse, GenerateSecret, GetCsvheaderRequest, GetCsvheaderResponse
    , GetDeviceRequest, GetDeviceResponse, GetGroupRequest, GetGroupResponse, GetIdentityProviderByIdentifierRequest
    , GetIdentityProviderByIdentifierResponse, GetSigningCertificateRequest, GetSigningCertificateResponse
    , GetUicustomizationRequest, GetUicustomizationResponse, GetUserAttributeVerificationCodeRequest
    , GetUserAttributeVerificationCodeResponse, GetUserPoolMfaConfigRequest, GetUserPoolMfaConfigResponse, GetUserRequest
    , GetUserResponse, GlobalSignOutRequest, GlobalSignOutResponse, GroupListType, GroupNameType, GroupType, HexStringType, HttpHeader
    , HttpHeaderList, IdentityProviderType, IdentityProviderTypeType(..), IdpIdentifierType, IdpIdentifiersListType, ImageFileType
    , ImageUrlType, InitiateAuthRequest, InitiateAuthResponse, IntegerType, LambdaConfigType, ListDevicesRequest, ListDevicesResponse
    , ListGroupsRequest, ListGroupsResponse, ListIdentityProvidersRequest, ListIdentityProvidersResponse, ListOfStringTypes
    , ListProvidersLimitType, ListResourceServersLimitType, ListResourceServersRequest, ListResourceServersResponse
    , ListTagsForResourceRequest, ListTagsForResourceResponse, ListUserImportJobsRequest, ListUserImportJobsResponse
    , ListUserPoolClientsRequest, ListUserPoolClientsResponse, ListUserPoolsRequest, ListUserPoolsResponse, ListUsersInGroupRequest
    , ListUsersInGroupResponse, ListUsersRequest, ListUsersResponse, LogoutUrlsListType, LongType, MessageActionType(..), MessageTemplateType
    , MfaoptionListType, MfaoptionType, NewDeviceMetadataType, NotifyConfigurationType, NotifyEmailType, NumberAttributeConstraintsType
    , OauthFlowType(..), OauthFlowsType, PaginationKey, PaginationKeyType, PasswordPolicyMinLengthType, PasswordPolicyType, PasswordType
    , PoolQueryLimitType, PreSignedUrlType, PrecedenceType, ProviderDescription, ProviderDetailsType, ProviderNameType, ProviderNameTypeV1
    , ProviderUserIdentifierType, ProvidersListType, QueryLimit, QueryLimitType, RedirectUrlType, RefreshTokenValidityType
    , ResendConfirmationCodeRequest, ResendConfirmationCodeResponse, ResourceServerIdentifierType, ResourceServerNameType
    , ResourceServerScopeDescriptionType, ResourceServerScopeListType, ResourceServerScopeNameType, ResourceServerScopeType
    , ResourceServerType, ResourceServersListType, RespondToAuthChallengeRequest, RespondToAuthChallengeResponse
    , RiskConfigurationType, RiskDecisionType(..), RiskExceptionConfigurationType, RiskLevelType(..), S3BucketType, SchemaAttributeType
    , SchemaAttributesListType, ScopeListType, ScopeType, SearchPaginationTokenType, SearchedAttributeNamesListType, SecretCodeType
    , SecretHashType, SessionType, SetRiskConfigurationRequest, SetRiskConfigurationResponse, SetUicustomizationRequest
    , SetUicustomizationResponse, SetUserMfapreferenceRequest, SetUserMfapreferenceResponse, SetUserPoolMfaConfigRequest
    , SetUserPoolMfaConfigResponse, SetUserSettingsRequest, SetUserSettingsResponse, SignUpRequest, SignUpResponse
    , SkippedIprangeListType, SmsConfigurationType, SmsMfaConfigType, SmsVerificationMessageType, SmsmfaSettingsType
    , SoftwareTokenMfaConfigType, SoftwareTokenMfaSettingsType, SoftwareTokenMfauserCodeType, StartUserImportJobRequest
    , StartUserImportJobResponse, StatusType(..), StopUserImportJobRequest, StopUserImportJobResponse, StringAttributeConstraintsType
    , StringType, SupportedIdentityProvidersListType, TagKeysType, TagResourceRequest, TagResourceResponse, TagValueType
    , TemporaryPasswordValidityDaysType, TokenModelType, UicustomizationType, UntagResourceRequest, UntagResourceResponse
    , UpdateAuthEventFeedbackRequest, UpdateAuthEventFeedbackResponse, UpdateDeviceStatusRequest, UpdateDeviceStatusResponse
    , UpdateGroupRequest, UpdateGroupResponse, UpdateIdentityProviderRequest, UpdateIdentityProviderResponse
    , UpdateResourceServerRequest, UpdateResourceServerResponse, UpdateUserAttributesRequest, UpdateUserAttributesResponse
    , UpdateUserPoolClientRequest, UpdateUserPoolClientResponse, UpdateUserPoolDomainRequest, UpdateUserPoolDomainResponse
    , UpdateUserPoolRequest, UpdateUserPoolResponse, UserContextDataType, UserFilterType, UserImportJobIdType, UserImportJobNameType
    , UserImportJobStatusType(..), UserImportJobType, UserImportJobsListType, UserMfasettingListType, UserPoolAddOnsType
    , UserPoolClientDescription, UserPoolClientListType, UserPoolClientType, UserPoolDescriptionType, UserPoolIdType, UserPoolListType
    , UserPoolMfaType(..), UserPoolNameType, UserPoolPolicyType, UserPoolTagsListType, UserPoolTagsType, UserPoolType, UserStatusType(..), UserType
    , UsernameAttributeType(..), UsernameAttributesListType, UsernameType, UsersListType, VerificationMessageTemplateType
    , VerifiedAttributeType(..), VerifiedAttributesListType, VerifySoftwareTokenRequest, VerifySoftwareTokenResponse
    , VerifySoftwareTokenResponseType(..), VerifyUserAttributeRequest, VerifyUserAttributeResponse, accountTakeoverEventActionType
    , adminCreateUserUnusedAccountValidityDaysType, advancedSecurityModeType, aliasAttributeType, arnType, attributeDataType
    , attributeMappingKeyType, attributeNameType, attributeValueType, authFlowType, challengeName, challengeNameType, challengeResponse
    , clientIdType, clientNameType, clientPermissionType, clientSecretType, completionMessageType, compromisedCredentialsEventActionType
    , confirmationCodeType, customAttributeNameType, defaultEmailOptionType, deliveryMediumType, descriptionType, deviceKeyType
    , deviceNameType, deviceRememberedStatusType, domainStatusType, domainType, domainVersionType, emailAddressType
    , emailNotificationBodyType, emailNotificationSubjectType, emailSendingAccountType, emailVerificationMessageByLinkType
    , emailVerificationMessageType, emailVerificationSubjectByLinkType, emailVerificationSubjectType, eventFilterType, eventIdType
    , eventResponseType, eventType, explicitAuthFlowsType, feedbackValueType, groupNameType, hexStringType, identityProviderTypeType
    , idpIdentifierType, listProvidersLimitType, listResourceServersLimitType, messageActionType, oauthFlowType, paginationKey
    , paginationKeyType, passwordPolicyMinLengthType, passwordType, poolQueryLimitType, preSignedUrlType, precedenceType, providerNameType
    , providerNameTypeV1, queryLimit, queryLimitType, redirectUrlType, refreshTokenValidityType, resourceServerIdentifierType
    , resourceServerNameType, resourceServerScopeDescriptionType, resourceServerScopeNameType, riskDecisionType, riskLevelType
    , s3BucketType, scopeType, searchPaginationTokenType, secretCodeType, secretHashType, sessionType, smsVerificationMessageType
    , softwareTokenMfauserCodeType, statusType, tagKeysType, tagValueType, temporaryPasswordValidityDaysType, tokenModelType
    , userFilterType, userImportJobIdType, userImportJobNameType, userImportJobStatusType, userPoolIdType, userPoolMfaType
    , userPoolNameType, userStatusType, usernameAttributeType, usernameType, verifiedAttributeType, verifySoftwareTokenResponseType
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

@docs AccountTakeoverActionNotifyType, AccountTakeoverActionType, AccountTakeoverActionsType, AccountTakeoverEventActionType
@docs AccountTakeoverRiskConfigurationType, AddCustomAttributesRequest, AddCustomAttributesResponse, AdminAddUserToGroupRequest
@docs AdminConfirmSignUpRequest, AdminConfirmSignUpResponse, AdminCreateUserConfigType, AdminCreateUserRequest
@docs AdminCreateUserResponse, AdminCreateUserUnusedAccountValidityDaysType, AdminDeleteUserAttributesRequest
@docs AdminDeleteUserAttributesResponse, AdminDeleteUserRequest, AdminDisableProviderForUserRequest
@docs AdminDisableProviderForUserResponse, AdminDisableUserRequest, AdminDisableUserResponse, AdminEnableUserRequest
@docs AdminEnableUserResponse, AdminForgetDeviceRequest, AdminGetDeviceRequest, AdminGetDeviceResponse, AdminGetUserRequest
@docs AdminGetUserResponse, AdminInitiateAuthRequest, AdminInitiateAuthResponse, AdminLinkProviderForUserRequest
@docs AdminLinkProviderForUserResponse, AdminListDevicesRequest, AdminListDevicesResponse, AdminListGroupsForUserRequest
@docs AdminListGroupsForUserResponse, AdminListUserAuthEventsRequest, AdminListUserAuthEventsResponse
@docs AdminRemoveUserFromGroupRequest, AdminResetUserPasswordRequest, AdminResetUserPasswordResponse
@docs AdminRespondToAuthChallengeRequest, AdminRespondToAuthChallengeResponse, AdminSetUserMfapreferenceRequest
@docs AdminSetUserMfapreferenceResponse, AdminSetUserPasswordRequest, AdminSetUserPasswordResponse, AdminSetUserSettingsRequest
@docs AdminSetUserSettingsResponse, AdminUpdateAuthEventFeedbackRequest, AdminUpdateAuthEventFeedbackResponse
@docs AdminUpdateDeviceStatusRequest, AdminUpdateDeviceStatusResponse, AdminUpdateUserAttributesRequest
@docs AdminUpdateUserAttributesResponse, AdminUserGlobalSignOutRequest, AdminUserGlobalSignOutResponse, AdvancedSecurityModeType
@docs AliasAttributeType, AliasAttributesListType, AnalyticsConfigurationType, AnalyticsMetadataType, ArnType
@docs AssociateSoftwareTokenRequest, AssociateSoftwareTokenResponse, AttributeDataType, AttributeListType, AttributeMappingKeyType
@docs AttributeMappingType, AttributeNameListType, AttributeNameType, AttributeType, AttributeValueType, AuthEventType, AuthEventsType
@docs AuthFlowType, AuthParametersType, AuthenticationResultType, AwsaccountIdType, BlockedIprangeListType, BooleanType
@docs CallbackUrlsListType, ChallengeName, ChallengeNameType, ChallengeParametersType, ChallengeResponse, ChallengeResponseListType
@docs ChallengeResponseType, ChallengeResponsesType, ChangePasswordRequest, ChangePasswordResponse, ClientIdType, ClientMetadataType
@docs ClientNameType, ClientPermissionListType, ClientPermissionType, ClientSecretType, CodeDeliveryDetailsListType
@docs CodeDeliveryDetailsType, CompletionMessageType, CompromisedCredentialsActionsType, CompromisedCredentialsEventActionType
@docs CompromisedCredentialsRiskConfigurationType, ConfirmDeviceRequest, ConfirmDeviceResponse, ConfirmForgotPasswordRequest
@docs ConfirmForgotPasswordResponse, ConfirmSignUpRequest, ConfirmSignUpResponse, ConfirmationCodeType, ContextDataType
@docs CreateGroupRequest, CreateGroupResponse, CreateIdentityProviderRequest, CreateIdentityProviderResponse
@docs CreateResourceServerRequest, CreateResourceServerResponse, CreateUserImportJobRequest, CreateUserImportJobResponse
@docs CreateUserPoolClientRequest, CreateUserPoolClientResponse, CreateUserPoolDomainRequest, CreateUserPoolDomainResponse
@docs CreateUserPoolRequest, CreateUserPoolResponse, Csstype, CssversionType, CustomAttributeNameType, CustomAttributesListType
@docs CustomDomainConfigType, DateType, DefaultEmailOptionType, DeleteGroupRequest, DeleteIdentityProviderRequest
@docs DeleteResourceServerRequest, DeleteUserAttributesRequest, DeleteUserAttributesResponse, DeleteUserPoolClientRequest
@docs DeleteUserPoolDomainRequest, DeleteUserPoolDomainResponse, DeleteUserPoolRequest, DeleteUserRequest, DeliveryMediumListType
@docs DeliveryMediumType, DescribeIdentityProviderRequest, DescribeIdentityProviderResponse, DescribeResourceServerRequest
@docs DescribeResourceServerResponse, DescribeRiskConfigurationRequest, DescribeRiskConfigurationResponse
@docs DescribeUserImportJobRequest, DescribeUserImportJobResponse, DescribeUserPoolClientRequest, DescribeUserPoolClientResponse
@docs DescribeUserPoolDomainRequest, DescribeUserPoolDomainResponse, DescribeUserPoolRequest, DescribeUserPoolResponse
@docs DescriptionType, DeviceConfigurationType, DeviceKeyType, DeviceListType, DeviceNameType, DeviceRememberedStatusType
@docs DeviceSecretVerifierConfigType, DeviceType, DomainDescriptionType, DomainStatusType, DomainType, DomainVersionType, EmailAddressType
@docs EmailConfigurationType, EmailNotificationBodyType, EmailNotificationSubjectType, EmailSendingAccountType
@docs EmailVerificationMessageByLinkType, EmailVerificationMessageType, EmailVerificationSubjectByLinkType
@docs EmailVerificationSubjectType, EventContextDataType, EventFeedbackType, EventFilterType, EventFiltersType, EventIdType
@docs EventResponseType, EventRiskType, EventType, ExplicitAuthFlowsListType, ExplicitAuthFlowsType, FeedbackValueType, ForceAliasCreation
@docs ForgetDeviceRequest, ForgotPasswordRequest, ForgotPasswordResponse, GenerateSecret, GetCsvheaderRequest, GetCsvheaderResponse
@docs GetDeviceRequest, GetDeviceResponse, GetGroupRequest, GetGroupResponse, GetIdentityProviderByIdentifierRequest
@docs GetIdentityProviderByIdentifierResponse, GetSigningCertificateRequest, GetSigningCertificateResponse
@docs GetUicustomizationRequest, GetUicustomizationResponse, GetUserAttributeVerificationCodeRequest
@docs GetUserAttributeVerificationCodeResponse, GetUserPoolMfaConfigRequest, GetUserPoolMfaConfigResponse, GetUserRequest
@docs GetUserResponse, GlobalSignOutRequest, GlobalSignOutResponse, GroupListType, GroupNameType, GroupType, HexStringType, HttpHeader
@docs HttpHeaderList, IdentityProviderType, IdentityProviderTypeType, IdpIdentifierType, IdpIdentifiersListType, ImageFileType
@docs ImageUrlType, InitiateAuthRequest, InitiateAuthResponse, IntegerType, LambdaConfigType, ListDevicesRequest, ListDevicesResponse
@docs ListGroupsRequest, ListGroupsResponse, ListIdentityProvidersRequest, ListIdentityProvidersResponse, ListOfStringTypes
@docs ListProvidersLimitType, ListResourceServersLimitType, ListResourceServersRequest, ListResourceServersResponse
@docs ListTagsForResourceRequest, ListTagsForResourceResponse, ListUserImportJobsRequest, ListUserImportJobsResponse
@docs ListUserPoolClientsRequest, ListUserPoolClientsResponse, ListUserPoolsRequest, ListUserPoolsResponse, ListUsersInGroupRequest
@docs ListUsersInGroupResponse, ListUsersRequest, ListUsersResponse, LogoutUrlsListType, LongType, MessageActionType, MessageTemplateType
@docs MfaoptionListType, MfaoptionType, NewDeviceMetadataType, NotifyConfigurationType, NotifyEmailType, NumberAttributeConstraintsType
@docs OauthFlowType, OauthFlowsType, PaginationKey, PaginationKeyType, PasswordPolicyMinLengthType, PasswordPolicyType, PasswordType
@docs PoolQueryLimitType, PreSignedUrlType, PrecedenceType, ProviderDescription, ProviderDetailsType, ProviderNameType, ProviderNameTypeV1
@docs ProviderUserIdentifierType, ProvidersListType, QueryLimit, QueryLimitType, RedirectUrlType, RefreshTokenValidityType
@docs ResendConfirmationCodeRequest, ResendConfirmationCodeResponse, ResourceServerIdentifierType, ResourceServerNameType
@docs ResourceServerScopeDescriptionType, ResourceServerScopeListType, ResourceServerScopeNameType, ResourceServerScopeType
@docs ResourceServerType, ResourceServersListType, RespondToAuthChallengeRequest, RespondToAuthChallengeResponse
@docs RiskConfigurationType, RiskDecisionType, RiskExceptionConfigurationType, RiskLevelType, S3BucketType, SchemaAttributeType
@docs SchemaAttributesListType, ScopeListType, ScopeType, SearchPaginationTokenType, SearchedAttributeNamesListType, SecretCodeType
@docs SecretHashType, SessionType, SetRiskConfigurationRequest, SetRiskConfigurationResponse, SetUicustomizationRequest
@docs SetUicustomizationResponse, SetUserMfapreferenceRequest, SetUserMfapreferenceResponse, SetUserPoolMfaConfigRequest
@docs SetUserPoolMfaConfigResponse, SetUserSettingsRequest, SetUserSettingsResponse, SignUpRequest, SignUpResponse
@docs SkippedIprangeListType, SmsConfigurationType, SmsMfaConfigType, SmsVerificationMessageType, SmsmfaSettingsType
@docs SoftwareTokenMfaConfigType, SoftwareTokenMfaSettingsType, SoftwareTokenMfauserCodeType, StartUserImportJobRequest
@docs StartUserImportJobResponse, StatusType, StopUserImportJobRequest, StopUserImportJobResponse, StringAttributeConstraintsType
@docs StringType, SupportedIdentityProvidersListType, TagKeysType, TagResourceRequest, TagResourceResponse, TagValueType
@docs TemporaryPasswordValidityDaysType, TokenModelType, UicustomizationType, UntagResourceRequest, UntagResourceResponse
@docs UpdateAuthEventFeedbackRequest, UpdateAuthEventFeedbackResponse, UpdateDeviceStatusRequest, UpdateDeviceStatusResponse
@docs UpdateGroupRequest, UpdateGroupResponse, UpdateIdentityProviderRequest, UpdateIdentityProviderResponse
@docs UpdateResourceServerRequest, UpdateResourceServerResponse, UpdateUserAttributesRequest, UpdateUserAttributesResponse
@docs UpdateUserPoolClientRequest, UpdateUserPoolClientResponse, UpdateUserPoolDomainRequest, UpdateUserPoolDomainResponse
@docs UpdateUserPoolRequest, UpdateUserPoolResponse, UserContextDataType, UserFilterType, UserImportJobIdType, UserImportJobNameType
@docs UserImportJobStatusType, UserImportJobType, UserImportJobsListType, UserMfasettingListType, UserPoolAddOnsType
@docs UserPoolClientDescription, UserPoolClientListType, UserPoolClientType, UserPoolDescriptionType, UserPoolIdType, UserPoolListType
@docs UserPoolMfaType, UserPoolNameType, UserPoolPolicyType, UserPoolTagsListType, UserPoolTagsType, UserPoolType, UserStatusType, UserType
@docs UsernameAttributeType, UsernameAttributesListType, UsernameType, UsersListType, VerificationMessageTemplateType
@docs VerifiedAttributeType, VerifiedAttributesListType, VerifySoftwareTokenRequest, VerifySoftwareTokenResponse
@docs VerifySoftwareTokenResponseType, VerifyUserAttributeRequest, VerifyUserAttributeResponse, accountTakeoverEventActionType
@docs adminCreateUserUnusedAccountValidityDaysType, advancedSecurityModeType, aliasAttributeType, arnType, attributeDataType
@docs attributeMappingKeyType, attributeNameType, attributeValueType, authFlowType, challengeName, challengeNameType, challengeResponse
@docs clientIdType, clientNameType, clientPermissionType, clientSecretType, completionMessageType, compromisedCredentialsEventActionType
@docs confirmationCodeType, customAttributeNameType, defaultEmailOptionType, deliveryMediumType, descriptionType, deviceKeyType
@docs deviceNameType, deviceRememberedStatusType, domainStatusType, domainType, domainVersionType, emailAddressType
@docs emailNotificationBodyType, emailNotificationSubjectType, emailSendingAccountType, emailVerificationMessageByLinkType
@docs emailVerificationMessageType, emailVerificationSubjectByLinkType, emailVerificationSubjectType, eventFilterType, eventIdType
@docs eventResponseType, eventType, explicitAuthFlowsType, feedbackValueType, groupNameType, hexStringType, identityProviderTypeType
@docs idpIdentifierType, listProvidersLimitType, listResourceServersLimitType, messageActionType, oauthFlowType, paginationKey
@docs paginationKeyType, passwordPolicyMinLengthType, passwordType, poolQueryLimitType, preSignedUrlType, precedenceType, providerNameType
@docs providerNameTypeV1, queryLimit, queryLimitType, redirectUrlType, refreshTokenValidityType, resourceServerIdentifierType
@docs resourceServerNameType, resourceServerScopeDescriptionType, resourceServerScopeNameType, riskDecisionType, riskLevelType
@docs s3BucketType, scopeType, searchPaginationTokenType, secretCodeType, secretHashType, sessionType, smsVerificationMessageType
@docs softwareTokenMfauserCodeType, statusType, tagKeysType, tagValueType, temporaryPasswordValidityDaysType, tokenModelType
@docs userFilterType, userImportJobIdType, userImportJobNameType, userImportJobStatusType, userPoolIdType, userPoolMfaType
@docs userPoolNameType, userStatusType, usernameAttributeType, usernameType, verifiedAttributeType, verifySoftwareTokenResponseType

-}

import AWS.Config
import AWS.Http
import AWS.KVDecode exposing (KVDecoder)
import AWS.Service
import Codec exposing (Codec)
import Dict exposing (Dict)
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
    AWS.Config.defineRegional "cognito-idp" "2016-04-18" AWS.Config.JSON AWS.Config.SignV4 region
        |> AWS.Config.withJsonVersion "1.1"
        |> AWS.Config.withTargetPrefix "AWSCognitoIdentityProviderService"
        |> AWS.Service.service


{-| Verifies the specified user attributes in the user pool.
-}
verifyUserAttribute : VerifyUserAttributeRequest -> AWS.Http.Request ()
verifyUserAttribute req =
    let
        encoder val =
            [ ( "Code", val.code ) |> EncodeOpt.field confirmationCodeTypeEncoder
            , ( "AttributeName", val.attributeName ) |> EncodeOpt.field (Codec.encoder attributeNameTypeCodec)
            , ( "AccessToken", val.accessToken ) |> EncodeOpt.field (Codec.encoder tokenModelTypeCodec)
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "VerifyUserAttribute" AWS.Http.POST url jsonBody decoder


{-| Use this API to register a user's entered TOTP code and mark the user's software token MFA status as "verified" if successful. The request takes an access token or a session string, but not both.
-}
verifySoftwareToken : VerifySoftwareTokenRequest -> AWS.Http.Request VerifySoftwareTokenResponse
verifySoftwareToken req =
    let
        encoder val =
            [ ( "UserCode", val.userCode ) |> EncodeOpt.field softwareTokenMfauserCodeTypeEncoder
            , ( "Session", val.session ) |> EncodeOpt.optionalField (Codec.encoder sessionTypeCodec)
            , ( "FriendlyDeviceName", val.friendlyDeviceName )
                |> EncodeOpt.optionalField (Codec.encoder stringTypeCodec)
            , ( "AccessToken", val.accessToken ) |> EncodeOpt.optionalField (Codec.encoder tokenModelTypeCodec)
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\statusFld sessionFld -> { session = sessionFld, status = statusFld }) |> Json.Decode.succeed)
                |> Pipeline.optional "Status" (Json.Decode.maybe verifySoftwareTokenResponseTypeDecoder) Nothing
                |> Pipeline.optional "Session" (Json.Decode.maybe (Codec.decoder sessionTypeCodec)) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "VerifySoftwareToken" AWS.Http.POST url jsonBody decoder


{-| Updates the Secure Sockets Layer (SSL) certificate for the custom domain for your user pool.

You can use this operation to provide the Amazon Resource Name (ARN) of a new certificate to Amazon Cognito. You cannot use it to change the domain for a user pool.

A custom domain is used to host the Amazon Cognito hosted UI, which provides sign-up and sign-in pages for your application. When you set up a custom domain, you provide a certificate that you manage with AWS Certificate Manager (ACM). When necessary, you can use this operation to change the certificate that you applied to your custom domain.

Usually, this is unnecessary following routine certificate renewal with ACM. When you renew your existing certificate in ACM, the ARN for your certificate remains the same, and your custom domain uses the new certificate automatically.

However, if you replace your existing certificate with a new one, ACM gives the new certificate a new ARN. To apply the new certificate to your custom domain, you must provide this ARN to Amazon Cognito.

When you add your new certificate in ACM, you must choose US East (N. Virginia) as the AWS Region.

After you submit your request, Amazon Cognito requires up to 1 hour to distribute your new certificate to your custom domain.

For more information about adding a custom domain to your user pool, see `Using Your Own Domain for the Hosted UI`.

-}
updateUserPoolDomain : UpdateUserPoolDomainRequest -> AWS.Http.Request UpdateUserPoolDomainResponse
updateUserPoolDomain req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "Domain", val.domain ) |> EncodeOpt.field (Codec.encoder domainTypeCodec)
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
                |> Pipeline.optional "CloudFrontDomain" (Json.Decode.maybe (Codec.decoder domainTypeCodec)) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "UpdateUserPoolDomain" AWS.Http.POST url jsonBody decoder


{-| Updates the specified user pool app client with the specified attributes. If you don't provide a value for an attribute, it will be set to the default value. You can get a list of the current user pool app client settings with .
-}
updateUserPoolClient : UpdateUserPoolClientRequest -> AWS.Http.Request UpdateUserPoolClientResponse
updateUserPoolClient req =
    let
        encoder val =
            [ ( "WriteAttributes", val.writeAttributes )
                |> EncodeOpt.optionalField (Codec.encoder clientPermissionListTypeCodec)
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "SupportedIdentityProviders", val.supportedIdentityProviders )
                |> EncodeOpt.optionalField (Codec.encoder supportedIdentityProvidersListTypeCodec)
            , ( "RefreshTokenValidity", val.refreshTokenValidity )
                |> EncodeOpt.optionalField (Codec.encoder refreshTokenValidityTypeCodec)
            , ( "ReadAttributes", val.readAttributes )
                |> EncodeOpt.optionalField (Codec.encoder clientPermissionListTypeCodec)
            , ( "LogoutURLs", val.logoutUrls ) |> EncodeOpt.optionalField (Codec.encoder logoutUrlsListTypeCodec)
            , ( "ExplicitAuthFlows", val.explicitAuthFlows )
                |> EncodeOpt.optionalField (Codec.encoder explicitAuthFlowsListTypeCodec)
            , ( "DefaultRedirectURI", val.defaultRedirectUri )
                |> EncodeOpt.optionalField (Codec.encoder redirectUrlTypeCodec)
            , ( "ClientName", val.clientName ) |> EncodeOpt.optionalField (Codec.encoder clientNameTypeCodec)
            , ( "ClientId", val.clientId ) |> EncodeOpt.field (Codec.encoder clientIdTypeCodec)
            , ( "CallbackURLs", val.callbackUrls ) |> EncodeOpt.optionalField (Codec.encoder callbackUrlsListTypeCodec)
            , ( "AnalyticsConfiguration", val.analyticsConfiguration )
                |> EncodeOpt.optionalField (Codec.encoder analyticsConfigurationTypeCodec)
            , ( "AllowedOAuthScopes", val.allowedOauthScopes )
                |> EncodeOpt.optionalField (Codec.encoder scopeListTypeCodec)
            , ( "AllowedOAuthFlowsUserPoolClient", val.allowedOauthFlowsUserPoolClient )
                |> EncodeOpt.optionalField (Codec.encoder booleanTypeCodec)
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
    AWS.Http.request "UpdateUserPoolClient" AWS.Http.POST url jsonBody decoder


{-| Updates the specified user pool with the specified attributes. If you don't provide a value for an attribute, it will be set to the default value. You can get a list of the current user pool settings with .
-}
updateUserPool : UpdateUserPoolRequest -> AWS.Http.Request ()
updateUserPool req =
    let
        encoder val =
            [ ( "VerificationMessageTemplate", val.verificationMessageTemplate )
                |> EncodeOpt.optionalField (Codec.encoder verificationMessageTemplateTypeCodec)
            , ( "UserPoolTags", val.userPoolTags ) |> EncodeOpt.optionalField (Codec.encoder userPoolTagsTypeCodec)
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "UserPoolAddOns", val.userPoolAddOns )
                |> EncodeOpt.optionalField (Codec.encoder userPoolAddOnsTypeCodec)
            , ( "SmsVerificationMessage", val.smsVerificationMessage )
                |> EncodeOpt.optionalField (Codec.encoder smsVerificationMessageTypeCodec)
            , ( "SmsConfiguration", val.smsConfiguration )
                |> EncodeOpt.optionalField (Codec.encoder smsConfigurationTypeCodec)
            , ( "SmsAuthenticationMessage", val.smsAuthenticationMessage )
                |> EncodeOpt.optionalField (Codec.encoder smsVerificationMessageTypeCodec)
            , ( "Policies", val.policies ) |> EncodeOpt.optionalField (Codec.encoder userPoolPolicyTypeCodec)
            , ( "MfaConfiguration", val.mfaConfiguration )
                |> EncodeOpt.optionalField (Codec.encoder userPoolMfaTypeCodec)
            , ( "LambdaConfig", val.lambdaConfig ) |> EncodeOpt.optionalField (Codec.encoder lambdaConfigTypeCodec)
            , ( "EmailVerificationSubject", val.emailVerificationSubject )
                |> EncodeOpt.optionalField (Codec.encoder emailVerificationSubjectTypeCodec)
            , ( "EmailVerificationMessage", val.emailVerificationMessage )
                |> EncodeOpt.optionalField (Codec.encoder emailVerificationMessageTypeCodec)
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
    AWS.Http.request "UpdateUserPool" AWS.Http.POST url jsonBody decoder


{-| Allows a user to update a specific attribute (one at a time).
-}
updateUserAttributes : UpdateUserAttributesRequest -> AWS.Http.Request UpdateUserAttributesResponse
updateUserAttributes req =
    let
        encoder val =
            [ ( "UserAttributes", val.userAttributes ) |> EncodeOpt.field (Codec.encoder attributeListTypeCodec)
            , ( "AccessToken", val.accessToken ) |> EncodeOpt.field (Codec.encoder tokenModelTypeCodec)
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
    AWS.Http.request "UpdateUserAttributes" AWS.Http.POST url jsonBody decoder


{-| Updates the name and scopes of resource server. All other fields are read-only.
-}
updateResourceServer : UpdateResourceServerRequest -> AWS.Http.Request UpdateResourceServerResponse
updateResourceServer req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "Scopes", val.scopes ) |> EncodeOpt.optionalField (Codec.encoder resourceServerScopeListTypeCodec)
            , ( "Name", val.name ) |> EncodeOpt.field (Codec.encoder resourceServerNameTypeCodec)
            , ( "Identifier", val.identifier ) |> EncodeOpt.field (Codec.encoder resourceServerIdentifierTypeCodec)
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
    AWS.Http.request "UpdateResourceServer" AWS.Http.POST url jsonBody decoder


{-| Updates identity provider information for a user pool.
-}
updateIdentityProvider : UpdateIdentityProviderRequest -> AWS.Http.Request UpdateIdentityProviderResponse
updateIdentityProvider req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "ProviderName", val.providerName ) |> EncodeOpt.field (Codec.encoder providerNameTypeCodec)
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
    AWS.Http.request "UpdateIdentityProvider" AWS.Http.POST url jsonBody decoder


{-| Updates the specified group with the specified attributes.

Requires developer credentials.

-}
updateGroup : UpdateGroupRequest -> AWS.Http.Request UpdateGroupResponse
updateGroup req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "RoleArn", val.roleArn ) |> EncodeOpt.optionalField (Codec.encoder arnTypeCodec)
            , ( "Precedence", val.precedence ) |> EncodeOpt.optionalField (Codec.encoder precedenceTypeCodec)
            , ( "GroupName", val.groupName ) |> EncodeOpt.field (Codec.encoder groupNameTypeCodec)
            , ( "Description", val.description ) |> EncodeOpt.optionalField (Codec.encoder descriptionTypeCodec)
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
    AWS.Http.request "UpdateGroup" AWS.Http.POST url jsonBody decoder


{-| Updates the device status.
-}
updateDeviceStatus : UpdateDeviceStatusRequest -> AWS.Http.Request ()
updateDeviceStatus req =
    let
        encoder val =
            [ ( "DeviceRememberedStatus", val.deviceRememberedStatus )
                |> EncodeOpt.optionalField deviceRememberedStatusTypeEncoder
            , ( "DeviceKey", val.deviceKey ) |> EncodeOpt.field (Codec.encoder deviceKeyTypeCodec)
            , ( "AccessToken", val.accessToken ) |> EncodeOpt.field (Codec.encoder tokenModelTypeCodec)
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "UpdateDeviceStatus" AWS.Http.POST url jsonBody decoder


{-| Provides the feedback for an authentication event whether it was from a valid user or not. This feedback is used for improving the risk evaluation decision for the user pool as part of Amazon Cognito advanced security.
-}
updateAuthEventFeedback : UpdateAuthEventFeedbackRequest -> AWS.Http.Request ()
updateAuthEventFeedback req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field (Codec.encoder usernameTypeCodec)
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "FeedbackValue", val.feedbackValue ) |> EncodeOpt.field (Codec.encoder feedbackValueTypeCodec)
            , ( "FeedbackToken", val.feedbackToken ) |> EncodeOpt.field (Codec.encoder tokenModelTypeCodec)
            , ( "EventId", val.eventId ) |> EncodeOpt.field eventIdTypeEncoder
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "UpdateAuthEventFeedback" AWS.Http.POST url jsonBody decoder


{-| Removes the specified tags from an Amazon Cognito user pool. You can use this action up to 5 times per second, per account
-}
untagResource : UntagResourceRequest -> AWS.Http.Request ()
untagResource req =
    let
        encoder val =
            [ ( "TagKeys", val.tagKeys ) |> EncodeOpt.optionalField userPoolTagsListTypeEncoder
            , ( "ResourceArn", val.resourceArn ) |> EncodeOpt.field (Codec.encoder arnTypeCodec)
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "UntagResource" AWS.Http.POST url jsonBody decoder


{-| Assigns a set of tags to an Amazon Cognito user pool. A tag is a label that you can use to categorize and manage user pools in different ways, such as by purpose, owner, environment, or other criteria.

Each tag consists of a key and value, both of which you define. A key is a general category for more specific values. For example, if you have two versions of a user pool, one for testing and another for production, you might assign an `Environment` tag key to both user pools. The value of this key might be `Test` for one user pool and `Production` for the other.

Tags are useful for cost tracking and access control. You can activate your tags so that they appear on the Billing and Cost Management console, where you can track the costs associated with your user pools. In an IAM policy, you can constrain permissions for user pools based on specific tags or tag values.

You can use this action up to 5 times per second, per account. A user pool can have as many as 50 tags.

-}
tagResource : TagResourceRequest -> AWS.Http.Request ()
tagResource req =
    let
        encoder val =
            [ ( "Tags", val.tags ) |> EncodeOpt.optionalField (Codec.encoder userPoolTagsTypeCodec)
            , ( "ResourceArn", val.resourceArn ) |> EncodeOpt.field (Codec.encoder arnTypeCodec)
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "TagResource" AWS.Http.POST url jsonBody decoder


{-| Stops the user import job.
-}
stopUserImportJob : StopUserImportJobRequest -> AWS.Http.Request StopUserImportJobResponse
stopUserImportJob req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "JobId", val.jobId ) |> EncodeOpt.field (Codec.encoder userImportJobIdTypeCodec)
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
    AWS.Http.request "StopUserImportJob" AWS.Http.POST url jsonBody decoder


{-| Starts the user import.
-}
startUserImportJob : StartUserImportJobRequest -> AWS.Http.Request StartUserImportJobResponse
startUserImportJob req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "JobId", val.jobId ) |> EncodeOpt.field (Codec.encoder userImportJobIdTypeCodec)
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
    AWS.Http.request "StartUserImportJob" AWS.Http.POST url jsonBody decoder


{-| Registers the user in the specified user pool and creates a user name, password, and user attributes.
-}
signUp : SignUpRequest -> AWS.Http.Request SignUpResponse
signUp req =
    let
        encoder val =
            [ ( "ValidationData", val.validationData ) |> EncodeOpt.optionalField (Codec.encoder attributeListTypeCodec)
            , ( "Username", val.username ) |> EncodeOpt.field (Codec.encoder usernameTypeCodec)
            , ( "UserContextData", val.userContextData ) |> EncodeOpt.optionalField userContextDataTypeEncoder
            , ( "UserAttributes", val.userAttributes ) |> EncodeOpt.optionalField (Codec.encoder attributeListTypeCodec)
            , ( "SecretHash", val.secretHash ) |> EncodeOpt.optionalField secretHashTypeEncoder
            , ( "Password", val.password ) |> EncodeOpt.field passwordTypeEncoder
            , ( "ClientId", val.clientId ) |> EncodeOpt.field (Codec.encoder clientIdTypeCodec)
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
                |> Pipeline.required "UserSub" (Codec.decoder stringTypeCodec)
                |> Pipeline.required "UserConfirmed" (Codec.decoder booleanTypeCodec)
                |> Pipeline.optional "CodeDeliveryDetails" (Json.Decode.maybe codeDeliveryDetailsTypeDecoder) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "SignUp" AWS.Http.POST url jsonBody decoder


{-| Sets the user settings like multi-factor authentication (MFA). If MFA is to be removed for a particular attribute pass the attribute with code delivery as null. If null list is passed, all MFA options are removed.
-}
setUserSettings : SetUserSettingsRequest -> AWS.Http.Request ()
setUserSettings req =
    let
        encoder val =
            [ ( "MFAOptions", val.mfaoptions ) |> EncodeOpt.field (Codec.encoder mfaoptionListTypeCodec)
            , ( "AccessToken", val.accessToken ) |> EncodeOpt.field (Codec.encoder tokenModelTypeCodec)
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "SetUserSettings" AWS.Http.POST url jsonBody decoder


{-| Set the user pool MFA configuration.
-}
setUserPoolMfaConfig : SetUserPoolMfaConfigRequest -> AWS.Http.Request SetUserPoolMfaConfigResponse
setUserPoolMfaConfig req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
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
    AWS.Http.request "SetUserPoolMfaConfig" AWS.Http.POST url jsonBody decoder


{-| Set the user's multi-factor authentication (MFA) method preference.
-}
setUserMfapreference : SetUserMfapreferenceRequest -> AWS.Http.Request ()
setUserMfapreference req =
    let
        encoder val =
            [ ( "SoftwareTokenMfaSettings", val.softwareTokenMfaSettings )
                |> EncodeOpt.optionalField softwareTokenMfaSettingsTypeEncoder
            , ( "SMSMfaSettings", val.smsmfaSettings ) |> EncodeOpt.optionalField smsmfaSettingsTypeEncoder
            , ( "AccessToken", val.accessToken ) |> EncodeOpt.field (Codec.encoder tokenModelTypeCodec)
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "SetUserMfapreference" AWS.Http.POST url jsonBody decoder


{-| Sets the UI customization information for a user pool's built-in app UI.

You can specify app UI customization settings for a single client (with a specific `clientId`) or for all clients (by setting the `clientId` to `ALL`). If you specify `ALL`, the default configuration will be used for every client that has no UI customization set previously. If you specify UI customization settings for a particular client, it will no longer fall back to the `ALL` configuration.

To use this API, your user pool must have a domain associated with it. Otherwise, there is no place to host the app's pages, and the service will throw an error.

-}
setUicustomization : SetUicustomizationRequest -> AWS.Http.Request SetUicustomizationResponse
setUicustomization req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "ImageFile", val.imageFile ) |> EncodeOpt.optionalField imageFileTypeEncoder
            , ( "ClientId", val.clientId ) |> EncodeOpt.optionalField (Codec.encoder clientIdTypeCodec)
            , ( "CSS", val.css ) |> EncodeOpt.optionalField (Codec.encoder csstypeCodec)
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
    AWS.Http.request "SetUicustomization" AWS.Http.POST url jsonBody decoder


{-| Configures actions on detected risks. To delete the risk configuration for `UserPoolId` or `ClientId`, pass null values for all four configuration types.

To enable Amazon Cognito advanced security features, update the user pool to include the `UserPoolAddOns` key`AdvancedSecurityMode`.

See .

-}
setRiskConfiguration : SetRiskConfigurationRequest -> AWS.Http.Request SetRiskConfigurationResponse
setRiskConfiguration req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "RiskExceptionConfiguration", val.riskExceptionConfiguration )
                |> EncodeOpt.optionalField (Codec.encoder riskExceptionConfigurationTypeCodec)
            , ( "CompromisedCredentialsRiskConfiguration", val.compromisedCredentialsRiskConfiguration )
                |> EncodeOpt.optionalField (Codec.encoder compromisedCredentialsRiskConfigurationTypeCodec)
            , ( "ClientId", val.clientId ) |> EncodeOpt.optionalField (Codec.encoder clientIdTypeCodec)
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
    AWS.Http.request "SetRiskConfiguration" AWS.Http.POST url jsonBody decoder


{-| Responds to the authentication challenge.
-}
respondToAuthChallenge : RespondToAuthChallengeRequest -> AWS.Http.Request RespondToAuthChallengeResponse
respondToAuthChallenge req =
    let
        encoder val =
            [ ( "UserContextData", val.userContextData ) |> EncodeOpt.optionalField userContextDataTypeEncoder
            , ( "Session", val.session ) |> EncodeOpt.optionalField (Codec.encoder sessionTypeCodec)
            , ( "ClientId", val.clientId ) |> EncodeOpt.field (Codec.encoder clientIdTypeCodec)
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
                |> Pipeline.optional "Session" (Json.Decode.maybe (Codec.decoder sessionTypeCodec)) Nothing
                |> Pipeline.optional "ChallengeParameters" (Json.Decode.maybe challengeParametersTypeDecoder) Nothing
                |> Pipeline.optional "ChallengeName" (Json.Decode.maybe (Codec.decoder challengeNameTypeCodec)) Nothing
                |> Pipeline.optional "AuthenticationResult" (Json.Decode.maybe authenticationResultTypeDecoder) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "RespondToAuthChallenge" AWS.Http.POST url jsonBody decoder


{-| Resends the confirmation (for confirmation of registration) to a specific user in the user pool.
-}
resendConfirmationCode : ResendConfirmationCodeRequest -> AWS.Http.Request ResendConfirmationCodeResponse
resendConfirmationCode req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field (Codec.encoder usernameTypeCodec)
            , ( "UserContextData", val.userContextData ) |> EncodeOpt.optionalField userContextDataTypeEncoder
            , ( "SecretHash", val.secretHash ) |> EncodeOpt.optionalField secretHashTypeEncoder
            , ( "ClientId", val.clientId ) |> EncodeOpt.field (Codec.encoder clientIdTypeCodec)
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
    AWS.Http.request "ResendConfirmationCode" AWS.Http.POST url jsonBody decoder


{-| Lists the users in the specified group.

Requires developer credentials.

-}
listUsersInGroup : ListUsersInGroupRequest -> AWS.Http.Request ListUsersInGroupResponse
listUsersInGroup req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "NextToken", val.nextToken ) |> EncodeOpt.optionalField (Codec.encoder paginationKeyCodec)
            , ( "Limit", val.limit ) |> EncodeOpt.optionalField queryLimitTypeEncoder
            , ( "GroupName", val.groupName ) |> EncodeOpt.field (Codec.encoder groupNameTypeCodec)
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\usersFld nextTokenFld -> { nextToken = nextTokenFld, users = usersFld }) |> Json.Decode.succeed)
                |> Pipeline.optional "Users" (Json.Decode.maybe usersListTypeDecoder) Nothing
                |> Pipeline.optional "NextToken" (Json.Decode.maybe (Codec.decoder paginationKeyCodec)) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "ListUsersInGroup" AWS.Http.POST url jsonBody decoder


{-| Lists the users in the Amazon Cognito user pool.
-}
listUsers : ListUsersRequest -> AWS.Http.Request ListUsersResponse
listUsers req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "PaginationToken", val.paginationToken )
                |> EncodeOpt.optionalField (Codec.encoder searchPaginationTokenTypeCodec)
            , ( "Limit", val.limit ) |> EncodeOpt.optionalField queryLimitTypeEncoder
            , ( "Filter", val.filter ) |> EncodeOpt.optionalField userFilterTypeEncoder
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
                |> Pipeline.optional
                    "PaginationToken"
                    (Json.Decode.maybe (Codec.decoder searchPaginationTokenTypeCodec))
                    Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "ListUsers" AWS.Http.POST url jsonBody decoder


{-| Lists the user pools associated with an AWS account.
-}
listUserPools : ListUserPoolsRequest -> AWS.Http.Request ListUserPoolsResponse
listUserPools req =
    let
        encoder val =
            [ ( "NextToken", val.nextToken ) |> EncodeOpt.optionalField (Codec.encoder paginationKeyTypeCodec)
            , ( "MaxResults", val.maxResults ) |> EncodeOpt.field poolQueryLimitTypeEncoder
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
                |> Pipeline.optional "NextToken" (Json.Decode.maybe (Codec.decoder paginationKeyTypeCodec)) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "ListUserPools" AWS.Http.POST url jsonBody decoder


{-| Lists the clients that have been created for the specified user pool.
-}
listUserPoolClients : ListUserPoolClientsRequest -> AWS.Http.Request ListUserPoolClientsResponse
listUserPoolClients req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "NextToken", val.nextToken ) |> EncodeOpt.optionalField (Codec.encoder paginationKeyCodec)
            , ( "MaxResults", val.maxResults ) |> EncodeOpt.optionalField queryLimitEncoder
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
                |> Pipeline.optional "NextToken" (Json.Decode.maybe (Codec.decoder paginationKeyCodec)) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "ListUserPoolClients" AWS.Http.POST url jsonBody decoder


{-| Lists the user import jobs.
-}
listUserImportJobs : ListUserImportJobsRequest -> AWS.Http.Request ListUserImportJobsResponse
listUserImportJobs req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "PaginationToken", val.paginationToken )
                |> EncodeOpt.optionalField (Codec.encoder paginationKeyTypeCodec)
            , ( "MaxResults", val.maxResults ) |> EncodeOpt.field poolQueryLimitTypeEncoder
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
                |> Pipeline.optional
                    "PaginationToken"
                    (Json.Decode.maybe (Codec.decoder paginationKeyTypeCodec))
                    Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "ListUserImportJobs" AWS.Http.POST url jsonBody decoder


{-| Lists the tags that are assigned to an Amazon Cognito user pool.

A tag is a label that you can apply to user pools to categorize and manage them in different ways, such as by purpose, owner, environment, or other criteria.

You can use this action up to 10 times per second, per account.

-}
listTagsForResource : ListTagsForResourceRequest -> AWS.Http.Request ListTagsForResourceResponse
listTagsForResource req =
    let
        encoder val =
            [ ( "ResourceArn", val.resourceArn ) |> EncodeOpt.field (Codec.encoder arnTypeCodec) ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\tagsFld -> { tags = tagsFld }) |> Json.Decode.succeed)
                |> Pipeline.optional "Tags" (Json.Decode.maybe (Codec.decoder userPoolTagsTypeCodec)) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "ListTagsForResource" AWS.Http.POST url jsonBody decoder


{-| Lists the resource servers for a user pool.
-}
listResourceServers : ListResourceServersRequest -> AWS.Http.Request ListResourceServersResponse
listResourceServers req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "NextToken", val.nextToken ) |> EncodeOpt.optionalField (Codec.encoder paginationKeyTypeCodec)
            , ( "MaxResults", val.maxResults ) |> EncodeOpt.optionalField listResourceServersLimitTypeEncoder
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
                |> Pipeline.optional "NextToken" (Json.Decode.maybe (Codec.decoder paginationKeyTypeCodec)) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "ListResourceServers" AWS.Http.POST url jsonBody decoder


{-| Lists information about all identity providers for a user pool.
-}
listIdentityProviders : ListIdentityProvidersRequest -> AWS.Http.Request ListIdentityProvidersResponse
listIdentityProviders req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "NextToken", val.nextToken ) |> EncodeOpt.optionalField (Codec.encoder paginationKeyTypeCodec)
            , ( "MaxResults", val.maxResults ) |> EncodeOpt.optionalField listProvidersLimitTypeEncoder
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
                |> Pipeline.optional "NextToken" (Json.Decode.maybe (Codec.decoder paginationKeyTypeCodec)) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "ListIdentityProviders" AWS.Http.POST url jsonBody decoder


{-| Lists the groups associated with a user pool.

Requires developer credentials.

-}
listGroups : ListGroupsRequest -> AWS.Http.Request ListGroupsResponse
listGroups req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "NextToken", val.nextToken ) |> EncodeOpt.optionalField (Codec.encoder paginationKeyCodec)
            , ( "Limit", val.limit ) |> EncodeOpt.optionalField queryLimitTypeEncoder
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\nextTokenFld groupsFld -> { groups = groupsFld, nextToken = nextTokenFld }) |> Json.Decode.succeed)
                |> Pipeline.optional "NextToken" (Json.Decode.maybe (Codec.decoder paginationKeyCodec)) Nothing
                |> Pipeline.optional "Groups" (Json.Decode.maybe groupListTypeDecoder) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "ListGroups" AWS.Http.POST url jsonBody decoder


{-| Lists the devices.
-}
listDevices : ListDevicesRequest -> AWS.Http.Request ListDevicesResponse
listDevices req =
    let
        encoder val =
            [ ( "PaginationToken", val.paginationToken )
                |> EncodeOpt.optionalField (Codec.encoder searchPaginationTokenTypeCodec)
            , ( "Limit", val.limit ) |> EncodeOpt.optionalField queryLimitTypeEncoder
            , ( "AccessToken", val.accessToken ) |> EncodeOpt.field (Codec.encoder tokenModelTypeCodec)
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
                |> Pipeline.optional
                    "PaginationToken"
                    (Json.Decode.maybe (Codec.decoder searchPaginationTokenTypeCodec))
                    Nothing
                |> Pipeline.optional "Devices" (Json.Decode.maybe deviceListTypeDecoder) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "ListDevices" AWS.Http.POST url jsonBody decoder


{-| Initiates the authentication flow.
-}
initiateAuth : InitiateAuthRequest -> AWS.Http.Request InitiateAuthResponse
initiateAuth req =
    let
        encoder val =
            [ ( "UserContextData", val.userContextData ) |> EncodeOpt.optionalField userContextDataTypeEncoder
            , ( "ClientMetadata", val.clientMetadata ) |> EncodeOpt.optionalField clientMetadataTypeEncoder
            , ( "ClientId", val.clientId ) |> EncodeOpt.field (Codec.encoder clientIdTypeCodec)
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
                |> Pipeline.optional "Session" (Json.Decode.maybe (Codec.decoder sessionTypeCodec)) Nothing
                |> Pipeline.optional "ChallengeParameters" (Json.Decode.maybe challengeParametersTypeDecoder) Nothing
                |> Pipeline.optional "ChallengeName" (Json.Decode.maybe (Codec.decoder challengeNameTypeCodec)) Nothing
                |> Pipeline.optional "AuthenticationResult" (Json.Decode.maybe authenticationResultTypeDecoder) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "InitiateAuth" AWS.Http.POST url jsonBody decoder


{-| Signs out users from all devices.
-}
globalSignOut : GlobalSignOutRequest -> AWS.Http.Request ()
globalSignOut req =
    let
        encoder val =
            [ ( "AccessToken", val.accessToken ) |> EncodeOpt.field (Codec.encoder tokenModelTypeCodec) ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "GlobalSignOut" AWS.Http.POST url jsonBody decoder


{-| Gets the user pool multi-factor authentication (MFA) configuration.
-}
getUserPoolMfaConfig : GetUserPoolMfaConfigRequest -> AWS.Http.Request GetUserPoolMfaConfigResponse
getUserPoolMfaConfig req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec) ]
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
    AWS.Http.request "GetUserPoolMfaConfig" AWS.Http.POST url jsonBody decoder


{-| Gets the user attribute verification code for the specified attribute name.
-}
getUserAttributeVerificationCode : GetUserAttributeVerificationCodeRequest -> AWS.Http.Request GetUserAttributeVerificationCodeResponse
getUserAttributeVerificationCode req =
    let
        encoder val =
            [ ( "AttributeName", val.attributeName ) |> EncodeOpt.field (Codec.encoder attributeNameTypeCodec)
            , ( "AccessToken", val.accessToken ) |> EncodeOpt.field (Codec.encoder tokenModelTypeCodec)
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
    AWS.Http.request "GetUserAttributeVerificationCode" AWS.Http.POST url jsonBody decoder


{-| Gets the user attributes and metadata for a user.
-}
getUser : GetUserRequest -> AWS.Http.Request GetUserResponse
getUser req =
    let
        encoder val =
            [ ( "AccessToken", val.accessToken ) |> EncodeOpt.field (Codec.encoder tokenModelTypeCodec) ]
                |> EncodeOpt.objectMaySkip

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
                |> Pipeline.required "Username" (Codec.decoder usernameTypeCodec)
                |> Pipeline.optional "UserMFASettingList" (Json.Decode.maybe userMfasettingListTypeDecoder) Nothing
                |> Pipeline.required "UserAttributes" (Codec.decoder attributeListTypeCodec)
                |> Pipeline.optional "PreferredMfaSetting" (Json.Decode.maybe (Codec.decoder stringTypeCodec)) Nothing
                |> Pipeline.optional "MFAOptions" (Json.Decode.maybe (Codec.decoder mfaoptionListTypeCodec)) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "GetUser" AWS.Http.POST url jsonBody decoder


{-| Gets the UI Customization information for a particular app client's app UI, if there is something set. If nothing is set for the particular client, but there is an existing pool level customization (app `clientId` will be `ALL`), then that is returned. If nothing is present, then an empty shape is returned.
-}
getUicustomization : GetUicustomizationRequest -> AWS.Http.Request GetUicustomizationResponse
getUicustomization req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "ClientId", val.clientId ) |> EncodeOpt.optionalField (Codec.encoder clientIdTypeCodec)
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
    AWS.Http.request "GetUicustomization" AWS.Http.POST url jsonBody decoder


{-| This method takes a user pool ID, and returns the signing certificate.
-}
getSigningCertificate : GetSigningCertificateRequest -> AWS.Http.Request GetSigningCertificateResponse
getSigningCertificate req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec) ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\certificateFld -> { certificate = certificateFld }) |> Json.Decode.succeed)
                |> Pipeline.optional "Certificate" (Json.Decode.maybe (Codec.decoder stringTypeCodec)) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "GetSigningCertificate" AWS.Http.POST url jsonBody decoder


{-| Gets the specified identity provider.
-}
getIdentityProviderByIdentifier : GetIdentityProviderByIdentifierRequest -> AWS.Http.Request GetIdentityProviderByIdentifierResponse
getIdentityProviderByIdentifier req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "IdpIdentifier", val.idpIdentifier ) |> EncodeOpt.field (Codec.encoder idpIdentifierTypeCodec)
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
    AWS.Http.request "GetIdentityProviderByIdentifier" AWS.Http.POST url jsonBody decoder


{-| Gets a group.

Requires developer credentials.

-}
getGroup : GetGroupRequest -> AWS.Http.Request GetGroupResponse
getGroup req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "GroupName", val.groupName ) |> EncodeOpt.field (Codec.encoder groupNameTypeCodec)
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
    AWS.Http.request "GetGroup" AWS.Http.POST url jsonBody decoder


{-| Gets the device.
-}
getDevice : GetDeviceRequest -> AWS.Http.Request GetDeviceResponse
getDevice req =
    let
        encoder val =
            [ ( "DeviceKey", val.deviceKey ) |> EncodeOpt.field (Codec.encoder deviceKeyTypeCodec)
            , ( "AccessToken", val.accessToken ) |> EncodeOpt.optionalField (Codec.encoder tokenModelTypeCodec)
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
    AWS.Http.request "GetDevice" AWS.Http.POST url jsonBody decoder


{-| Gets the header information for the .csv file to be used as input for the user import job.
-}
getCsvheader : GetCsvheaderRequest -> AWS.Http.Request GetCsvheaderResponse
getCsvheader req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec) ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\userPoolIdFld csvheaderFld -> { csvheader = csvheaderFld, userPoolId = userPoolIdFld })
                |> Json.Decode.succeed
            )
                |> Pipeline.optional "UserPoolId" (Json.Decode.maybe (Codec.decoder userPoolIdTypeCodec)) Nothing
                |> Pipeline.optional "CSVHeader" (Json.Decode.maybe listOfStringTypesDecoder) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "GetCsvheader" AWS.Http.POST url jsonBody decoder


{-| Calling this API causes a message to be sent to the end user with a confirmation code that is required to change the user's password. For the `Username` parameter, you can use the username or user alias. If a verified phone number exists for the user, the confirmation code is sent to the phone number. Otherwise, if a verified email exists, the confirmation code is sent to the email. If neither a verified phone number nor a verified email exists, `InvalidParameterException` is thrown. To use the confirmation code for resetting the password, call .
-}
forgotPassword : ForgotPasswordRequest -> AWS.Http.Request ForgotPasswordResponse
forgotPassword req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field (Codec.encoder usernameTypeCodec)
            , ( "UserContextData", val.userContextData ) |> EncodeOpt.optionalField userContextDataTypeEncoder
            , ( "SecretHash", val.secretHash ) |> EncodeOpt.optionalField secretHashTypeEncoder
            , ( "ClientId", val.clientId ) |> EncodeOpt.field (Codec.encoder clientIdTypeCodec)
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
    AWS.Http.request "ForgotPassword" AWS.Http.POST url jsonBody decoder


{-| Forgets the specified device.
-}
forgetDevice : ForgetDeviceRequest -> AWS.Http.Request ()
forgetDevice req =
    let
        encoder val =
            [ ( "DeviceKey", val.deviceKey ) |> EncodeOpt.field (Codec.encoder deviceKeyTypeCodec)
            , ( "AccessToken", val.accessToken ) |> EncodeOpt.optionalField (Codec.encoder tokenModelTypeCodec)
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "ForgetDevice" AWS.Http.POST url jsonBody decoder


{-| Gets information about a domain.
-}
describeUserPoolDomain : DescribeUserPoolDomainRequest -> AWS.Http.Request DescribeUserPoolDomainResponse
describeUserPoolDomain req =
    let
        encoder val =
            [ ( "Domain", val.domain ) |> EncodeOpt.field (Codec.encoder domainTypeCodec) ] |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\domainDescriptionFld -> { domainDescription = domainDescriptionFld }) |> Json.Decode.succeed)
                |> Pipeline.optional "DomainDescription" (Json.Decode.maybe domainDescriptionTypeDecoder) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "DescribeUserPoolDomain" AWS.Http.POST url jsonBody decoder


{-| Client method for returning the configuration information and metadata of the specified user pool app client.
-}
describeUserPoolClient : DescribeUserPoolClientRequest -> AWS.Http.Request DescribeUserPoolClientResponse
describeUserPoolClient req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "ClientId", val.clientId ) |> EncodeOpt.field (Codec.encoder clientIdTypeCodec)
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
    AWS.Http.request "DescribeUserPoolClient" AWS.Http.POST url jsonBody decoder


{-| Returns the configuration information and metadata of the specified user pool.
-}
describeUserPool : DescribeUserPoolRequest -> AWS.Http.Request DescribeUserPoolResponse
describeUserPool req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec) ]
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
    AWS.Http.request "DescribeUserPool" AWS.Http.POST url jsonBody decoder


{-| Describes the user import job.
-}
describeUserImportJob : DescribeUserImportJobRequest -> AWS.Http.Request DescribeUserImportJobResponse
describeUserImportJob req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "JobId", val.jobId ) |> EncodeOpt.field (Codec.encoder userImportJobIdTypeCodec)
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
    AWS.Http.request "DescribeUserImportJob" AWS.Http.POST url jsonBody decoder


{-| Describes the risk configuration.
-}
describeRiskConfiguration : DescribeRiskConfigurationRequest -> AWS.Http.Request DescribeRiskConfigurationResponse
describeRiskConfiguration req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "ClientId", val.clientId ) |> EncodeOpt.optionalField (Codec.encoder clientIdTypeCodec)
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
    AWS.Http.request "DescribeRiskConfiguration" AWS.Http.POST url jsonBody decoder


{-| Describes a resource server.
-}
describeResourceServer : DescribeResourceServerRequest -> AWS.Http.Request DescribeResourceServerResponse
describeResourceServer req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "Identifier", val.identifier ) |> EncodeOpt.field (Codec.encoder resourceServerIdentifierTypeCodec)
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
    AWS.Http.request "DescribeResourceServer" AWS.Http.POST url jsonBody decoder


{-| Gets information about a specific identity provider.
-}
describeIdentityProvider : DescribeIdentityProviderRequest -> AWS.Http.Request DescribeIdentityProviderResponse
describeIdentityProvider req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "ProviderName", val.providerName ) |> EncodeOpt.field (Codec.encoder providerNameTypeCodec)
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
    AWS.Http.request "DescribeIdentityProvider" AWS.Http.POST url jsonBody decoder


{-| Deletes a domain for a user pool.
-}
deleteUserPoolDomain : DeleteUserPoolDomainRequest -> AWS.Http.Request ()
deleteUserPoolDomain req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "Domain", val.domain ) |> EncodeOpt.field (Codec.encoder domainTypeCodec)
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "DeleteUserPoolDomain" AWS.Http.POST url jsonBody decoder


{-| Allows the developer to delete the user pool client.
-}
deleteUserPoolClient : DeleteUserPoolClientRequest -> AWS.Http.Request ()
deleteUserPoolClient req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "ClientId", val.clientId ) |> EncodeOpt.field (Codec.encoder clientIdTypeCodec)
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "DeleteUserPoolClient" AWS.Http.POST url jsonBody decoder


{-| Deletes the specified Amazon Cognito user pool.
-}
deleteUserPool : DeleteUserPoolRequest -> AWS.Http.Request ()
deleteUserPool req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec) ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "DeleteUserPool" AWS.Http.POST url jsonBody decoder


{-| Deletes the attributes for a user.
-}
deleteUserAttributes : DeleteUserAttributesRequest -> AWS.Http.Request ()
deleteUserAttributes req =
    let
        encoder val =
            [ ( "UserAttributeNames", val.userAttributeNames ) |> EncodeOpt.field attributeNameListTypeEncoder
            , ( "AccessToken", val.accessToken ) |> EncodeOpt.field (Codec.encoder tokenModelTypeCodec)
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "DeleteUserAttributes" AWS.Http.POST url jsonBody decoder


{-| Allows a user to delete himself or herself.
-}
deleteUser : DeleteUserRequest -> AWS.Http.Request ()
deleteUser req =
    let
        encoder val =
            [ ( "AccessToken", val.accessToken ) |> EncodeOpt.field (Codec.encoder tokenModelTypeCodec) ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "DeleteUser" AWS.Http.POST url jsonBody decoder


{-| Deletes a resource server.
-}
deleteResourceServer : DeleteResourceServerRequest -> AWS.Http.Request ()
deleteResourceServer req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "Identifier", val.identifier ) |> EncodeOpt.field (Codec.encoder resourceServerIdentifierTypeCodec)
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "DeleteResourceServer" AWS.Http.POST url jsonBody decoder


{-| Deletes an identity provider for a user pool.
-}
deleteIdentityProvider : DeleteIdentityProviderRequest -> AWS.Http.Request ()
deleteIdentityProvider req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "ProviderName", val.providerName ) |> EncodeOpt.field (Codec.encoder providerNameTypeCodec)
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "DeleteIdentityProvider" AWS.Http.POST url jsonBody decoder


{-| Deletes a group. Currently only groups with no members can be deleted.

Requires developer credentials.

-}
deleteGroup : DeleteGroupRequest -> AWS.Http.Request ()
deleteGroup req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "GroupName", val.groupName ) |> EncodeOpt.field (Codec.encoder groupNameTypeCodec)
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "DeleteGroup" AWS.Http.POST url jsonBody decoder


{-| Creates a new domain for a user pool.
-}
createUserPoolDomain : CreateUserPoolDomainRequest -> AWS.Http.Request CreateUserPoolDomainResponse
createUserPoolDomain req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "Domain", val.domain ) |> EncodeOpt.field (Codec.encoder domainTypeCodec)
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
                |> Pipeline.optional "CloudFrontDomain" (Json.Decode.maybe (Codec.decoder domainTypeCodec)) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "CreateUserPoolDomain" AWS.Http.POST url jsonBody decoder


{-| Creates the user pool client.
-}
createUserPoolClient : CreateUserPoolClientRequest -> AWS.Http.Request CreateUserPoolClientResponse
createUserPoolClient req =
    let
        encoder val =
            [ ( "WriteAttributes", val.writeAttributes )
                |> EncodeOpt.optionalField (Codec.encoder clientPermissionListTypeCodec)
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "SupportedIdentityProviders", val.supportedIdentityProviders )
                |> EncodeOpt.optionalField (Codec.encoder supportedIdentityProvidersListTypeCodec)
            , ( "RefreshTokenValidity", val.refreshTokenValidity )
                |> EncodeOpt.optionalField (Codec.encoder refreshTokenValidityTypeCodec)
            , ( "ReadAttributes", val.readAttributes )
                |> EncodeOpt.optionalField (Codec.encoder clientPermissionListTypeCodec)
            , ( "LogoutURLs", val.logoutUrls ) |> EncodeOpt.optionalField (Codec.encoder logoutUrlsListTypeCodec)
            , ( "GenerateSecret", val.generateSecret ) |> EncodeOpt.optionalField generateSecretEncoder
            , ( "ExplicitAuthFlows", val.explicitAuthFlows )
                |> EncodeOpt.optionalField (Codec.encoder explicitAuthFlowsListTypeCodec)
            , ( "DefaultRedirectURI", val.defaultRedirectUri )
                |> EncodeOpt.optionalField (Codec.encoder redirectUrlTypeCodec)
            , ( "ClientName", val.clientName ) |> EncodeOpt.field (Codec.encoder clientNameTypeCodec)
            , ( "CallbackURLs", val.callbackUrls ) |> EncodeOpt.optionalField (Codec.encoder callbackUrlsListTypeCodec)
            , ( "AnalyticsConfiguration", val.analyticsConfiguration )
                |> EncodeOpt.optionalField (Codec.encoder analyticsConfigurationTypeCodec)
            , ( "AllowedOAuthScopes", val.allowedOauthScopes )
                |> EncodeOpt.optionalField (Codec.encoder scopeListTypeCodec)
            , ( "AllowedOAuthFlowsUserPoolClient", val.allowedOauthFlowsUserPoolClient )
                |> EncodeOpt.optionalField (Codec.encoder booleanTypeCodec)
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
    AWS.Http.request "CreateUserPoolClient" AWS.Http.POST url jsonBody decoder


{-| Creates a new Amazon Cognito user pool and sets the password policy for the pool.
-}
createUserPool : CreateUserPoolRequest -> AWS.Http.Request CreateUserPoolResponse
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
            , ( "SmsVerificationMessage", val.smsVerificationMessage )
                |> EncodeOpt.optionalField (Codec.encoder smsVerificationMessageTypeCodec)
            , ( "SmsConfiguration", val.smsConfiguration )
                |> EncodeOpt.optionalField (Codec.encoder smsConfigurationTypeCodec)
            , ( "SmsAuthenticationMessage", val.smsAuthenticationMessage )
                |> EncodeOpt.optionalField (Codec.encoder smsVerificationMessageTypeCodec)
            , ( "Schema", val.schema ) |> EncodeOpt.optionalField (Codec.encoder schemaAttributesListTypeCodec)
            , ( "PoolName", val.poolName ) |> EncodeOpt.field (Codec.encoder userPoolNameTypeCodec)
            , ( "Policies", val.policies ) |> EncodeOpt.optionalField (Codec.encoder userPoolPolicyTypeCodec)
            , ( "MfaConfiguration", val.mfaConfiguration )
                |> EncodeOpt.optionalField (Codec.encoder userPoolMfaTypeCodec)
            , ( "LambdaConfig", val.lambdaConfig ) |> EncodeOpt.optionalField (Codec.encoder lambdaConfigTypeCodec)
            , ( "EmailVerificationSubject", val.emailVerificationSubject )
                |> EncodeOpt.optionalField (Codec.encoder emailVerificationSubjectTypeCodec)
            , ( "EmailVerificationMessage", val.emailVerificationMessage )
                |> EncodeOpt.optionalField (Codec.encoder emailVerificationMessageTypeCodec)
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
    AWS.Http.request "CreateUserPool" AWS.Http.POST url jsonBody decoder


{-| Creates the user import job.
-}
createUserImportJob : CreateUserImportJobRequest -> AWS.Http.Request CreateUserImportJobResponse
createUserImportJob req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "JobName", val.jobName ) |> EncodeOpt.field (Codec.encoder userImportJobNameTypeCodec)
            , ( "CloudWatchLogsRoleArn", val.cloudWatchLogsRoleArn ) |> EncodeOpt.field (Codec.encoder arnTypeCodec)
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
    AWS.Http.request "CreateUserImportJob" AWS.Http.POST url jsonBody decoder


{-| Creates a new OAuth2.0 resource server and defines custom scopes in it.
-}
createResourceServer : CreateResourceServerRequest -> AWS.Http.Request CreateResourceServerResponse
createResourceServer req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "Scopes", val.scopes ) |> EncodeOpt.optionalField (Codec.encoder resourceServerScopeListTypeCodec)
            , ( "Name", val.name ) |> EncodeOpt.field (Codec.encoder resourceServerNameTypeCodec)
            , ( "Identifier", val.identifier ) |> EncodeOpt.field (Codec.encoder resourceServerIdentifierTypeCodec)
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
    AWS.Http.request "CreateResourceServer" AWS.Http.POST url jsonBody decoder


{-| Creates an identity provider for a user pool.
-}
createIdentityProvider : CreateIdentityProviderRequest -> AWS.Http.Request CreateIdentityProviderResponse
createIdentityProvider req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "ProviderType", val.providerType ) |> EncodeOpt.field (Codec.encoder identityProviderTypeTypeCodec)
            , ( "ProviderName", val.providerName ) |> EncodeOpt.field providerNameTypeV1Encoder
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
    AWS.Http.request "CreateIdentityProvider" AWS.Http.POST url jsonBody decoder


{-| Creates a new group in the specified user pool.

Requires developer credentials.

-}
createGroup : CreateGroupRequest -> AWS.Http.Request CreateGroupResponse
createGroup req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "RoleArn", val.roleArn ) |> EncodeOpt.optionalField (Codec.encoder arnTypeCodec)
            , ( "Precedence", val.precedence ) |> EncodeOpt.optionalField (Codec.encoder precedenceTypeCodec)
            , ( "GroupName", val.groupName ) |> EncodeOpt.field (Codec.encoder groupNameTypeCodec)
            , ( "Description", val.description ) |> EncodeOpt.optionalField (Codec.encoder descriptionTypeCodec)
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
    AWS.Http.request "CreateGroup" AWS.Http.POST url jsonBody decoder


{-| Confirms registration of a user and handles the existing alias from a previous user.
-}
confirmSignUp : ConfirmSignUpRequest -> AWS.Http.Request ()
confirmSignUp req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field (Codec.encoder usernameTypeCodec)
            , ( "UserContextData", val.userContextData ) |> EncodeOpt.optionalField userContextDataTypeEncoder
            , ( "SecretHash", val.secretHash ) |> EncodeOpt.optionalField secretHashTypeEncoder
            , ( "ForceAliasCreation", val.forceAliasCreation ) |> EncodeOpt.optionalField forceAliasCreationEncoder
            , ( "ConfirmationCode", val.confirmationCode ) |> EncodeOpt.field confirmationCodeTypeEncoder
            , ( "ClientId", val.clientId ) |> EncodeOpt.field (Codec.encoder clientIdTypeCodec)
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
    AWS.Http.request "ConfirmSignUp" AWS.Http.POST url jsonBody decoder


{-| Allows a user to enter a confirmation code to reset a forgotten password.
-}
confirmForgotPassword : ConfirmForgotPasswordRequest -> AWS.Http.Request ()
confirmForgotPassword req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field (Codec.encoder usernameTypeCodec)
            , ( "UserContextData", val.userContextData ) |> EncodeOpt.optionalField userContextDataTypeEncoder
            , ( "SecretHash", val.secretHash ) |> EncodeOpt.optionalField secretHashTypeEncoder
            , ( "Password", val.password ) |> EncodeOpt.field passwordTypeEncoder
            , ( "ConfirmationCode", val.confirmationCode ) |> EncodeOpt.field confirmationCodeTypeEncoder
            , ( "ClientId", val.clientId ) |> EncodeOpt.field (Codec.encoder clientIdTypeCodec)
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
    AWS.Http.request "ConfirmForgotPassword" AWS.Http.POST url jsonBody decoder


{-| Confirms tracking of the device. This API call is the call that begins device tracking.
-}
confirmDevice : ConfirmDeviceRequest -> AWS.Http.Request ConfirmDeviceResponse
confirmDevice req =
    let
        encoder val =
            [ ( "DeviceSecretVerifierConfig", val.deviceSecretVerifierConfig )
                |> EncodeOpt.optionalField deviceSecretVerifierConfigTypeEncoder
            , ( "DeviceName", val.deviceName ) |> EncodeOpt.optionalField deviceNameTypeEncoder
            , ( "DeviceKey", val.deviceKey ) |> EncodeOpt.field (Codec.encoder deviceKeyTypeCodec)
            , ( "AccessToken", val.accessToken ) |> EncodeOpt.field (Codec.encoder tokenModelTypeCodec)
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
                |> Pipeline.optional
                    "UserConfirmationNecessary"
                    (Json.Decode.maybe (Codec.decoder booleanTypeCodec))
                    Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "ConfirmDevice" AWS.Http.POST url jsonBody decoder


{-| Changes the password for a specified user in a user pool.
-}
changePassword : ChangePasswordRequest -> AWS.Http.Request ()
changePassword req =
    let
        encoder val =
            [ ( "ProposedPassword", val.proposedPassword ) |> EncodeOpt.field passwordTypeEncoder
            , ( "PreviousPassword", val.previousPassword ) |> EncodeOpt.field passwordTypeEncoder
            , ( "AccessToken", val.accessToken ) |> EncodeOpt.field (Codec.encoder tokenModelTypeCodec)
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "ChangePassword" AWS.Http.POST url jsonBody decoder


{-| Returns a unique generated shared secret key code for the user account. The request takes an access token or a session string, but not both.
-}
associateSoftwareToken : AssociateSoftwareTokenRequest -> AWS.Http.Request AssociateSoftwareTokenResponse
associateSoftwareToken req =
    let
        encoder val =
            [ ( "Session", val.session ) |> EncodeOpt.optionalField (Codec.encoder sessionTypeCodec)
            , ( "AccessToken", val.accessToken ) |> EncodeOpt.optionalField (Codec.encoder tokenModelTypeCodec)
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\sessionFld secretCodeFld -> { secretCode = secretCodeFld, session = sessionFld }) |> Json.Decode.succeed)
                |> Pipeline.optional "Session" (Json.Decode.maybe (Codec.decoder sessionTypeCodec)) Nothing
                |> Pipeline.optional "SecretCode" (Json.Decode.maybe secretCodeTypeDecoder) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "AssociateSoftwareToken" AWS.Http.POST url jsonBody decoder


{-| Signs out users from all devices, as an administrator.

Requires developer credentials.

-}
adminUserGlobalSignOut : AdminUserGlobalSignOutRequest -> AWS.Http.Request ()
adminUserGlobalSignOut req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field (Codec.encoder usernameTypeCodec)
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "AdminUserGlobalSignOut" AWS.Http.POST url jsonBody decoder


{-| Updates the specified user's attributes, including developer attributes, as an administrator. Works on any user.

For custom attributes, you must prepend the `custom:` prefix to the attribute name.

In addition to updating user attributes, this API can also be used to mark phone and email as verified.

Requires developer credentials.

-}
adminUpdateUserAttributes : AdminUpdateUserAttributesRequest -> AWS.Http.Request ()
adminUpdateUserAttributes req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field (Codec.encoder usernameTypeCodec)
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
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
    AWS.Http.request "AdminUpdateUserAttributes" AWS.Http.POST url jsonBody decoder


{-| Updates the device status as an administrator.

Requires developer credentials.

-}
adminUpdateDeviceStatus : AdminUpdateDeviceStatusRequest -> AWS.Http.Request ()
adminUpdateDeviceStatus req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field (Codec.encoder usernameTypeCodec)
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "DeviceRememberedStatus", val.deviceRememberedStatus )
                |> EncodeOpt.optionalField deviceRememberedStatusTypeEncoder
            , ( "DeviceKey", val.deviceKey ) |> EncodeOpt.field (Codec.encoder deviceKeyTypeCodec)
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "AdminUpdateDeviceStatus" AWS.Http.POST url jsonBody decoder


{-| Provides feedback for an authentication event as to whether it was from a valid user. This feedback is used for improving the risk evaluation decision for the user pool as part of Amazon Cognito advanced security.
-}
adminUpdateAuthEventFeedback : AdminUpdateAuthEventFeedbackRequest -> AWS.Http.Request ()
adminUpdateAuthEventFeedback req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field (Codec.encoder usernameTypeCodec)
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "FeedbackValue", val.feedbackValue ) |> EncodeOpt.field (Codec.encoder feedbackValueTypeCodec)
            , ( "EventId", val.eventId ) |> EncodeOpt.field eventIdTypeEncoder
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "AdminUpdateAuthEventFeedback" AWS.Http.POST url jsonBody decoder


{-| Sets all the user settings for a specified user name. Works on any user.

Requires developer credentials.

-}
adminSetUserSettings : AdminSetUserSettingsRequest -> AWS.Http.Request ()
adminSetUserSettings req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field (Codec.encoder usernameTypeCodec)
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
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
    AWS.Http.request "AdminSetUserSettings" AWS.Http.POST url jsonBody decoder


{-| -}
adminSetUserPassword : AdminSetUserPasswordRequest -> AWS.Http.Request ()
adminSetUserPassword req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field (Codec.encoder usernameTypeCodec)
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "Permanent", val.permanent ) |> EncodeOpt.optionalField (Codec.encoder booleanTypeCodec)
            , ( "Password", val.password ) |> EncodeOpt.field passwordTypeEncoder
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "AdminSetUserPassword" AWS.Http.POST url jsonBody decoder


{-| Sets the user's multi-factor authentication (MFA) preference.
-}
adminSetUserMfapreference : AdminSetUserMfapreferenceRequest -> AWS.Http.Request ()
adminSetUserMfapreference req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field (Codec.encoder usernameTypeCodec)
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
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
    AWS.Http.request "AdminSetUserMfapreference" AWS.Http.POST url jsonBody decoder


{-| Responds to an authentication challenge, as an administrator.

Requires developer credentials.

-}
adminRespondToAuthChallenge : AdminRespondToAuthChallengeRequest -> AWS.Http.Request AdminRespondToAuthChallengeResponse
adminRespondToAuthChallenge req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "Session", val.session ) |> EncodeOpt.optionalField (Codec.encoder sessionTypeCodec)
            , ( "ContextData", val.contextData ) |> EncodeOpt.optionalField contextDataTypeEncoder
            , ( "ClientId", val.clientId ) |> EncodeOpt.field (Codec.encoder clientIdTypeCodec)
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
                |> Pipeline.optional "Session" (Json.Decode.maybe (Codec.decoder sessionTypeCodec)) Nothing
                |> Pipeline.optional "ChallengeParameters" (Json.Decode.maybe challengeParametersTypeDecoder) Nothing
                |> Pipeline.optional "ChallengeName" (Json.Decode.maybe (Codec.decoder challengeNameTypeCodec)) Nothing
                |> Pipeline.optional "AuthenticationResult" (Json.Decode.maybe authenticationResultTypeDecoder) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "AdminRespondToAuthChallenge" AWS.Http.POST url jsonBody decoder


{-| Resets the specified user's password in a user pool as an administrator. Works on any user.

When a developer calls this API, the current password is invalidated, so it must be changed. If a user tries to sign in after the API is called, the app will get a PasswordResetRequiredException exception back and should direct the user down the flow to reset the password, which is the same as the forgot password flow. In addition, if the user pool has phone verification selected and a verified phone number exists for the user, or if email verification is selected and a verified email exists for the user, calling this API will also result in sending a message to the end user with the code to change their password.

Requires developer credentials.

-}
adminResetUserPassword : AdminResetUserPasswordRequest -> AWS.Http.Request ()
adminResetUserPassword req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field (Codec.encoder usernameTypeCodec)
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "AdminResetUserPassword" AWS.Http.POST url jsonBody decoder


{-| Removes the specified user from the specified group.

Requires developer credentials.

-}
adminRemoveUserFromGroup : AdminRemoveUserFromGroupRequest -> AWS.Http.Request ()
adminRemoveUserFromGroup req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field (Codec.encoder usernameTypeCodec)
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "GroupName", val.groupName ) |> EncodeOpt.field (Codec.encoder groupNameTypeCodec)
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "AdminRemoveUserFromGroup" AWS.Http.POST url jsonBody decoder


{-| Lists a history of user activity and any risks detected as part of Amazon Cognito advanced security.
-}
adminListUserAuthEvents : AdminListUserAuthEventsRequest -> AWS.Http.Request AdminListUserAuthEventsResponse
adminListUserAuthEvents req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field (Codec.encoder usernameTypeCodec)
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "NextToken", val.nextToken ) |> EncodeOpt.optionalField (Codec.encoder paginationKeyCodec)
            , ( "MaxResults", val.maxResults ) |> EncodeOpt.optionalField queryLimitTypeEncoder
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
                |> Pipeline.optional "NextToken" (Json.Decode.maybe (Codec.decoder paginationKeyCodec)) Nothing
                |> Pipeline.optional "AuthEvents" (Json.Decode.maybe authEventsTypeDecoder) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "AdminListUserAuthEvents" AWS.Http.POST url jsonBody decoder


{-| Lists the groups that the user belongs to.

Requires developer credentials.

-}
adminListGroupsForUser : AdminListGroupsForUserRequest -> AWS.Http.Request AdminListGroupsForUserResponse
adminListGroupsForUser req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field (Codec.encoder usernameTypeCodec)
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "NextToken", val.nextToken ) |> EncodeOpt.optionalField (Codec.encoder paginationKeyCodec)
            , ( "Limit", val.limit ) |> EncodeOpt.optionalField queryLimitTypeEncoder
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            ((\nextTokenFld groupsFld -> { groups = groupsFld, nextToken = nextTokenFld }) |> Json.Decode.succeed)
                |> Pipeline.optional "NextToken" (Json.Decode.maybe (Codec.decoder paginationKeyCodec)) Nothing
                |> Pipeline.optional "Groups" (Json.Decode.maybe groupListTypeDecoder) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "AdminListGroupsForUser" AWS.Http.POST url jsonBody decoder


{-| Lists devices, as an administrator.

Requires developer credentials.

-}
adminListDevices : AdminListDevicesRequest -> AWS.Http.Request AdminListDevicesResponse
adminListDevices req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field (Codec.encoder usernameTypeCodec)
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "PaginationToken", val.paginationToken )
                |> EncodeOpt.optionalField (Codec.encoder searchPaginationTokenTypeCodec)
            , ( "Limit", val.limit ) |> EncodeOpt.optionalField queryLimitTypeEncoder
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
                |> Pipeline.optional
                    "PaginationToken"
                    (Json.Decode.maybe (Codec.decoder searchPaginationTokenTypeCodec))
                    Nothing
                |> Pipeline.optional "Devices" (Json.Decode.maybe deviceListTypeDecoder) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "AdminListDevices" AWS.Http.POST url jsonBody decoder


{-| Links an existing user account in a user pool (`DestinationUser`) to an identity from an external identity provider (`SourceUser`) based on a specified attribute name and value from the external identity provider. This allows you to create a link from the existing user account to an external federated user identity that has not yet been used to sign in, so that the federated user identity can be used to sign in as the existing user account.

For example, if there is an existing user with a username and password, this API links that user to a federated user identity, so that when the federated user identity is used, the user signs in as the existing user account.

Because this API allows a user with an external federated identity to sign in as an existing user in the user pool, it is critical that it only be used with external identity providers and provider attributes that have been trusted by the application owner.

See also .

This action is enabled only for admin access and requires developer credentials.

-}
adminLinkProviderForUser : AdminLinkProviderForUserRequest -> AWS.Http.Request ()
adminLinkProviderForUser req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder stringTypeCodec)
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
    AWS.Http.request "AdminLinkProviderForUser" AWS.Http.POST url jsonBody decoder


{-| Initiates the authentication flow, as an administrator.

Requires developer credentials.

-}
adminInitiateAuth : AdminInitiateAuthRequest -> AWS.Http.Request AdminInitiateAuthResponse
adminInitiateAuth req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "ContextData", val.contextData ) |> EncodeOpt.optionalField contextDataTypeEncoder
            , ( "ClientMetadata", val.clientMetadata ) |> EncodeOpt.optionalField clientMetadataTypeEncoder
            , ( "ClientId", val.clientId ) |> EncodeOpt.field (Codec.encoder clientIdTypeCodec)
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
                |> Pipeline.optional "Session" (Json.Decode.maybe (Codec.decoder sessionTypeCodec)) Nothing
                |> Pipeline.optional "ChallengeParameters" (Json.Decode.maybe challengeParametersTypeDecoder) Nothing
                |> Pipeline.optional "ChallengeName" (Json.Decode.maybe (Codec.decoder challengeNameTypeCodec)) Nothing
                |> Pipeline.optional "AuthenticationResult" (Json.Decode.maybe authenticationResultTypeDecoder) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "AdminInitiateAuth" AWS.Http.POST url jsonBody decoder


{-| Gets the specified user by user name in a user pool as an administrator. Works on any user.

Requires developer credentials.

-}
adminGetUser : AdminGetUserRequest -> AWS.Http.Request AdminGetUserResponse
adminGetUser req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field (Codec.encoder usernameTypeCodec)
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
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
                |> Pipeline.required "Username" (Codec.decoder usernameTypeCodec)
                |> Pipeline.optional "UserStatus" (Json.Decode.maybe userStatusTypeDecoder) Nothing
                |> Pipeline.optional "UserMFASettingList" (Json.Decode.maybe userMfasettingListTypeDecoder) Nothing
                |> Pipeline.optional "UserLastModifiedDate" (Json.Decode.maybe dateTypeDecoder) Nothing
                |> Pipeline.optional "UserCreateDate" (Json.Decode.maybe dateTypeDecoder) Nothing
                |> Pipeline.optional "UserAttributes" (Json.Decode.maybe (Codec.decoder attributeListTypeCodec)) Nothing
                |> Pipeline.optional "PreferredMfaSetting" (Json.Decode.maybe (Codec.decoder stringTypeCodec)) Nothing
                |> Pipeline.optional "MFAOptions" (Json.Decode.maybe (Codec.decoder mfaoptionListTypeCodec)) Nothing
                |> Pipeline.optional "Enabled" (Json.Decode.maybe (Codec.decoder booleanTypeCodec)) Nothing
                |> AWS.Http.jsonBodyDecoder
    in
    AWS.Http.request "AdminGetUser" AWS.Http.POST url jsonBody decoder


{-| Gets the device, as an administrator.

Requires developer credentials.

-}
adminGetDevice : AdminGetDeviceRequest -> AWS.Http.Request AdminGetDeviceResponse
adminGetDevice req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field (Codec.encoder usernameTypeCodec)
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "DeviceKey", val.deviceKey ) |> EncodeOpt.field (Codec.encoder deviceKeyTypeCodec)
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
    AWS.Http.request "AdminGetDevice" AWS.Http.POST url jsonBody decoder


{-| Forgets the device, as an administrator.

Requires developer credentials.

-}
adminForgetDevice : AdminForgetDeviceRequest -> AWS.Http.Request ()
adminForgetDevice req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field (Codec.encoder usernameTypeCodec)
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "DeviceKey", val.deviceKey ) |> EncodeOpt.field (Codec.encoder deviceKeyTypeCodec)
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "AdminForgetDevice" AWS.Http.POST url jsonBody decoder


{-| Enables the specified user as an administrator. Works on any user.

Requires developer credentials.

-}
adminEnableUser : AdminEnableUserRequest -> AWS.Http.Request ()
adminEnableUser req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field (Codec.encoder usernameTypeCodec)
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "AdminEnableUser" AWS.Http.POST url jsonBody decoder


{-| Disables the specified user as an administrator. Works on any user.

Requires developer credentials.

-}
adminDisableUser : AdminDisableUserRequest -> AWS.Http.Request ()
adminDisableUser req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field (Codec.encoder usernameTypeCodec)
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "AdminDisableUser" AWS.Http.POST url jsonBody decoder


{-| Disables the user from signing in with the specified external (SAML or social) identity provider. If the user to disable is a Cognito User Pools native username + password user, they are not permitted to use their password to sign-in. If the user to disable is a linked external IdP user, any link between that user and an existing user is removed. The next time the external user (no longer attached to the previously linked `DestinationUser`) signs in, they must create a new user account. See .

This action is enabled only for admin access and requires developer credentials.

The `ProviderName` must match the value specified when creating an IdP for the pool.

To disable a native username + password user, the `ProviderName` value must be `Cognito` and the `ProviderAttributeName` must be `Cognito_Subject`, with the `ProviderAttributeValue` being the name that is used in the user pool for the user.

The `ProviderAttributeName` must always be `Cognito_Subject` for social identity providers. The `ProviderAttributeValue` must always be the exact subject that was used when the user was originally linked as a source user.

For de-linking a SAML identity, there are two scenarios. If the linked identity has not yet been used to sign-in, the `ProviderAttributeName` and `ProviderAttributeValue` must be the same values that were used for the `SourceUser` when the identities were originally linked in the call. (If the linking was done with `ProviderAttributeName` set to `Cognito_Subject`, the same applies here). However, if the user has already signed in, the `ProviderAttributeName` must be `Cognito_Subject` and `ProviderAttributeValue` must be the subject of the SAML assertion.

-}
adminDisableProviderForUser : AdminDisableProviderForUserRequest -> AWS.Http.Request ()
adminDisableProviderForUser req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder stringTypeCodec)
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
    AWS.Http.request "AdminDisableProviderForUser" AWS.Http.POST url jsonBody decoder


{-| Deletes the user attributes in a user pool as an administrator. Works on any user.

Requires developer credentials.

-}
adminDeleteUserAttributes : AdminDeleteUserAttributesRequest -> AWS.Http.Request ()
adminDeleteUserAttributes req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field (Codec.encoder usernameTypeCodec)
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
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
    AWS.Http.request "AdminDeleteUserAttributes" AWS.Http.POST url jsonBody decoder


{-| Deletes a user as an administrator. Works on any user.

Requires developer credentials.

-}
adminDeleteUser : AdminDeleteUserRequest -> AWS.Http.Request ()
adminDeleteUser req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field (Codec.encoder usernameTypeCodec)
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "AdminDeleteUser" AWS.Http.POST url jsonBody decoder


{-| Creates a new user in the specified user pool.

If `MessageAction` is not set, the default is to send a welcome message via email or phone (SMS).

This message is based on a template that you configured in your call to or . This template includes your custom sign-up instructions and placeholders for user name and temporary password.

Alternatively, you can call AdminCreateUser with “SUPPRESS” for the `MessageAction` parameter, and Amazon Cognito will not send any email.

In either case, the user will be in the `FORCE_CHANGE_PASSWORD` state until they sign in and change their password.

AdminCreateUser requires developer credentials.

-}
adminCreateUser : AdminCreateUserRequest -> AWS.Http.Request AdminCreateUserResponse
adminCreateUser req =
    let
        encoder val =
            [ ( "ValidationData", val.validationData ) |> EncodeOpt.optionalField (Codec.encoder attributeListTypeCodec)
            , ( "Username", val.username ) |> EncodeOpt.field (Codec.encoder usernameTypeCodec)
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "UserAttributes", val.userAttributes ) |> EncodeOpt.optionalField (Codec.encoder attributeListTypeCodec)
            , ( "TemporaryPassword", val.temporaryPassword ) |> EncodeOpt.optionalField passwordTypeEncoder
            , ( "MessageAction", val.messageAction ) |> EncodeOpt.optionalField messageActionTypeEncoder
            , ( "ForceAliasCreation", val.forceAliasCreation ) |> EncodeOpt.optionalField forceAliasCreationEncoder
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
    AWS.Http.request "AdminCreateUser" AWS.Http.POST url jsonBody decoder


{-| Confirms user registration as an admin without using a confirmation code. Works on any user.

Requires developer credentials.

-}
adminConfirmSignUp : AdminConfirmSignUpRequest -> AWS.Http.Request ()
adminConfirmSignUp req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field (Codec.encoder usernameTypeCodec)
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "AdminConfirmSignUp" AWS.Http.POST url jsonBody decoder


{-| Adds the specified user to the specified group.

Requires developer credentials.

-}
adminAddUserToGroup : AdminAddUserToGroupRequest -> AWS.Http.Request ()
adminAddUserToGroup req =
    let
        encoder val =
            [ ( "Username", val.username ) |> EncodeOpt.field (Codec.encoder usernameTypeCodec)
            , ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
            , ( "GroupName", val.groupName ) |> EncodeOpt.field (Codec.encoder groupNameTypeCodec)
            ]
                |> EncodeOpt.objectMaySkip

        jsonBody =
            req |> encoder |> AWS.Http.jsonBody

        url =
            "/"

        decoder =
            AWS.Http.constantDecoder ()
    in
    AWS.Http.request "AdminAddUserToGroup" AWS.Http.POST url jsonBody decoder


{-| Adds additional user attributes to the user pool schema.
-}
addCustomAttributes : AddCustomAttributesRequest -> AWS.Http.Request ()
addCustomAttributes req =
    let
        encoder val =
            [ ( "UserPoolId", val.userPoolId ) |> EncodeOpt.field (Codec.encoder userPoolIdTypeCodec)
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
    AWS.Http.request "AddCustomAttributes" AWS.Http.POST url jsonBody decoder


{-| The VerifyUserAttributeResponse data model.
-}
type alias VerifyUserAttributeResponse =
    {}


{-| The VerifyUserAttributeRequest data model.
-}
type alias VerifyUserAttributeRequest =
    { accessToken : TokenModelType, attributeName : AttributeNameType, code : ConfirmationCodeType }


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
    { session : Maybe SessionType, status : Maybe VerifySoftwareTokenResponseType }


{-| The VerifySoftwareTokenRequest data model.
-}
type alias VerifySoftwareTokenRequest =
    { accessToken : Maybe TokenModelType
    , friendlyDeviceName : Maybe StringType
    , session : Maybe SessionType
    , userCode : SoftwareTokenMfauserCodeType
    }


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
    , emailMessage : Maybe EmailVerificationMessageType
    , emailMessageByLink : Maybe EmailVerificationMessageByLinkType
    , emailSubject : Maybe EmailVerificationSubjectType
    , emailSubjectByLink : Maybe EmailVerificationSubjectByLinkType
    , smsMessage : Maybe SmsVerificationMessageType
    }


{-| The UsersListType data model.
-}
type alias UsersListType =
    List UserType


{-| The UsernameType data model.
-}
type UsernameType
    = UsernameType String


{-| The UsernameType data model.
-}
usernameType : Refined String UsernameType StringError
usernameType =
    let
        guardFn val =
            Refined.minLength 1 val
                |> Result.andThen (Refined.maxLength 128)
                |> Result.andThen (Refined.regexMatch "[\\p{L}\\p{M}\\p{S}\\p{N}\\p{P}]+")
                |> Result.map UsernameType

        unboxFn (UsernameType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


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
    , enabled : Maybe BooleanType
    , mfaoptions : Maybe MfaoptionListType
    , userCreateDate : Maybe DateType
    , userLastModifiedDate : Maybe DateType
    , userStatus : Maybe UserStatusType
    , username : Maybe UsernameType
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
    , arn : Maybe ArnType
    , autoVerifiedAttributes : Maybe VerifiedAttributesListType
    , creationDate : Maybe DateType
    , customDomain : Maybe DomainType
    , deviceConfiguration : Maybe DeviceConfigurationType
    , domain : Maybe DomainType
    , emailConfiguration : Maybe EmailConfigurationType
    , emailConfigurationFailure : Maybe StringType
    , emailVerificationMessage : Maybe EmailVerificationMessageType
    , emailVerificationSubject : Maybe EmailVerificationSubjectType
    , estimatedNumberOfUsers : Maybe IntegerType
    , id : Maybe UserPoolIdType
    , lambdaConfig : Maybe LambdaConfigType
    , lastModifiedDate : Maybe DateType
    , mfaConfiguration : Maybe UserPoolMfaType
    , name : Maybe UserPoolNameType
    , policies : Maybe UserPoolPolicyType
    , schemaAttributes : Maybe SchemaAttributesListType
    , smsAuthenticationMessage : Maybe SmsVerificationMessageType
    , smsConfiguration : Maybe SmsConfigurationType
    , smsConfigurationFailure : Maybe StringType
    , smsVerificationMessage : Maybe SmsVerificationMessageType
    , status : Maybe StatusType
    , userPoolAddOns : Maybe UserPoolAddOnsType
    , userPoolTags : Maybe UserPoolTagsType
    , usernameAttributes : Maybe UsernameAttributesListType
    , verificationMessageTemplate : Maybe VerificationMessageTemplateType
    }


{-| The UserPoolTagsType data model.
-}
type alias UserPoolTagsType =
    Dict.Refined.Dict String TagKeysType TagValueType


{-| The UserPoolTagsListType data model.
-}
type alias UserPoolTagsListType =
    List TagKeysType


{-| The UserPoolPolicyType data model.
-}
type alias UserPoolPolicyType =
    { passwordPolicy : Maybe PasswordPolicyType }


{-| The UserPoolNameType data model.
-}
type UserPoolNameType
    = UserPoolNameType String


{-| The UserPoolNameType data model.
-}
userPoolNameType : Refined String UserPoolNameType StringError
userPoolNameType =
    let
        guardFn val =
            Refined.minLength 1 val
                |> Result.andThen (Refined.maxLength 128)
                |> Result.andThen (Refined.regexMatch "[\\w\\s+=,.@-]+")
                |> Result.map UserPoolNameType

        unboxFn (UserPoolNameType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


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


{-| The UserPoolIdType data model.
-}
type UserPoolIdType
    = UserPoolIdType String


{-| The UserPoolIdType data model.
-}
userPoolIdType : Refined String UserPoolIdType StringError
userPoolIdType =
    let
        guardFn val =
            Refined.minLength 1 val
                |> Result.andThen (Refined.maxLength 55)
                |> Result.andThen (Refined.regexMatch "[\\w-]+_[0-9a-zA-Z]+")
                |> Result.map UserPoolIdType

        unboxFn (UserPoolIdType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The UserPoolDescriptionType data model.
-}
type alias UserPoolDescriptionType =
    { creationDate : Maybe DateType
    , id : Maybe UserPoolIdType
    , lambdaConfig : Maybe LambdaConfigType
    , lastModifiedDate : Maybe DateType
    , name : Maybe UserPoolNameType
    , status : Maybe StatusType
    }


{-| The UserPoolClientType data model.
-}
type alias UserPoolClientType =
    { allowedOauthFlows : Maybe OauthFlowsType
    , allowedOauthFlowsUserPoolClient : Maybe BooleanType
    , allowedOauthScopes : Maybe ScopeListType
    , analyticsConfiguration : Maybe AnalyticsConfigurationType
    , callbackUrls : Maybe CallbackUrlsListType
    , clientId : Maybe ClientIdType
    , clientName : Maybe ClientNameType
    , clientSecret : Maybe ClientSecretType
    , creationDate : Maybe DateType
    , defaultRedirectUri : Maybe RedirectUrlType
    , explicitAuthFlows : Maybe ExplicitAuthFlowsListType
    , lastModifiedDate : Maybe DateType
    , logoutUrls : Maybe LogoutUrlsListType
    , readAttributes : Maybe ClientPermissionListType
    , refreshTokenValidity : Maybe RefreshTokenValidityType
    , supportedIdentityProviders : Maybe SupportedIdentityProvidersListType
    , userPoolId : Maybe UserPoolIdType
    , writeAttributes : Maybe ClientPermissionListType
    }


{-| The UserPoolClientListType data model.
-}
type alias UserPoolClientListType =
    List UserPoolClientDescription


{-| The UserPoolClientDescription data model.
-}
type alias UserPoolClientDescription =
    { clientId : Maybe ClientIdType, clientName : Maybe ClientNameType, userPoolId : Maybe UserPoolIdType }


{-| The UserPoolAddOnsType data model.
-}
type alias UserPoolAddOnsType =
    { advancedSecurityMode : AdvancedSecurityModeType }


{-| The UserMfasettingListType data model.
-}
type alias UserMfasettingListType =
    List StringType


{-| The UserImportJobsListType data model.
-}
type alias UserImportJobsListType =
    List UserImportJobType


{-| The UserImportJobType data model.
-}
type alias UserImportJobType =
    { cloudWatchLogsRoleArn : Maybe ArnType
    , completionDate : Maybe DateType
    , completionMessage : Maybe CompletionMessageType
    , creationDate : Maybe DateType
    , failedUsers : Maybe LongType
    , importedUsers : Maybe LongType
    , jobId : Maybe UserImportJobIdType
    , jobName : Maybe UserImportJobNameType
    , preSignedUrl : Maybe PreSignedUrlType
    , skippedUsers : Maybe LongType
    , startDate : Maybe DateType
    , status : Maybe UserImportJobStatusType
    , userPoolId : Maybe UserPoolIdType
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


{-| The UserImportJobNameType data model.
-}
type UserImportJobNameType
    = UserImportJobNameType String


{-| The UserImportJobNameType data model.
-}
userImportJobNameType : Refined String UserImportJobNameType StringError
userImportJobNameType =
    let
        guardFn val =
            Refined.minLength 1 val
                |> Result.andThen (Refined.maxLength 128)
                |> Result.andThen (Refined.regexMatch "[\\w\\s+=,.@-]+")
                |> Result.map UserImportJobNameType

        unboxFn (UserImportJobNameType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The UserImportJobIdType data model.
-}
type UserImportJobIdType
    = UserImportJobIdType String


{-| The UserImportJobIdType data model.
-}
userImportJobIdType : Refined String UserImportJobIdType StringError
userImportJobIdType =
    let
        guardFn val =
            Refined.minLength 1 val
                |> Result.andThen (Refined.maxLength 55)
                |> Result.andThen (Refined.regexMatch "import-[0-9a-zA-Z-]+")
                |> Result.map UserImportJobIdType

        unboxFn (UserImportJobIdType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The UserFilterType data model.
-}
type UserFilterType
    = UserFilterType String


{-| The UserFilterType data model.
-}
userFilterType : Refined String UserFilterType StringError
userFilterType =
    let
        guardFn val =
            Refined.maxLength 256 val |> Result.map UserFilterType

        unboxFn (UserFilterType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The UserContextDataType data model.
-}
type alias UserContextDataType =
    { encodedData : Maybe StringType }


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
    , emailVerificationMessage : Maybe EmailVerificationMessageType
    , emailVerificationSubject : Maybe EmailVerificationSubjectType
    , lambdaConfig : Maybe LambdaConfigType
    , mfaConfiguration : Maybe UserPoolMfaType
    , policies : Maybe UserPoolPolicyType
    , smsAuthenticationMessage : Maybe SmsVerificationMessageType
    , smsConfiguration : Maybe SmsConfigurationType
    , smsVerificationMessage : Maybe SmsVerificationMessageType
    , userPoolAddOns : Maybe UserPoolAddOnsType
    , userPoolId : UserPoolIdType
    , userPoolTags : Maybe UserPoolTagsType
    , verificationMessageTemplate : Maybe VerificationMessageTemplateType
    }


{-| The UpdateUserPoolDomainResponse data model.
-}
type alias UpdateUserPoolDomainResponse =
    { cloudFrontDomain : Maybe DomainType }


{-| The UpdateUserPoolDomainRequest data model.
-}
type alias UpdateUserPoolDomainRequest =
    { customDomainConfig : CustomDomainConfigType, domain : DomainType, userPoolId : UserPoolIdType }


{-| The UpdateUserPoolClientResponse data model.
-}
type alias UpdateUserPoolClientResponse =
    { userPoolClient : Maybe UserPoolClientType }


{-| The UpdateUserPoolClientRequest data model.
-}
type alias UpdateUserPoolClientRequest =
    { allowedOauthFlows : Maybe OauthFlowsType
    , allowedOauthFlowsUserPoolClient : Maybe BooleanType
    , allowedOauthScopes : Maybe ScopeListType
    , analyticsConfiguration : Maybe AnalyticsConfigurationType
    , callbackUrls : Maybe CallbackUrlsListType
    , clientId : ClientIdType
    , clientName : Maybe ClientNameType
    , defaultRedirectUri : Maybe RedirectUrlType
    , explicitAuthFlows : Maybe ExplicitAuthFlowsListType
    , logoutUrls : Maybe LogoutUrlsListType
    , readAttributes : Maybe ClientPermissionListType
    , refreshTokenValidity : Maybe RefreshTokenValidityType
    , supportedIdentityProviders : Maybe SupportedIdentityProvidersListType
    , userPoolId : UserPoolIdType
    , writeAttributes : Maybe ClientPermissionListType
    }


{-| The UpdateUserAttributesResponse data model.
-}
type alias UpdateUserAttributesResponse =
    { codeDeliveryDetailsList : Maybe CodeDeliveryDetailsListType }


{-| The UpdateUserAttributesRequest data model.
-}
type alias UpdateUserAttributesRequest =
    { accessToken : TokenModelType, userAttributes : AttributeListType }


{-| The UpdateResourceServerResponse data model.
-}
type alias UpdateResourceServerResponse =
    { resourceServer : ResourceServerType }


{-| The UpdateResourceServerRequest data model.
-}
type alias UpdateResourceServerRequest =
    { identifier : ResourceServerIdentifierType
    , name : ResourceServerNameType
    , scopes : Maybe ResourceServerScopeListType
    , userPoolId : UserPoolIdType
    }


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
    , providerName : ProviderNameType
    , userPoolId : UserPoolIdType
    }


{-| The UpdateGroupResponse data model.
-}
type alias UpdateGroupResponse =
    { group : Maybe GroupType }


{-| The UpdateGroupRequest data model.
-}
type alias UpdateGroupRequest =
    { description : Maybe DescriptionType
    , groupName : GroupNameType
    , precedence : Maybe PrecedenceType
    , roleArn : Maybe ArnType
    , userPoolId : UserPoolIdType
    }


{-| The UpdateDeviceStatusResponse data model.
-}
type alias UpdateDeviceStatusResponse =
    {}


{-| The UpdateDeviceStatusRequest data model.
-}
type alias UpdateDeviceStatusRequest =
    { accessToken : TokenModelType
    , deviceKey : DeviceKeyType
    , deviceRememberedStatus : Maybe DeviceRememberedStatusType
    }


{-| The UpdateAuthEventFeedbackResponse data model.
-}
type alias UpdateAuthEventFeedbackResponse =
    {}


{-| The UpdateAuthEventFeedbackRequest data model.
-}
type alias UpdateAuthEventFeedbackRequest =
    { eventId : EventIdType
    , feedbackToken : TokenModelType
    , feedbackValue : FeedbackValueType
    , userPoolId : UserPoolIdType
    , username : UsernameType
    }


{-| The UntagResourceResponse data model.
-}
type alias UntagResourceResponse =
    {}


{-| The UntagResourceRequest data model.
-}
type alias UntagResourceRequest =
    { resourceArn : ArnType, tagKeys : Maybe UserPoolTagsListType }


{-| The UicustomizationType data model.
-}
type alias UicustomizationType =
    { css : Maybe Csstype
    , cssversion : Maybe CssversionType
    , clientId : Maybe ClientIdType
    , creationDate : Maybe DateType
    , imageUrl : Maybe ImageUrlType
    , lastModifiedDate : Maybe DateType
    , userPoolId : Maybe UserPoolIdType
    }


{-| The TokenModelType data model.
-}
type TokenModelType
    = TokenModelType String


{-| The TokenModelType data model.
-}
tokenModelType : Refined String TokenModelType StringError
tokenModelType =
    let
        guardFn val =
            Refined.regexMatch "[A-Za-z0-9-_=.]+" val |> Result.map TokenModelType

        unboxFn (TokenModelType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The TemporaryPasswordValidityDaysType data model.
-}
type TemporaryPasswordValidityDaysType
    = TemporaryPasswordValidityDaysType Int


{-| The TemporaryPasswordValidityDaysType data model.
-}
temporaryPasswordValidityDaysType : Refined Int TemporaryPasswordValidityDaysType IntError
temporaryPasswordValidityDaysType =
    let
        guardFn val =
            Refined.gte 0 val |> Result.andThen (Refined.lte 365) |> Result.map TemporaryPasswordValidityDaysType

        unboxFn (TemporaryPasswordValidityDaysType val) =
            val
    in
    Refined.define guardFn Json.Decode.int Json.Encode.int Refined.intErrorToString unboxFn


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


{-| The TagResourceRequest data model.
-}
type alias TagResourceRequest =
    { resourceArn : ArnType, tags : Maybe UserPoolTagsType }


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


{-| The SupportedIdentityProvidersListType data model.
-}
type alias SupportedIdentityProvidersListType =
    List ProviderNameType


{-| The StringType data model.
-}
type alias StringType =
    String


{-| The StringAttributeConstraintsType data model.
-}
type alias StringAttributeConstraintsType =
    { maxLength : Maybe StringType, minLength : Maybe StringType }


{-| The StopUserImportJobResponse data model.
-}
type alias StopUserImportJobResponse =
    { userImportJob : Maybe UserImportJobType }


{-| The StopUserImportJobRequest data model.
-}
type alias StopUserImportJobRequest =
    { jobId : UserImportJobIdType, userPoolId : UserPoolIdType }


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
    { jobId : UserImportJobIdType, userPoolId : UserPoolIdType }


{-| The SoftwareTokenMfaSettingsType data model.
-}
type alias SoftwareTokenMfaSettingsType =
    { enabled : Maybe BooleanType, preferredMfa : Maybe BooleanType }


{-| The SoftwareTokenMfaConfigType data model.
-}
type alias SoftwareTokenMfaConfigType =
    { enabled : Maybe BooleanType }


{-| The SoftwareTokenMfauserCodeType data model.
-}
type SoftwareTokenMfauserCodeType
    = SoftwareTokenMfauserCodeType String


{-| The SoftwareTokenMfauserCodeType data model.
-}
softwareTokenMfauserCodeType : Refined String SoftwareTokenMfauserCodeType StringError
softwareTokenMfauserCodeType =
    let
        guardFn val =
            Refined.minLength 6 val
                |> Result.andThen (Refined.maxLength 6)
                |> Result.andThen (Refined.regexMatch "[0-9]+")
                |> Result.map SoftwareTokenMfauserCodeType

        unboxFn (SoftwareTokenMfauserCodeType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The SmsVerificationMessageType data model.
-}
type SmsVerificationMessageType
    = SmsVerificationMessageType String


{-| The SmsVerificationMessageType data model.
-}
smsVerificationMessageType : Refined String SmsVerificationMessageType StringError
smsVerificationMessageType =
    let
        guardFn val =
            Refined.minLength 6 val
                |> Result.andThen (Refined.maxLength 140)
                |> Result.andThen (Refined.regexMatch ".*\\{####\\}.*")
                |> Result.map SmsVerificationMessageType

        unboxFn (SmsVerificationMessageType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The SmsMfaConfigType data model.
-}
type alias SmsMfaConfigType =
    { smsAuthenticationMessage : Maybe SmsVerificationMessageType, smsConfiguration : Maybe SmsConfigurationType }


{-| The SmsConfigurationType data model.
-}
type alias SmsConfigurationType =
    { externalId : Maybe StringType, snsCallerArn : ArnType }


{-| The SkippedIprangeListType data model.
-}
type alias SkippedIprangeListType =
    List StringType


{-| The SignUpResponse data model.
-}
type alias SignUpResponse =
    { codeDeliveryDetails : Maybe CodeDeliveryDetailsType, userConfirmed : BooleanType, userSub : StringType }


{-| The SignUpRequest data model.
-}
type alias SignUpRequest =
    { analyticsMetadata : Maybe AnalyticsMetadataType
    , clientId : ClientIdType
    , password : PasswordType
    , secretHash : Maybe SecretHashType
    , userAttributes : Maybe AttributeListType
    , userContextData : Maybe UserContextDataType
    , username : UsernameType
    , validationData : Maybe AttributeListType
    }


{-| The SetUserSettingsResponse data model.
-}
type alias SetUserSettingsResponse =
    {}


{-| The SetUserSettingsRequest data model.
-}
type alias SetUserSettingsRequest =
    { accessToken : TokenModelType, mfaoptions : MfaoptionListType }


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
    , userPoolId : UserPoolIdType
    }


{-| The SetUserMfapreferenceResponse data model.
-}
type alias SetUserMfapreferenceResponse =
    {}


{-| The SetUserMfapreferenceRequest data model.
-}
type alias SetUserMfapreferenceRequest =
    { accessToken : TokenModelType
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
    { css : Maybe Csstype, clientId : Maybe ClientIdType, imageFile : Maybe ImageFileType, userPoolId : UserPoolIdType }


{-| The SetRiskConfigurationResponse data model.
-}
type alias SetRiskConfigurationResponse =
    { riskConfiguration : RiskConfigurationType }


{-| The SetRiskConfigurationRequest data model.
-}
type alias SetRiskConfigurationRequest =
    { accountTakeoverRiskConfiguration : Maybe AccountTakeoverRiskConfigurationType
    , clientId : Maybe ClientIdType
    , compromisedCredentialsRiskConfiguration : Maybe CompromisedCredentialsRiskConfigurationType
    , riskExceptionConfiguration : Maybe RiskExceptionConfigurationType
    , userPoolId : UserPoolIdType
    }


{-| The SessionType data model.
-}
type SessionType
    = SessionType String


{-| The SessionType data model.
-}
sessionType : Refined String SessionType StringError
sessionType =
    let
        guardFn val =
            Refined.minLength 20 val |> Result.andThen (Refined.maxLength 2048) |> Result.map SessionType

        unboxFn (SessionType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The SecretHashType data model.
-}
type SecretHashType
    = SecretHashType String


{-| The SecretHashType data model.
-}
secretHashType : Refined String SecretHashType StringError
secretHashType =
    let
        guardFn val =
            Refined.minLength 1 val
                |> Result.andThen (Refined.maxLength 128)
                |> Result.andThen (Refined.regexMatch "[\\w+=/]+")
                |> Result.map SecretHashType

        unboxFn (SecretHashType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The SecretCodeType data model.
-}
type SecretCodeType
    = SecretCodeType String


{-| The SecretCodeType data model.
-}
secretCodeType : Refined String SecretCodeType StringError
secretCodeType =
    let
        guardFn val =
            Refined.minLength 16 val |> Result.andThen (Refined.regexMatch "[A-Za-z0-9]+") |> Result.map SecretCodeType

        unboxFn (SecretCodeType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The SearchedAttributeNamesListType data model.
-}
type alias SearchedAttributeNamesListType =
    List AttributeNameType


{-| The SearchPaginationTokenType data model.
-}
type SearchPaginationTokenType
    = SearchPaginationTokenType String


{-| The SearchPaginationTokenType data model.
-}
searchPaginationTokenType : Refined String SearchPaginationTokenType StringError
searchPaginationTokenType =
    let
        guardFn val =
            Refined.minLength 1 val
                |> Result.andThen (Refined.regexMatch "[\\S]+")
                |> Result.map SearchPaginationTokenType

        unboxFn (SearchPaginationTokenType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The ScopeType data model.
-}
type ScopeType
    = ScopeType String


{-| The ScopeType data model.
-}
scopeType : Refined String ScopeType StringError
scopeType =
    let
        guardFn val =
            Refined.minLength 1 val
                |> Result.andThen (Refined.maxLength 256)
                |> Result.andThen (Refined.regexMatch "[\\x21\\x23-\\x5B\\x5D-\\x7E]+")
                |> Result.map ScopeType

        unboxFn (ScopeType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The ScopeListType data model.
-}
type alias ScopeListType =
    List ScopeType


{-| The SchemaAttributesListType data model.
-}
type alias SchemaAttributesListType =
    List SchemaAttributeType


{-| The SchemaAttributeType data model.
-}
type alias SchemaAttributeType =
    { attributeDataType : Maybe AttributeDataType
    , developerOnlyAttribute : Maybe BooleanType
    , mutable : Maybe BooleanType
    , name : Maybe CustomAttributeNameType
    , numberAttributeConstraints : Maybe NumberAttributeConstraintsType
    , required : Maybe BooleanType
    , stringAttributeConstraints : Maybe StringAttributeConstraintsType
    }


{-| The SmsmfaSettingsType data model.
-}
type alias SmsmfaSettingsType =
    { enabled : Maybe BooleanType, preferredMfa : Maybe BooleanType }


{-| The S3BucketType data model.
-}
type S3BucketType
    = S3BucketType String


{-| The S3BucketType data model.
-}
s3BucketType : Refined String S3BucketType StringError
s3BucketType =
    let
        guardFn val =
            Refined.minLength 3 val
                |> Result.andThen (Refined.maxLength 1024)
                |> Result.andThen (Refined.regexMatch "^[0-9A-Za-z\\.\\-_]*(?<!\\.)$")
                |> Result.map S3BucketType

        unboxFn (S3BucketType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


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
    , clientId : Maybe ClientIdType
    , compromisedCredentialsRiskConfiguration : Maybe CompromisedCredentialsRiskConfigurationType
    , lastModifiedDate : Maybe DateType
    , riskExceptionConfiguration : Maybe RiskExceptionConfigurationType
    , userPoolId : Maybe UserPoolIdType
    }


{-| The RespondToAuthChallengeResponse data model.
-}
type alias RespondToAuthChallengeResponse =
    { authenticationResult : Maybe AuthenticationResultType
    , challengeName : Maybe ChallengeNameType
    , challengeParameters : Maybe ChallengeParametersType
    , session : Maybe SessionType
    }


{-| The RespondToAuthChallengeRequest data model.
-}
type alias RespondToAuthChallengeRequest =
    { analyticsMetadata : Maybe AnalyticsMetadataType
    , challengeName : ChallengeNameType
    , challengeResponses : Maybe ChallengeResponsesType
    , clientId : ClientIdType
    , session : Maybe SessionType
    , userContextData : Maybe UserContextDataType
    }


{-| The ResourceServersListType data model.
-}
type alias ResourceServersListType =
    List ResourceServerType


{-| The ResourceServerType data model.
-}
type alias ResourceServerType =
    { identifier : Maybe ResourceServerIdentifierType
    , name : Maybe ResourceServerNameType
    , scopes : Maybe ResourceServerScopeListType
    , userPoolId : Maybe UserPoolIdType
    }


{-| The ResourceServerScopeType data model.
-}
type alias ResourceServerScopeType =
    { scopeDescription : ResourceServerScopeDescriptionType, scopeName : ResourceServerScopeNameType }


{-| The ResourceServerScopeNameType data model.
-}
type ResourceServerScopeNameType
    = ResourceServerScopeNameType String


{-| The ResourceServerScopeNameType data model.
-}
resourceServerScopeNameType : Refined String ResourceServerScopeNameType StringError
resourceServerScopeNameType =
    let
        guardFn val =
            Refined.minLength 1 val
                |> Result.andThen (Refined.maxLength 256)
                |> Result.andThen (Refined.regexMatch "[\\x21\\x23-\\x2E\\x30-\\x5B\\x5D-\\x7E]+")
                |> Result.map ResourceServerScopeNameType

        unboxFn (ResourceServerScopeNameType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The ResourceServerScopeListType data model.
-}
type alias ResourceServerScopeListType =
    List ResourceServerScopeType


{-| The ResourceServerScopeDescriptionType data model.
-}
type ResourceServerScopeDescriptionType
    = ResourceServerScopeDescriptionType String


{-| The ResourceServerScopeDescriptionType data model.
-}
resourceServerScopeDescriptionType : Refined String ResourceServerScopeDescriptionType StringError
resourceServerScopeDescriptionType =
    let
        guardFn val =
            Refined.minLength 1 val
                |> Result.andThen (Refined.maxLength 256)
                |> Result.map ResourceServerScopeDescriptionType

        unboxFn (ResourceServerScopeDescriptionType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The ResourceServerNameType data model.
-}
type ResourceServerNameType
    = ResourceServerNameType String


{-| The ResourceServerNameType data model.
-}
resourceServerNameType : Refined String ResourceServerNameType StringError
resourceServerNameType =
    let
        guardFn val =
            Refined.minLength 1 val
                |> Result.andThen (Refined.maxLength 256)
                |> Result.andThen (Refined.regexMatch "[\\w\\s+=,.@-]+")
                |> Result.map ResourceServerNameType

        unboxFn (ResourceServerNameType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The ResourceServerIdentifierType data model.
-}
type ResourceServerIdentifierType
    = ResourceServerIdentifierType String


{-| The ResourceServerIdentifierType data model.
-}
resourceServerIdentifierType : Refined String ResourceServerIdentifierType StringError
resourceServerIdentifierType =
    let
        guardFn val =
            Refined.minLength 1 val
                |> Result.andThen (Refined.maxLength 256)
                |> Result.andThen (Refined.regexMatch "[\\x21\\x23-\\x5B\\x5D-\\x7E]+")
                |> Result.map ResourceServerIdentifierType

        unboxFn (ResourceServerIdentifierType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The ResendConfirmationCodeResponse data model.
-}
type alias ResendConfirmationCodeResponse =
    { codeDeliveryDetails : Maybe CodeDeliveryDetailsType }


{-| The ResendConfirmationCodeRequest data model.
-}
type alias ResendConfirmationCodeRequest =
    { analyticsMetadata : Maybe AnalyticsMetadataType
    , clientId : ClientIdType
    , secretHash : Maybe SecretHashType
    , userContextData : Maybe UserContextDataType
    , username : UsernameType
    }


{-| The RefreshTokenValidityType data model.
-}
type RefreshTokenValidityType
    = RefreshTokenValidityType Int


{-| The RefreshTokenValidityType data model.
-}
refreshTokenValidityType : Refined Int RefreshTokenValidityType IntError
refreshTokenValidityType =
    let
        guardFn val =
            Refined.gte 0 val |> Result.andThen (Refined.lte 3650) |> Result.map RefreshTokenValidityType

        unboxFn (RefreshTokenValidityType val) =
            val
    in
    Refined.define guardFn Json.Decode.int Json.Encode.int Refined.intErrorToString unboxFn


{-| The RedirectUrlType data model.
-}
type RedirectUrlType
    = RedirectUrlType String


{-| The RedirectUrlType data model.
-}
redirectUrlType : Refined String RedirectUrlType StringError
redirectUrlType =
    let
        guardFn val =
            Refined.minLength 1 val
                |> Result.andThen (Refined.maxLength 1024)
                |> Result.andThen (Refined.regexMatch "[\\p{L}\\p{M}\\p{S}\\p{N}\\p{P}]+")
                |> Result.map RedirectUrlType

        unboxFn (RedirectUrlType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The QueryLimitType data model.
-}
type QueryLimitType
    = QueryLimitType Int


{-| The QueryLimitType data model.
-}
queryLimitType : Refined Int QueryLimitType IntError
queryLimitType =
    let
        guardFn val =
            Refined.gte 0 val |> Result.andThen (Refined.lte 60) |> Result.map QueryLimitType

        unboxFn (QueryLimitType val) =
            val
    in
    Refined.define guardFn Json.Decode.int Json.Encode.int Refined.intErrorToString unboxFn


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


{-| The ProvidersListType data model.
-}
type alias ProvidersListType =
    List ProviderDescription


{-| The ProviderUserIdentifierType data model.
-}
type alias ProviderUserIdentifierType =
    { providerAttributeName : Maybe StringType
    , providerAttributeValue : Maybe StringType
    , providerName : Maybe ProviderNameType
    }


{-| The ProviderNameTypeV1 data model.
-}
type ProviderNameTypeV1
    = ProviderNameTypeV1 String


{-| The ProviderNameTypeV1 data model.
-}
providerNameTypeV1 : Refined String ProviderNameTypeV1 StringError
providerNameTypeV1 =
    let
        guardFn val =
            Refined.minLength 1 val
                |> Result.andThen (Refined.maxLength 32)
                |> Result.andThen (Refined.regexMatch "[^_][\\p{L}\\p{M}\\p{S}\\p{N}\\p{P}][^_]+")
                |> Result.map ProviderNameTypeV1

        unboxFn (ProviderNameTypeV1 val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The ProviderNameType data model.
-}
type ProviderNameType
    = ProviderNameType String


{-| The ProviderNameType data model.
-}
providerNameType : Refined String ProviderNameType StringError
providerNameType =
    let
        guardFn val =
            Refined.minLength 1 val
                |> Result.andThen (Refined.maxLength 32)
                |> Result.andThen (Refined.regexMatch "[\\p{L}\\p{M}\\p{S}\\p{N}\\p{P}]+")
                |> Result.map ProviderNameType

        unboxFn (ProviderNameType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The ProviderDetailsType data model.
-}
type alias ProviderDetailsType =
    Dict StringType StringType


{-| The ProviderDescription data model.
-}
type alias ProviderDescription =
    { creationDate : Maybe DateType
    , lastModifiedDate : Maybe DateType
    , providerName : Maybe ProviderNameType
    , providerType : Maybe IdentityProviderTypeType
    }


{-| The PrecedenceType data model.
-}
type PrecedenceType
    = PrecedenceType Int


{-| The PrecedenceType data model.
-}
precedenceType : Refined Int PrecedenceType IntError
precedenceType =
    let
        guardFn val =
            Refined.gte 0 val |> Result.map PrecedenceType

        unboxFn (PrecedenceType val) =
            val
    in
    Refined.define guardFn Json.Decode.int Json.Encode.int Refined.intErrorToString unboxFn


{-| The PreSignedUrlType data model.
-}
type PreSignedUrlType
    = PreSignedUrlType String


{-| The PreSignedUrlType data model.
-}
preSignedUrlType : Refined String PreSignedUrlType StringError
preSignedUrlType =
    let
        guardFn val =
            Refined.minLength 0 val |> Result.andThen (Refined.maxLength 2048) |> Result.map PreSignedUrlType

        unboxFn (PreSignedUrlType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The PoolQueryLimitType data model.
-}
type PoolQueryLimitType
    = PoolQueryLimitType Int


{-| The PoolQueryLimitType data model.
-}
poolQueryLimitType : Refined Int PoolQueryLimitType IntError
poolQueryLimitType =
    let
        guardFn val =
            Refined.gte 1 val |> Result.andThen (Refined.lte 60) |> Result.map PoolQueryLimitType

        unboxFn (PoolQueryLimitType val) =
            val
    in
    Refined.define guardFn Json.Decode.int Json.Encode.int Refined.intErrorToString unboxFn


{-| The PasswordType data model.
-}
type PasswordType
    = PasswordType String


{-| The PasswordType data model.
-}
passwordType : Refined String PasswordType StringError
passwordType =
    let
        guardFn val =
            Refined.minLength 6 val
                |> Result.andThen (Refined.maxLength 256)
                |> Result.andThen (Refined.regexMatch "[\\S]+")
                |> Result.map PasswordType

        unboxFn (PasswordType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The PasswordPolicyType data model.
-}
type alias PasswordPolicyType =
    { minimumLength : Maybe PasswordPolicyMinLengthType
    , requireLowercase : Maybe BooleanType
    , requireNumbers : Maybe BooleanType
    , requireSymbols : Maybe BooleanType
    , requireUppercase : Maybe BooleanType
    , temporaryPasswordValidityDays : Maybe TemporaryPasswordValidityDaysType
    }


{-| The PasswordPolicyMinLengthType data model.
-}
type PasswordPolicyMinLengthType
    = PasswordPolicyMinLengthType Int


{-| The PasswordPolicyMinLengthType data model.
-}
passwordPolicyMinLengthType : Refined Int PasswordPolicyMinLengthType IntError
passwordPolicyMinLengthType =
    let
        guardFn val =
            Refined.gte 6 val |> Result.andThen (Refined.lte 99) |> Result.map PasswordPolicyMinLengthType

        unboxFn (PasswordPolicyMinLengthType val) =
            val
    in
    Refined.define guardFn Json.Decode.int Json.Encode.int Refined.intErrorToString unboxFn


{-| The PaginationKeyType data model.
-}
type PaginationKeyType
    = PaginationKeyType String


{-| The PaginationKeyType data model.
-}
paginationKeyType : Refined String PaginationKeyType StringError
paginationKeyType =
    let
        guardFn val =
            Refined.minLength 1 val |> Result.andThen (Refined.regexMatch "[\\S]+") |> Result.map PaginationKeyType

        unboxFn (PaginationKeyType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


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
    { maxValue : Maybe StringType, minValue : Maybe StringType }


{-| The NotifyEmailType data model.
-}
type alias NotifyEmailType =
    { htmlBody : Maybe EmailNotificationBodyType
    , subject : EmailNotificationSubjectType
    , textBody : Maybe EmailNotificationBodyType
    }


{-| The NotifyConfigurationType data model.
-}
type alias NotifyConfigurationType =
    { blockEmail : Maybe NotifyEmailType
    , from : Maybe StringType
    , mfaEmail : Maybe NotifyEmailType
    , noActionEmail : Maybe NotifyEmailType
    , replyTo : Maybe StringType
    , sourceArn : ArnType
    }


{-| The NewDeviceMetadataType data model.
-}
type alias NewDeviceMetadataType =
    { deviceGroupKey : Maybe StringType, deviceKey : Maybe DeviceKeyType }


{-| The MessageTemplateType data model.
-}
type alias MessageTemplateType =
    { emailMessage : Maybe EmailVerificationMessageType
    , emailSubject : Maybe EmailVerificationSubjectType
    , smsmessage : Maybe SmsVerificationMessageType
    }


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
    { attributeName : Maybe AttributeNameType, deliveryMedium : Maybe DeliveryMediumType }


{-| The MfaoptionListType data model.
-}
type alias MfaoptionListType =
    List MfaoptionType


{-| The LongType data model.
-}
type alias LongType =
    Int


{-| The LogoutUrlsListType data model.
-}
type alias LogoutUrlsListType =
    List RedirectUrlType


{-| The ListUsersResponse data model.
-}
type alias ListUsersResponse =
    { paginationToken : Maybe SearchPaginationTokenType, users : Maybe UsersListType }


{-| The ListUsersRequest data model.
-}
type alias ListUsersRequest =
    { attributesToGet : Maybe SearchedAttributeNamesListType
    , filter : Maybe UserFilterType
    , limit : Maybe QueryLimitType
    , paginationToken : Maybe SearchPaginationTokenType
    , userPoolId : UserPoolIdType
    }


{-| The ListUsersInGroupResponse data model.
-}
type alias ListUsersInGroupResponse =
    { nextToken : Maybe PaginationKey, users : Maybe UsersListType }


{-| The ListUsersInGroupRequest data model.
-}
type alias ListUsersInGroupRequest =
    { groupName : GroupNameType
    , limit : Maybe QueryLimitType
    , nextToken : Maybe PaginationKey
    , userPoolId : UserPoolIdType
    }


{-| The ListUserPoolsResponse data model.
-}
type alias ListUserPoolsResponse =
    { nextToken : Maybe PaginationKeyType, userPools : Maybe UserPoolListType }


{-| The ListUserPoolsRequest data model.
-}
type alias ListUserPoolsRequest =
    { maxResults : PoolQueryLimitType, nextToken : Maybe PaginationKeyType }


{-| The ListUserPoolClientsResponse data model.
-}
type alias ListUserPoolClientsResponse =
    { nextToken : Maybe PaginationKey, userPoolClients : Maybe UserPoolClientListType }


{-| The ListUserPoolClientsRequest data model.
-}
type alias ListUserPoolClientsRequest =
    { maxResults : Maybe QueryLimit, nextToken : Maybe PaginationKey, userPoolId : UserPoolIdType }


{-| The ListUserImportJobsResponse data model.
-}
type alias ListUserImportJobsResponse =
    { paginationToken : Maybe PaginationKeyType, userImportJobs : Maybe UserImportJobsListType }


{-| The ListUserImportJobsRequest data model.
-}
type alias ListUserImportJobsRequest =
    { maxResults : PoolQueryLimitType, paginationToken : Maybe PaginationKeyType, userPoolId : UserPoolIdType }


{-| The ListTagsForResourceResponse data model.
-}
type alias ListTagsForResourceResponse =
    { tags : Maybe UserPoolTagsType }


{-| The ListTagsForResourceRequest data model.
-}
type alias ListTagsForResourceRequest =
    { resourceArn : ArnType }


{-| The ListResourceServersResponse data model.
-}
type alias ListResourceServersResponse =
    { nextToken : Maybe PaginationKeyType, resourceServers : ResourceServersListType }


{-| The ListResourceServersRequest data model.
-}
type alias ListResourceServersRequest =
    { maxResults : Maybe ListResourceServersLimitType
    , nextToken : Maybe PaginationKeyType
    , userPoolId : UserPoolIdType
    }


{-| The ListResourceServersLimitType data model.
-}
type ListResourceServersLimitType
    = ListResourceServersLimitType Int


{-| The ListResourceServersLimitType data model.
-}
listResourceServersLimitType : Refined Int ListResourceServersLimitType IntError
listResourceServersLimitType =
    let
        guardFn val =
            Refined.gte 1 val |> Result.andThen (Refined.lte 50) |> Result.map ListResourceServersLimitType

        unboxFn (ListResourceServersLimitType val) =
            val
    in
    Refined.define guardFn Json.Decode.int Json.Encode.int Refined.intErrorToString unboxFn


{-| The ListProvidersLimitType data model.
-}
type ListProvidersLimitType
    = ListProvidersLimitType Int


{-| The ListProvidersLimitType data model.
-}
listProvidersLimitType : Refined Int ListProvidersLimitType IntError
listProvidersLimitType =
    let
        guardFn val =
            Refined.gte 0 val |> Result.andThen (Refined.lte 60) |> Result.map ListProvidersLimitType

        unboxFn (ListProvidersLimitType val) =
            val
    in
    Refined.define guardFn Json.Decode.int Json.Encode.int Refined.intErrorToString unboxFn


{-| The ListOfStringTypes data model.
-}
type alias ListOfStringTypes =
    List StringType


{-| The ListIdentityProvidersResponse data model.
-}
type alias ListIdentityProvidersResponse =
    { nextToken : Maybe PaginationKeyType, providers : ProvidersListType }


{-| The ListIdentityProvidersRequest data model.
-}
type alias ListIdentityProvidersRequest =
    { maxResults : Maybe ListProvidersLimitType, nextToken : Maybe PaginationKeyType, userPoolId : UserPoolIdType }


{-| The ListGroupsResponse data model.
-}
type alias ListGroupsResponse =
    { groups : Maybe GroupListType, nextToken : Maybe PaginationKey }


{-| The ListGroupsRequest data model.
-}
type alias ListGroupsRequest =
    { limit : Maybe QueryLimitType, nextToken : Maybe PaginationKey, userPoolId : UserPoolIdType }


{-| The ListDevicesResponse data model.
-}
type alias ListDevicesResponse =
    { devices : Maybe DeviceListType, paginationToken : Maybe SearchPaginationTokenType }


{-| The ListDevicesRequest data model.
-}
type alias ListDevicesRequest =
    { accessToken : TokenModelType, limit : Maybe QueryLimitType, paginationToken : Maybe SearchPaginationTokenType }


{-| The LambdaConfigType data model.
-}
type alias LambdaConfigType =
    { createAuthChallenge : Maybe ArnType
    , customMessage : Maybe ArnType
    , defineAuthChallenge : Maybe ArnType
    , postAuthentication : Maybe ArnType
    , postConfirmation : Maybe ArnType
    , preAuthentication : Maybe ArnType
    , preSignUp : Maybe ArnType
    , preTokenGeneration : Maybe ArnType
    , userMigration : Maybe ArnType
    , verifyAuthChallengeResponse : Maybe ArnType
    }


{-| The IntegerType data model.
-}
type alias IntegerType =
    Int


{-| The InitiateAuthResponse data model.
-}
type alias InitiateAuthResponse =
    { authenticationResult : Maybe AuthenticationResultType
    , challengeName : Maybe ChallengeNameType
    , challengeParameters : Maybe ChallengeParametersType
    , session : Maybe SessionType
    }


{-| The InitiateAuthRequest data model.
-}
type alias InitiateAuthRequest =
    { analyticsMetadata : Maybe AnalyticsMetadataType
    , authFlow : AuthFlowType
    , authParameters : Maybe AuthParametersType
    , clientId : ClientIdType
    , clientMetadata : Maybe ClientMetadataType
    , userContextData : Maybe UserContextDataType
    }


{-| The ImageUrlType data model.
-}
type alias ImageUrlType =
    String


{-| The ImageFileType data model.
-}
type alias ImageFileType =
    String


{-| The IdpIdentifiersListType data model.
-}
type alias IdpIdentifiersListType =
    List IdpIdentifierType


{-| The IdpIdentifierType data model.
-}
type IdpIdentifierType
    = IdpIdentifierType String


{-| The IdpIdentifierType data model.
-}
idpIdentifierType : Refined String IdpIdentifierType StringError
idpIdentifierType =
    let
        guardFn val =
            Refined.minLength 1 val
                |> Result.andThen (Refined.maxLength 40)
                |> Result.andThen (Refined.regexMatch "[\\w\\s+=.@-]+")
                |> Result.map IdpIdentifierType

        unboxFn (IdpIdentifierType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


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
    , creationDate : Maybe DateType
    , idpIdentifiers : Maybe IdpIdentifiersListType
    , lastModifiedDate : Maybe DateType
    , providerDetails : Maybe ProviderDetailsType
    , providerName : Maybe ProviderNameType
    , providerType : Maybe IdentityProviderTypeType
    , userPoolId : Maybe UserPoolIdType
    }


{-| The HttpHeaderList data model.
-}
type alias HttpHeaderList =
    List HttpHeader


{-| The HttpHeader data model.
-}
type alias HttpHeader =
    { headerName : Maybe StringType, headerValue : Maybe StringType }


{-| The HexStringType data model.
-}
type HexStringType
    = HexStringType String


{-| The HexStringType data model.
-}
hexStringType : Refined String HexStringType StringError
hexStringType =
    let
        guardFn val =
            Refined.regexMatch "^[0-9a-fA-F]+$" val |> Result.map HexStringType

        unboxFn (HexStringType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The GroupType data model.
-}
type alias GroupType =
    { creationDate : Maybe DateType
    , description : Maybe DescriptionType
    , groupName : Maybe GroupNameType
    , lastModifiedDate : Maybe DateType
    , precedence : Maybe PrecedenceType
    , roleArn : Maybe ArnType
    , userPoolId : Maybe UserPoolIdType
    }


{-| The GroupNameType data model.
-}
type GroupNameType
    = GroupNameType String


{-| The GroupNameType data model.
-}
groupNameType : Refined String GroupNameType StringError
groupNameType =
    let
        guardFn val =
            Refined.minLength 1 val
                |> Result.andThen (Refined.maxLength 128)
                |> Result.andThen (Refined.regexMatch "[\\p{L}\\p{M}\\p{S}\\p{N}\\p{P}]+")
                |> Result.map GroupNameType

        unboxFn (GroupNameType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


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
    { accessToken : TokenModelType }


{-| The GetUserResponse data model.
-}
type alias GetUserResponse =
    { mfaoptions : Maybe MfaoptionListType
    , preferredMfaSetting : Maybe StringType
    , userAttributes : AttributeListType
    , userMfasettingList : Maybe UserMfasettingListType
    , username : UsernameType
    }


{-| The GetUserRequest data model.
-}
type alias GetUserRequest =
    { accessToken : TokenModelType }


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
    { userPoolId : UserPoolIdType }


{-| The GetUserAttributeVerificationCodeResponse data model.
-}
type alias GetUserAttributeVerificationCodeResponse =
    { codeDeliveryDetails : Maybe CodeDeliveryDetailsType }


{-| The GetUserAttributeVerificationCodeRequest data model.
-}
type alias GetUserAttributeVerificationCodeRequest =
    { accessToken : TokenModelType, attributeName : AttributeNameType }


{-| The GetUicustomizationResponse data model.
-}
type alias GetUicustomizationResponse =
    { uicustomization : UicustomizationType }


{-| The GetUicustomizationRequest data model.
-}
type alias GetUicustomizationRequest =
    { clientId : Maybe ClientIdType, userPoolId : UserPoolIdType }


{-| The GetSigningCertificateResponse data model.
-}
type alias GetSigningCertificateResponse =
    { certificate : Maybe StringType }


{-| The GetSigningCertificateRequest data model.
-}
type alias GetSigningCertificateRequest =
    { userPoolId : UserPoolIdType }


{-| The GetIdentityProviderByIdentifierResponse data model.
-}
type alias GetIdentityProviderByIdentifierResponse =
    { identityProvider : IdentityProviderType }


{-| The GetIdentityProviderByIdentifierRequest data model.
-}
type alias GetIdentityProviderByIdentifierRequest =
    { idpIdentifier : IdpIdentifierType, userPoolId : UserPoolIdType }


{-| The GetGroupResponse data model.
-}
type alias GetGroupResponse =
    { group : Maybe GroupType }


{-| The GetGroupRequest data model.
-}
type alias GetGroupRequest =
    { groupName : GroupNameType, userPoolId : UserPoolIdType }


{-| The GetDeviceResponse data model.
-}
type alias GetDeviceResponse =
    { device : DeviceType }


{-| The GetDeviceRequest data model.
-}
type alias GetDeviceRequest =
    { accessToken : Maybe TokenModelType, deviceKey : DeviceKeyType }


{-| The GetCsvheaderResponse data model.
-}
type alias GetCsvheaderResponse =
    { csvheader : Maybe ListOfStringTypes, userPoolId : Maybe UserPoolIdType }


{-| The GetCsvheaderRequest data model.
-}
type alias GetCsvheaderRequest =
    { userPoolId : UserPoolIdType }


{-| The GenerateSecret data model.
-}
type alias GenerateSecret =
    Bool


{-| The ForgotPasswordResponse data model.
-}
type alias ForgotPasswordResponse =
    { codeDeliveryDetails : Maybe CodeDeliveryDetailsType }


{-| The ForgotPasswordRequest data model.
-}
type alias ForgotPasswordRequest =
    { analyticsMetadata : Maybe AnalyticsMetadataType
    , clientId : ClientIdType
    , secretHash : Maybe SecretHashType
    , userContextData : Maybe UserContextDataType
    , username : UsernameType
    }


{-| The ForgetDeviceRequest data model.
-}
type alias ForgetDeviceRequest =
    { accessToken : Maybe TokenModelType, deviceKey : DeviceKeyType }


{-| The ForceAliasCreation data model.
-}
type alias ForceAliasCreation =
    Bool


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


{-| The EventIdType data model.
-}
type EventIdType
    = EventIdType String


{-| The EventIdType data model.
-}
eventIdType : Refined String EventIdType StringError
eventIdType =
    let
        guardFn val =
            Refined.minLength 1 val
                |> Result.andThen (Refined.maxLength 50)
                |> Result.andThen (Refined.regexMatch "[\\w+-]+")
                |> Result.map EventIdType

        unboxFn (EventIdType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


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
    { feedbackDate : Maybe DateType, feedbackValue : FeedbackValueType, provider : StringType }


{-| The EventContextDataType data model.
-}
type alias EventContextDataType =
    { city : Maybe StringType
    , country : Maybe StringType
    , deviceName : Maybe StringType
    , ipAddress : Maybe StringType
    , timezone : Maybe StringType
    }


{-| The EmailVerificationSubjectType data model.
-}
type EmailVerificationSubjectType
    = EmailVerificationSubjectType String


{-| The EmailVerificationSubjectType data model.
-}
emailVerificationSubjectType : Refined String EmailVerificationSubjectType StringError
emailVerificationSubjectType =
    let
        guardFn val =
            Refined.minLength 1 val
                |> Result.andThen (Refined.maxLength 140)
                |> Result.andThen (Refined.regexMatch "[\\p{L}\\p{M}\\p{S}\\p{N}\\p{P}\\s]+")
                |> Result.map EmailVerificationSubjectType

        unboxFn (EmailVerificationSubjectType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The EmailVerificationSubjectByLinkType data model.
-}
type EmailVerificationSubjectByLinkType
    = EmailVerificationSubjectByLinkType String


{-| The EmailVerificationSubjectByLinkType data model.
-}
emailVerificationSubjectByLinkType : Refined String EmailVerificationSubjectByLinkType StringError
emailVerificationSubjectByLinkType =
    let
        guardFn val =
            Refined.minLength 1 val
                |> Result.andThen (Refined.maxLength 140)
                |> Result.andThen (Refined.regexMatch "[\\p{L}\\p{M}\\p{S}\\p{N}\\p{P}\\s]+")
                |> Result.map EmailVerificationSubjectByLinkType

        unboxFn (EmailVerificationSubjectByLinkType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The EmailVerificationMessageType data model.
-}
type EmailVerificationMessageType
    = EmailVerificationMessageType String


{-| The EmailVerificationMessageType data model.
-}
emailVerificationMessageType : Refined String EmailVerificationMessageType StringError
emailVerificationMessageType =
    let
        guardFn val =
            Refined.minLength 6 val
                |> Result.andThen (Refined.maxLength 20000)
                |> Result.andThen
                    (Refined.regexMatch
                        "[\\p{L}\\p{M}\\p{S}\\p{N}\\p{P}\\s*]*\\{####\\}[\\p{L}\\p{M}\\p{S}\\p{N}\\p{P}\\s*]*"
                    )
                |> Result.map EmailVerificationMessageType

        unboxFn (EmailVerificationMessageType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The EmailVerificationMessageByLinkType data model.
-}
type EmailVerificationMessageByLinkType
    = EmailVerificationMessageByLinkType String


{-| The EmailVerificationMessageByLinkType data model.
-}
emailVerificationMessageByLinkType : Refined String EmailVerificationMessageByLinkType StringError
emailVerificationMessageByLinkType =
    let
        guardFn val =
            Refined.minLength 6 val
                |> Result.andThen (Refined.maxLength 20000)
                |> Result.andThen
                    (Refined.regexMatch
                        "[\\p{L}\\p{M}\\p{S}\\p{N}\\p{P}\\s*]*\\{##[\\p{L}\\p{M}\\p{S}\\p{N}\\p{P}\\s*]*##\\}[\\p{L}\\p{M}\\p{S}\\p{N}\\p{P}\\s*]*"
                    )
                |> Result.map EmailVerificationMessageByLinkType

        unboxFn (EmailVerificationMessageByLinkType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


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


{-| The EmailNotificationSubjectType data model.
-}
type EmailNotificationSubjectType
    = EmailNotificationSubjectType String


{-| The EmailNotificationSubjectType data model.
-}
emailNotificationSubjectType : Refined String EmailNotificationSubjectType StringError
emailNotificationSubjectType =
    let
        guardFn val =
            Refined.minLength 1 val
                |> Result.andThen (Refined.maxLength 140)
                |> Result.andThen (Refined.regexMatch "[\\p{L}\\p{M}\\p{S}\\p{N}\\p{P}\\s]+")
                |> Result.map EmailNotificationSubjectType

        unboxFn (EmailNotificationSubjectType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The EmailNotificationBodyType data model.
-}
type EmailNotificationBodyType
    = EmailNotificationBodyType String


{-| The EmailNotificationBodyType data model.
-}
emailNotificationBodyType : Refined String EmailNotificationBodyType StringError
emailNotificationBodyType =
    let
        guardFn val =
            Refined.minLength 6 val
                |> Result.andThen (Refined.maxLength 20000)
                |> Result.andThen (Refined.regexMatch "[\\p{L}\\p{M}\\p{S}\\p{N}\\p{P}\\s*]+")
                |> Result.map EmailNotificationBodyType

        unboxFn (EmailNotificationBodyType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The EmailConfigurationType data model.
-}
type alias EmailConfigurationType =
    { emailSendingAccount : Maybe EmailSendingAccountType
    , replyToEmailAddress : Maybe EmailAddressType
    , sourceArn : Maybe ArnType
    }


{-| The EmailAddressType data model.
-}
type EmailAddressType
    = EmailAddressType String


{-| The EmailAddressType data model.
-}
emailAddressType : Refined String EmailAddressType StringError
emailAddressType =
    let
        guardFn val =
            Refined.regexMatch "[\\p{L}\\p{M}\\p{S}\\p{N}\\p{P}]+@[\\p{L}\\p{M}\\p{S}\\p{N}\\p{P}]+" val
                |> Result.map EmailAddressType

        unboxFn (EmailAddressType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The DomainVersionType data model.
-}
type DomainVersionType
    = DomainVersionType String


{-| The DomainVersionType data model.
-}
domainVersionType : Refined String DomainVersionType StringError
domainVersionType =
    let
        guardFn val =
            Refined.minLength 1 val |> Result.andThen (Refined.maxLength 20) |> Result.map DomainVersionType

        unboxFn (DomainVersionType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The DomainType data model.
-}
type DomainType
    = DomainType String


{-| The DomainType data model.
-}
domainType : Refined String DomainType StringError
domainType =
    let
        guardFn val =
            Refined.minLength 1 val
                |> Result.andThen (Refined.maxLength 63)
                |> Result.andThen (Refined.regexMatch "^[a-z0-9](?:[a-z0-9\\-]{0,61}[a-z0-9])?$")
                |> Result.map DomainType

        unboxFn (DomainType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


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
    { awsaccountId : Maybe AwsaccountIdType
    , cloudFrontDistribution : Maybe StringType
    , customDomainConfig : Maybe CustomDomainConfigType
    , domain : Maybe DomainType
    , s3Bucket : Maybe S3BucketType
    , status : Maybe DomainStatusType
    , userPoolId : Maybe UserPoolIdType
    , version : Maybe DomainVersionType
    }


{-| The DeviceType data model.
-}
type alias DeviceType =
    { deviceAttributes : Maybe AttributeListType
    , deviceCreateDate : Maybe DateType
    , deviceKey : Maybe DeviceKeyType
    , deviceLastAuthenticatedDate : Maybe DateType
    , deviceLastModifiedDate : Maybe DateType
    }


{-| The DeviceSecretVerifierConfigType data model.
-}
type alias DeviceSecretVerifierConfigType =
    { passwordVerifier : Maybe StringType, salt : Maybe StringType }


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


{-| The DeviceNameType data model.
-}
type DeviceNameType
    = DeviceNameType String


{-| The DeviceNameType data model.
-}
deviceNameType : Refined String DeviceNameType StringError
deviceNameType =
    let
        guardFn val =
            Refined.minLength 1 val |> Result.andThen (Refined.maxLength 1024) |> Result.map DeviceNameType

        unboxFn (DeviceNameType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The DeviceListType data model.
-}
type alias DeviceListType =
    List DeviceType


{-| The DeviceKeyType data model.
-}
type DeviceKeyType
    = DeviceKeyType String


{-| The DeviceKeyType data model.
-}
deviceKeyType : Refined String DeviceKeyType StringError
deviceKeyType =
    let
        guardFn val =
            Refined.minLength 1 val
                |> Result.andThen (Refined.maxLength 55)
                |> Result.andThen (Refined.regexMatch "[\\w-]+_[0-9a-f-]+")
                |> Result.map DeviceKeyType

        unboxFn (DeviceKeyType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The DeviceConfigurationType data model.
-}
type alias DeviceConfigurationType =
    { challengeRequiredOnNewDevice : Maybe BooleanType, deviceOnlyRememberedOnUserPrompt : Maybe BooleanType }


{-| The DescriptionType data model.
-}
type DescriptionType
    = DescriptionType String


{-| The DescriptionType data model.
-}
descriptionType : Refined String DescriptionType StringError
descriptionType =
    let
        guardFn val =
            Refined.maxLength 2048 val |> Result.map DescriptionType

        unboxFn (DescriptionType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The DescribeUserPoolResponse data model.
-}
type alias DescribeUserPoolResponse =
    { userPool : Maybe UserPoolType }


{-| The DescribeUserPoolRequest data model.
-}
type alias DescribeUserPoolRequest =
    { userPoolId : UserPoolIdType }


{-| The DescribeUserPoolDomainResponse data model.
-}
type alias DescribeUserPoolDomainResponse =
    { domainDescription : Maybe DomainDescriptionType }


{-| The DescribeUserPoolDomainRequest data model.
-}
type alias DescribeUserPoolDomainRequest =
    { domain : DomainType }


{-| The DescribeUserPoolClientResponse data model.
-}
type alias DescribeUserPoolClientResponse =
    { userPoolClient : Maybe UserPoolClientType }


{-| The DescribeUserPoolClientRequest data model.
-}
type alias DescribeUserPoolClientRequest =
    { clientId : ClientIdType, userPoolId : UserPoolIdType }


{-| The DescribeUserImportJobResponse data model.
-}
type alias DescribeUserImportJobResponse =
    { userImportJob : Maybe UserImportJobType }


{-| The DescribeUserImportJobRequest data model.
-}
type alias DescribeUserImportJobRequest =
    { jobId : UserImportJobIdType, userPoolId : UserPoolIdType }


{-| The DescribeRiskConfigurationResponse data model.
-}
type alias DescribeRiskConfigurationResponse =
    { riskConfiguration : RiskConfigurationType }


{-| The DescribeRiskConfigurationRequest data model.
-}
type alias DescribeRiskConfigurationRequest =
    { clientId : Maybe ClientIdType, userPoolId : UserPoolIdType }


{-| The DescribeResourceServerResponse data model.
-}
type alias DescribeResourceServerResponse =
    { resourceServer : ResourceServerType }


{-| The DescribeResourceServerRequest data model.
-}
type alias DescribeResourceServerRequest =
    { identifier : ResourceServerIdentifierType, userPoolId : UserPoolIdType }


{-| The DescribeIdentityProviderResponse data model.
-}
type alias DescribeIdentityProviderResponse =
    { identityProvider : IdentityProviderType }


{-| The DescribeIdentityProviderRequest data model.
-}
type alias DescribeIdentityProviderRequest =
    { providerName : ProviderNameType, userPoolId : UserPoolIdType }


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
    { accessToken : TokenModelType }


{-| The DeleteUserPoolRequest data model.
-}
type alias DeleteUserPoolRequest =
    { userPoolId : UserPoolIdType }


{-| The DeleteUserPoolDomainResponse data model.
-}
type alias DeleteUserPoolDomainResponse =
    {}


{-| The DeleteUserPoolDomainRequest data model.
-}
type alias DeleteUserPoolDomainRequest =
    { domain : DomainType, userPoolId : UserPoolIdType }


{-| The DeleteUserPoolClientRequest data model.
-}
type alias DeleteUserPoolClientRequest =
    { clientId : ClientIdType, userPoolId : UserPoolIdType }


{-| The DeleteUserAttributesResponse data model.
-}
type alias DeleteUserAttributesResponse =
    {}


{-| The DeleteUserAttributesRequest data model.
-}
type alias DeleteUserAttributesRequest =
    { accessToken : TokenModelType, userAttributeNames : AttributeNameListType }


{-| The DeleteResourceServerRequest data model.
-}
type alias DeleteResourceServerRequest =
    { identifier : ResourceServerIdentifierType, userPoolId : UserPoolIdType }


{-| The DeleteIdentityProviderRequest data model.
-}
type alias DeleteIdentityProviderRequest =
    { providerName : ProviderNameType, userPoolId : UserPoolIdType }


{-| The DeleteGroupRequest data model.
-}
type alias DeleteGroupRequest =
    { groupName : GroupNameType, userPoolId : UserPoolIdType }


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


{-| The DateType data model.
-}
type alias DateType =
    String


{-| The CustomDomainConfigType data model.
-}
type alias CustomDomainConfigType =
    { certificateArn : ArnType }


{-| The CustomAttributesListType data model.
-}
type alias CustomAttributesListType =
    List SchemaAttributeType


{-| The CustomAttributeNameType data model.
-}
type CustomAttributeNameType
    = CustomAttributeNameType String


{-| The CustomAttributeNameType data model.
-}
customAttributeNameType : Refined String CustomAttributeNameType StringError
customAttributeNameType =
    let
        guardFn val =
            Refined.minLength 1 val
                |> Result.andThen (Refined.maxLength 20)
                |> Result.andThen (Refined.regexMatch "[\\p{L}\\p{M}\\p{S}\\p{N}\\p{P}]+")
                |> Result.map CustomAttributeNameType

        unboxFn (CustomAttributeNameType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


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
    , emailVerificationMessage : Maybe EmailVerificationMessageType
    , emailVerificationSubject : Maybe EmailVerificationSubjectType
    , lambdaConfig : Maybe LambdaConfigType
    , mfaConfiguration : Maybe UserPoolMfaType
    , policies : Maybe UserPoolPolicyType
    , poolName : UserPoolNameType
    , schema : Maybe SchemaAttributesListType
    , smsAuthenticationMessage : Maybe SmsVerificationMessageType
    , smsConfiguration : Maybe SmsConfigurationType
    , smsVerificationMessage : Maybe SmsVerificationMessageType
    , userPoolAddOns : Maybe UserPoolAddOnsType
    , userPoolTags : Maybe UserPoolTagsType
    , usernameAttributes : Maybe UsernameAttributesListType
    , verificationMessageTemplate : Maybe VerificationMessageTemplateType
    }


{-| The CreateUserPoolDomainResponse data model.
-}
type alias CreateUserPoolDomainResponse =
    { cloudFrontDomain : Maybe DomainType }


{-| The CreateUserPoolDomainRequest data model.
-}
type alias CreateUserPoolDomainRequest =
    { customDomainConfig : Maybe CustomDomainConfigType, domain : DomainType, userPoolId : UserPoolIdType }


{-| The CreateUserPoolClientResponse data model.
-}
type alias CreateUserPoolClientResponse =
    { userPoolClient : Maybe UserPoolClientType }


{-| The CreateUserPoolClientRequest data model.
-}
type alias CreateUserPoolClientRequest =
    { allowedOauthFlows : Maybe OauthFlowsType
    , allowedOauthFlowsUserPoolClient : Maybe BooleanType
    , allowedOauthScopes : Maybe ScopeListType
    , analyticsConfiguration : Maybe AnalyticsConfigurationType
    , callbackUrls : Maybe CallbackUrlsListType
    , clientName : ClientNameType
    , defaultRedirectUri : Maybe RedirectUrlType
    , explicitAuthFlows : Maybe ExplicitAuthFlowsListType
    , generateSecret : Maybe GenerateSecret
    , logoutUrls : Maybe LogoutUrlsListType
    , readAttributes : Maybe ClientPermissionListType
    , refreshTokenValidity : Maybe RefreshTokenValidityType
    , supportedIdentityProviders : Maybe SupportedIdentityProvidersListType
    , userPoolId : UserPoolIdType
    , writeAttributes : Maybe ClientPermissionListType
    }


{-| The CreateUserImportJobResponse data model.
-}
type alias CreateUserImportJobResponse =
    { userImportJob : Maybe UserImportJobType }


{-| The CreateUserImportJobRequest data model.
-}
type alias CreateUserImportJobRequest =
    { cloudWatchLogsRoleArn : ArnType, jobName : UserImportJobNameType, userPoolId : UserPoolIdType }


{-| The CreateResourceServerResponse data model.
-}
type alias CreateResourceServerResponse =
    { resourceServer : ResourceServerType }


{-| The CreateResourceServerRequest data model.
-}
type alias CreateResourceServerRequest =
    { identifier : ResourceServerIdentifierType
    , name : ResourceServerNameType
    , scopes : Maybe ResourceServerScopeListType
    , userPoolId : UserPoolIdType
    }


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
    , providerName : ProviderNameTypeV1
    , providerType : IdentityProviderTypeType
    , userPoolId : UserPoolIdType
    }


{-| The CreateGroupResponse data model.
-}
type alias CreateGroupResponse =
    { group : Maybe GroupType }


{-| The CreateGroupRequest data model.
-}
type alias CreateGroupRequest =
    { description : Maybe DescriptionType
    , groupName : GroupNameType
    , precedence : Maybe PrecedenceType
    , roleArn : Maybe ArnType
    , userPoolId : UserPoolIdType
    }


{-| The ContextDataType data model.
-}
type alias ContextDataType =
    { encodedData : Maybe StringType
    , httpHeaders : HttpHeaderList
    , ipAddress : StringType
    , serverName : StringType
    , serverPath : StringType
    }


{-| The ConfirmationCodeType data model.
-}
type ConfirmationCodeType
    = ConfirmationCodeType String


{-| The ConfirmationCodeType data model.
-}
confirmationCodeType : Refined String ConfirmationCodeType StringError
confirmationCodeType =
    let
        guardFn val =
            Refined.minLength 1 val
                |> Result.andThen (Refined.maxLength 2048)
                |> Result.andThen (Refined.regexMatch "[\\S]+")
                |> Result.map ConfirmationCodeType

        unboxFn (ConfirmationCodeType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The ConfirmSignUpResponse data model.
-}
type alias ConfirmSignUpResponse =
    {}


{-| The ConfirmSignUpRequest data model.
-}
type alias ConfirmSignUpRequest =
    { analyticsMetadata : Maybe AnalyticsMetadataType
    , clientId : ClientIdType
    , confirmationCode : ConfirmationCodeType
    , forceAliasCreation : Maybe ForceAliasCreation
    , secretHash : Maybe SecretHashType
    , userContextData : Maybe UserContextDataType
    , username : UsernameType
    }


{-| The ConfirmForgotPasswordResponse data model.
-}
type alias ConfirmForgotPasswordResponse =
    {}


{-| The ConfirmForgotPasswordRequest data model.
-}
type alias ConfirmForgotPasswordRequest =
    { analyticsMetadata : Maybe AnalyticsMetadataType
    , clientId : ClientIdType
    , confirmationCode : ConfirmationCodeType
    , password : PasswordType
    , secretHash : Maybe SecretHashType
    , userContextData : Maybe UserContextDataType
    , username : UsernameType
    }


{-| The ConfirmDeviceResponse data model.
-}
type alias ConfirmDeviceResponse =
    { userConfirmationNecessary : Maybe BooleanType }


{-| The ConfirmDeviceRequest data model.
-}
type alias ConfirmDeviceRequest =
    { accessToken : TokenModelType
    , deviceKey : DeviceKeyType
    , deviceName : Maybe DeviceNameType
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


{-| The CompletionMessageType data model.
-}
type CompletionMessageType
    = CompletionMessageType String


{-| The CompletionMessageType data model.
-}
completionMessageType : Refined String CompletionMessageType StringError
completionMessageType =
    let
        guardFn val =
            Refined.minLength 1 val
                |> Result.andThen (Refined.maxLength 128)
                |> Result.andThen (Refined.regexMatch "[\\w]+")
                |> Result.map CompletionMessageType

        unboxFn (CompletionMessageType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The CodeDeliveryDetailsType data model.
-}
type alias CodeDeliveryDetailsType =
    { attributeName : Maybe AttributeNameType
    , deliveryMedium : Maybe DeliveryMediumType
    , destination : Maybe StringType
    }


{-| The CodeDeliveryDetailsListType data model.
-}
type alias CodeDeliveryDetailsListType =
    List CodeDeliveryDetailsType


{-| The ClientSecretType data model.
-}
type ClientSecretType
    = ClientSecretType String


{-| The ClientSecretType data model.
-}
clientSecretType : Refined String ClientSecretType StringError
clientSecretType =
    let
        guardFn val =
            Refined.minLength 1 val
                |> Result.andThen (Refined.maxLength 64)
                |> Result.andThen (Refined.regexMatch "[\\w+]+")
                |> Result.map ClientSecretType

        unboxFn (ClientSecretType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The ClientPermissionType data model.
-}
type ClientPermissionType
    = ClientPermissionType String


{-| The ClientPermissionType data model.
-}
clientPermissionType : Refined String ClientPermissionType StringError
clientPermissionType =
    let
        guardFn val =
            Refined.minLength 1 val |> Result.andThen (Refined.maxLength 2048) |> Result.map ClientPermissionType

        unboxFn (ClientPermissionType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The ClientPermissionListType data model.
-}
type alias ClientPermissionListType =
    List ClientPermissionType


{-| The ClientNameType data model.
-}
type ClientNameType
    = ClientNameType String


{-| The ClientNameType data model.
-}
clientNameType : Refined String ClientNameType StringError
clientNameType =
    let
        guardFn val =
            Refined.minLength 1 val
                |> Result.andThen (Refined.maxLength 128)
                |> Result.andThen (Refined.regexMatch "[\\w\\s+=,.@-]+")
                |> Result.map ClientNameType

        unboxFn (ClientNameType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The ClientMetadataType data model.
-}
type alias ClientMetadataType =
    Dict StringType StringType


{-| The ClientIdType data model.
-}
type ClientIdType
    = ClientIdType String


{-| The ClientIdType data model.
-}
clientIdType : Refined String ClientIdType StringError
clientIdType =
    let
        guardFn val =
            Refined.minLength 1 val
                |> Result.andThen (Refined.maxLength 128)
                |> Result.andThen (Refined.regexMatch "[\\w+]+")
                |> Result.map ClientIdType

        unboxFn (ClientIdType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The ChangePasswordResponse data model.
-}
type alias ChangePasswordResponse =
    {}


{-| The ChangePasswordRequest data model.
-}
type alias ChangePasswordRequest =
    { accessToken : TokenModelType, previousPassword : PasswordType, proposedPassword : PasswordType }


{-| The ChallengeResponsesType data model.
-}
type alias ChallengeResponsesType =
    Dict StringType StringType


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
    Dict StringType StringType


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
    List RedirectUrlType


{-| The CssversionType data model.
-}
type alias CssversionType =
    String


{-| The Csstype data model.
-}
type alias Csstype =
    String


{-| The BooleanType data model.
-}
type alias BooleanType =
    Bool


{-| The BlockedIprangeListType data model.
-}
type alias BlockedIprangeListType =
    List StringType


{-| The AuthenticationResultType data model.
-}
type alias AuthenticationResultType =
    { accessToken : Maybe TokenModelType
    , expiresIn : Maybe IntegerType
    , idToken : Maybe TokenModelType
    , newDeviceMetadata : Maybe NewDeviceMetadataType
    , refreshToken : Maybe TokenModelType
    , tokenType : Maybe StringType
    }


{-| The AuthParametersType data model.
-}
type alias AuthParametersType =
    Dict StringType StringType


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
    , creationDate : Maybe DateType
    , eventContextData : Maybe EventContextDataType
    , eventFeedback : Maybe EventFeedbackType
    , eventId : Maybe StringType
    , eventResponse : Maybe EventResponseType
    , eventRisk : Maybe EventRiskType
    , eventType : Maybe EventType
    }


{-| The AttributeValueType data model.
-}
type AttributeValueType
    = AttributeValueType String


{-| The AttributeValueType data model.
-}
attributeValueType : Refined String AttributeValueType StringError
attributeValueType =
    let
        guardFn val =
            Refined.maxLength 2048 val |> Result.map AttributeValueType

        unboxFn (AttributeValueType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The AttributeType data model.
-}
type alias AttributeType =
    { name : AttributeNameType, value : Maybe AttributeValueType }


{-| The AttributeNameType data model.
-}
type AttributeNameType
    = AttributeNameType String


{-| The AttributeNameType data model.
-}
attributeNameType : Refined String AttributeNameType StringError
attributeNameType =
    let
        guardFn val =
            Refined.minLength 1 val
                |> Result.andThen (Refined.maxLength 32)
                |> Result.andThen (Refined.regexMatch "[\\p{L}\\p{M}\\p{S}\\p{N}\\p{P}]+")
                |> Result.map AttributeNameType

        unboxFn (AttributeNameType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The AttributeNameListType data model.
-}
type alias AttributeNameListType =
    List AttributeNameType


{-| The AttributeMappingType data model.
-}
type alias AttributeMappingType =
    Dict.Refined.Dict String AttributeMappingKeyType StringType


{-| The AttributeMappingKeyType data model.
-}
type AttributeMappingKeyType
    = AttributeMappingKeyType String


{-| The AttributeMappingKeyType data model.
-}
attributeMappingKeyType : Refined String AttributeMappingKeyType StringError
attributeMappingKeyType =
    let
        guardFn val =
            Refined.minLength 1 val |> Result.andThen (Refined.maxLength 32) |> Result.map AttributeMappingKeyType

        unboxFn (AttributeMappingKeyType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


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
    { secretCode : Maybe SecretCodeType, session : Maybe SessionType }


{-| The AssociateSoftwareTokenRequest data model.
-}
type alias AssociateSoftwareTokenRequest =
    { accessToken : Maybe TokenModelType, session : Maybe SessionType }


{-| The ArnType data model.
-}
type ArnType
    = ArnType String


{-| The ArnType data model.
-}
arnType : Refined String ArnType StringError
arnType =
    let
        guardFn val =
            Refined.minLength 20 val
                |> Result.andThen (Refined.maxLength 2048)
                |> Result.andThen
                    (Refined.regexMatch
                        "arn:[\\w+=/,.@-]+:[\\w+=/,.@-]+:([\\w+=/,.@-]*)?:[0-9]+:[\\w+=/,.@-]+(:[\\w+=/,.@-]+)?(:[\\w+=/,.@-]+)?"
                    )
                |> Result.map ArnType

        unboxFn (ArnType val) =
            val
    in
    Refined.define guardFn Json.Decode.string Json.Encode.string Refined.stringErrorToString unboxFn


{-| The AnalyticsMetadataType data model.
-}
type alias AnalyticsMetadataType =
    { analyticsEndpointId : Maybe StringType }


{-| The AnalyticsConfigurationType data model.
-}
type alias AnalyticsConfigurationType =
    { applicationId : HexStringType, externalId : StringType, roleArn : ArnType, userDataShared : Maybe BooleanType }


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
    { userPoolId : UserPoolIdType, username : UsernameType }


{-| The AdminUpdateUserAttributesResponse data model.
-}
type alias AdminUpdateUserAttributesResponse =
    {}


{-| The AdminUpdateUserAttributesRequest data model.
-}
type alias AdminUpdateUserAttributesRequest =
    { userAttributes : AttributeListType, userPoolId : UserPoolIdType, username : UsernameType }


{-| The AdminUpdateDeviceStatusResponse data model.
-}
type alias AdminUpdateDeviceStatusResponse =
    {}


{-| The AdminUpdateDeviceStatusRequest data model.
-}
type alias AdminUpdateDeviceStatusRequest =
    { deviceKey : DeviceKeyType
    , deviceRememberedStatus : Maybe DeviceRememberedStatusType
    , userPoolId : UserPoolIdType
    , username : UsernameType
    }


{-| The AdminUpdateAuthEventFeedbackResponse data model.
-}
type alias AdminUpdateAuthEventFeedbackResponse =
    {}


{-| The AdminUpdateAuthEventFeedbackRequest data model.
-}
type alias AdminUpdateAuthEventFeedbackRequest =
    { eventId : EventIdType, feedbackValue : FeedbackValueType, userPoolId : UserPoolIdType, username : UsernameType }


{-| The AdminSetUserSettingsResponse data model.
-}
type alias AdminSetUserSettingsResponse =
    {}


{-| The AdminSetUserSettingsRequest data model.
-}
type alias AdminSetUserSettingsRequest =
    { mfaoptions : MfaoptionListType, userPoolId : UserPoolIdType, username : UsernameType }


{-| The AdminSetUserPasswordResponse data model.
-}
type alias AdminSetUserPasswordResponse =
    {}


{-| The AdminSetUserPasswordRequest data model.
-}
type alias AdminSetUserPasswordRequest =
    { password : PasswordType, permanent : Maybe BooleanType, userPoolId : UserPoolIdType, username : UsernameType }


{-| The AdminSetUserMfapreferenceResponse data model.
-}
type alias AdminSetUserMfapreferenceResponse =
    {}


{-| The AdminSetUserMfapreferenceRequest data model.
-}
type alias AdminSetUserMfapreferenceRequest =
    { smsmfaSettings : Maybe SmsmfaSettingsType
    , softwareTokenMfaSettings : Maybe SoftwareTokenMfaSettingsType
    , userPoolId : UserPoolIdType
    , username : UsernameType
    }


{-| The AdminRespondToAuthChallengeResponse data model.
-}
type alias AdminRespondToAuthChallengeResponse =
    { authenticationResult : Maybe AuthenticationResultType
    , challengeName : Maybe ChallengeNameType
    , challengeParameters : Maybe ChallengeParametersType
    , session : Maybe SessionType
    }


{-| The AdminRespondToAuthChallengeRequest data model.
-}
type alias AdminRespondToAuthChallengeRequest =
    { analyticsMetadata : Maybe AnalyticsMetadataType
    , challengeName : ChallengeNameType
    , challengeResponses : Maybe ChallengeResponsesType
    , clientId : ClientIdType
    , contextData : Maybe ContextDataType
    , session : Maybe SessionType
    , userPoolId : UserPoolIdType
    }


{-| The AdminResetUserPasswordResponse data model.
-}
type alias AdminResetUserPasswordResponse =
    {}


{-| The AdminResetUserPasswordRequest data model.
-}
type alias AdminResetUserPasswordRequest =
    { userPoolId : UserPoolIdType, username : UsernameType }


{-| The AdminRemoveUserFromGroupRequest data model.
-}
type alias AdminRemoveUserFromGroupRequest =
    { groupName : GroupNameType, userPoolId : UserPoolIdType, username : UsernameType }


{-| The AdminListUserAuthEventsResponse data model.
-}
type alias AdminListUserAuthEventsResponse =
    { authEvents : Maybe AuthEventsType, nextToken : Maybe PaginationKey }


{-| The AdminListUserAuthEventsRequest data model.
-}
type alias AdminListUserAuthEventsRequest =
    { maxResults : Maybe QueryLimitType
    , nextToken : Maybe PaginationKey
    , userPoolId : UserPoolIdType
    , username : UsernameType
    }


{-| The AdminListGroupsForUserResponse data model.
-}
type alias AdminListGroupsForUserResponse =
    { groups : Maybe GroupListType, nextToken : Maybe PaginationKey }


{-| The AdminListGroupsForUserRequest data model.
-}
type alias AdminListGroupsForUserRequest =
    { limit : Maybe QueryLimitType
    , nextToken : Maybe PaginationKey
    , userPoolId : UserPoolIdType
    , username : UsernameType
    }


{-| The AdminListDevicesResponse data model.
-}
type alias AdminListDevicesResponse =
    { devices : Maybe DeviceListType, paginationToken : Maybe SearchPaginationTokenType }


{-| The AdminListDevicesRequest data model.
-}
type alias AdminListDevicesRequest =
    { limit : Maybe QueryLimitType
    , paginationToken : Maybe SearchPaginationTokenType
    , userPoolId : UserPoolIdType
    , username : UsernameType
    }


{-| The AdminLinkProviderForUserResponse data model.
-}
type alias AdminLinkProviderForUserResponse =
    {}


{-| The AdminLinkProviderForUserRequest data model.
-}
type alias AdminLinkProviderForUserRequest =
    { destinationUser : ProviderUserIdentifierType, sourceUser : ProviderUserIdentifierType, userPoolId : StringType }


{-| The AdminInitiateAuthResponse data model.
-}
type alias AdminInitiateAuthResponse =
    { authenticationResult : Maybe AuthenticationResultType
    , challengeName : Maybe ChallengeNameType
    , challengeParameters : Maybe ChallengeParametersType
    , session : Maybe SessionType
    }


{-| The AdminInitiateAuthRequest data model.
-}
type alias AdminInitiateAuthRequest =
    { analyticsMetadata : Maybe AnalyticsMetadataType
    , authFlow : AuthFlowType
    , authParameters : Maybe AuthParametersType
    , clientId : ClientIdType
    , clientMetadata : Maybe ClientMetadataType
    , contextData : Maybe ContextDataType
    , userPoolId : UserPoolIdType
    }


{-| The AdminGetUserResponse data model.
-}
type alias AdminGetUserResponse =
    { enabled : Maybe BooleanType
    , mfaoptions : Maybe MfaoptionListType
    , preferredMfaSetting : Maybe StringType
    , userAttributes : Maybe AttributeListType
    , userCreateDate : Maybe DateType
    , userLastModifiedDate : Maybe DateType
    , userMfasettingList : Maybe UserMfasettingListType
    , userStatus : Maybe UserStatusType
    , username : UsernameType
    }


{-| The AdminGetUserRequest data model.
-}
type alias AdminGetUserRequest =
    { userPoolId : UserPoolIdType, username : UsernameType }


{-| The AdminGetDeviceResponse data model.
-}
type alias AdminGetDeviceResponse =
    { device : DeviceType }


{-| The AdminGetDeviceRequest data model.
-}
type alias AdminGetDeviceRequest =
    { deviceKey : DeviceKeyType, userPoolId : UserPoolIdType, username : UsernameType }


{-| The AdminForgetDeviceRequest data model.
-}
type alias AdminForgetDeviceRequest =
    { deviceKey : DeviceKeyType, userPoolId : UserPoolIdType, username : UsernameType }


{-| The AdminEnableUserResponse data model.
-}
type alias AdminEnableUserResponse =
    {}


{-| The AdminEnableUserRequest data model.
-}
type alias AdminEnableUserRequest =
    { userPoolId : UserPoolIdType, username : UsernameType }


{-| The AdminDisableUserResponse data model.
-}
type alias AdminDisableUserResponse =
    {}


{-| The AdminDisableUserRequest data model.
-}
type alias AdminDisableUserRequest =
    { userPoolId : UserPoolIdType, username : UsernameType }


{-| The AdminDisableProviderForUserResponse data model.
-}
type alias AdminDisableProviderForUserResponse =
    {}


{-| The AdminDisableProviderForUserRequest data model.
-}
type alias AdminDisableProviderForUserRequest =
    { user : ProviderUserIdentifierType, userPoolId : StringType }


{-| The AdminDeleteUserRequest data model.
-}
type alias AdminDeleteUserRequest =
    { userPoolId : UserPoolIdType, username : UsernameType }


{-| The AdminDeleteUserAttributesResponse data model.
-}
type alias AdminDeleteUserAttributesResponse =
    {}


{-| The AdminDeleteUserAttributesRequest data model.
-}
type alias AdminDeleteUserAttributesRequest =
    { userAttributeNames : AttributeNameListType, userPoolId : UserPoolIdType, username : UsernameType }


{-| The AdminCreateUserUnusedAccountValidityDaysType data model.
-}
type AdminCreateUserUnusedAccountValidityDaysType
    = AdminCreateUserUnusedAccountValidityDaysType Int


{-| The AdminCreateUserUnusedAccountValidityDaysType data model.
-}
adminCreateUserUnusedAccountValidityDaysType : Refined Int AdminCreateUserUnusedAccountValidityDaysType IntError
adminCreateUserUnusedAccountValidityDaysType =
    let
        guardFn val =
            Refined.gte 0 val
                |> Result.andThen (Refined.lte 365)
                |> Result.map AdminCreateUserUnusedAccountValidityDaysType

        unboxFn (AdminCreateUserUnusedAccountValidityDaysType val) =
            val
    in
    Refined.define guardFn Json.Decode.int Json.Encode.int Refined.intErrorToString unboxFn


{-| The AdminCreateUserResponse data model.
-}
type alias AdminCreateUserResponse =
    { user : Maybe UserType }


{-| The AdminCreateUserRequest data model.
-}
type alias AdminCreateUserRequest =
    { desiredDeliveryMediums : Maybe DeliveryMediumListType
    , forceAliasCreation : Maybe ForceAliasCreation
    , messageAction : Maybe MessageActionType
    , temporaryPassword : Maybe PasswordType
    , userAttributes : Maybe AttributeListType
    , userPoolId : UserPoolIdType
    , username : UsernameType
    , validationData : Maybe AttributeListType
    }


{-| The AdminCreateUserConfigType data model.
-}
type alias AdminCreateUserConfigType =
    { allowAdminCreateUserOnly : Maybe BooleanType
    , inviteMessageTemplate : Maybe MessageTemplateType
    , unusedAccountValidityDays : Maybe AdminCreateUserUnusedAccountValidityDaysType
    }


{-| The AdminConfirmSignUpResponse data model.
-}
type alias AdminConfirmSignUpResponse =
    {}


{-| The AdminConfirmSignUpRequest data model.
-}
type alias AdminConfirmSignUpRequest =
    { userPoolId : UserPoolIdType, username : UsernameType }


{-| The AdminAddUserToGroupRequest data model.
-}
type alias AdminAddUserToGroupRequest =
    { groupName : GroupNameType, userPoolId : UserPoolIdType, username : UsernameType }


{-| The AddCustomAttributesResponse data model.
-}
type alias AddCustomAttributesResponse =
    {}


{-| The AddCustomAttributesRequest data model.
-}
type alias AddCustomAttributesRequest =
    { customAttributes : CustomAttributesListType, userPoolId : UserPoolIdType }


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
    { eventAction : AccountTakeoverEventActionType, notify : AccountTakeoverActionNotifyType }


{-| The AccountTakeoverActionNotifyType data model.
-}
type alias AccountTakeoverActionNotifyType =
    Bool


{-| The AwsaccountIdType data model.
-}
type alias AwsaccountIdType =
    String


{-| Decoder for AwsaccountIdType.
-}
awsaccountIdTypeDecoder : Decoder AwsaccountIdType
awsaccountIdTypeDecoder =
    Json.Decode.string


{-| Codec for AccountTakeoverActionNotifyType.
-}
accountTakeoverActionNotifyTypeCodec : Codec AccountTakeoverActionNotifyType
accountTakeoverActionNotifyTypeCodec =
    Codec.bool


{-| Codec for AccountTakeoverActionType.
-}
accountTakeoverActionTypeCodec : Codec AccountTakeoverActionType
accountTakeoverActionTypeCodec =
    Codec.object AccountTakeoverActionType
        |> Codec.field "EventAction" .eventAction accountTakeoverEventActionTypeCodec
        |> Codec.field "Notify" .notify accountTakeoverActionNotifyTypeCodec
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
        |> Codec.optionalField "AllowAdminCreateUserOnly" .allowAdminCreateUserOnly booleanTypeCodec
        |> Codec.optionalField "InviteMessageTemplate" .inviteMessageTemplate messageTemplateTypeCodec
        |> Codec.optionalField
            "UnusedAccountValidityDays"
            .unusedAccountValidityDays
            adminCreateUserUnusedAccountValidityDaysTypeCodec
        |> Codec.buildObject


{-| Codec for AdminCreateUserUnusedAccountValidityDaysType.
-}
adminCreateUserUnusedAccountValidityDaysTypeCodec : Codec AdminCreateUserUnusedAccountValidityDaysType
adminCreateUserUnusedAccountValidityDaysTypeCodec =
    Codec.build
        (Refined.encoder adminCreateUserUnusedAccountValidityDaysType)
        (Refined.decoder adminCreateUserUnusedAccountValidityDaysType)


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
        |> Codec.field "ApplicationId" .applicationId hexStringTypeCodec
        |> Codec.field "ExternalId" .externalId stringTypeCodec
        |> Codec.field "RoleArn" .roleArn arnTypeCodec
        |> Codec.optionalField "UserDataShared" .userDataShared booleanTypeCodec
        |> Codec.buildObject


{-| Encoder for AnalyticsMetadataType.
-}
analyticsMetadataTypeEncoder : AnalyticsMetadataType -> Value
analyticsMetadataTypeEncoder val =
    [ ( "AnalyticsEndpointId", val.analyticsEndpointId ) |> EncodeOpt.optionalField (Codec.encoder stringTypeCodec) ]
        |> EncodeOpt.objectMaySkip


{-| Codec for ArnType.
-}
arnTypeCodec : Codec ArnType
arnTypeCodec =
    Codec.build (Refined.encoder arnType) (Refined.decoder arnType)


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


{-| Codec for AttributeMappingKeyType.
-}
attributeMappingKeyTypeCodec : Codec AttributeMappingKeyType
attributeMappingKeyTypeCodec =
    Codec.build (Refined.encoder attributeMappingKeyType) (Refined.decoder attributeMappingKeyType)


{-| Codec for AttributeMappingType.
-}
attributeMappingTypeCodec : Codec AttributeMappingType
attributeMappingTypeCodec =
    Codec.build
        (Refined.dictEncoder attributeMappingKeyType (Codec.encoder stringTypeCodec))
        (Refined.dictDecoder attributeMappingKeyType (Codec.decoder stringTypeCodec))


{-| Encoder for AttributeNameListType.
-}
attributeNameListTypeEncoder : AttributeNameListType -> Value
attributeNameListTypeEncoder val =
    Json.Encode.list (Codec.encoder attributeNameTypeCodec) val


{-| Codec for AttributeNameType.
-}
attributeNameTypeCodec : Codec AttributeNameType
attributeNameTypeCodec =
    Codec.build (Refined.encoder attributeNameType) (Refined.decoder attributeNameType)


{-| Codec for AttributeType.
-}
attributeTypeCodec : Codec AttributeType
attributeTypeCodec =
    Codec.object AttributeType
        |> Codec.field "Name" .name attributeNameTypeCodec
        |> Codec.optionalField "Value" .value attributeValueTypeCodec
        |> Codec.buildObject


{-| Codec for AttributeValueType.
-}
attributeValueTypeCodec : Codec AttributeValueType
attributeValueTypeCodec =
    Codec.build (Refined.encoder attributeValueType) (Refined.decoder attributeValueType)


{-| Decoder for AuthEventType.
-}
authEventTypeDecoder : Decoder AuthEventType
authEventTypeDecoder =
    Json.Decode.succeed AuthEventType
        |> Pipeline.optional "ChallengeResponses" (Json.Decode.maybe challengeResponseListTypeDecoder) Nothing
        |> Pipeline.optional "CreationDate" (Json.Decode.maybe dateTypeDecoder) Nothing
        |> Pipeline.optional "EventContextData" (Json.Decode.maybe eventContextDataTypeDecoder) Nothing
        |> Pipeline.optional "EventFeedback" (Json.Decode.maybe eventFeedbackTypeDecoder) Nothing
        |> Pipeline.optional "EventId" (Json.Decode.maybe (Codec.decoder stringTypeCodec)) Nothing
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
    Json.Encode.dict identity (Codec.encoder stringTypeCodec) val


{-| Decoder for AuthenticationResultType.
-}
authenticationResultTypeDecoder : Decoder AuthenticationResultType
authenticationResultTypeDecoder =
    Json.Decode.succeed AuthenticationResultType
        |> Pipeline.optional "AccessToken" (Json.Decode.maybe (Codec.decoder tokenModelTypeCodec)) Nothing
        |> Pipeline.optional "ExpiresIn" (Json.Decode.maybe integerTypeDecoder) Nothing
        |> Pipeline.optional "IdToken" (Json.Decode.maybe (Codec.decoder tokenModelTypeCodec)) Nothing
        |> Pipeline.optional "NewDeviceMetadata" (Json.Decode.maybe newDeviceMetadataTypeDecoder) Nothing
        |> Pipeline.optional "RefreshToken" (Json.Decode.maybe (Codec.decoder tokenModelTypeCodec)) Nothing
        |> Pipeline.optional "TokenType" (Json.Decode.maybe (Codec.decoder stringTypeCodec)) Nothing


{-| Codec for BlockedIprangeListType.
-}
blockedIprangeListTypeCodec : Codec BlockedIprangeListType
blockedIprangeListTypeCodec =
    Codec.list stringTypeCodec


{-| Codec for BooleanType.
-}
booleanTypeCodec : Codec BooleanType
booleanTypeCodec =
    Codec.bool


{-| Codec for Csstype.
-}
csstypeCodec : Codec Csstype
csstypeCodec =
    Codec.string


{-| Decoder for CssversionType.
-}
cssversionTypeDecoder : Decoder CssversionType
cssversionTypeDecoder =
    Json.Decode.string


{-| Codec for CallbackUrlsListType.
-}
callbackUrlsListTypeCodec : Codec CallbackUrlsListType
callbackUrlsListTypeCodec =
    Codec.list redirectUrlTypeCodec


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
    Json.Decode.dict (Codec.decoder stringTypeCodec)


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
    Json.Encode.dict identity (Codec.encoder stringTypeCodec) val


{-| Codec for ClientIdType.
-}
clientIdTypeCodec : Codec ClientIdType
clientIdTypeCodec =
    Codec.build (Refined.encoder clientIdType) (Refined.decoder clientIdType)


{-| Encoder for ClientMetadataType.
-}
clientMetadataTypeEncoder : ClientMetadataType -> Value
clientMetadataTypeEncoder val =
    Json.Encode.dict identity (Codec.encoder stringTypeCodec) val


{-| Codec for ClientNameType.
-}
clientNameTypeCodec : Codec ClientNameType
clientNameTypeCodec =
    Codec.build (Refined.encoder clientNameType) (Refined.decoder clientNameType)


{-| Codec for ClientPermissionListType.
-}
clientPermissionListTypeCodec : Codec ClientPermissionListType
clientPermissionListTypeCodec =
    Codec.list clientPermissionTypeCodec


{-| Codec for ClientPermissionType.
-}
clientPermissionTypeCodec : Codec ClientPermissionType
clientPermissionTypeCodec =
    Codec.build (Refined.encoder clientPermissionType) (Refined.decoder clientPermissionType)


{-| Decoder for ClientSecretType.
-}
clientSecretTypeDecoder : Decoder ClientSecretType
clientSecretTypeDecoder =
    Refined.decoder clientSecretType


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
        |> Pipeline.optional "AttributeName" (Json.Decode.maybe (Codec.decoder attributeNameTypeCodec)) Nothing
        |> Pipeline.optional "DeliveryMedium" (Json.Decode.maybe (Codec.decoder deliveryMediumTypeCodec)) Nothing
        |> Pipeline.optional "Destination" (Json.Decode.maybe (Codec.decoder stringTypeCodec)) Nothing


{-| Decoder for CompletionMessageType.
-}
completionMessageTypeDecoder : Decoder CompletionMessageType
completionMessageTypeDecoder =
    Refined.decoder completionMessageType


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


{-| Encoder for ConfirmationCodeType.
-}
confirmationCodeTypeEncoder : ConfirmationCodeType -> Value
confirmationCodeTypeEncoder =
    Refined.encoder confirmationCodeType


{-| Encoder for ContextDataType.
-}
contextDataTypeEncoder : ContextDataType -> Value
contextDataTypeEncoder val =
    [ ( "EncodedData", val.encodedData ) |> EncodeOpt.optionalField (Codec.encoder stringTypeCodec)
    , ( "HttpHeaders", val.httpHeaders ) |> EncodeOpt.field httpHeaderListEncoder
    , ( "IpAddress", val.ipAddress ) |> EncodeOpt.field (Codec.encoder stringTypeCodec)
    , ( "ServerName", val.serverName ) |> EncodeOpt.field (Codec.encoder stringTypeCodec)
    , ( "ServerPath", val.serverPath ) |> EncodeOpt.field (Codec.encoder stringTypeCodec)
    ]
        |> EncodeOpt.objectMaySkip


{-| Codec for CustomAttributeNameType.
-}
customAttributeNameTypeCodec : Codec CustomAttributeNameType
customAttributeNameTypeCodec =
    Codec.build (Refined.encoder customAttributeNameType) (Refined.decoder customAttributeNameType)


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
        |> Codec.field "CertificateArn" .certificateArn arnTypeCodec
        |> Codec.buildObject


{-| Decoder for DateType.
-}
dateTypeDecoder : Decoder DateType
dateTypeDecoder =
    Json.Decode.string


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


{-| Codec for DescriptionType.
-}
descriptionTypeCodec : Codec DescriptionType
descriptionTypeCodec =
    Codec.build (Refined.encoder descriptionType) (Refined.decoder descriptionType)


{-| Codec for DeviceConfigurationType.
-}
deviceConfigurationTypeCodec : Codec DeviceConfigurationType
deviceConfigurationTypeCodec =
    Codec.object DeviceConfigurationType
        |> Codec.optionalField "ChallengeRequiredOnNewDevice" .challengeRequiredOnNewDevice booleanTypeCodec
        |> Codec.optionalField "DeviceOnlyRememberedOnUserPrompt" .deviceOnlyRememberedOnUserPrompt booleanTypeCodec
        |> Codec.buildObject


{-| Codec for DeviceKeyType.
-}
deviceKeyTypeCodec : Codec DeviceKeyType
deviceKeyTypeCodec =
    Codec.build (Refined.encoder deviceKeyType) (Refined.decoder deviceKeyType)


{-| Decoder for DeviceListType.
-}
deviceListTypeDecoder : Decoder DeviceListType
deviceListTypeDecoder =
    Json.Decode.list deviceTypeDecoder


{-| Encoder for DeviceNameType.
-}
deviceNameTypeEncoder : DeviceNameType -> Value
deviceNameTypeEncoder =
    Refined.encoder deviceNameType


{-| Encoder for DeviceRememberedStatusType.
-}
deviceRememberedStatusTypeEncoder : DeviceRememberedStatusType -> Value
deviceRememberedStatusTypeEncoder =
    Enum.encoder deviceRememberedStatusType


{-| Encoder for DeviceSecretVerifierConfigType.
-}
deviceSecretVerifierConfigTypeEncoder : DeviceSecretVerifierConfigType -> Value
deviceSecretVerifierConfigTypeEncoder val =
    [ ( "PasswordVerifier", val.passwordVerifier ) |> EncodeOpt.optionalField (Codec.encoder stringTypeCodec)
    , ( "Salt", val.salt ) |> EncodeOpt.optionalField (Codec.encoder stringTypeCodec)
    ]
        |> EncodeOpt.objectMaySkip


{-| Decoder for DeviceType.
-}
deviceTypeDecoder : Decoder DeviceType
deviceTypeDecoder =
    Json.Decode.succeed DeviceType
        |> Pipeline.optional "DeviceAttributes" (Json.Decode.maybe (Codec.decoder attributeListTypeCodec)) Nothing
        |> Pipeline.optional "DeviceCreateDate" (Json.Decode.maybe dateTypeDecoder) Nothing
        |> Pipeline.optional "DeviceKey" (Json.Decode.maybe (Codec.decoder deviceKeyTypeCodec)) Nothing
        |> Pipeline.optional "DeviceLastAuthenticatedDate" (Json.Decode.maybe dateTypeDecoder) Nothing
        |> Pipeline.optional "DeviceLastModifiedDate" (Json.Decode.maybe dateTypeDecoder) Nothing


{-| Decoder for DomainDescriptionType.
-}
domainDescriptionTypeDecoder : Decoder DomainDescriptionType
domainDescriptionTypeDecoder =
    Json.Decode.succeed DomainDescriptionType
        |> Pipeline.optional "AWSAccountId" (Json.Decode.maybe awsaccountIdTypeDecoder) Nothing
        |> Pipeline.optional "CloudFrontDistribution" (Json.Decode.maybe (Codec.decoder stringTypeCodec)) Nothing
        |> Pipeline.optional
            "CustomDomainConfig"
            (Json.Decode.maybe (Codec.decoder customDomainConfigTypeCodec))
            Nothing
        |> Pipeline.optional "Domain" (Json.Decode.maybe (Codec.decoder domainTypeCodec)) Nothing
        |> Pipeline.optional "S3Bucket" (Json.Decode.maybe s3BucketTypeDecoder) Nothing
        |> Pipeline.optional "Status" (Json.Decode.maybe domainStatusTypeDecoder) Nothing
        |> Pipeline.optional "UserPoolId" (Json.Decode.maybe (Codec.decoder userPoolIdTypeCodec)) Nothing
        |> Pipeline.optional "Version" (Json.Decode.maybe domainVersionTypeDecoder) Nothing


{-| Decoder for DomainStatusType.
-}
domainStatusTypeDecoder : Decoder DomainStatusType
domainStatusTypeDecoder =
    Enum.decoder domainStatusType


{-| Codec for DomainType.
-}
domainTypeCodec : Codec DomainType
domainTypeCodec =
    Codec.build (Refined.encoder domainType) (Refined.decoder domainType)


{-| Decoder for DomainVersionType.
-}
domainVersionTypeDecoder : Decoder DomainVersionType
domainVersionTypeDecoder =
    Refined.decoder domainVersionType


{-| Codec for EmailAddressType.
-}
emailAddressTypeCodec : Codec EmailAddressType
emailAddressTypeCodec =
    Codec.build (Refined.encoder emailAddressType) (Refined.decoder emailAddressType)


{-| Codec for EmailConfigurationType.
-}
emailConfigurationTypeCodec : Codec EmailConfigurationType
emailConfigurationTypeCodec =
    Codec.object EmailConfigurationType
        |> Codec.optionalField "EmailSendingAccount" .emailSendingAccount emailSendingAccountTypeCodec
        |> Codec.optionalField "ReplyToEmailAddress" .replyToEmailAddress emailAddressTypeCodec
        |> Codec.optionalField "SourceArn" .sourceArn arnTypeCodec
        |> Codec.buildObject


{-| Codec for EmailNotificationBodyType.
-}
emailNotificationBodyTypeCodec : Codec EmailNotificationBodyType
emailNotificationBodyTypeCodec =
    Codec.build (Refined.encoder emailNotificationBodyType) (Refined.decoder emailNotificationBodyType)


{-| Codec for EmailNotificationSubjectType.
-}
emailNotificationSubjectTypeCodec : Codec EmailNotificationSubjectType
emailNotificationSubjectTypeCodec =
    Codec.build (Refined.encoder emailNotificationSubjectType) (Refined.decoder emailNotificationSubjectType)


{-| Codec for EmailSendingAccountType.
-}
emailSendingAccountTypeCodec : Codec EmailSendingAccountType
emailSendingAccountTypeCodec =
    Codec.build (Enum.encoder emailSendingAccountType) (Enum.decoder emailSendingAccountType)


{-| Codec for EmailVerificationMessageByLinkType.
-}
emailVerificationMessageByLinkTypeCodec : Codec EmailVerificationMessageByLinkType
emailVerificationMessageByLinkTypeCodec =
    Codec.build
        (Refined.encoder emailVerificationMessageByLinkType)
        (Refined.decoder emailVerificationMessageByLinkType)


{-| Codec for EmailVerificationMessageType.
-}
emailVerificationMessageTypeCodec : Codec EmailVerificationMessageType
emailVerificationMessageTypeCodec =
    Codec.build (Refined.encoder emailVerificationMessageType) (Refined.decoder emailVerificationMessageType)


{-| Codec for EmailVerificationSubjectByLinkType.
-}
emailVerificationSubjectByLinkTypeCodec : Codec EmailVerificationSubjectByLinkType
emailVerificationSubjectByLinkTypeCodec =
    Codec.build
        (Refined.encoder emailVerificationSubjectByLinkType)
        (Refined.decoder emailVerificationSubjectByLinkType)


{-| Codec for EmailVerificationSubjectType.
-}
emailVerificationSubjectTypeCodec : Codec EmailVerificationSubjectType
emailVerificationSubjectTypeCodec =
    Codec.build (Refined.encoder emailVerificationSubjectType) (Refined.decoder emailVerificationSubjectType)


{-| Decoder for EventContextDataType.
-}
eventContextDataTypeDecoder : Decoder EventContextDataType
eventContextDataTypeDecoder =
    Json.Decode.succeed EventContextDataType
        |> Pipeline.optional "City" (Json.Decode.maybe (Codec.decoder stringTypeCodec)) Nothing
        |> Pipeline.optional "Country" (Json.Decode.maybe (Codec.decoder stringTypeCodec)) Nothing
        |> Pipeline.optional "DeviceName" (Json.Decode.maybe (Codec.decoder stringTypeCodec)) Nothing
        |> Pipeline.optional "IpAddress" (Json.Decode.maybe (Codec.decoder stringTypeCodec)) Nothing
        |> Pipeline.optional "Timezone" (Json.Decode.maybe (Codec.decoder stringTypeCodec)) Nothing


{-| Decoder for EventFeedbackType.
-}
eventFeedbackTypeDecoder : Decoder EventFeedbackType
eventFeedbackTypeDecoder =
    Json.Decode.succeed EventFeedbackType
        |> Pipeline.optional "FeedbackDate" (Json.Decode.maybe dateTypeDecoder) Nothing
        |> Pipeline.required "FeedbackValue" (Codec.decoder feedbackValueTypeCodec)
        |> Pipeline.required "Provider" (Codec.decoder stringTypeCodec)


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


{-| Encoder for EventIdType.
-}
eventIdTypeEncoder : EventIdType -> Value
eventIdTypeEncoder =
    Refined.encoder eventIdType


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


{-| Encoder for ForceAliasCreation.
-}
forceAliasCreationEncoder : ForceAliasCreation -> Value
forceAliasCreationEncoder val =
    Json.Encode.bool val


{-| Encoder for GenerateSecret.
-}
generateSecretEncoder : GenerateSecret -> Value
generateSecretEncoder val =
    Json.Encode.bool val


{-| Decoder for GroupListType.
-}
groupListTypeDecoder : Decoder GroupListType
groupListTypeDecoder =
    Json.Decode.list groupTypeDecoder


{-| Codec for GroupNameType.
-}
groupNameTypeCodec : Codec GroupNameType
groupNameTypeCodec =
    Codec.build (Refined.encoder groupNameType) (Refined.decoder groupNameType)


{-| Decoder for GroupType.
-}
groupTypeDecoder : Decoder GroupType
groupTypeDecoder =
    Json.Decode.succeed GroupType
        |> Pipeline.optional "CreationDate" (Json.Decode.maybe dateTypeDecoder) Nothing
        |> Pipeline.optional "Description" (Json.Decode.maybe (Codec.decoder descriptionTypeCodec)) Nothing
        |> Pipeline.optional "GroupName" (Json.Decode.maybe (Codec.decoder groupNameTypeCodec)) Nothing
        |> Pipeline.optional "LastModifiedDate" (Json.Decode.maybe dateTypeDecoder) Nothing
        |> Pipeline.optional "Precedence" (Json.Decode.maybe (Codec.decoder precedenceTypeCodec)) Nothing
        |> Pipeline.optional "RoleArn" (Json.Decode.maybe (Codec.decoder arnTypeCodec)) Nothing
        |> Pipeline.optional "UserPoolId" (Json.Decode.maybe (Codec.decoder userPoolIdTypeCodec)) Nothing


{-| Codec for HexStringType.
-}
hexStringTypeCodec : Codec HexStringType
hexStringTypeCodec =
    Codec.build (Refined.encoder hexStringType) (Refined.decoder hexStringType)


{-| Encoder for HttpHeader.
-}
httpHeaderEncoder : HttpHeader -> Value
httpHeaderEncoder val =
    [ ( "headerName", val.headerName ) |> EncodeOpt.optionalField (Codec.encoder stringTypeCodec)
    , ( "headerValue", val.headerValue ) |> EncodeOpt.optionalField (Codec.encoder stringTypeCodec)
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
        |> Pipeline.optional "CreationDate" (Json.Decode.maybe dateTypeDecoder) Nothing
        |> Pipeline.optional "IdpIdentifiers" (Json.Decode.maybe (Codec.decoder idpIdentifiersListTypeCodec)) Nothing
        |> Pipeline.optional "LastModifiedDate" (Json.Decode.maybe dateTypeDecoder) Nothing
        |> Pipeline.optional "ProviderDetails" (Json.Decode.maybe (Codec.decoder providerDetailsTypeCodec)) Nothing
        |> Pipeline.optional "ProviderName" (Json.Decode.maybe (Codec.decoder providerNameTypeCodec)) Nothing
        |> Pipeline.optional "ProviderType" (Json.Decode.maybe (Codec.decoder identityProviderTypeTypeCodec)) Nothing
        |> Pipeline.optional "UserPoolId" (Json.Decode.maybe (Codec.decoder userPoolIdTypeCodec)) Nothing


{-| Codec for IdentityProviderTypeType.
-}
identityProviderTypeTypeCodec : Codec IdentityProviderTypeType
identityProviderTypeTypeCodec =
    Codec.build (Enum.encoder identityProviderTypeType) (Enum.decoder identityProviderTypeType)


{-| Codec for IdpIdentifierType.
-}
idpIdentifierTypeCodec : Codec IdpIdentifierType
idpIdentifierTypeCodec =
    Codec.build (Refined.encoder idpIdentifierType) (Refined.decoder idpIdentifierType)


{-| Codec for IdpIdentifiersListType.
-}
idpIdentifiersListTypeCodec : Codec IdpIdentifiersListType
idpIdentifiersListTypeCodec =
    Codec.list idpIdentifierTypeCodec


{-| Encoder for ImageFileType.
-}
imageFileTypeEncoder : ImageFileType -> Value
imageFileTypeEncoder val =
    Json.Encode.string val


{-| Decoder for ImageUrlType.
-}
imageUrlTypeDecoder : Decoder ImageUrlType
imageUrlTypeDecoder =
    Json.Decode.string


{-| Decoder for IntegerType.
-}
integerTypeDecoder : Decoder IntegerType
integerTypeDecoder =
    Json.Decode.int


{-| Codec for LambdaConfigType.
-}
lambdaConfigTypeCodec : Codec LambdaConfigType
lambdaConfigTypeCodec =
    Codec.object LambdaConfigType
        |> Codec.optionalField "CreateAuthChallenge" .createAuthChallenge arnTypeCodec
        |> Codec.optionalField "CustomMessage" .customMessage arnTypeCodec
        |> Codec.optionalField "DefineAuthChallenge" .defineAuthChallenge arnTypeCodec
        |> Codec.optionalField "PostAuthentication" .postAuthentication arnTypeCodec
        |> Codec.optionalField "PostConfirmation" .postConfirmation arnTypeCodec
        |> Codec.optionalField "PreAuthentication" .preAuthentication arnTypeCodec
        |> Codec.optionalField "PreSignUp" .preSignUp arnTypeCodec
        |> Codec.optionalField "PreTokenGeneration" .preTokenGeneration arnTypeCodec
        |> Codec.optionalField "UserMigration" .userMigration arnTypeCodec
        |> Codec.optionalField "VerifyAuthChallengeResponse" .verifyAuthChallengeResponse arnTypeCodec
        |> Codec.buildObject


{-| Decoder for ListOfStringTypes.
-}
listOfStringTypesDecoder : Decoder ListOfStringTypes
listOfStringTypesDecoder =
    Json.Decode.list (Codec.decoder stringTypeCodec)


{-| Encoder for ListProvidersLimitType.
-}
listProvidersLimitTypeEncoder : ListProvidersLimitType -> Value
listProvidersLimitTypeEncoder =
    Refined.encoder listProvidersLimitType


{-| Encoder for ListResourceServersLimitType.
-}
listResourceServersLimitTypeEncoder : ListResourceServersLimitType -> Value
listResourceServersLimitTypeEncoder =
    Refined.encoder listResourceServersLimitType


{-| Codec for LogoutUrlsListType.
-}
logoutUrlsListTypeCodec : Codec LogoutUrlsListType
logoutUrlsListTypeCodec =
    Codec.list redirectUrlTypeCodec


{-| Decoder for LongType.
-}
longTypeDecoder : Decoder LongType
longTypeDecoder =
    Json.Decode.int


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
        |> Codec.optionalField "AttributeName" .attributeName attributeNameTypeCodec
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
        |> Codec.optionalField "EmailMessage" .emailMessage emailVerificationMessageTypeCodec
        |> Codec.optionalField "EmailSubject" .emailSubject emailVerificationSubjectTypeCodec
        |> Codec.optionalField "SMSMessage" .smsmessage smsVerificationMessageTypeCodec
        |> Codec.buildObject


{-| Decoder for NewDeviceMetadataType.
-}
newDeviceMetadataTypeDecoder : Decoder NewDeviceMetadataType
newDeviceMetadataTypeDecoder =
    Json.Decode.succeed NewDeviceMetadataType
        |> Pipeline.optional "DeviceGroupKey" (Json.Decode.maybe (Codec.decoder stringTypeCodec)) Nothing
        |> Pipeline.optional "DeviceKey" (Json.Decode.maybe (Codec.decoder deviceKeyTypeCodec)) Nothing


{-| Codec for NotifyConfigurationType.
-}
notifyConfigurationTypeCodec : Codec NotifyConfigurationType
notifyConfigurationTypeCodec =
    Codec.object NotifyConfigurationType
        |> Codec.optionalField "BlockEmail" .blockEmail notifyEmailTypeCodec
        |> Codec.optionalField "From" .from stringTypeCodec
        |> Codec.optionalField "MfaEmail" .mfaEmail notifyEmailTypeCodec
        |> Codec.optionalField "NoActionEmail" .noActionEmail notifyEmailTypeCodec
        |> Codec.optionalField "ReplyTo" .replyTo stringTypeCodec
        |> Codec.field "SourceArn" .sourceArn arnTypeCodec
        |> Codec.buildObject


{-| Codec for NotifyEmailType.
-}
notifyEmailTypeCodec : Codec NotifyEmailType
notifyEmailTypeCodec =
    Codec.object NotifyEmailType
        |> Codec.optionalField "HtmlBody" .htmlBody emailNotificationBodyTypeCodec
        |> Codec.field "Subject" .subject emailNotificationSubjectTypeCodec
        |> Codec.optionalField "TextBody" .textBody emailNotificationBodyTypeCodec
        |> Codec.buildObject


{-| Codec for NumberAttributeConstraintsType.
-}
numberAttributeConstraintsTypeCodec : Codec NumberAttributeConstraintsType
numberAttributeConstraintsTypeCodec =
    Codec.object NumberAttributeConstraintsType
        |> Codec.optionalField "MaxValue" .maxValue stringTypeCodec
        |> Codec.optionalField "MinValue" .minValue stringTypeCodec
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


{-| Codec for PaginationKey.
-}
paginationKeyCodec : Codec PaginationKey
paginationKeyCodec =
    Codec.build (Refined.encoder paginationKey) (Refined.decoder paginationKey)


{-| Codec for PaginationKeyType.
-}
paginationKeyTypeCodec : Codec PaginationKeyType
paginationKeyTypeCodec =
    Codec.build (Refined.encoder paginationKeyType) (Refined.decoder paginationKeyType)


{-| Codec for PasswordPolicyMinLengthType.
-}
passwordPolicyMinLengthTypeCodec : Codec PasswordPolicyMinLengthType
passwordPolicyMinLengthTypeCodec =
    Codec.build (Refined.encoder passwordPolicyMinLengthType) (Refined.decoder passwordPolicyMinLengthType)


{-| Codec for PasswordPolicyType.
-}
passwordPolicyTypeCodec : Codec PasswordPolicyType
passwordPolicyTypeCodec =
    Codec.object PasswordPolicyType
        |> Codec.optionalField "MinimumLength" .minimumLength passwordPolicyMinLengthTypeCodec
        |> Codec.optionalField "RequireLowercase" .requireLowercase booleanTypeCodec
        |> Codec.optionalField "RequireNumbers" .requireNumbers booleanTypeCodec
        |> Codec.optionalField "RequireSymbols" .requireSymbols booleanTypeCodec
        |> Codec.optionalField "RequireUppercase" .requireUppercase booleanTypeCodec
        |> Codec.optionalField
            "TemporaryPasswordValidityDays"
            .temporaryPasswordValidityDays
            temporaryPasswordValidityDaysTypeCodec
        |> Codec.buildObject


{-| Encoder for PasswordType.
-}
passwordTypeEncoder : PasswordType -> Value
passwordTypeEncoder =
    Refined.encoder passwordType


{-| Encoder for PoolQueryLimitType.
-}
poolQueryLimitTypeEncoder : PoolQueryLimitType -> Value
poolQueryLimitTypeEncoder =
    Refined.encoder poolQueryLimitType


{-| Decoder for PreSignedUrlType.
-}
preSignedUrlTypeDecoder : Decoder PreSignedUrlType
preSignedUrlTypeDecoder =
    Refined.decoder preSignedUrlType


{-| Codec for PrecedenceType.
-}
precedenceTypeCodec : Codec PrecedenceType
precedenceTypeCodec =
    Codec.build (Refined.encoder precedenceType) (Refined.decoder precedenceType)


{-| Decoder for ProviderDescription.
-}
providerDescriptionDecoder : Decoder ProviderDescription
providerDescriptionDecoder =
    Json.Decode.succeed ProviderDescription
        |> Pipeline.optional "CreationDate" (Json.Decode.maybe dateTypeDecoder) Nothing
        |> Pipeline.optional "LastModifiedDate" (Json.Decode.maybe dateTypeDecoder) Nothing
        |> Pipeline.optional "ProviderName" (Json.Decode.maybe (Codec.decoder providerNameTypeCodec)) Nothing
        |> Pipeline.optional "ProviderType" (Json.Decode.maybe (Codec.decoder identityProviderTypeTypeCodec)) Nothing


{-| Codec for ProviderDetailsType.
-}
providerDetailsTypeCodec : Codec ProviderDetailsType
providerDetailsTypeCodec =
    Codec.dict stringTypeCodec


{-| Codec for ProviderNameType.
-}
providerNameTypeCodec : Codec ProviderNameType
providerNameTypeCodec =
    Codec.build (Refined.encoder providerNameType) (Refined.decoder providerNameType)


{-| Encoder for ProviderNameTypeV1.
-}
providerNameTypeV1Encoder : ProviderNameTypeV1 -> Value
providerNameTypeV1Encoder =
    Refined.encoder providerNameTypeV1


{-| Encoder for ProviderUserIdentifierType.
-}
providerUserIdentifierTypeEncoder : ProviderUserIdentifierType -> Value
providerUserIdentifierTypeEncoder val =
    [ ( "ProviderAttributeName", val.providerAttributeName ) |> EncodeOpt.optionalField (Codec.encoder stringTypeCodec)
    , ( "ProviderAttributeValue", val.providerAttributeValue )
        |> EncodeOpt.optionalField (Codec.encoder stringTypeCodec)
    , ( "ProviderName", val.providerName ) |> EncodeOpt.optionalField (Codec.encoder providerNameTypeCodec)
    ]
        |> EncodeOpt.objectMaySkip


{-| Decoder for ProvidersListType.
-}
providersListTypeDecoder : Decoder ProvidersListType
providersListTypeDecoder =
    Json.Decode.list providerDescriptionDecoder


{-| Encoder for QueryLimit.
-}
queryLimitEncoder : QueryLimit -> Value
queryLimitEncoder =
    Refined.encoder queryLimit


{-| Encoder for QueryLimitType.
-}
queryLimitTypeEncoder : QueryLimitType -> Value
queryLimitTypeEncoder =
    Refined.encoder queryLimitType


{-| Codec for RedirectUrlType.
-}
redirectUrlTypeCodec : Codec RedirectUrlType
redirectUrlTypeCodec =
    Codec.build (Refined.encoder redirectUrlType) (Refined.decoder redirectUrlType)


{-| Codec for RefreshTokenValidityType.
-}
refreshTokenValidityTypeCodec : Codec RefreshTokenValidityType
refreshTokenValidityTypeCodec =
    Codec.build (Refined.encoder refreshTokenValidityType) (Refined.decoder refreshTokenValidityType)


{-| Codec for ResourceServerIdentifierType.
-}
resourceServerIdentifierTypeCodec : Codec ResourceServerIdentifierType
resourceServerIdentifierTypeCodec =
    Codec.build (Refined.encoder resourceServerIdentifierType) (Refined.decoder resourceServerIdentifierType)


{-| Codec for ResourceServerNameType.
-}
resourceServerNameTypeCodec : Codec ResourceServerNameType
resourceServerNameTypeCodec =
    Codec.build (Refined.encoder resourceServerNameType) (Refined.decoder resourceServerNameType)


{-| Codec for ResourceServerScopeDescriptionType.
-}
resourceServerScopeDescriptionTypeCodec : Codec ResourceServerScopeDescriptionType
resourceServerScopeDescriptionTypeCodec =
    Codec.build
        (Refined.encoder resourceServerScopeDescriptionType)
        (Refined.decoder resourceServerScopeDescriptionType)


{-| Codec for ResourceServerScopeListType.
-}
resourceServerScopeListTypeCodec : Codec ResourceServerScopeListType
resourceServerScopeListTypeCodec =
    Codec.list resourceServerScopeTypeCodec


{-| Codec for ResourceServerScopeNameType.
-}
resourceServerScopeNameTypeCodec : Codec ResourceServerScopeNameType
resourceServerScopeNameTypeCodec =
    Codec.build (Refined.encoder resourceServerScopeNameType) (Refined.decoder resourceServerScopeNameType)


{-| Codec for ResourceServerScopeType.
-}
resourceServerScopeTypeCodec : Codec ResourceServerScopeType
resourceServerScopeTypeCodec =
    Codec.object ResourceServerScopeType
        |> Codec.field "ScopeDescription" .scopeDescription resourceServerScopeDescriptionTypeCodec
        |> Codec.field "ScopeName" .scopeName resourceServerScopeNameTypeCodec
        |> Codec.buildObject


{-| Decoder for ResourceServerType.
-}
resourceServerTypeDecoder : Decoder ResourceServerType
resourceServerTypeDecoder =
    Json.Decode.succeed ResourceServerType
        |> Pipeline.optional "Identifier" (Json.Decode.maybe (Codec.decoder resourceServerIdentifierTypeCodec)) Nothing
        |> Pipeline.optional "Name" (Json.Decode.maybe (Codec.decoder resourceServerNameTypeCodec)) Nothing
        |> Pipeline.optional "Scopes" (Json.Decode.maybe (Codec.decoder resourceServerScopeListTypeCodec)) Nothing
        |> Pipeline.optional "UserPoolId" (Json.Decode.maybe (Codec.decoder userPoolIdTypeCodec)) Nothing


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
        |> Pipeline.optional "ClientId" (Json.Decode.maybe (Codec.decoder clientIdTypeCodec)) Nothing
        |> Pipeline.optional
            "CompromisedCredentialsRiskConfiguration"
            (Json.Decode.maybe (Codec.decoder compromisedCredentialsRiskConfigurationTypeCodec))
            Nothing
        |> Pipeline.optional "LastModifiedDate" (Json.Decode.maybe dateTypeDecoder) Nothing
        |> Pipeline.optional
            "RiskExceptionConfiguration"
            (Json.Decode.maybe (Codec.decoder riskExceptionConfigurationTypeCodec))
            Nothing
        |> Pipeline.optional "UserPoolId" (Json.Decode.maybe (Codec.decoder userPoolIdTypeCodec)) Nothing


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


{-| Decoder for S3BucketType.
-}
s3BucketTypeDecoder : Decoder S3BucketType
s3BucketTypeDecoder =
    Refined.decoder s3BucketType


{-| Encoder for SmsmfaSettingsType.
-}
smsmfaSettingsTypeEncoder : SmsmfaSettingsType -> Value
smsmfaSettingsTypeEncoder val =
    [ ( "Enabled", val.enabled ) |> EncodeOpt.optionalField (Codec.encoder booleanTypeCodec)
    , ( "PreferredMfa", val.preferredMfa ) |> EncodeOpt.optionalField (Codec.encoder booleanTypeCodec)
    ]
        |> EncodeOpt.objectMaySkip


{-| Codec for SchemaAttributeType.
-}
schemaAttributeTypeCodec : Codec SchemaAttributeType
schemaAttributeTypeCodec =
    Codec.object SchemaAttributeType
        |> Codec.optionalField "AttributeDataType" .attributeDataType attributeDataTypeCodec
        |> Codec.optionalField "DeveloperOnlyAttribute" .developerOnlyAttribute booleanTypeCodec
        |> Codec.optionalField "Mutable" .mutable booleanTypeCodec
        |> Codec.optionalField "Name" .name customAttributeNameTypeCodec
        |> Codec.optionalField
            "NumberAttributeConstraints"
            .numberAttributeConstraints
            numberAttributeConstraintsTypeCodec
        |> Codec.optionalField "Required" .required booleanTypeCodec
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
    Codec.list scopeTypeCodec


{-| Codec for ScopeType.
-}
scopeTypeCodec : Codec ScopeType
scopeTypeCodec =
    Codec.build (Refined.encoder scopeType) (Refined.decoder scopeType)


{-| Codec for SearchPaginationTokenType.
-}
searchPaginationTokenTypeCodec : Codec SearchPaginationTokenType
searchPaginationTokenTypeCodec =
    Codec.build (Refined.encoder searchPaginationTokenType) (Refined.decoder searchPaginationTokenType)


{-| Encoder for SearchedAttributeNamesListType.
-}
searchedAttributeNamesListTypeEncoder : SearchedAttributeNamesListType -> Value
searchedAttributeNamesListTypeEncoder val =
    Json.Encode.list (Codec.encoder attributeNameTypeCodec) val


{-| Decoder for SecretCodeType.
-}
secretCodeTypeDecoder : Decoder SecretCodeType
secretCodeTypeDecoder =
    Refined.decoder secretCodeType


{-| Encoder for SecretHashType.
-}
secretHashTypeEncoder : SecretHashType -> Value
secretHashTypeEncoder =
    Refined.encoder secretHashType


{-| Codec for SessionType.
-}
sessionTypeCodec : Codec SessionType
sessionTypeCodec =
    Codec.build (Refined.encoder sessionType) (Refined.decoder sessionType)


{-| Codec for SkippedIprangeListType.
-}
skippedIprangeListTypeCodec : Codec SkippedIprangeListType
skippedIprangeListTypeCodec =
    Codec.list stringTypeCodec


{-| Codec for SmsConfigurationType.
-}
smsConfigurationTypeCodec : Codec SmsConfigurationType
smsConfigurationTypeCodec =
    Codec.object SmsConfigurationType
        |> Codec.optionalField "ExternalId" .externalId stringTypeCodec
        |> Codec.field "SnsCallerArn" .snsCallerArn arnTypeCodec
        |> Codec.buildObject


{-| Codec for SmsMfaConfigType.
-}
smsMfaConfigTypeCodec : Codec SmsMfaConfigType
smsMfaConfigTypeCodec =
    Codec.object SmsMfaConfigType
        |> Codec.optionalField "SmsAuthenticationMessage" .smsAuthenticationMessage smsVerificationMessageTypeCodec
        |> Codec.optionalField "SmsConfiguration" .smsConfiguration smsConfigurationTypeCodec
        |> Codec.buildObject


{-| Codec for SmsVerificationMessageType.
-}
smsVerificationMessageTypeCodec : Codec SmsVerificationMessageType
smsVerificationMessageTypeCodec =
    Codec.build (Refined.encoder smsVerificationMessageType) (Refined.decoder smsVerificationMessageType)


{-| Encoder for SoftwareTokenMfauserCodeType.
-}
softwareTokenMfauserCodeTypeEncoder : SoftwareTokenMfauserCodeType -> Value
softwareTokenMfauserCodeTypeEncoder =
    Refined.encoder softwareTokenMfauserCodeType


{-| Codec for SoftwareTokenMfaConfigType.
-}
softwareTokenMfaConfigTypeCodec : Codec SoftwareTokenMfaConfigType
softwareTokenMfaConfigTypeCodec =
    Codec.object SoftwareTokenMfaConfigType
        |> Codec.optionalField "Enabled" .enabled booleanTypeCodec
        |> Codec.buildObject


{-| Encoder for SoftwareTokenMfaSettingsType.
-}
softwareTokenMfaSettingsTypeEncoder : SoftwareTokenMfaSettingsType -> Value
softwareTokenMfaSettingsTypeEncoder val =
    [ ( "Enabled", val.enabled ) |> EncodeOpt.optionalField (Codec.encoder booleanTypeCodec)
    , ( "PreferredMfa", val.preferredMfa ) |> EncodeOpt.optionalField (Codec.encoder booleanTypeCodec)
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
        |> Codec.optionalField "MaxLength" .maxLength stringTypeCodec
        |> Codec.optionalField "MinLength" .minLength stringTypeCodec
        |> Codec.buildObject


{-| Codec for StringType.
-}
stringTypeCodec : Codec StringType
stringTypeCodec =
    Codec.string


{-| Codec for SupportedIdentityProvidersListType.
-}
supportedIdentityProvidersListTypeCodec : Codec SupportedIdentityProvidersListType
supportedIdentityProvidersListTypeCodec =
    Codec.list providerNameTypeCodec


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


{-| Codec for TemporaryPasswordValidityDaysType.
-}
temporaryPasswordValidityDaysTypeCodec : Codec TemporaryPasswordValidityDaysType
temporaryPasswordValidityDaysTypeCodec =
    Codec.build (Refined.encoder temporaryPasswordValidityDaysType) (Refined.decoder temporaryPasswordValidityDaysType)


{-| Codec for TokenModelType.
-}
tokenModelTypeCodec : Codec TokenModelType
tokenModelTypeCodec =
    Codec.build (Refined.encoder tokenModelType) (Refined.decoder tokenModelType)


{-| Decoder for UicustomizationType.
-}
uicustomizationTypeDecoder : Decoder UicustomizationType
uicustomizationTypeDecoder =
    Json.Decode.succeed UicustomizationType
        |> Pipeline.optional "CSS" (Json.Decode.maybe (Codec.decoder csstypeCodec)) Nothing
        |> Pipeline.optional "CSSVersion" (Json.Decode.maybe cssversionTypeDecoder) Nothing
        |> Pipeline.optional "ClientId" (Json.Decode.maybe (Codec.decoder clientIdTypeCodec)) Nothing
        |> Pipeline.optional "CreationDate" (Json.Decode.maybe dateTypeDecoder) Nothing
        |> Pipeline.optional "ImageUrl" (Json.Decode.maybe imageUrlTypeDecoder) Nothing
        |> Pipeline.optional "LastModifiedDate" (Json.Decode.maybe dateTypeDecoder) Nothing
        |> Pipeline.optional "UserPoolId" (Json.Decode.maybe (Codec.decoder userPoolIdTypeCodec)) Nothing


{-| Encoder for UserContextDataType.
-}
userContextDataTypeEncoder : UserContextDataType -> Value
userContextDataTypeEncoder val =
    [ ( "EncodedData", val.encodedData ) |> EncodeOpt.optionalField (Codec.encoder stringTypeCodec) ]
        |> EncodeOpt.objectMaySkip


{-| Encoder for UserFilterType.
-}
userFilterTypeEncoder : UserFilterType -> Value
userFilterTypeEncoder =
    Refined.encoder userFilterType


{-| Codec for UserImportJobIdType.
-}
userImportJobIdTypeCodec : Codec UserImportJobIdType
userImportJobIdTypeCodec =
    Codec.build (Refined.encoder userImportJobIdType) (Refined.decoder userImportJobIdType)


{-| Codec for UserImportJobNameType.
-}
userImportJobNameTypeCodec : Codec UserImportJobNameType
userImportJobNameTypeCodec =
    Codec.build (Refined.encoder userImportJobNameType) (Refined.decoder userImportJobNameType)


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
        |> Pipeline.optional "CloudWatchLogsRoleArn" (Json.Decode.maybe (Codec.decoder arnTypeCodec)) Nothing
        |> Pipeline.optional "CompletionDate" (Json.Decode.maybe dateTypeDecoder) Nothing
        |> Pipeline.optional "CompletionMessage" (Json.Decode.maybe completionMessageTypeDecoder) Nothing
        |> Pipeline.optional "CreationDate" (Json.Decode.maybe dateTypeDecoder) Nothing
        |> Pipeline.optional "FailedUsers" (Json.Decode.maybe longTypeDecoder) Nothing
        |> Pipeline.optional "ImportedUsers" (Json.Decode.maybe longTypeDecoder) Nothing
        |> Pipeline.optional "JobId" (Json.Decode.maybe (Codec.decoder userImportJobIdTypeCodec)) Nothing
        |> Pipeline.optional "JobName" (Json.Decode.maybe (Codec.decoder userImportJobNameTypeCodec)) Nothing
        |> Pipeline.optional "PreSignedUrl" (Json.Decode.maybe preSignedUrlTypeDecoder) Nothing
        |> Pipeline.optional "SkippedUsers" (Json.Decode.maybe longTypeDecoder) Nothing
        |> Pipeline.optional "StartDate" (Json.Decode.maybe dateTypeDecoder) Nothing
        |> Pipeline.optional "Status" (Json.Decode.maybe userImportJobStatusTypeDecoder) Nothing
        |> Pipeline.optional "UserPoolId" (Json.Decode.maybe (Codec.decoder userPoolIdTypeCodec)) Nothing


{-| Decoder for UserImportJobsListType.
-}
userImportJobsListTypeDecoder : Decoder UserImportJobsListType
userImportJobsListTypeDecoder =
    Json.Decode.list userImportJobTypeDecoder


{-| Decoder for UserMfasettingListType.
-}
userMfasettingListTypeDecoder : Decoder UserMfasettingListType
userMfasettingListTypeDecoder =
    Json.Decode.list (Codec.decoder stringTypeCodec)


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
        |> Pipeline.optional "ClientId" (Json.Decode.maybe (Codec.decoder clientIdTypeCodec)) Nothing
        |> Pipeline.optional "ClientName" (Json.Decode.maybe (Codec.decoder clientNameTypeCodec)) Nothing
        |> Pipeline.optional "UserPoolId" (Json.Decode.maybe (Codec.decoder userPoolIdTypeCodec)) Nothing


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
        |> Pipeline.optional
            "AllowedOAuthFlowsUserPoolClient"
            (Json.Decode.maybe (Codec.decoder booleanTypeCodec))
            Nothing
        |> Pipeline.optional "AllowedOAuthScopes" (Json.Decode.maybe (Codec.decoder scopeListTypeCodec)) Nothing
        |> Pipeline.optional
            "AnalyticsConfiguration"
            (Json.Decode.maybe (Codec.decoder analyticsConfigurationTypeCodec))
            Nothing
        |> Pipeline.optional "CallbackURLs" (Json.Decode.maybe (Codec.decoder callbackUrlsListTypeCodec)) Nothing
        |> Pipeline.optional "ClientId" (Json.Decode.maybe (Codec.decoder clientIdTypeCodec)) Nothing
        |> Pipeline.optional "ClientName" (Json.Decode.maybe (Codec.decoder clientNameTypeCodec)) Nothing
        |> Pipeline.optional "ClientSecret" (Json.Decode.maybe clientSecretTypeDecoder) Nothing
        |> Pipeline.optional "CreationDate" (Json.Decode.maybe dateTypeDecoder) Nothing
        |> Pipeline.optional "DefaultRedirectURI" (Json.Decode.maybe (Codec.decoder redirectUrlTypeCodec)) Nothing
        |> Pipeline.optional
            "ExplicitAuthFlows"
            (Json.Decode.maybe (Codec.decoder explicitAuthFlowsListTypeCodec))
            Nothing
        |> Pipeline.optional "LastModifiedDate" (Json.Decode.maybe dateTypeDecoder) Nothing
        |> Pipeline.optional "LogoutURLs" (Json.Decode.maybe (Codec.decoder logoutUrlsListTypeCodec)) Nothing
        |> Pipeline.optional "ReadAttributes" (Json.Decode.maybe (Codec.decoder clientPermissionListTypeCodec)) Nothing
        |> Pipeline.optional
            "RefreshTokenValidity"
            (Json.Decode.maybe (Codec.decoder refreshTokenValidityTypeCodec))
            Nothing
        |> Pipeline.optional
            "SupportedIdentityProviders"
            (Json.Decode.maybe (Codec.decoder supportedIdentityProvidersListTypeCodec))
            Nothing
        |> Pipeline.optional "UserPoolId" (Json.Decode.maybe (Codec.decoder userPoolIdTypeCodec)) Nothing
        |> Pipeline.optional "WriteAttributes" (Json.Decode.maybe (Codec.decoder clientPermissionListTypeCodec)) Nothing


{-| Decoder for UserPoolDescriptionType.
-}
userPoolDescriptionTypeDecoder : Decoder UserPoolDescriptionType
userPoolDescriptionTypeDecoder =
    Json.Decode.succeed UserPoolDescriptionType
        |> Pipeline.optional "CreationDate" (Json.Decode.maybe dateTypeDecoder) Nothing
        |> Pipeline.optional "Id" (Json.Decode.maybe (Codec.decoder userPoolIdTypeCodec)) Nothing
        |> Pipeline.optional "LambdaConfig" (Json.Decode.maybe (Codec.decoder lambdaConfigTypeCodec)) Nothing
        |> Pipeline.optional "LastModifiedDate" (Json.Decode.maybe dateTypeDecoder) Nothing
        |> Pipeline.optional "Name" (Json.Decode.maybe (Codec.decoder userPoolNameTypeCodec)) Nothing
        |> Pipeline.optional "Status" (Json.Decode.maybe statusTypeDecoder) Nothing


{-| Codec for UserPoolIdType.
-}
userPoolIdTypeCodec : Codec UserPoolIdType
userPoolIdTypeCodec =
    Codec.build (Refined.encoder userPoolIdType) (Refined.decoder userPoolIdType)


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


{-| Codec for UserPoolNameType.
-}
userPoolNameTypeCodec : Codec UserPoolNameType
userPoolNameTypeCodec =
    Codec.build (Refined.encoder userPoolNameType) (Refined.decoder userPoolNameType)


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
    Json.Encode.list (Codec.encoder tagKeysTypeCodec) val


{-| Codec for UserPoolTagsType.
-}
userPoolTagsTypeCodec : Codec UserPoolTagsType
userPoolTagsTypeCodec =
    Codec.build
        (Refined.dictEncoder tagKeysType (Codec.encoder tagValueTypeCodec))
        (Refined.dictDecoder tagKeysType (Codec.decoder tagValueTypeCodec))


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
        |> Pipeline.optional "Arn" (Json.Decode.maybe (Codec.decoder arnTypeCodec)) Nothing
        |> Pipeline.optional
            "AutoVerifiedAttributes"
            (Json.Decode.maybe (Codec.decoder verifiedAttributesListTypeCodec))
            Nothing
        |> Pipeline.optional "CreationDate" (Json.Decode.maybe dateTypeDecoder) Nothing
        |> Pipeline.optional "CustomDomain" (Json.Decode.maybe (Codec.decoder domainTypeCodec)) Nothing
        |> Pipeline.optional
            "DeviceConfiguration"
            (Json.Decode.maybe (Codec.decoder deviceConfigurationTypeCodec))
            Nothing
        |> Pipeline.optional "Domain" (Json.Decode.maybe (Codec.decoder domainTypeCodec)) Nothing
        |> Pipeline.optional
            "EmailConfiguration"
            (Json.Decode.maybe (Codec.decoder emailConfigurationTypeCodec))
            Nothing
        |> Pipeline.optional "EmailConfigurationFailure" (Json.Decode.maybe (Codec.decoder stringTypeCodec)) Nothing
        |> Pipeline.optional
            "EmailVerificationMessage"
            (Json.Decode.maybe (Codec.decoder emailVerificationMessageTypeCodec))
            Nothing
        |> Pipeline.optional
            "EmailVerificationSubject"
            (Json.Decode.maybe (Codec.decoder emailVerificationSubjectTypeCodec))
            Nothing
        |> Pipeline.optional "EstimatedNumberOfUsers" (Json.Decode.maybe integerTypeDecoder) Nothing
        |> Pipeline.optional "Id" (Json.Decode.maybe (Codec.decoder userPoolIdTypeCodec)) Nothing
        |> Pipeline.optional "LambdaConfig" (Json.Decode.maybe (Codec.decoder lambdaConfigTypeCodec)) Nothing
        |> Pipeline.optional "LastModifiedDate" (Json.Decode.maybe dateTypeDecoder) Nothing
        |> Pipeline.optional "MfaConfiguration" (Json.Decode.maybe (Codec.decoder userPoolMfaTypeCodec)) Nothing
        |> Pipeline.optional "Name" (Json.Decode.maybe (Codec.decoder userPoolNameTypeCodec)) Nothing
        |> Pipeline.optional "Policies" (Json.Decode.maybe (Codec.decoder userPoolPolicyTypeCodec)) Nothing
        |> Pipeline.optional
            "SchemaAttributes"
            (Json.Decode.maybe (Codec.decoder schemaAttributesListTypeCodec))
            Nothing
        |> Pipeline.optional
            "SmsAuthenticationMessage"
            (Json.Decode.maybe (Codec.decoder smsVerificationMessageTypeCodec))
            Nothing
        |> Pipeline.optional "SmsConfiguration" (Json.Decode.maybe (Codec.decoder smsConfigurationTypeCodec)) Nothing
        |> Pipeline.optional "SmsConfigurationFailure" (Json.Decode.maybe (Codec.decoder stringTypeCodec)) Nothing
        |> Pipeline.optional
            "SmsVerificationMessage"
            (Json.Decode.maybe (Codec.decoder smsVerificationMessageTypeCodec))
            Nothing
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
        |> Pipeline.optional "Enabled" (Json.Decode.maybe (Codec.decoder booleanTypeCodec)) Nothing
        |> Pipeline.optional "MFAOptions" (Json.Decode.maybe (Codec.decoder mfaoptionListTypeCodec)) Nothing
        |> Pipeline.optional "UserCreateDate" (Json.Decode.maybe dateTypeDecoder) Nothing
        |> Pipeline.optional "UserLastModifiedDate" (Json.Decode.maybe dateTypeDecoder) Nothing
        |> Pipeline.optional "UserStatus" (Json.Decode.maybe userStatusTypeDecoder) Nothing
        |> Pipeline.optional "Username" (Json.Decode.maybe (Codec.decoder usernameTypeCodec)) Nothing


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


{-| Codec for UsernameType.
-}
usernameTypeCodec : Codec UsernameType
usernameTypeCodec =
    Codec.build (Refined.encoder usernameType) (Refined.decoder usernameType)


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
        |> Codec.optionalField "EmailMessage" .emailMessage emailVerificationMessageTypeCodec
        |> Codec.optionalField "EmailMessageByLink" .emailMessageByLink emailVerificationMessageByLinkTypeCodec
        |> Codec.optionalField "EmailSubject" .emailSubject emailVerificationSubjectTypeCodec
        |> Codec.optionalField "EmailSubjectByLink" .emailSubjectByLink emailVerificationSubjectByLinkTypeCodec
        |> Codec.optionalField "SmsMessage" .smsMessage smsVerificationMessageTypeCodec
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
