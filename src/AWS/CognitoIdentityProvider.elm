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
    , AdminCreateUserResponse, AdminDeleteUserAttributesRequest, AdminDeleteUserAttributesResponse, AdminDeleteUserRequest
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
    , AuthEventType, AuthEventsType, AuthFlowType(..), AuthParametersType, AuthenticationResultType, AwsaccountIdType, BlockedIprangeListType
    , BooleanType, CallbackUrlsListType, ChallengeName(..), ChallengeNameType(..), ChallengeParametersType, ChallengeResponse(..)
    , ChallengeResponseListType, ChallengeResponseType, ChallengeResponsesType, ChangePasswordRequest, ChangePasswordResponse
    , ClientMetadataType, ClientPermissionListType, CodeDeliveryDetailsListType, CodeDeliveryDetailsType
    , CompromisedCredentialsActionsType, CompromisedCredentialsEventActionType(..), CompromisedCredentialsRiskConfigurationType
    , ConfirmDeviceRequest, ConfirmDeviceResponse, ConfirmForgotPasswordRequest, ConfirmForgotPasswordResponse, ConfirmSignUpRequest
    , ConfirmSignUpResponse, ContextDataType, CreateGroupRequest, CreateGroupResponse, CreateIdentityProviderRequest
    , CreateIdentityProviderResponse, CreateResourceServerRequest, CreateResourceServerResponse, CreateUserImportJobRequest
    , CreateUserImportJobResponse, CreateUserPoolClientRequest, CreateUserPoolClientResponse, CreateUserPoolDomainRequest
    , CreateUserPoolDomainResponse, CreateUserPoolRequest, CreateUserPoolResponse, Csstype, CssversionType, CustomAttributesListType
    , CustomDomainConfigType, DateType, DefaultEmailOptionType(..), DeleteGroupRequest, DeleteIdentityProviderRequest
    , DeleteResourceServerRequest, DeleteUserAttributesRequest, DeleteUserAttributesResponse, DeleteUserPoolClientRequest
    , DeleteUserPoolDomainRequest, DeleteUserPoolDomainResponse, DeleteUserPoolRequest, DeleteUserRequest, DeliveryMediumListType
    , DeliveryMediumType(..), DescribeIdentityProviderRequest, DescribeIdentityProviderResponse, DescribeResourceServerRequest
    , DescribeResourceServerResponse, DescribeRiskConfigurationRequest, DescribeRiskConfigurationResponse
    , DescribeUserImportJobRequest, DescribeUserImportJobResponse, DescribeUserPoolClientRequest, DescribeUserPoolClientResponse
    , DescribeUserPoolDomainRequest, DescribeUserPoolDomainResponse, DescribeUserPoolRequest, DescribeUserPoolResponse
    , DeviceConfigurationType, DeviceListType, DeviceRememberedStatusType(..), DeviceSecretVerifierConfigType, DeviceType
    , DomainDescriptionType, DomainStatusType(..), EmailConfigurationType, EmailSendingAccountType(..), EventContextDataType, EventFeedbackType
    , EventFilterType(..), EventFiltersType, EventResponseType(..), EventRiskType, EventType(..), ExplicitAuthFlowsListType, ExplicitAuthFlowsType(..)
    , FeedbackValueType(..), ForceAliasCreation, ForgetDeviceRequest, ForgotPasswordRequest, ForgotPasswordResponse, GenerateSecret
    , GetCsvheaderRequest, GetCsvheaderResponse, GetDeviceRequest, GetDeviceResponse, GetGroupRequest, GetGroupResponse
    , GetIdentityProviderByIdentifierRequest, GetIdentityProviderByIdentifierResponse, GetSigningCertificateRequest
    , GetSigningCertificateResponse, GetUicustomizationRequest, GetUicustomizationResponse, GetUserAttributeVerificationCodeRequest
    , GetUserAttributeVerificationCodeResponse, GetUserPoolMfaConfigRequest, GetUserPoolMfaConfigResponse, GetUserRequest
    , GetUserResponse, GlobalSignOutRequest, GlobalSignOutResponse, GroupListType, GroupType, HttpHeader, HttpHeaderList
    , IdentityProviderType, IdentityProviderTypeType(..), IdpIdentifiersListType, ImageFileType, ImageUrlType, InitiateAuthRequest
    , InitiateAuthResponse, IntegerType, LambdaConfigType, ListDevicesRequest, ListDevicesResponse, ListGroupsRequest, ListGroupsResponse
    , ListIdentityProvidersRequest, ListIdentityProvidersResponse, ListOfStringTypes, ListResourceServersRequest
    , ListResourceServersResponse, ListTagsForResourceRequest, ListTagsForResourceResponse, ListUserImportJobsRequest
    , ListUserImportJobsResponse, ListUserPoolClientsRequest, ListUserPoolClientsResponse, ListUserPoolsRequest, ListUserPoolsResponse
    , ListUsersInGroupRequest, ListUsersInGroupResponse, ListUsersRequest, ListUsersResponse, LogoutUrlsListType, LongType
    , MessageActionType(..), MessageTemplateType, MfaoptionListType, MfaoptionType, NewDeviceMetadataType, NotifyConfigurationType
    , NotifyEmailType, NumberAttributeConstraintsType, OauthFlowType(..), OauthFlowsType, PasswordPolicyType, ProviderDescription
    , ProviderDetailsType, ProviderUserIdentifierType, ProvidersListType, ResendConfirmationCodeRequest
    , ResendConfirmationCodeResponse, ResourceServerScopeListType, ResourceServerScopeType, ResourceServerType
    , ResourceServersListType, RespondToAuthChallengeRequest, RespondToAuthChallengeResponse, RiskConfigurationType, RiskDecisionType(..)
    , RiskExceptionConfigurationType, RiskLevelType(..), SchemaAttributeType, SchemaAttributesListType, ScopeListType
    , SearchedAttributeNamesListType, SetRiskConfigurationRequest, SetRiskConfigurationResponse, SetUicustomizationRequest
    , SetUicustomizationResponse, SetUserMfapreferenceRequest, SetUserMfapreferenceResponse, SetUserPoolMfaConfigRequest
    , SetUserPoolMfaConfigResponse, SetUserSettingsRequest, SetUserSettingsResponse, SignUpRequest, SignUpResponse
    , SkippedIprangeListType, SmsConfigurationType, SmsMfaConfigType, SmsmfaSettingsType, SoftwareTokenMfaConfigType
    , SoftwareTokenMfaSettingsType, StartUserImportJobRequest, StartUserImportJobResponse, StatusType(..), StopUserImportJobRequest
    , StopUserImportJobResponse, StringAttributeConstraintsType, StringType, SupportedIdentityProvidersListType, TagResourceRequest
    , TagResourceResponse, UicustomizationType, UntagResourceRequest, UntagResourceResponse, UpdateAuthEventFeedbackRequest
    , UpdateAuthEventFeedbackResponse, UpdateDeviceStatusRequest, UpdateDeviceStatusResponse, UpdateGroupRequest, UpdateGroupResponse
    , UpdateIdentityProviderRequest, UpdateIdentityProviderResponse, UpdateResourceServerRequest, UpdateResourceServerResponse
    , UpdateUserAttributesRequest, UpdateUserAttributesResponse, UpdateUserPoolClientRequest, UpdateUserPoolClientResponse
    , UpdateUserPoolDomainRequest, UpdateUserPoolDomainResponse, UpdateUserPoolRequest, UpdateUserPoolResponse, UserContextDataType
    , UserImportJobStatusType(..), UserImportJobType, UserImportJobsListType, UserMfasettingListType, UserPoolAddOnsType
    , UserPoolClientDescription, UserPoolClientListType, UserPoolClientType, UserPoolDescriptionType, UserPoolListType, UserPoolMfaType(..)
    , UserPoolPolicyType, UserPoolTagsListType, UserPoolTagsType, UserPoolType, UserStatusType(..), UserType, UsernameAttributeType(..)
    , UsernameAttributesListType, UsersListType, VerificationMessageTemplateType, VerifiedAttributeType(..), VerifiedAttributesListType
    , VerifySoftwareTokenRequest, VerifySoftwareTokenResponse, VerifySoftwareTokenResponseType(..), VerifyUserAttributeRequest
    , VerifyUserAttributeResponse, accountTakeoverEventActionType, adminCreateUserUnusedAccountValidityDaysType
    , advancedSecurityModeType, aliasAttributeType, arnType, attributeDataType, attributeMappingKeyType, attributeNameType
    , attributeValueType, authFlowType, challengeName, challengeNameType, challengeResponse, clientIdType, clientNameType
    , clientPermissionType, clientSecretType, completionMessageType, compromisedCredentialsEventActionType, confirmationCodeType
    , customAttributeNameType, defaultEmailOptionType, deliveryMediumType, descriptionType, deviceKeyType, deviceNameType
    , deviceRememberedStatusType, domainStatusType, domainType, domainVersionType, emailAddressType, emailNotificationBodyType
    , emailNotificationSubjectType, emailSendingAccountType, emailVerificationMessageByLinkType, emailVerificationMessageType
    , emailVerificationSubjectByLinkType, emailVerificationSubjectType, eventFilterType, eventIdType, eventResponseType, eventType
    , explicitAuthFlowsType, feedbackValueType, groupNameType, hexStringType, identityProviderTypeType, idpIdentifierType
    , listProvidersLimitType, listResourceServersLimitType, messageActionType, oauthFlowType, paginationKey, paginationKeyType
    , passwordPolicyMinLengthType, passwordType, poolQueryLimitType, preSignedUrlType, precedenceType, providerNameType
    , providerNameTypeV1, queryLimit, queryLimitType, redirectUrlType, refreshTokenValidityType, resourceServerIdentifierType
    , resourceServerNameType, resourceServerScopeDescriptionType, resourceServerScopeNameType, riskDecisionType, riskLevelType
    , s3BucketType, scopeType, searchPaginationTokenType, secretCodeType, secretHashType, sessionType, smsVerificationMessageType
    , softwareTokenMfauserCodeType, statusType, tagKeysType, tagValueType, temporaryPasswordValidityDaysType, tokenModelType
    , userFilterType, userImportJobIdType, userImportJobNameType, userImportJobStatusType, userPoolIdType, userPoolMfaType
    , userPoolNameType, userStatusType, usernameAttributeType, usernameType, verifiedAttributeType, verifySoftwareTokenResponseType
    , accountTakeoverActionNotifyTypeCodec, accountTakeoverActionTypeCodec, accountTakeoverActionsTypeCodec
    , accountTakeoverEventActionTypeCodec, accountTakeoverRiskConfigurationTypeCodec, addCustomAttributesRequestCodec
    , addCustomAttributesResponseCodec, adminAddUserToGroupRequestCodec, adminConfirmSignUpRequestCodec
    , adminConfirmSignUpResponseCodec, adminCreateUserConfigTypeCodec, adminCreateUserRequestCodec, adminCreateUserResponseCodec
    , adminCreateUserUnusedAccountValidityDaysTypeCodec, adminDeleteUserAttributesRequestCodec
    , adminDeleteUserAttributesResponseCodec, adminDeleteUserRequestCodec, adminDisableProviderForUserRequestCodec
    , adminDisableProviderForUserResponseCodec, adminDisableUserRequestCodec, adminDisableUserResponseCodec
    , adminEnableUserRequestCodec, adminEnableUserResponseCodec, adminForgetDeviceRequestCodec, adminGetDeviceRequestCodec
    , adminGetDeviceResponseCodec, adminGetUserRequestCodec, adminGetUserResponseCodec, adminInitiateAuthRequestCodec
    , adminInitiateAuthResponseCodec, adminLinkProviderForUserRequestCodec, adminLinkProviderForUserResponseCodec
    , adminListDevicesRequestCodec, adminListDevicesResponseCodec, adminListGroupsForUserRequestCodec
    , adminListGroupsForUserResponseCodec, adminListUserAuthEventsRequestCodec, adminListUserAuthEventsResponseCodec
    , adminRemoveUserFromGroupRequestCodec, adminResetUserPasswordRequestCodec, adminResetUserPasswordResponseCodec
    , adminRespondToAuthChallengeRequestCodec, adminRespondToAuthChallengeResponseCodec, adminSetUserMfapreferenceRequestCodec
    , adminSetUserMfapreferenceResponseCodec, adminSetUserPasswordRequestCodec, adminSetUserPasswordResponseCodec
    , adminSetUserSettingsRequestCodec, adminSetUserSettingsResponseCodec, adminUpdateAuthEventFeedbackRequestCodec
    , adminUpdateAuthEventFeedbackResponseCodec, adminUpdateDeviceStatusRequestCodec, adminUpdateDeviceStatusResponseCodec
    , adminUpdateUserAttributesRequestCodec, adminUpdateUserAttributesResponseCodec, adminUserGlobalSignOutRequestCodec
    , adminUserGlobalSignOutResponseCodec, advancedSecurityModeTypeCodec, aliasAttributeTypeCodec, aliasAttributesListTypeCodec
    , analyticsConfigurationTypeCodec, analyticsMetadataTypeCodec, arnTypeCodec, associateSoftwareTokenRequestCodec
    , associateSoftwareTokenResponseCodec, attributeDataTypeCodec, attributeListTypeCodec, attributeMappingKeyTypeCodec
    , attributeMappingTypeCodec, attributeNameListTypeCodec, attributeNameTypeCodec, attributeTypeCodec, attributeValueTypeCodec
    , authEventTypeCodec, authEventsTypeCodec, authFlowTypeCodec, authParametersTypeCodec, authenticationResultTypeCodec
    , awsaccountIdTypeCodec, blockedIprangeListTypeCodec, booleanTypeCodec, callbackUrlsListTypeCodec, challengeNameCodec
    , challengeNameTypeCodec, challengeParametersTypeCodec, challengeResponseCodec, challengeResponseListTypeCodec
    , challengeResponseTypeCodec, challengeResponsesTypeCodec, changePasswordRequestCodec, changePasswordResponseCodec
    , clientIdTypeCodec, clientMetadataTypeCodec, clientNameTypeCodec, clientPermissionListTypeCodec, clientPermissionTypeCodec
    , clientSecretTypeCodec, codeDeliveryDetailsListTypeCodec, codeDeliveryDetailsTypeCodec, completionMessageTypeCodec
    , compromisedCredentialsActionsTypeCodec, compromisedCredentialsEventActionTypeCodec
    , compromisedCredentialsRiskConfigurationTypeCodec, confirmDeviceRequestCodec, confirmDeviceResponseCodec
    , confirmForgotPasswordRequestCodec, confirmForgotPasswordResponseCodec, confirmSignUpRequestCodec, confirmSignUpResponseCodec
    , confirmationCodeTypeCodec, contextDataTypeCodec, createGroupRequestCodec, createGroupResponseCodec
    , createIdentityProviderRequestCodec, createIdentityProviderResponseCodec, createResourceServerRequestCodec
    , createResourceServerResponseCodec, createUserImportJobRequestCodec, createUserImportJobResponseCodec
    , createUserPoolClientRequestCodec, createUserPoolClientResponseCodec, createUserPoolDomainRequestCodec
    , createUserPoolDomainResponseCodec, createUserPoolRequestCodec, createUserPoolResponseCodec, csstypeCodec, cssversionTypeCodec
    , customAttributeNameTypeCodec, customAttributesListTypeCodec, customDomainConfigTypeCodec, dateTypeCodec
    , defaultEmailOptionTypeCodec, deleteGroupRequestCodec, deleteIdentityProviderRequestCodec, deleteResourceServerRequestCodec
    , deleteUserAttributesRequestCodec, deleteUserAttributesResponseCodec, deleteUserPoolClientRequestCodec
    , deleteUserPoolDomainRequestCodec, deleteUserPoolDomainResponseCodec, deleteUserPoolRequestCodec, deleteUserRequestCodec
    , deliveryMediumListTypeCodec, deliveryMediumTypeCodec, describeIdentityProviderRequestCodec
    , describeIdentityProviderResponseCodec, describeResourceServerRequestCodec, describeResourceServerResponseCodec
    , describeRiskConfigurationRequestCodec, describeRiskConfigurationResponseCodec, describeUserImportJobRequestCodec
    , describeUserImportJobResponseCodec, describeUserPoolClientRequestCodec, describeUserPoolClientResponseCodec
    , describeUserPoolDomainRequestCodec, describeUserPoolDomainResponseCodec, describeUserPoolRequestCodec
    , describeUserPoolResponseCodec, descriptionTypeCodec, deviceConfigurationTypeCodec, deviceKeyTypeCodec, deviceListTypeCodec
    , deviceNameTypeCodec, deviceRememberedStatusTypeCodec, deviceSecretVerifierConfigTypeCodec, deviceTypeCodec
    , domainDescriptionTypeCodec, domainStatusTypeCodec, domainTypeCodec, domainVersionTypeCodec, emailAddressTypeCodec
    , emailConfigurationTypeCodec, emailNotificationBodyTypeCodec, emailNotificationSubjectTypeCodec, emailSendingAccountTypeCodec
    , emailVerificationMessageByLinkTypeCodec, emailVerificationMessageTypeCodec, emailVerificationSubjectByLinkTypeCodec
    , emailVerificationSubjectTypeCodec, eventContextDataTypeCodec, eventFeedbackTypeCodec, eventFilterTypeCodec
    , eventFiltersTypeCodec, eventIdTypeCodec, eventResponseTypeCodec, eventRiskTypeCodec, eventTypeCodec
    , explicitAuthFlowsListTypeCodec, explicitAuthFlowsTypeCodec, feedbackValueTypeCodec, forceAliasCreationCodec
    , forgetDeviceRequestCodec, forgotPasswordRequestCodec, forgotPasswordResponseCodec, generateSecretCodec, getCsvheaderRequestCodec
    , getCsvheaderResponseCodec, getDeviceRequestCodec, getDeviceResponseCodec, getGroupRequestCodec, getGroupResponseCodec
    , getIdentityProviderByIdentifierRequestCodec, getIdentityProviderByIdentifierResponseCodec, getSigningCertificateRequestCodec
    , getSigningCertificateResponseCodec, getUicustomizationRequestCodec, getUicustomizationResponseCodec
    , getUserAttributeVerificationCodeRequestCodec, getUserAttributeVerificationCodeResponseCodec
    , getUserPoolMfaConfigRequestCodec, getUserPoolMfaConfigResponseCodec, getUserRequestCodec, getUserResponseCodec
    , globalSignOutRequestCodec, globalSignOutResponseCodec, groupListTypeCodec, groupNameTypeCodec, groupTypeCodec, hexStringTypeCodec
    , httpHeaderCodec, httpHeaderListCodec, identityProviderTypeCodec, identityProviderTypeTypeCodec, idpIdentifierTypeCodec
    , idpIdentifiersListTypeCodec, imageFileTypeCodec, imageUrlTypeCodec, initiateAuthRequestCodec, initiateAuthResponseCodec
    , integerTypeCodec, lambdaConfigTypeCodec, listDevicesRequestCodec, listDevicesResponseCodec, listGroupsRequestCodec
    , listGroupsResponseCodec, listIdentityProvidersRequestCodec, listIdentityProvidersResponseCodec, listOfStringTypesCodec
    , listProvidersLimitTypeCodec, listResourceServersLimitTypeCodec, listResourceServersRequestCodec
    , listResourceServersResponseCodec, listTagsForResourceRequestCodec, listTagsForResourceResponseCodec
    , listUserImportJobsRequestCodec, listUserImportJobsResponseCodec, listUserPoolClientsRequestCodec
    , listUserPoolClientsResponseCodec, listUserPoolsRequestCodec, listUserPoolsResponseCodec, listUsersInGroupRequestCodec
    , listUsersInGroupResponseCodec, listUsersRequestCodec, listUsersResponseCodec, logoutUrlsListTypeCodec, longTypeCodec
    , messageActionTypeCodec, messageTemplateTypeCodec, mfaoptionListTypeCodec, mfaoptionTypeCodec, newDeviceMetadataTypeCodec
    , notifyConfigurationTypeCodec, notifyEmailTypeCodec, numberAttributeConstraintsTypeCodec, oauthFlowTypeCodec, oauthFlowsTypeCodec
    , paginationKeyCodec, paginationKeyTypeCodec, passwordPolicyMinLengthTypeCodec, passwordPolicyTypeCodec, passwordTypeCodec
    , poolQueryLimitTypeCodec, preSignedUrlTypeCodec, precedenceTypeCodec, providerDescriptionCodec, providerDetailsTypeCodec
    , providerNameTypeCodec, providerNameTypeV1Codec, providerUserIdentifierTypeCodec, providersListTypeCodec, queryLimitCodec
    , queryLimitTypeCodec, redirectUrlTypeCodec, refreshTokenValidityTypeCodec, resendConfirmationCodeRequestCodec
    , resendConfirmationCodeResponseCodec, resourceServerIdentifierTypeCodec, resourceServerNameTypeCodec
    , resourceServerScopeDescriptionTypeCodec, resourceServerScopeListTypeCodec, resourceServerScopeNameTypeCodec
    , resourceServerScopeTypeCodec, resourceServerTypeCodec, resourceServersListTypeCodec, respondToAuthChallengeRequestCodec
    , respondToAuthChallengeResponseCodec, riskConfigurationTypeCodec, riskDecisionTypeCodec, riskExceptionConfigurationTypeCodec
    , riskLevelTypeCodec, s3BucketTypeCodec, schemaAttributeTypeCodec, schemaAttributesListTypeCodec, scopeListTypeCodec, scopeTypeCodec
    , searchPaginationTokenTypeCodec, searchedAttributeNamesListTypeCodec, secretCodeTypeCodec, secretHashTypeCodec, sessionTypeCodec
    , setRiskConfigurationRequestCodec, setRiskConfigurationResponseCodec, setUicustomizationRequestCodec
    , setUicustomizationResponseCodec, setUserMfapreferenceRequestCodec, setUserMfapreferenceResponseCodec
    , setUserPoolMfaConfigRequestCodec, setUserPoolMfaConfigResponseCodec, setUserSettingsRequestCodec, setUserSettingsResponseCodec
    , signUpRequestCodec, signUpResponseCodec, skippedIprangeListTypeCodec, smsConfigurationTypeCodec, smsMfaConfigTypeCodec
    , smsVerificationMessageTypeCodec, smsmfaSettingsTypeCodec, softwareTokenMfaConfigTypeCodec, softwareTokenMfaSettingsTypeCodec
    , softwareTokenMfauserCodeTypeCodec, startUserImportJobRequestCodec, startUserImportJobResponseCodec, statusTypeCodec
    , stopUserImportJobRequestCodec, stopUserImportJobResponseCodec, stringAttributeConstraintsTypeCodec, stringTypeCodec
    , supportedIdentityProvidersListTypeCodec, tagKeysTypeCodec, tagResourceRequestCodec, tagResourceResponseCodec, tagValueTypeCodec
    , temporaryPasswordValidityDaysTypeCodec, tokenModelTypeCodec, uicustomizationTypeCodec, untagResourceRequestCodec
    , untagResourceResponseCodec, updateAuthEventFeedbackRequestCodec, updateAuthEventFeedbackResponseCodec
    , updateDeviceStatusRequestCodec, updateDeviceStatusResponseCodec, updateGroupRequestCodec, updateGroupResponseCodec
    , updateIdentityProviderRequestCodec, updateIdentityProviderResponseCodec, updateResourceServerRequestCodec
    , updateResourceServerResponseCodec, updateUserAttributesRequestCodec, updateUserAttributesResponseCodec
    , updateUserPoolClientRequestCodec, updateUserPoolClientResponseCodec, updateUserPoolDomainRequestCodec
    , updateUserPoolDomainResponseCodec, updateUserPoolRequestCodec, updateUserPoolResponseCodec, userContextDataTypeCodec
    , userFilterTypeCodec, userImportJobIdTypeCodec, userImportJobNameTypeCodec, userImportJobStatusTypeCodec, userImportJobTypeCodec
    , userImportJobsListTypeCodec, userMfasettingListTypeCodec, userPoolAddOnsTypeCodec, userPoolClientDescriptionCodec
    , userPoolClientListTypeCodec, userPoolClientTypeCodec, userPoolDescriptionTypeCodec, userPoolIdTypeCodec, userPoolListTypeCodec
    , userPoolMfaTypeCodec, userPoolNameTypeCodec, userPoolPolicyTypeCodec, userPoolTagsListTypeCodec, userPoolTagsTypeCodec
    , userPoolTypeCodec, userStatusTypeCodec, userTypeCodec, usernameAttributeTypeCodec, usernameAttributesListTypeCodec
    , usernameTypeCodec, usersListTypeCodec, verificationMessageTemplateTypeCodec, verifiedAttributeTypeCodec
    , verifiedAttributesListTypeCodec, verifySoftwareTokenRequestCodec, verifySoftwareTokenResponseCodec
    , verifySoftwareTokenResponseTypeCodec, verifyUserAttributeRequestCodec, verifyUserAttributeResponseCodec
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
@docs AdminCreateUserResponse, AdminDeleteUserAttributesRequest, AdminDeleteUserAttributesResponse, AdminDeleteUserRequest
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
@docs AuthEventType, AuthEventsType, AuthFlowType, AuthParametersType, AuthenticationResultType, AwsaccountIdType, BlockedIprangeListType
@docs BooleanType, CallbackUrlsListType, ChallengeName, ChallengeNameType, ChallengeParametersType, ChallengeResponse
@docs ChallengeResponseListType, ChallengeResponseType, ChallengeResponsesType, ChangePasswordRequest, ChangePasswordResponse
@docs ClientMetadataType, ClientPermissionListType, CodeDeliveryDetailsListType, CodeDeliveryDetailsType
@docs CompromisedCredentialsActionsType, CompromisedCredentialsEventActionType, CompromisedCredentialsRiskConfigurationType
@docs ConfirmDeviceRequest, ConfirmDeviceResponse, ConfirmForgotPasswordRequest, ConfirmForgotPasswordResponse, ConfirmSignUpRequest
@docs ConfirmSignUpResponse, ContextDataType, CreateGroupRequest, CreateGroupResponse, CreateIdentityProviderRequest
@docs CreateIdentityProviderResponse, CreateResourceServerRequest, CreateResourceServerResponse, CreateUserImportJobRequest
@docs CreateUserImportJobResponse, CreateUserPoolClientRequest, CreateUserPoolClientResponse, CreateUserPoolDomainRequest
@docs CreateUserPoolDomainResponse, CreateUserPoolRequest, CreateUserPoolResponse, Csstype, CssversionType, CustomAttributesListType
@docs CustomDomainConfigType, DateType, DefaultEmailOptionType, DeleteGroupRequest, DeleteIdentityProviderRequest
@docs DeleteResourceServerRequest, DeleteUserAttributesRequest, DeleteUserAttributesResponse, DeleteUserPoolClientRequest
@docs DeleteUserPoolDomainRequest, DeleteUserPoolDomainResponse, DeleteUserPoolRequest, DeleteUserRequest, DeliveryMediumListType
@docs DeliveryMediumType, DescribeIdentityProviderRequest, DescribeIdentityProviderResponse, DescribeResourceServerRequest
@docs DescribeResourceServerResponse, DescribeRiskConfigurationRequest, DescribeRiskConfigurationResponse
@docs DescribeUserImportJobRequest, DescribeUserImportJobResponse, DescribeUserPoolClientRequest, DescribeUserPoolClientResponse
@docs DescribeUserPoolDomainRequest, DescribeUserPoolDomainResponse, DescribeUserPoolRequest, DescribeUserPoolResponse
@docs DeviceConfigurationType, DeviceListType, DeviceRememberedStatusType, DeviceSecretVerifierConfigType, DeviceType
@docs DomainDescriptionType, DomainStatusType, EmailConfigurationType, EmailSendingAccountType, EventContextDataType, EventFeedbackType
@docs EventFilterType, EventFiltersType, EventResponseType, EventRiskType, EventType, ExplicitAuthFlowsListType, ExplicitAuthFlowsType
@docs FeedbackValueType, ForceAliasCreation, ForgetDeviceRequest, ForgotPasswordRequest, ForgotPasswordResponse, GenerateSecret
@docs GetCsvheaderRequest, GetCsvheaderResponse, GetDeviceRequest, GetDeviceResponse, GetGroupRequest, GetGroupResponse
@docs GetIdentityProviderByIdentifierRequest, GetIdentityProviderByIdentifierResponse, GetSigningCertificateRequest
@docs GetSigningCertificateResponse, GetUicustomizationRequest, GetUicustomizationResponse, GetUserAttributeVerificationCodeRequest
@docs GetUserAttributeVerificationCodeResponse, GetUserPoolMfaConfigRequest, GetUserPoolMfaConfigResponse, GetUserRequest
@docs GetUserResponse, GlobalSignOutRequest, GlobalSignOutResponse, GroupListType, GroupType, HttpHeader, HttpHeaderList
@docs IdentityProviderType, IdentityProviderTypeType, IdpIdentifiersListType, ImageFileType, ImageUrlType, InitiateAuthRequest
@docs InitiateAuthResponse, IntegerType, LambdaConfigType, ListDevicesRequest, ListDevicesResponse, ListGroupsRequest, ListGroupsResponse
@docs ListIdentityProvidersRequest, ListIdentityProvidersResponse, ListOfStringTypes, ListResourceServersRequest
@docs ListResourceServersResponse, ListTagsForResourceRequest, ListTagsForResourceResponse, ListUserImportJobsRequest
@docs ListUserImportJobsResponse, ListUserPoolClientsRequest, ListUserPoolClientsResponse, ListUserPoolsRequest, ListUserPoolsResponse
@docs ListUsersInGroupRequest, ListUsersInGroupResponse, ListUsersRequest, ListUsersResponse, LogoutUrlsListType, LongType
@docs MessageActionType, MessageTemplateType, MfaoptionListType, MfaoptionType, NewDeviceMetadataType, NotifyConfigurationType
@docs NotifyEmailType, NumberAttributeConstraintsType, OauthFlowType, OauthFlowsType, PasswordPolicyType, ProviderDescription
@docs ProviderDetailsType, ProviderUserIdentifierType, ProvidersListType, ResendConfirmationCodeRequest
@docs ResendConfirmationCodeResponse, ResourceServerScopeListType, ResourceServerScopeType, ResourceServerType
@docs ResourceServersListType, RespondToAuthChallengeRequest, RespondToAuthChallengeResponse, RiskConfigurationType, RiskDecisionType
@docs RiskExceptionConfigurationType, RiskLevelType, SchemaAttributeType, SchemaAttributesListType, ScopeListType
@docs SearchedAttributeNamesListType, SetRiskConfigurationRequest, SetRiskConfigurationResponse, SetUicustomizationRequest
@docs SetUicustomizationResponse, SetUserMfapreferenceRequest, SetUserMfapreferenceResponse, SetUserPoolMfaConfigRequest
@docs SetUserPoolMfaConfigResponse, SetUserSettingsRequest, SetUserSettingsResponse, SignUpRequest, SignUpResponse
@docs SkippedIprangeListType, SmsConfigurationType, SmsMfaConfigType, SmsmfaSettingsType, SoftwareTokenMfaConfigType
@docs SoftwareTokenMfaSettingsType, StartUserImportJobRequest, StartUserImportJobResponse, StatusType, StopUserImportJobRequest
@docs StopUserImportJobResponse, StringAttributeConstraintsType, StringType, SupportedIdentityProvidersListType, TagResourceRequest
@docs TagResourceResponse, UicustomizationType, UntagResourceRequest, UntagResourceResponse, UpdateAuthEventFeedbackRequest
@docs UpdateAuthEventFeedbackResponse, UpdateDeviceStatusRequest, UpdateDeviceStatusResponse, UpdateGroupRequest, UpdateGroupResponse
@docs UpdateIdentityProviderRequest, UpdateIdentityProviderResponse, UpdateResourceServerRequest, UpdateResourceServerResponse
@docs UpdateUserAttributesRequest, UpdateUserAttributesResponse, UpdateUserPoolClientRequest, UpdateUserPoolClientResponse
@docs UpdateUserPoolDomainRequest, UpdateUserPoolDomainResponse, UpdateUserPoolRequest, UpdateUserPoolResponse, UserContextDataType
@docs UserImportJobStatusType, UserImportJobType, UserImportJobsListType, UserMfasettingListType, UserPoolAddOnsType
@docs UserPoolClientDescription, UserPoolClientListType, UserPoolClientType, UserPoolDescriptionType, UserPoolListType, UserPoolMfaType
@docs UserPoolPolicyType, UserPoolTagsListType, UserPoolTagsType, UserPoolType, UserStatusType, UserType, UsernameAttributeType
@docs UsernameAttributesListType, UsersListType, VerificationMessageTemplateType, VerifiedAttributeType, VerifiedAttributesListType
@docs VerifySoftwareTokenRequest, VerifySoftwareTokenResponse, VerifySoftwareTokenResponseType, VerifyUserAttributeRequest
@docs VerifyUserAttributeResponse, accountTakeoverEventActionType, adminCreateUserUnusedAccountValidityDaysType
@docs advancedSecurityModeType, aliasAttributeType, arnType, attributeDataType, attributeMappingKeyType, attributeNameType
@docs attributeValueType, authFlowType, challengeName, challengeNameType, challengeResponse, clientIdType, clientNameType
@docs clientPermissionType, clientSecretType, completionMessageType, compromisedCredentialsEventActionType, confirmationCodeType
@docs customAttributeNameType, defaultEmailOptionType, deliveryMediumType, descriptionType, deviceKeyType, deviceNameType
@docs deviceRememberedStatusType, domainStatusType, domainType, domainVersionType, emailAddressType, emailNotificationBodyType
@docs emailNotificationSubjectType, emailSendingAccountType, emailVerificationMessageByLinkType, emailVerificationMessageType
@docs emailVerificationSubjectByLinkType, emailVerificationSubjectType, eventFilterType, eventIdType, eventResponseType, eventType
@docs explicitAuthFlowsType, feedbackValueType, groupNameType, hexStringType, identityProviderTypeType, idpIdentifierType
@docs listProvidersLimitType, listResourceServersLimitType, messageActionType, oauthFlowType, paginationKey, paginationKeyType
@docs passwordPolicyMinLengthType, passwordType, poolQueryLimitType, preSignedUrlType, precedenceType, providerNameType
@docs providerNameTypeV1, queryLimit, queryLimitType, redirectUrlType, refreshTokenValidityType, resourceServerIdentifierType
@docs resourceServerNameType, resourceServerScopeDescriptionType, resourceServerScopeNameType, riskDecisionType, riskLevelType
@docs s3BucketType, scopeType, searchPaginationTokenType, secretCodeType, secretHashType, sessionType, smsVerificationMessageType
@docs softwareTokenMfauserCodeType, statusType, tagKeysType, tagValueType, temporaryPasswordValidityDaysType, tokenModelType
@docs userFilterType, userImportJobIdType, userImportJobNameType, userImportJobStatusType, userPoolIdType, userPoolMfaType
@docs userPoolNameType, userStatusType, usernameAttributeType, usernameType, verifiedAttributeType, verifySoftwareTokenResponseType


# Codecs for the data model.

@docs accountTakeoverActionNotifyTypeCodec, accountTakeoverActionTypeCodec, accountTakeoverActionsTypeCodec
@docs accountTakeoverEventActionTypeCodec, accountTakeoverRiskConfigurationTypeCodec, addCustomAttributesRequestCodec
@docs addCustomAttributesResponseCodec, adminAddUserToGroupRequestCodec, adminConfirmSignUpRequestCodec
@docs adminConfirmSignUpResponseCodec, adminCreateUserConfigTypeCodec, adminCreateUserRequestCodec, adminCreateUserResponseCodec
@docs adminCreateUserUnusedAccountValidityDaysTypeCodec, adminDeleteUserAttributesRequestCodec
@docs adminDeleteUserAttributesResponseCodec, adminDeleteUserRequestCodec, adminDisableProviderForUserRequestCodec
@docs adminDisableProviderForUserResponseCodec, adminDisableUserRequestCodec, adminDisableUserResponseCodec
@docs adminEnableUserRequestCodec, adminEnableUserResponseCodec, adminForgetDeviceRequestCodec, adminGetDeviceRequestCodec
@docs adminGetDeviceResponseCodec, adminGetUserRequestCodec, adminGetUserResponseCodec, adminInitiateAuthRequestCodec
@docs adminInitiateAuthResponseCodec, adminLinkProviderForUserRequestCodec, adminLinkProviderForUserResponseCodec
@docs adminListDevicesRequestCodec, adminListDevicesResponseCodec, adminListGroupsForUserRequestCodec
@docs adminListGroupsForUserResponseCodec, adminListUserAuthEventsRequestCodec, adminListUserAuthEventsResponseCodec
@docs adminRemoveUserFromGroupRequestCodec, adminResetUserPasswordRequestCodec, adminResetUserPasswordResponseCodec
@docs adminRespondToAuthChallengeRequestCodec, adminRespondToAuthChallengeResponseCodec, adminSetUserMfapreferenceRequestCodec
@docs adminSetUserMfapreferenceResponseCodec, adminSetUserPasswordRequestCodec, adminSetUserPasswordResponseCodec
@docs adminSetUserSettingsRequestCodec, adminSetUserSettingsResponseCodec, adminUpdateAuthEventFeedbackRequestCodec
@docs adminUpdateAuthEventFeedbackResponseCodec, adminUpdateDeviceStatusRequestCodec, adminUpdateDeviceStatusResponseCodec
@docs adminUpdateUserAttributesRequestCodec, adminUpdateUserAttributesResponseCodec, adminUserGlobalSignOutRequestCodec
@docs adminUserGlobalSignOutResponseCodec, advancedSecurityModeTypeCodec, aliasAttributeTypeCodec, aliasAttributesListTypeCodec
@docs analyticsConfigurationTypeCodec, analyticsMetadataTypeCodec, arnTypeCodec, associateSoftwareTokenRequestCodec
@docs associateSoftwareTokenResponseCodec, attributeDataTypeCodec, attributeListTypeCodec, attributeMappingKeyTypeCodec
@docs attributeMappingTypeCodec, attributeNameListTypeCodec, attributeNameTypeCodec, attributeTypeCodec, attributeValueTypeCodec
@docs authEventTypeCodec, authEventsTypeCodec, authFlowTypeCodec, authParametersTypeCodec, authenticationResultTypeCodec
@docs awsaccountIdTypeCodec, blockedIprangeListTypeCodec, booleanTypeCodec, callbackUrlsListTypeCodec, challengeNameCodec
@docs challengeNameTypeCodec, challengeParametersTypeCodec, challengeResponseCodec, challengeResponseListTypeCodec
@docs challengeResponseTypeCodec, challengeResponsesTypeCodec, changePasswordRequestCodec, changePasswordResponseCodec
@docs clientIdTypeCodec, clientMetadataTypeCodec, clientNameTypeCodec, clientPermissionListTypeCodec, clientPermissionTypeCodec
@docs clientSecretTypeCodec, codeDeliveryDetailsListTypeCodec, codeDeliveryDetailsTypeCodec, completionMessageTypeCodec
@docs compromisedCredentialsActionsTypeCodec, compromisedCredentialsEventActionTypeCodec
@docs compromisedCredentialsRiskConfigurationTypeCodec, confirmDeviceRequestCodec, confirmDeviceResponseCodec
@docs confirmForgotPasswordRequestCodec, confirmForgotPasswordResponseCodec, confirmSignUpRequestCodec, confirmSignUpResponseCodec
@docs confirmationCodeTypeCodec, contextDataTypeCodec, createGroupRequestCodec, createGroupResponseCodec
@docs createIdentityProviderRequestCodec, createIdentityProviderResponseCodec, createResourceServerRequestCodec
@docs createResourceServerResponseCodec, createUserImportJobRequestCodec, createUserImportJobResponseCodec
@docs createUserPoolClientRequestCodec, createUserPoolClientResponseCodec, createUserPoolDomainRequestCodec
@docs createUserPoolDomainResponseCodec, createUserPoolRequestCodec, createUserPoolResponseCodec, csstypeCodec, cssversionTypeCodec
@docs customAttributeNameTypeCodec, customAttributesListTypeCodec, customDomainConfigTypeCodec, dateTypeCodec
@docs defaultEmailOptionTypeCodec, deleteGroupRequestCodec, deleteIdentityProviderRequestCodec, deleteResourceServerRequestCodec
@docs deleteUserAttributesRequestCodec, deleteUserAttributesResponseCodec, deleteUserPoolClientRequestCodec
@docs deleteUserPoolDomainRequestCodec, deleteUserPoolDomainResponseCodec, deleteUserPoolRequestCodec, deleteUserRequestCodec
@docs deliveryMediumListTypeCodec, deliveryMediumTypeCodec, describeIdentityProviderRequestCodec
@docs describeIdentityProviderResponseCodec, describeResourceServerRequestCodec, describeResourceServerResponseCodec
@docs describeRiskConfigurationRequestCodec, describeRiskConfigurationResponseCodec, describeUserImportJobRequestCodec
@docs describeUserImportJobResponseCodec, describeUserPoolClientRequestCodec, describeUserPoolClientResponseCodec
@docs describeUserPoolDomainRequestCodec, describeUserPoolDomainResponseCodec, describeUserPoolRequestCodec
@docs describeUserPoolResponseCodec, descriptionTypeCodec, deviceConfigurationTypeCodec, deviceKeyTypeCodec, deviceListTypeCodec
@docs deviceNameTypeCodec, deviceRememberedStatusTypeCodec, deviceSecretVerifierConfigTypeCodec, deviceTypeCodec
@docs domainDescriptionTypeCodec, domainStatusTypeCodec, domainTypeCodec, domainVersionTypeCodec, emailAddressTypeCodec
@docs emailConfigurationTypeCodec, emailNotificationBodyTypeCodec, emailNotificationSubjectTypeCodec, emailSendingAccountTypeCodec
@docs emailVerificationMessageByLinkTypeCodec, emailVerificationMessageTypeCodec, emailVerificationSubjectByLinkTypeCodec
@docs emailVerificationSubjectTypeCodec, eventContextDataTypeCodec, eventFeedbackTypeCodec, eventFilterTypeCodec
@docs eventFiltersTypeCodec, eventIdTypeCodec, eventResponseTypeCodec, eventRiskTypeCodec, eventTypeCodec
@docs explicitAuthFlowsListTypeCodec, explicitAuthFlowsTypeCodec, feedbackValueTypeCodec, forceAliasCreationCodec
@docs forgetDeviceRequestCodec, forgotPasswordRequestCodec, forgotPasswordResponseCodec, generateSecretCodec, getCsvheaderRequestCodec
@docs getCsvheaderResponseCodec, getDeviceRequestCodec, getDeviceResponseCodec, getGroupRequestCodec, getGroupResponseCodec
@docs getIdentityProviderByIdentifierRequestCodec, getIdentityProviderByIdentifierResponseCodec, getSigningCertificateRequestCodec
@docs getSigningCertificateResponseCodec, getUicustomizationRequestCodec, getUicustomizationResponseCodec
@docs getUserAttributeVerificationCodeRequestCodec, getUserAttributeVerificationCodeResponseCodec
@docs getUserPoolMfaConfigRequestCodec, getUserPoolMfaConfigResponseCodec, getUserRequestCodec, getUserResponseCodec
@docs globalSignOutRequestCodec, globalSignOutResponseCodec, groupListTypeCodec, groupNameTypeCodec, groupTypeCodec, hexStringTypeCodec
@docs httpHeaderCodec, httpHeaderListCodec, identityProviderTypeCodec, identityProviderTypeTypeCodec, idpIdentifierTypeCodec
@docs idpIdentifiersListTypeCodec, imageFileTypeCodec, imageUrlTypeCodec, initiateAuthRequestCodec, initiateAuthResponseCodec
@docs integerTypeCodec, lambdaConfigTypeCodec, listDevicesRequestCodec, listDevicesResponseCodec, listGroupsRequestCodec
@docs listGroupsResponseCodec, listIdentityProvidersRequestCodec, listIdentityProvidersResponseCodec, listOfStringTypesCodec
@docs listProvidersLimitTypeCodec, listResourceServersLimitTypeCodec, listResourceServersRequestCodec
@docs listResourceServersResponseCodec, listTagsForResourceRequestCodec, listTagsForResourceResponseCodec
@docs listUserImportJobsRequestCodec, listUserImportJobsResponseCodec, listUserPoolClientsRequestCodec
@docs listUserPoolClientsResponseCodec, listUserPoolsRequestCodec, listUserPoolsResponseCodec, listUsersInGroupRequestCodec
@docs listUsersInGroupResponseCodec, listUsersRequestCodec, listUsersResponseCodec, logoutUrlsListTypeCodec, longTypeCodec
@docs messageActionTypeCodec, messageTemplateTypeCodec, mfaoptionListTypeCodec, mfaoptionTypeCodec, newDeviceMetadataTypeCodec
@docs notifyConfigurationTypeCodec, notifyEmailTypeCodec, numberAttributeConstraintsTypeCodec, oauthFlowTypeCodec, oauthFlowsTypeCodec
@docs paginationKeyCodec, paginationKeyTypeCodec, passwordPolicyMinLengthTypeCodec, passwordPolicyTypeCodec, passwordTypeCodec
@docs poolQueryLimitTypeCodec, preSignedUrlTypeCodec, precedenceTypeCodec, providerDescriptionCodec, providerDetailsTypeCodec
@docs providerNameTypeCodec, providerNameTypeV1Codec, providerUserIdentifierTypeCodec, providersListTypeCodec, queryLimitCodec
@docs queryLimitTypeCodec, redirectUrlTypeCodec, refreshTokenValidityTypeCodec, resendConfirmationCodeRequestCodec
@docs resendConfirmationCodeResponseCodec, resourceServerIdentifierTypeCodec, resourceServerNameTypeCodec
@docs resourceServerScopeDescriptionTypeCodec, resourceServerScopeListTypeCodec, resourceServerScopeNameTypeCodec
@docs resourceServerScopeTypeCodec, resourceServerTypeCodec, resourceServersListTypeCodec, respondToAuthChallengeRequestCodec
@docs respondToAuthChallengeResponseCodec, riskConfigurationTypeCodec, riskDecisionTypeCodec, riskExceptionConfigurationTypeCodec
@docs riskLevelTypeCodec, s3BucketTypeCodec, schemaAttributeTypeCodec, schemaAttributesListTypeCodec, scopeListTypeCodec, scopeTypeCodec
@docs searchPaginationTokenTypeCodec, searchedAttributeNamesListTypeCodec, secretCodeTypeCodec, secretHashTypeCodec, sessionTypeCodec
@docs setRiskConfigurationRequestCodec, setRiskConfigurationResponseCodec, setUicustomizationRequestCodec
@docs setUicustomizationResponseCodec, setUserMfapreferenceRequestCodec, setUserMfapreferenceResponseCodec
@docs setUserPoolMfaConfigRequestCodec, setUserPoolMfaConfigResponseCodec, setUserSettingsRequestCodec, setUserSettingsResponseCodec
@docs signUpRequestCodec, signUpResponseCodec, skippedIprangeListTypeCodec, smsConfigurationTypeCodec, smsMfaConfigTypeCodec
@docs smsVerificationMessageTypeCodec, smsmfaSettingsTypeCodec, softwareTokenMfaConfigTypeCodec, softwareTokenMfaSettingsTypeCodec
@docs softwareTokenMfauserCodeTypeCodec, startUserImportJobRequestCodec, startUserImportJobResponseCodec, statusTypeCodec
@docs stopUserImportJobRequestCodec, stopUserImportJobResponseCodec, stringAttributeConstraintsTypeCodec, stringTypeCodec
@docs supportedIdentityProvidersListTypeCodec, tagKeysTypeCodec, tagResourceRequestCodec, tagResourceResponseCodec, tagValueTypeCodec
@docs temporaryPasswordValidityDaysTypeCodec, tokenModelTypeCodec, uicustomizationTypeCodec, untagResourceRequestCodec
@docs untagResourceResponseCodec, updateAuthEventFeedbackRequestCodec, updateAuthEventFeedbackResponseCodec
@docs updateDeviceStatusRequestCodec, updateDeviceStatusResponseCodec, updateGroupRequestCodec, updateGroupResponseCodec
@docs updateIdentityProviderRequestCodec, updateIdentityProviderResponseCodec, updateResourceServerRequestCodec
@docs updateResourceServerResponseCodec, updateUserAttributesRequestCodec, updateUserAttributesResponseCodec
@docs updateUserPoolClientRequestCodec, updateUserPoolClientResponseCodec, updateUserPoolDomainRequestCodec
@docs updateUserPoolDomainResponseCodec, updateUserPoolRequestCodec, updateUserPoolResponseCodec, userContextDataTypeCodec
@docs userFilterTypeCodec, userImportJobIdTypeCodec, userImportJobNameTypeCodec, userImportJobStatusTypeCodec, userImportJobTypeCodec
@docs userImportJobsListTypeCodec, userMfasettingListTypeCodec, userPoolAddOnsTypeCodec, userPoolClientDescriptionCodec
@docs userPoolClientListTypeCodec, userPoolClientTypeCodec, userPoolDescriptionTypeCodec, userPoolIdTypeCodec, userPoolListTypeCodec
@docs userPoolMfaTypeCodec, userPoolNameTypeCodec, userPoolPolicyTypeCodec, userPoolTagsListTypeCodec, userPoolTagsTypeCodec
@docs userPoolTypeCodec, userStatusTypeCodec, userTypeCodec, usernameAttributeTypeCodec, usernameAttributesListTypeCodec
@docs usernameTypeCodec, usersListTypeCodec, verificationMessageTemplateTypeCodec, verifiedAttributeTypeCodec
@docs verifiedAttributesListTypeCodec, verifySoftwareTokenRequestCodec, verifySoftwareTokenResponseCodec
@docs verifySoftwareTokenResponseTypeCodec, verifyUserAttributeRequestCodec, verifyUserAttributeResponseCodec

-}

import AWS.Core.Decode
import AWS.Core.Http
import AWS.Core.Service
import Codec exposing (Codec)
import Dict exposing (Dict)
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
            AWS.Core.Service.setJsonVersion "1.1"
                >> AWS.Core.Service.setTargetPrefix "AWSCognitoIdentityProviderService"
    in
    AWS.Core.Service.defineRegional "cognito-idp" "2016-04-18" AWS.Core.Service.JSON AWS.Core.Service.SignV4 optionsFn


{-| Verifies the specified user attributes in the user pool.
-}
verifyUserAttribute : VerifyUserAttributeRequest -> AWS.Core.Http.Request VerifyUserAttributeResponse
verifyUserAttribute req =
    let
        jsonBody =
            req |> Codec.encoder verifyUserAttributeRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder verifyUserAttributeResponseCodec
    in
    AWS.Core.Http.request "VerifyUserAttribute" AWS.Core.Http.POST "/" jsonBody decoder


{-| Use this API to register a user's entered TOTP code and mark the user's software token MFA status as "verified" if successful. The request takes an access token or a session string, but not both.
-}
verifySoftwareToken : VerifySoftwareTokenRequest -> AWS.Core.Http.Request VerifySoftwareTokenResponse
verifySoftwareToken req =
    let
        jsonBody =
            req |> Codec.encoder verifySoftwareTokenRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder verifySoftwareTokenResponseCodec
    in
    AWS.Core.Http.request "VerifySoftwareToken" AWS.Core.Http.POST "/" jsonBody decoder


{-| Updates the Secure Sockets Layer (SSL) certificate for the custom domain for your user pool.

You can use this operation to provide the Amazon Resource Name (ARN) of a new certificate to Amazon Cognito. You cannot use it to change the domain for a user pool.

A custom domain is used to host the Amazon Cognito hosted UI, which provides sign-up and sign-in pages for your application. When you set up a custom domain, you provide a certificate that you manage with AWS Certificate Manager (ACM). When necessary, you can use this operation to change the certificate that you applied to your custom domain.

Usually, this is unnecessary following routine certificate renewal with ACM. When you renew your existing certificate in ACM, the ARN for your certificate remains the same, and your custom domain uses the new certificate automatically.

However, if you replace your existing certificate with a new one, ACM gives the new certificate a new ARN. To apply the new certificate to your custom domain, you must provide this ARN to Amazon Cognito.

When you add your new certificate in ACM, you must choose US East (N. Virginia) as the AWS Region.

After you submit your request, Amazon Cognito requires up to 1 hour to distribute your new certificate to your custom domain.

For more information about adding a custom domain to your user pool, see `Using Your Own Domain for the Hosted UI`.

-}
updateUserPoolDomain : UpdateUserPoolDomainRequest -> AWS.Core.Http.Request UpdateUserPoolDomainResponse
updateUserPoolDomain req =
    let
        jsonBody =
            req |> Codec.encoder updateUserPoolDomainRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder updateUserPoolDomainResponseCodec
    in
    AWS.Core.Http.request "UpdateUserPoolDomain" AWS.Core.Http.POST "/" jsonBody decoder


{-| Updates the specified user pool app client with the specified attributes. If you don't provide a value for an attribute, it will be set to the default value. You can get a list of the current user pool app client settings with .
-}
updateUserPoolClient : UpdateUserPoolClientRequest -> AWS.Core.Http.Request UpdateUserPoolClientResponse
updateUserPoolClient req =
    let
        jsonBody =
            req |> Codec.encoder updateUserPoolClientRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder updateUserPoolClientResponseCodec
    in
    AWS.Core.Http.request "UpdateUserPoolClient" AWS.Core.Http.POST "/" jsonBody decoder


{-| Updates the specified user pool with the specified attributes. If you don't provide a value for an attribute, it will be set to the default value. You can get a list of the current user pool settings with .
-}
updateUserPool : UpdateUserPoolRequest -> AWS.Core.Http.Request UpdateUserPoolResponse
updateUserPool req =
    let
        jsonBody =
            req |> Codec.encoder updateUserPoolRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder updateUserPoolResponseCodec
    in
    AWS.Core.Http.request "UpdateUserPool" AWS.Core.Http.POST "/" jsonBody decoder


{-| Allows a user to update a specific attribute (one at a time).
-}
updateUserAttributes : UpdateUserAttributesRequest -> AWS.Core.Http.Request UpdateUserAttributesResponse
updateUserAttributes req =
    let
        jsonBody =
            req |> Codec.encoder updateUserAttributesRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder updateUserAttributesResponseCodec
    in
    AWS.Core.Http.request "UpdateUserAttributes" AWS.Core.Http.POST "/" jsonBody decoder


{-| Updates the name and scopes of resource server. All other fields are read-only.
-}
updateResourceServer : UpdateResourceServerRequest -> AWS.Core.Http.Request UpdateResourceServerResponse
updateResourceServer req =
    let
        jsonBody =
            req |> Codec.encoder updateResourceServerRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder updateResourceServerResponseCodec
    in
    AWS.Core.Http.request "UpdateResourceServer" AWS.Core.Http.POST "/" jsonBody decoder


{-| Updates identity provider information for a user pool.
-}
updateIdentityProvider : UpdateIdentityProviderRequest -> AWS.Core.Http.Request UpdateIdentityProviderResponse
updateIdentityProvider req =
    let
        jsonBody =
            req |> Codec.encoder updateIdentityProviderRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder updateIdentityProviderResponseCodec
    in
    AWS.Core.Http.request "UpdateIdentityProvider" AWS.Core.Http.POST "/" jsonBody decoder


{-| Updates the specified group with the specified attributes.

Requires developer credentials.

-}
updateGroup : UpdateGroupRequest -> AWS.Core.Http.Request UpdateGroupResponse
updateGroup req =
    let
        jsonBody =
            req |> Codec.encoder updateGroupRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder updateGroupResponseCodec
    in
    AWS.Core.Http.request "UpdateGroup" AWS.Core.Http.POST "/" jsonBody decoder


{-| Updates the device status.
-}
updateDeviceStatus : UpdateDeviceStatusRequest -> AWS.Core.Http.Request UpdateDeviceStatusResponse
updateDeviceStatus req =
    let
        jsonBody =
            req |> Codec.encoder updateDeviceStatusRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder updateDeviceStatusResponseCodec
    in
    AWS.Core.Http.request "UpdateDeviceStatus" AWS.Core.Http.POST "/" jsonBody decoder


{-| Provides the feedback for an authentication event whether it was from a valid user or not. This feedback is used for improving the risk evaluation decision for the user pool as part of Amazon Cognito advanced security.
-}
updateAuthEventFeedback : UpdateAuthEventFeedbackRequest -> AWS.Core.Http.Request UpdateAuthEventFeedbackResponse
updateAuthEventFeedback req =
    let
        jsonBody =
            req |> Codec.encoder updateAuthEventFeedbackRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder updateAuthEventFeedbackResponseCodec
    in
    AWS.Core.Http.request "UpdateAuthEventFeedback" AWS.Core.Http.POST "/" jsonBody decoder


{-| Removes the specified tags from an Amazon Cognito user pool. You can use this action up to 5 times per second, per account
-}
untagResource : UntagResourceRequest -> AWS.Core.Http.Request UntagResourceResponse
untagResource req =
    let
        jsonBody =
            req |> Codec.encoder untagResourceRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder untagResourceResponseCodec
    in
    AWS.Core.Http.request "UntagResource" AWS.Core.Http.POST "/" jsonBody decoder


{-| Assigns a set of tags to an Amazon Cognito user pool. A tag is a label that you can use to categorize and manage user pools in different ways, such as by purpose, owner, environment, or other criteria.

Each tag consists of a key and value, both of which you define. A key is a general category for more specific values. For example, if you have two versions of a user pool, one for testing and another for production, you might assign an `Environment` tag key to both user pools. The value of this key might be `Test` for one user pool and `Production` for the other.

Tags are useful for cost tracking and access control. You can activate your tags so that they appear on the Billing and Cost Management console, where you can track the costs associated with your user pools. In an IAM policy, you can constrain permissions for user pools based on specific tags or tag values.

You can use this action up to 5 times per second, per account. A user pool can have as many as 50 tags.

-}
tagResource : TagResourceRequest -> AWS.Core.Http.Request TagResourceResponse
tagResource req =
    let
        jsonBody =
            req |> Codec.encoder tagResourceRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder tagResourceResponseCodec
    in
    AWS.Core.Http.request "TagResource" AWS.Core.Http.POST "/" jsonBody decoder


{-| Stops the user import job.
-}
stopUserImportJob : StopUserImportJobRequest -> AWS.Core.Http.Request StopUserImportJobResponse
stopUserImportJob req =
    let
        jsonBody =
            req |> Codec.encoder stopUserImportJobRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder stopUserImportJobResponseCodec
    in
    AWS.Core.Http.request "StopUserImportJob" AWS.Core.Http.POST "/" jsonBody decoder


{-| Starts the user import.
-}
startUserImportJob : StartUserImportJobRequest -> AWS.Core.Http.Request StartUserImportJobResponse
startUserImportJob req =
    let
        jsonBody =
            req |> Codec.encoder startUserImportJobRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder startUserImportJobResponseCodec
    in
    AWS.Core.Http.request "StartUserImportJob" AWS.Core.Http.POST "/" jsonBody decoder


{-| Registers the user in the specified user pool and creates a user name, password, and user attributes.
-}
signUp : SignUpRequest -> AWS.Core.Http.Request SignUpResponse
signUp req =
    let
        jsonBody =
            req |> Codec.encoder signUpRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder signUpResponseCodec
    in
    AWS.Core.Http.request "SignUp" AWS.Core.Http.POST "/" jsonBody decoder


{-| Sets the user settings like multi-factor authentication (MFA). If MFA is to be removed for a particular attribute pass the attribute with code delivery as null. If null list is passed, all MFA options are removed.
-}
setUserSettings : SetUserSettingsRequest -> AWS.Core.Http.Request SetUserSettingsResponse
setUserSettings req =
    let
        jsonBody =
            req |> Codec.encoder setUserSettingsRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder setUserSettingsResponseCodec
    in
    AWS.Core.Http.request "SetUserSettings" AWS.Core.Http.POST "/" jsonBody decoder


{-| Set the user pool MFA configuration.
-}
setUserPoolMfaConfig : SetUserPoolMfaConfigRequest -> AWS.Core.Http.Request SetUserPoolMfaConfigResponse
setUserPoolMfaConfig req =
    let
        jsonBody =
            req |> Codec.encoder setUserPoolMfaConfigRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder setUserPoolMfaConfigResponseCodec
    in
    AWS.Core.Http.request "SetUserPoolMfaConfig" AWS.Core.Http.POST "/" jsonBody decoder


{-| Set the user's multi-factor authentication (MFA) method preference.
-}
setUserMfapreference : SetUserMfapreferenceRequest -> AWS.Core.Http.Request SetUserMfapreferenceResponse
setUserMfapreference req =
    let
        jsonBody =
            req |> Codec.encoder setUserMfapreferenceRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder setUserMfapreferenceResponseCodec
    in
    AWS.Core.Http.request "SetUserMfapreference" AWS.Core.Http.POST "/" jsonBody decoder


{-| Sets the UI customization information for a user pool's built-in app UI.

You can specify app UI customization settings for a single client (with a specific `clientId`) or for all clients (by setting the `clientId` to `ALL`). If you specify `ALL`, the default configuration will be used for every client that has no UI customization set previously. If you specify UI customization settings for a particular client, it will no longer fall back to the `ALL` configuration.

To use this API, your user pool must have a domain associated with it. Otherwise, there is no place to host the app's pages, and the service will throw an error.

-}
setUicustomization : SetUicustomizationRequest -> AWS.Core.Http.Request SetUicustomizationResponse
setUicustomization req =
    let
        jsonBody =
            req |> Codec.encoder setUicustomizationRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder setUicustomizationResponseCodec
    in
    AWS.Core.Http.request "SetUicustomization" AWS.Core.Http.POST "/" jsonBody decoder


{-| Configures actions on detected risks. To delete the risk configuration for `UserPoolId` or `ClientId`, pass null values for all four configuration types.

To enable Amazon Cognito advanced security features, update the user pool to include the `UserPoolAddOns` key`AdvancedSecurityMode`.

See .

-}
setRiskConfiguration : SetRiskConfigurationRequest -> AWS.Core.Http.Request SetRiskConfigurationResponse
setRiskConfiguration req =
    let
        jsonBody =
            req |> Codec.encoder setRiskConfigurationRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder setRiskConfigurationResponseCodec
    in
    AWS.Core.Http.request "SetRiskConfiguration" AWS.Core.Http.POST "/" jsonBody decoder


{-| Responds to the authentication challenge.
-}
respondToAuthChallenge : RespondToAuthChallengeRequest -> AWS.Core.Http.Request RespondToAuthChallengeResponse
respondToAuthChallenge req =
    let
        jsonBody =
            req |> Codec.encoder respondToAuthChallengeRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder respondToAuthChallengeResponseCodec
    in
    AWS.Core.Http.request "RespondToAuthChallenge" AWS.Core.Http.POST "/" jsonBody decoder


{-| Resends the confirmation (for confirmation of registration) to a specific user in the user pool.
-}
resendConfirmationCode : ResendConfirmationCodeRequest -> AWS.Core.Http.Request ResendConfirmationCodeResponse
resendConfirmationCode req =
    let
        jsonBody =
            req |> Codec.encoder resendConfirmationCodeRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder resendConfirmationCodeResponseCodec
    in
    AWS.Core.Http.request "ResendConfirmationCode" AWS.Core.Http.POST "/" jsonBody decoder


{-| Lists the users in the specified group.

Requires developer credentials.

-}
listUsersInGroup : ListUsersInGroupRequest -> AWS.Core.Http.Request ListUsersInGroupResponse
listUsersInGroup req =
    let
        jsonBody =
            req |> Codec.encoder listUsersInGroupRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder listUsersInGroupResponseCodec
    in
    AWS.Core.Http.request "ListUsersInGroup" AWS.Core.Http.POST "/" jsonBody decoder


{-| Lists the users in the Amazon Cognito user pool.
-}
listUsers : ListUsersRequest -> AWS.Core.Http.Request ListUsersResponse
listUsers req =
    let
        jsonBody =
            req |> Codec.encoder listUsersRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder listUsersResponseCodec
    in
    AWS.Core.Http.request "ListUsers" AWS.Core.Http.POST "/" jsonBody decoder


{-| Lists the user pools associated with an AWS account.
-}
listUserPools : ListUserPoolsRequest -> AWS.Core.Http.Request ListUserPoolsResponse
listUserPools req =
    let
        jsonBody =
            req |> Codec.encoder listUserPoolsRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder listUserPoolsResponseCodec
    in
    AWS.Core.Http.request "ListUserPools" AWS.Core.Http.POST "/" jsonBody decoder


{-| Lists the clients that have been created for the specified user pool.
-}
listUserPoolClients : ListUserPoolClientsRequest -> AWS.Core.Http.Request ListUserPoolClientsResponse
listUserPoolClients req =
    let
        jsonBody =
            req |> Codec.encoder listUserPoolClientsRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder listUserPoolClientsResponseCodec
    in
    AWS.Core.Http.request "ListUserPoolClients" AWS.Core.Http.POST "/" jsonBody decoder


{-| Lists the user import jobs.
-}
listUserImportJobs : ListUserImportJobsRequest -> AWS.Core.Http.Request ListUserImportJobsResponse
listUserImportJobs req =
    let
        jsonBody =
            req |> Codec.encoder listUserImportJobsRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder listUserImportJobsResponseCodec
    in
    AWS.Core.Http.request "ListUserImportJobs" AWS.Core.Http.POST "/" jsonBody decoder


{-| Lists the tags that are assigned to an Amazon Cognito user pool.

A tag is a label that you can apply to user pools to categorize and manage them in different ways, such as by purpose, owner, environment, or other criteria.

You can use this action up to 10 times per second, per account.

-}
listTagsForResource : ListTagsForResourceRequest -> AWS.Core.Http.Request ListTagsForResourceResponse
listTagsForResource req =
    let
        jsonBody =
            req |> Codec.encoder listTagsForResourceRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder listTagsForResourceResponseCodec
    in
    AWS.Core.Http.request "ListTagsForResource" AWS.Core.Http.POST "/" jsonBody decoder


{-| Lists the resource servers for a user pool.
-}
listResourceServers : ListResourceServersRequest -> AWS.Core.Http.Request ListResourceServersResponse
listResourceServers req =
    let
        jsonBody =
            req |> Codec.encoder listResourceServersRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder listResourceServersResponseCodec
    in
    AWS.Core.Http.request "ListResourceServers" AWS.Core.Http.POST "/" jsonBody decoder


{-| Lists information about all identity providers for a user pool.
-}
listIdentityProviders : ListIdentityProvidersRequest -> AWS.Core.Http.Request ListIdentityProvidersResponse
listIdentityProviders req =
    let
        jsonBody =
            req |> Codec.encoder listIdentityProvidersRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder listIdentityProvidersResponseCodec
    in
    AWS.Core.Http.request "ListIdentityProviders" AWS.Core.Http.POST "/" jsonBody decoder


{-| Lists the groups associated with a user pool.

Requires developer credentials.

-}
listGroups : ListGroupsRequest -> AWS.Core.Http.Request ListGroupsResponse
listGroups req =
    let
        jsonBody =
            req |> Codec.encoder listGroupsRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder listGroupsResponseCodec
    in
    AWS.Core.Http.request "ListGroups" AWS.Core.Http.POST "/" jsonBody decoder


{-| Lists the devices.
-}
listDevices : ListDevicesRequest -> AWS.Core.Http.Request ListDevicesResponse
listDevices req =
    let
        jsonBody =
            req |> Codec.encoder listDevicesRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder listDevicesResponseCodec
    in
    AWS.Core.Http.request "ListDevices" AWS.Core.Http.POST "/" jsonBody decoder


{-| Initiates the authentication flow.
-}
initiateAuth : InitiateAuthRequest -> AWS.Core.Http.Request InitiateAuthResponse
initiateAuth req =
    let
        jsonBody =
            req |> Codec.encoder initiateAuthRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder initiateAuthResponseCodec
    in
    AWS.Core.Http.request "InitiateAuth" AWS.Core.Http.POST "/" jsonBody decoder


{-| Signs out users from all devices.
-}
globalSignOut : GlobalSignOutRequest -> AWS.Core.Http.Request GlobalSignOutResponse
globalSignOut req =
    let
        jsonBody =
            req |> Codec.encoder globalSignOutRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder globalSignOutResponseCodec
    in
    AWS.Core.Http.request "GlobalSignOut" AWS.Core.Http.POST "/" jsonBody decoder


{-| Gets the user pool multi-factor authentication (MFA) configuration.
-}
getUserPoolMfaConfig : GetUserPoolMfaConfigRequest -> AWS.Core.Http.Request GetUserPoolMfaConfigResponse
getUserPoolMfaConfig req =
    let
        jsonBody =
            req |> Codec.encoder getUserPoolMfaConfigRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder getUserPoolMfaConfigResponseCodec
    in
    AWS.Core.Http.request "GetUserPoolMfaConfig" AWS.Core.Http.POST "/" jsonBody decoder


{-| Gets the user attribute verification code for the specified attribute name.
-}
getUserAttributeVerificationCode : GetUserAttributeVerificationCodeRequest -> AWS.Core.Http.Request GetUserAttributeVerificationCodeResponse
getUserAttributeVerificationCode req =
    let
        jsonBody =
            req |> Codec.encoder getUserAttributeVerificationCodeRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder getUserAttributeVerificationCodeResponseCodec
    in
    AWS.Core.Http.request "GetUserAttributeVerificationCode" AWS.Core.Http.POST "/" jsonBody decoder


{-| Gets the user attributes and metadata for a user.
-}
getUser : GetUserRequest -> AWS.Core.Http.Request GetUserResponse
getUser req =
    let
        jsonBody =
            req |> Codec.encoder getUserRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder getUserResponseCodec
    in
    AWS.Core.Http.request "GetUser" AWS.Core.Http.POST "/" jsonBody decoder


{-| Gets the UI Customization information for a particular app client's app UI, if there is something set. If nothing is set for the particular client, but there is an existing pool level customization (app `clientId` will be `ALL`), then that is returned. If nothing is present, then an empty shape is returned.
-}
getUicustomization : GetUicustomizationRequest -> AWS.Core.Http.Request GetUicustomizationResponse
getUicustomization req =
    let
        jsonBody =
            req |> Codec.encoder getUicustomizationRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder getUicustomizationResponseCodec
    in
    AWS.Core.Http.request "GetUicustomization" AWS.Core.Http.POST "/" jsonBody decoder


{-| This method takes a user pool ID, and returns the signing certificate.
-}
getSigningCertificate : GetSigningCertificateRequest -> AWS.Core.Http.Request GetSigningCertificateResponse
getSigningCertificate req =
    let
        jsonBody =
            req |> Codec.encoder getSigningCertificateRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder getSigningCertificateResponseCodec
    in
    AWS.Core.Http.request "GetSigningCertificate" AWS.Core.Http.POST "/" jsonBody decoder


{-| Gets the specified identity provider.
-}
getIdentityProviderByIdentifier : GetIdentityProviderByIdentifierRequest -> AWS.Core.Http.Request GetIdentityProviderByIdentifierResponse
getIdentityProviderByIdentifier req =
    let
        jsonBody =
            req |> Codec.encoder getIdentityProviderByIdentifierRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder getIdentityProviderByIdentifierResponseCodec
    in
    AWS.Core.Http.request "GetIdentityProviderByIdentifier" AWS.Core.Http.POST "/" jsonBody decoder


{-| Gets a group.

Requires developer credentials.

-}
getGroup : GetGroupRequest -> AWS.Core.Http.Request GetGroupResponse
getGroup req =
    let
        jsonBody =
            req |> Codec.encoder getGroupRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder getGroupResponseCodec
    in
    AWS.Core.Http.request "GetGroup" AWS.Core.Http.POST "/" jsonBody decoder


{-| Gets the device.
-}
getDevice : GetDeviceRequest -> AWS.Core.Http.Request GetDeviceResponse
getDevice req =
    let
        jsonBody =
            req |> Codec.encoder getDeviceRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder getDeviceResponseCodec
    in
    AWS.Core.Http.request "GetDevice" AWS.Core.Http.POST "/" jsonBody decoder


{-| Gets the header information for the .csv file to be used as input for the user import job.
-}
getCsvheader : GetCsvheaderRequest -> AWS.Core.Http.Request GetCsvheaderResponse
getCsvheader req =
    let
        jsonBody =
            req |> Codec.encoder getCsvheaderRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder getCsvheaderResponseCodec
    in
    AWS.Core.Http.request "GetCsvheader" AWS.Core.Http.POST "/" jsonBody decoder


{-| Calling this API causes a message to be sent to the end user with a confirmation code that is required to change the user's password. For the `Username` parameter, you can use the username or user alias. If a verified phone number exists for the user, the confirmation code is sent to the phone number. Otherwise, if a verified email exists, the confirmation code is sent to the email. If neither a verified phone number nor a verified email exists, `InvalidParameterException` is thrown. To use the confirmation code for resetting the password, call .
-}
forgotPassword : ForgotPasswordRequest -> AWS.Core.Http.Request ForgotPasswordResponse
forgotPassword req =
    let
        jsonBody =
            req |> Codec.encoder forgotPasswordRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder forgotPasswordResponseCodec
    in
    AWS.Core.Http.request "ForgotPassword" AWS.Core.Http.POST "/" jsonBody decoder


{-| Forgets the specified device.
-}
forgetDevice : ForgetDeviceRequest -> AWS.Core.Http.Request ()
forgetDevice req =
    let
        jsonBody =
            req |> Codec.encoder forgetDeviceRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Json.Decode.succeed ()
    in
    AWS.Core.Http.request "ForgetDevice" AWS.Core.Http.POST "/" jsonBody decoder


{-| Gets information about a domain.
-}
describeUserPoolDomain : DescribeUserPoolDomainRequest -> AWS.Core.Http.Request DescribeUserPoolDomainResponse
describeUserPoolDomain req =
    let
        jsonBody =
            req |> Codec.encoder describeUserPoolDomainRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder describeUserPoolDomainResponseCodec
    in
    AWS.Core.Http.request "DescribeUserPoolDomain" AWS.Core.Http.POST "/" jsonBody decoder


{-| Client method for returning the configuration information and metadata of the specified user pool app client.
-}
describeUserPoolClient : DescribeUserPoolClientRequest -> AWS.Core.Http.Request DescribeUserPoolClientResponse
describeUserPoolClient req =
    let
        jsonBody =
            req |> Codec.encoder describeUserPoolClientRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder describeUserPoolClientResponseCodec
    in
    AWS.Core.Http.request "DescribeUserPoolClient" AWS.Core.Http.POST "/" jsonBody decoder


{-| Returns the configuration information and metadata of the specified user pool.
-}
describeUserPool : DescribeUserPoolRequest -> AWS.Core.Http.Request DescribeUserPoolResponse
describeUserPool req =
    let
        jsonBody =
            req |> Codec.encoder describeUserPoolRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder describeUserPoolResponseCodec
    in
    AWS.Core.Http.request "DescribeUserPool" AWS.Core.Http.POST "/" jsonBody decoder


{-| Describes the user import job.
-}
describeUserImportJob : DescribeUserImportJobRequest -> AWS.Core.Http.Request DescribeUserImportJobResponse
describeUserImportJob req =
    let
        jsonBody =
            req |> Codec.encoder describeUserImportJobRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder describeUserImportJobResponseCodec
    in
    AWS.Core.Http.request "DescribeUserImportJob" AWS.Core.Http.POST "/" jsonBody decoder


{-| Describes the risk configuration.
-}
describeRiskConfiguration : DescribeRiskConfigurationRequest -> AWS.Core.Http.Request DescribeRiskConfigurationResponse
describeRiskConfiguration req =
    let
        jsonBody =
            req |> Codec.encoder describeRiskConfigurationRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder describeRiskConfigurationResponseCodec
    in
    AWS.Core.Http.request "DescribeRiskConfiguration" AWS.Core.Http.POST "/" jsonBody decoder


{-| Describes a resource server.
-}
describeResourceServer : DescribeResourceServerRequest -> AWS.Core.Http.Request DescribeResourceServerResponse
describeResourceServer req =
    let
        jsonBody =
            req |> Codec.encoder describeResourceServerRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder describeResourceServerResponseCodec
    in
    AWS.Core.Http.request "DescribeResourceServer" AWS.Core.Http.POST "/" jsonBody decoder


{-| Gets information about a specific identity provider.
-}
describeIdentityProvider : DescribeIdentityProviderRequest -> AWS.Core.Http.Request DescribeIdentityProviderResponse
describeIdentityProvider req =
    let
        jsonBody =
            req |> Codec.encoder describeIdentityProviderRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder describeIdentityProviderResponseCodec
    in
    AWS.Core.Http.request "DescribeIdentityProvider" AWS.Core.Http.POST "/" jsonBody decoder


{-| Deletes a domain for a user pool.
-}
deleteUserPoolDomain : DeleteUserPoolDomainRequest -> AWS.Core.Http.Request DeleteUserPoolDomainResponse
deleteUserPoolDomain req =
    let
        jsonBody =
            req |> Codec.encoder deleteUserPoolDomainRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder deleteUserPoolDomainResponseCodec
    in
    AWS.Core.Http.request "DeleteUserPoolDomain" AWS.Core.Http.POST "/" jsonBody decoder


{-| Allows the developer to delete the user pool client.
-}
deleteUserPoolClient : DeleteUserPoolClientRequest -> AWS.Core.Http.Request ()
deleteUserPoolClient req =
    let
        jsonBody =
            req |> Codec.encoder deleteUserPoolClientRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Json.Decode.succeed ()
    in
    AWS.Core.Http.request "DeleteUserPoolClient" AWS.Core.Http.POST "/" jsonBody decoder


{-| Deletes the specified Amazon Cognito user pool.
-}
deleteUserPool : DeleteUserPoolRequest -> AWS.Core.Http.Request ()
deleteUserPool req =
    let
        jsonBody =
            req |> Codec.encoder deleteUserPoolRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Json.Decode.succeed ()
    in
    AWS.Core.Http.request "DeleteUserPool" AWS.Core.Http.POST "/" jsonBody decoder


{-| Deletes the attributes for a user.
-}
deleteUserAttributes : DeleteUserAttributesRequest -> AWS.Core.Http.Request DeleteUserAttributesResponse
deleteUserAttributes req =
    let
        jsonBody =
            req |> Codec.encoder deleteUserAttributesRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder deleteUserAttributesResponseCodec
    in
    AWS.Core.Http.request "DeleteUserAttributes" AWS.Core.Http.POST "/" jsonBody decoder


{-| Allows a user to delete himself or herself.
-}
deleteUser : DeleteUserRequest -> AWS.Core.Http.Request ()
deleteUser req =
    let
        jsonBody =
            req |> Codec.encoder deleteUserRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Json.Decode.succeed ()
    in
    AWS.Core.Http.request "DeleteUser" AWS.Core.Http.POST "/" jsonBody decoder


{-| Deletes a resource server.
-}
deleteResourceServer : DeleteResourceServerRequest -> AWS.Core.Http.Request ()
deleteResourceServer req =
    let
        jsonBody =
            req |> Codec.encoder deleteResourceServerRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Json.Decode.succeed ()
    in
    AWS.Core.Http.request "DeleteResourceServer" AWS.Core.Http.POST "/" jsonBody decoder


{-| Deletes an identity provider for a user pool.
-}
deleteIdentityProvider : DeleteIdentityProviderRequest -> AWS.Core.Http.Request ()
deleteIdentityProvider req =
    let
        jsonBody =
            req |> Codec.encoder deleteIdentityProviderRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Json.Decode.succeed ()
    in
    AWS.Core.Http.request "DeleteIdentityProvider" AWS.Core.Http.POST "/" jsonBody decoder


{-| Deletes a group. Currently only groups with no members can be deleted.

Requires developer credentials.

-}
deleteGroup : DeleteGroupRequest -> AWS.Core.Http.Request ()
deleteGroup req =
    let
        jsonBody =
            req |> Codec.encoder deleteGroupRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Json.Decode.succeed ()
    in
    AWS.Core.Http.request "DeleteGroup" AWS.Core.Http.POST "/" jsonBody decoder


{-| Creates a new domain for a user pool.
-}
createUserPoolDomain : CreateUserPoolDomainRequest -> AWS.Core.Http.Request CreateUserPoolDomainResponse
createUserPoolDomain req =
    let
        jsonBody =
            req |> Codec.encoder createUserPoolDomainRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder createUserPoolDomainResponseCodec
    in
    AWS.Core.Http.request "CreateUserPoolDomain" AWS.Core.Http.POST "/" jsonBody decoder


{-| Creates the user pool client.
-}
createUserPoolClient : CreateUserPoolClientRequest -> AWS.Core.Http.Request CreateUserPoolClientResponse
createUserPoolClient req =
    let
        jsonBody =
            req |> Codec.encoder createUserPoolClientRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder createUserPoolClientResponseCodec
    in
    AWS.Core.Http.request "CreateUserPoolClient" AWS.Core.Http.POST "/" jsonBody decoder


{-| Creates a new Amazon Cognito user pool and sets the password policy for the pool.
-}
createUserPool : CreateUserPoolRequest -> AWS.Core.Http.Request CreateUserPoolResponse
createUserPool req =
    let
        jsonBody =
            req |> Codec.encoder createUserPoolRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder createUserPoolResponseCodec
    in
    AWS.Core.Http.request "CreateUserPool" AWS.Core.Http.POST "/" jsonBody decoder


{-| Creates the user import job.
-}
createUserImportJob : CreateUserImportJobRequest -> AWS.Core.Http.Request CreateUserImportJobResponse
createUserImportJob req =
    let
        jsonBody =
            req |> Codec.encoder createUserImportJobRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder createUserImportJobResponseCodec
    in
    AWS.Core.Http.request "CreateUserImportJob" AWS.Core.Http.POST "/" jsonBody decoder


{-| Creates a new OAuth2.0 resource server and defines custom scopes in it.
-}
createResourceServer : CreateResourceServerRequest -> AWS.Core.Http.Request CreateResourceServerResponse
createResourceServer req =
    let
        jsonBody =
            req |> Codec.encoder createResourceServerRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder createResourceServerResponseCodec
    in
    AWS.Core.Http.request "CreateResourceServer" AWS.Core.Http.POST "/" jsonBody decoder


{-| Creates an identity provider for a user pool.
-}
createIdentityProvider : CreateIdentityProviderRequest -> AWS.Core.Http.Request CreateIdentityProviderResponse
createIdentityProvider req =
    let
        jsonBody =
            req |> Codec.encoder createIdentityProviderRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder createIdentityProviderResponseCodec
    in
    AWS.Core.Http.request "CreateIdentityProvider" AWS.Core.Http.POST "/" jsonBody decoder


{-| Creates a new group in the specified user pool.

Requires developer credentials.

-}
createGroup : CreateGroupRequest -> AWS.Core.Http.Request CreateGroupResponse
createGroup req =
    let
        jsonBody =
            req |> Codec.encoder createGroupRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder createGroupResponseCodec
    in
    AWS.Core.Http.request "CreateGroup" AWS.Core.Http.POST "/" jsonBody decoder


{-| Confirms registration of a user and handles the existing alias from a previous user.
-}
confirmSignUp : ConfirmSignUpRequest -> AWS.Core.Http.Request ConfirmSignUpResponse
confirmSignUp req =
    let
        jsonBody =
            req |> Codec.encoder confirmSignUpRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder confirmSignUpResponseCodec
    in
    AWS.Core.Http.request "ConfirmSignUp" AWS.Core.Http.POST "/" jsonBody decoder


{-| Allows a user to enter a confirmation code to reset a forgotten password.
-}
confirmForgotPassword : ConfirmForgotPasswordRequest -> AWS.Core.Http.Request ConfirmForgotPasswordResponse
confirmForgotPassword req =
    let
        jsonBody =
            req |> Codec.encoder confirmForgotPasswordRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder confirmForgotPasswordResponseCodec
    in
    AWS.Core.Http.request "ConfirmForgotPassword" AWS.Core.Http.POST "/" jsonBody decoder


{-| Confirms tracking of the device. This API call is the call that begins device tracking.
-}
confirmDevice : ConfirmDeviceRequest -> AWS.Core.Http.Request ConfirmDeviceResponse
confirmDevice req =
    let
        jsonBody =
            req |> Codec.encoder confirmDeviceRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder confirmDeviceResponseCodec
    in
    AWS.Core.Http.request "ConfirmDevice" AWS.Core.Http.POST "/" jsonBody decoder


{-| Changes the password for a specified user in a user pool.
-}
changePassword : ChangePasswordRequest -> AWS.Core.Http.Request ChangePasswordResponse
changePassword req =
    let
        jsonBody =
            req |> Codec.encoder changePasswordRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder changePasswordResponseCodec
    in
    AWS.Core.Http.request "ChangePassword" AWS.Core.Http.POST "/" jsonBody decoder


{-| Returns a unique generated shared secret key code for the user account. The request takes an access token or a session string, but not both.
-}
associateSoftwareToken : AssociateSoftwareTokenRequest -> AWS.Core.Http.Request AssociateSoftwareTokenResponse
associateSoftwareToken req =
    let
        jsonBody =
            req |> Codec.encoder associateSoftwareTokenRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder associateSoftwareTokenResponseCodec
    in
    AWS.Core.Http.request "AssociateSoftwareToken" AWS.Core.Http.POST "/" jsonBody decoder


{-| Signs out users from all devices, as an administrator.

Requires developer credentials.

-}
adminUserGlobalSignOut : AdminUserGlobalSignOutRequest -> AWS.Core.Http.Request AdminUserGlobalSignOutResponse
adminUserGlobalSignOut req =
    let
        jsonBody =
            req |> Codec.encoder adminUserGlobalSignOutRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder adminUserGlobalSignOutResponseCodec
    in
    AWS.Core.Http.request "AdminUserGlobalSignOut" AWS.Core.Http.POST "/" jsonBody decoder


{-| Updates the specified user's attributes, including developer attributes, as an administrator. Works on any user.

For custom attributes, you must prepend the `custom:` prefix to the attribute name.

In addition to updating user attributes, this API can also be used to mark phone and email as verified.

Requires developer credentials.

-}
adminUpdateUserAttributes : AdminUpdateUserAttributesRequest -> AWS.Core.Http.Request AdminUpdateUserAttributesResponse
adminUpdateUserAttributes req =
    let
        jsonBody =
            req |> Codec.encoder adminUpdateUserAttributesRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder adminUpdateUserAttributesResponseCodec
    in
    AWS.Core.Http.request "AdminUpdateUserAttributes" AWS.Core.Http.POST "/" jsonBody decoder


{-| Updates the device status as an administrator.

Requires developer credentials.

-}
adminUpdateDeviceStatus : AdminUpdateDeviceStatusRequest -> AWS.Core.Http.Request AdminUpdateDeviceStatusResponse
adminUpdateDeviceStatus req =
    let
        jsonBody =
            req |> Codec.encoder adminUpdateDeviceStatusRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder adminUpdateDeviceStatusResponseCodec
    in
    AWS.Core.Http.request "AdminUpdateDeviceStatus" AWS.Core.Http.POST "/" jsonBody decoder


{-| Provides feedback for an authentication event as to whether it was from a valid user. This feedback is used for improving the risk evaluation decision for the user pool as part of Amazon Cognito advanced security.
-}
adminUpdateAuthEventFeedback : AdminUpdateAuthEventFeedbackRequest -> AWS.Core.Http.Request AdminUpdateAuthEventFeedbackResponse
adminUpdateAuthEventFeedback req =
    let
        jsonBody =
            req |> Codec.encoder adminUpdateAuthEventFeedbackRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder adminUpdateAuthEventFeedbackResponseCodec
    in
    AWS.Core.Http.request "AdminUpdateAuthEventFeedback" AWS.Core.Http.POST "/" jsonBody decoder


{-| Sets all the user settings for a specified user name. Works on any user.

Requires developer credentials.

-}
adminSetUserSettings : AdminSetUserSettingsRequest -> AWS.Core.Http.Request AdminSetUserSettingsResponse
adminSetUserSettings req =
    let
        jsonBody =
            req |> Codec.encoder adminSetUserSettingsRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder adminSetUserSettingsResponseCodec
    in
    AWS.Core.Http.request "AdminSetUserSettings" AWS.Core.Http.POST "/" jsonBody decoder


{-| -}
adminSetUserPassword : AdminSetUserPasswordRequest -> AWS.Core.Http.Request AdminSetUserPasswordResponse
adminSetUserPassword req =
    let
        jsonBody =
            req |> Codec.encoder adminSetUserPasswordRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder adminSetUserPasswordResponseCodec
    in
    AWS.Core.Http.request "AdminSetUserPassword" AWS.Core.Http.POST "/" jsonBody decoder


{-| Sets the user's multi-factor authentication (MFA) preference.
-}
adminSetUserMfapreference : AdminSetUserMfapreferenceRequest -> AWS.Core.Http.Request AdminSetUserMfapreferenceResponse
adminSetUserMfapreference req =
    let
        jsonBody =
            req |> Codec.encoder adminSetUserMfapreferenceRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder adminSetUserMfapreferenceResponseCodec
    in
    AWS.Core.Http.request "AdminSetUserMfapreference" AWS.Core.Http.POST "/" jsonBody decoder


{-| Responds to an authentication challenge, as an administrator.

Requires developer credentials.

-}
adminRespondToAuthChallenge : AdminRespondToAuthChallengeRequest -> AWS.Core.Http.Request AdminRespondToAuthChallengeResponse
adminRespondToAuthChallenge req =
    let
        jsonBody =
            req |> Codec.encoder adminRespondToAuthChallengeRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder adminRespondToAuthChallengeResponseCodec
    in
    AWS.Core.Http.request "AdminRespondToAuthChallenge" AWS.Core.Http.POST "/" jsonBody decoder


{-| Resets the specified user's password in a user pool as an administrator. Works on any user.

When a developer calls this API, the current password is invalidated, so it must be changed. If a user tries to sign in after the API is called, the app will get a PasswordResetRequiredException exception back and should direct the user down the flow to reset the password, which is the same as the forgot password flow. In addition, if the user pool has phone verification selected and a verified phone number exists for the user, or if email verification is selected and a verified email exists for the user, calling this API will also result in sending a message to the end user with the code to change their password.

Requires developer credentials.

-}
adminResetUserPassword : AdminResetUserPasswordRequest -> AWS.Core.Http.Request AdminResetUserPasswordResponse
adminResetUserPassword req =
    let
        jsonBody =
            req |> Codec.encoder adminResetUserPasswordRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder adminResetUserPasswordResponseCodec
    in
    AWS.Core.Http.request "AdminResetUserPassword" AWS.Core.Http.POST "/" jsonBody decoder


{-| Removes the specified user from the specified group.

Requires developer credentials.

-}
adminRemoveUserFromGroup : AdminRemoveUserFromGroupRequest -> AWS.Core.Http.Request ()
adminRemoveUserFromGroup req =
    let
        jsonBody =
            req |> Codec.encoder adminRemoveUserFromGroupRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Json.Decode.succeed ()
    in
    AWS.Core.Http.request "AdminRemoveUserFromGroup" AWS.Core.Http.POST "/" jsonBody decoder


{-| Lists a history of user activity and any risks detected as part of Amazon Cognito advanced security.
-}
adminListUserAuthEvents : AdminListUserAuthEventsRequest -> AWS.Core.Http.Request AdminListUserAuthEventsResponse
adminListUserAuthEvents req =
    let
        jsonBody =
            req |> Codec.encoder adminListUserAuthEventsRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder adminListUserAuthEventsResponseCodec
    in
    AWS.Core.Http.request "AdminListUserAuthEvents" AWS.Core.Http.POST "/" jsonBody decoder


{-| Lists the groups that the user belongs to.

Requires developer credentials.

-}
adminListGroupsForUser : AdminListGroupsForUserRequest -> AWS.Core.Http.Request AdminListGroupsForUserResponse
adminListGroupsForUser req =
    let
        jsonBody =
            req |> Codec.encoder adminListGroupsForUserRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder adminListGroupsForUserResponseCodec
    in
    AWS.Core.Http.request "AdminListGroupsForUser" AWS.Core.Http.POST "/" jsonBody decoder


{-| Lists devices, as an administrator.

Requires developer credentials.

-}
adminListDevices : AdminListDevicesRequest -> AWS.Core.Http.Request AdminListDevicesResponse
adminListDevices req =
    let
        jsonBody =
            req |> Codec.encoder adminListDevicesRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder adminListDevicesResponseCodec
    in
    AWS.Core.Http.request "AdminListDevices" AWS.Core.Http.POST "/" jsonBody decoder


{-| Links an existing user account in a user pool (`DestinationUser`) to an identity from an external identity provider (`SourceUser`) based on a specified attribute name and value from the external identity provider. This allows you to create a link from the existing user account to an external federated user identity that has not yet been used to sign in, so that the federated user identity can be used to sign in as the existing user account.

For example, if there is an existing user with a username and password, this API links that user to a federated user identity, so that when the federated user identity is used, the user signs in as the existing user account.

Because this API allows a user with an external federated identity to sign in as an existing user in the user pool, it is critical that it only be used with external identity providers and provider attributes that have been trusted by the application owner.

See also .

This action is enabled only for admin access and requires developer credentials.

-}
adminLinkProviderForUser : AdminLinkProviderForUserRequest -> AWS.Core.Http.Request AdminLinkProviderForUserResponse
adminLinkProviderForUser req =
    let
        jsonBody =
            req |> Codec.encoder adminLinkProviderForUserRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder adminLinkProviderForUserResponseCodec
    in
    AWS.Core.Http.request "AdminLinkProviderForUser" AWS.Core.Http.POST "/" jsonBody decoder


{-| Initiates the authentication flow, as an administrator.

Requires developer credentials.

-}
adminInitiateAuth : AdminInitiateAuthRequest -> AWS.Core.Http.Request AdminInitiateAuthResponse
adminInitiateAuth req =
    let
        jsonBody =
            req |> Codec.encoder adminInitiateAuthRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder adminInitiateAuthResponseCodec
    in
    AWS.Core.Http.request "AdminInitiateAuth" AWS.Core.Http.POST "/" jsonBody decoder


{-| Gets the specified user by user name in a user pool as an administrator. Works on any user.

Requires developer credentials.

-}
adminGetUser : AdminGetUserRequest -> AWS.Core.Http.Request AdminGetUserResponse
adminGetUser req =
    let
        jsonBody =
            req |> Codec.encoder adminGetUserRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder adminGetUserResponseCodec
    in
    AWS.Core.Http.request "AdminGetUser" AWS.Core.Http.POST "/" jsonBody decoder


{-| Gets the device, as an administrator.

Requires developer credentials.

-}
adminGetDevice : AdminGetDeviceRequest -> AWS.Core.Http.Request AdminGetDeviceResponse
adminGetDevice req =
    let
        jsonBody =
            req |> Codec.encoder adminGetDeviceRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder adminGetDeviceResponseCodec
    in
    AWS.Core.Http.request "AdminGetDevice" AWS.Core.Http.POST "/" jsonBody decoder


{-| Forgets the device, as an administrator.

Requires developer credentials.

-}
adminForgetDevice : AdminForgetDeviceRequest -> AWS.Core.Http.Request ()
adminForgetDevice req =
    let
        jsonBody =
            req |> Codec.encoder adminForgetDeviceRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Json.Decode.succeed ()
    in
    AWS.Core.Http.request "AdminForgetDevice" AWS.Core.Http.POST "/" jsonBody decoder


{-| Enables the specified user as an administrator. Works on any user.

Requires developer credentials.

-}
adminEnableUser : AdminEnableUserRequest -> AWS.Core.Http.Request AdminEnableUserResponse
adminEnableUser req =
    let
        jsonBody =
            req |> Codec.encoder adminEnableUserRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder adminEnableUserResponseCodec
    in
    AWS.Core.Http.request "AdminEnableUser" AWS.Core.Http.POST "/" jsonBody decoder


{-| Disables the specified user as an administrator. Works on any user.

Requires developer credentials.

-}
adminDisableUser : AdminDisableUserRequest -> AWS.Core.Http.Request AdminDisableUserResponse
adminDisableUser req =
    let
        jsonBody =
            req |> Codec.encoder adminDisableUserRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder adminDisableUserResponseCodec
    in
    AWS.Core.Http.request "AdminDisableUser" AWS.Core.Http.POST "/" jsonBody decoder


{-| Disables the user from signing in with the specified external (SAML or social) identity provider. If the user to disable is a Cognito User Pools native username + password user, they are not permitted to use their password to sign-in. If the user to disable is a linked external IdP user, any link between that user and an existing user is removed. The next time the external user (no longer attached to the previously linked `DestinationUser`) signs in, they must create a new user account. See .

This action is enabled only for admin access and requires developer credentials.

The `ProviderName` must match the value specified when creating an IdP for the pool.

To disable a native username + password user, the `ProviderName` value must be `Cognito` and the `ProviderAttributeName` must be `Cognito_Subject`, with the `ProviderAttributeValue` being the name that is used in the user pool for the user.

The `ProviderAttributeName` must always be `Cognito_Subject` for social identity providers. The `ProviderAttributeValue` must always be the exact subject that was used when the user was originally linked as a source user.

For de-linking a SAML identity, there are two scenarios. If the linked identity has not yet been used to sign-in, the `ProviderAttributeName` and `ProviderAttributeValue` must be the same values that were used for the `SourceUser` when the identities were originally linked in the call. (If the linking was done with `ProviderAttributeName` set to `Cognito_Subject`, the same applies here). However, if the user has already signed in, the `ProviderAttributeName` must be `Cognito_Subject` and `ProviderAttributeValue` must be the subject of the SAML assertion.

-}
adminDisableProviderForUser : AdminDisableProviderForUserRequest -> AWS.Core.Http.Request AdminDisableProviderForUserResponse
adminDisableProviderForUser req =
    let
        jsonBody =
            req |> Codec.encoder adminDisableProviderForUserRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder adminDisableProviderForUserResponseCodec
    in
    AWS.Core.Http.request "AdminDisableProviderForUser" AWS.Core.Http.POST "/" jsonBody decoder


{-| Deletes the user attributes in a user pool as an administrator. Works on any user.

Requires developer credentials.

-}
adminDeleteUserAttributes : AdminDeleteUserAttributesRequest -> AWS.Core.Http.Request AdminDeleteUserAttributesResponse
adminDeleteUserAttributes req =
    let
        jsonBody =
            req |> Codec.encoder adminDeleteUserAttributesRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder adminDeleteUserAttributesResponseCodec
    in
    AWS.Core.Http.request "AdminDeleteUserAttributes" AWS.Core.Http.POST "/" jsonBody decoder


{-| Deletes a user as an administrator. Works on any user.

Requires developer credentials.

-}
adminDeleteUser : AdminDeleteUserRequest -> AWS.Core.Http.Request ()
adminDeleteUser req =
    let
        jsonBody =
            req |> Codec.encoder adminDeleteUserRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Json.Decode.succeed ()
    in
    AWS.Core.Http.request "AdminDeleteUser" AWS.Core.Http.POST "/" jsonBody decoder


{-| Creates a new user in the specified user pool.

If `MessageAction` is not set, the default is to send a welcome message via email or phone (SMS).

This message is based on a template that you configured in your call to or . This template includes your custom sign-up instructions and placeholders for user name and temporary password.

Alternatively, you can call AdminCreateUser with “SUPPRESS” for the `MessageAction` parameter, and Amazon Cognito will not send any email.

In either case, the user will be in the `FORCE_CHANGE_PASSWORD` state until they sign in and change their password.

AdminCreateUser requires developer credentials.

-}
adminCreateUser : AdminCreateUserRequest -> AWS.Core.Http.Request AdminCreateUserResponse
adminCreateUser req =
    let
        jsonBody =
            req |> Codec.encoder adminCreateUserRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder adminCreateUserResponseCodec
    in
    AWS.Core.Http.request "AdminCreateUser" AWS.Core.Http.POST "/" jsonBody decoder


{-| Confirms user registration as an admin without using a confirmation code. Works on any user.

Requires developer credentials.

-}
adminConfirmSignUp : AdminConfirmSignUpRequest -> AWS.Core.Http.Request AdminConfirmSignUpResponse
adminConfirmSignUp req =
    let
        jsonBody =
            req |> Codec.encoder adminConfirmSignUpRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder adminConfirmSignUpResponseCodec
    in
    AWS.Core.Http.request "AdminConfirmSignUp" AWS.Core.Http.POST "/" jsonBody decoder


{-| Adds the specified user to the specified group.

Requires developer credentials.

-}
adminAddUserToGroup : AdminAddUserToGroupRequest -> AWS.Core.Http.Request ()
adminAddUserToGroup req =
    let
        jsonBody =
            req |> Codec.encoder adminAddUserToGroupRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Json.Decode.succeed ()
    in
    AWS.Core.Http.request "AdminAddUserToGroup" AWS.Core.Http.POST "/" jsonBody decoder


{-| Adds additional user attributes to the user pool schema.
-}
addCustomAttributes : AddCustomAttributesRequest -> AWS.Core.Http.Request AddCustomAttributesResponse
addCustomAttributes req =
    let
        jsonBody =
            req |> Codec.encoder addCustomAttributesRequestCodec |> AWS.Core.Http.jsonBody

        decoder =
            Codec.decoder addCustomAttributesResponseCodec
    in
    AWS.Core.Http.request "AddCustomAttributes" AWS.Core.Http.POST "/" jsonBody decoder


{-| The AwsaccountIdType data model.
-}
type alias AwsaccountIdType =
    String


{-| The AccountTakeoverActionNotifyType data model.
-}
type alias AccountTakeoverActionNotifyType =
    Bool


{-| The AccountTakeoverActionType data model.
-}
type alias AccountTakeoverActionType =
    { notify : Bool, eventAction : AccountTakeoverEventActionType }


{-| The AccountTakeoverActionsType data model.
-}
type alias AccountTakeoverActionsType =
    { mediumAction : Maybe AccountTakeoverActionType
    , lowAction : Maybe AccountTakeoverActionType
    , highAction : Maybe AccountTakeoverActionType
    }


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


{-| The AccountTakeoverRiskConfigurationType data model.
-}
type alias AccountTakeoverRiskConfigurationType =
    { notifyConfiguration : Maybe NotifyConfigurationType, actions : AccountTakeoverActionsType }


{-| The AddCustomAttributesRequest data model.
-}
type alias AddCustomAttributesRequest =
    { userPoolId : UserPoolIdType, customAttributes : CustomAttributesListType }


{-| The AddCustomAttributesResponse data model.
-}
type alias AddCustomAttributesResponse =
    {}


{-| The AdminAddUserToGroupRequest data model.
-}
type alias AdminAddUserToGroupRequest =
    { username : UsernameType, userPoolId : UserPoolIdType, groupName : GroupNameType }


{-| The AdminConfirmSignUpRequest data model.
-}
type alias AdminConfirmSignUpRequest =
    { username : UsernameType, userPoolId : UserPoolIdType }


{-| The AdminConfirmSignUpResponse data model.
-}
type alias AdminConfirmSignUpResponse =
    {}


{-| The AdminCreateUserConfigType data model.
-}
type alias AdminCreateUserConfigType =
    { unusedAccountValidityDays : Maybe AdminCreateUserUnusedAccountValidityDaysType
    , inviteMessageTemplate : Maybe MessageTemplateType
    , allowAdminCreateUserOnly : Maybe Bool
    }


{-| The AdminCreateUserRequest data model.
-}
type alias AdminCreateUserRequest =
    { validationData : Maybe AttributeListType
    , username : UsernameType
    , userPoolId : UserPoolIdType
    , userAttributes : Maybe AttributeListType
    , temporaryPassword : Maybe PasswordType
    , messageAction : Maybe MessageActionType
    , forceAliasCreation : Maybe Bool
    , desiredDeliveryMediums : Maybe DeliveryMediumListType
    }


{-| The AdminCreateUserResponse data model.
-}
type alias AdminCreateUserResponse =
    { user : Maybe UserType }


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


{-| The AdminDeleteUserAttributesRequest data model.
-}
type alias AdminDeleteUserAttributesRequest =
    { username : UsernameType, userPoolId : UserPoolIdType, userAttributeNames : AttributeNameListType }


{-| The AdminDeleteUserAttributesResponse data model.
-}
type alias AdminDeleteUserAttributesResponse =
    {}


{-| The AdminDeleteUserRequest data model.
-}
type alias AdminDeleteUserRequest =
    { username : UsernameType, userPoolId : UserPoolIdType }


{-| The AdminDisableProviderForUserRequest data model.
-}
type alias AdminDisableProviderForUserRequest =
    { userPoolId : String, user : ProviderUserIdentifierType }


{-| The AdminDisableProviderForUserResponse data model.
-}
type alias AdminDisableProviderForUserResponse =
    {}


{-| The AdminDisableUserRequest data model.
-}
type alias AdminDisableUserRequest =
    { username : UsernameType, userPoolId : UserPoolIdType }


{-| The AdminDisableUserResponse data model.
-}
type alias AdminDisableUserResponse =
    {}


{-| The AdminEnableUserRequest data model.
-}
type alias AdminEnableUserRequest =
    { username : UsernameType, userPoolId : UserPoolIdType }


{-| The AdminEnableUserResponse data model.
-}
type alias AdminEnableUserResponse =
    {}


{-| The AdminForgetDeviceRequest data model.
-}
type alias AdminForgetDeviceRequest =
    { username : UsernameType, userPoolId : UserPoolIdType, deviceKey : DeviceKeyType }


{-| The AdminGetDeviceRequest data model.
-}
type alias AdminGetDeviceRequest =
    { username : UsernameType, userPoolId : UserPoolIdType, deviceKey : DeviceKeyType }


{-| The AdminGetDeviceResponse data model.
-}
type alias AdminGetDeviceResponse =
    { device : DeviceType }


{-| The AdminGetUserRequest data model.
-}
type alias AdminGetUserRequest =
    { username : UsernameType, userPoolId : UserPoolIdType }


{-| The AdminGetUserResponse data model.
-}
type alias AdminGetUserResponse =
    { username : UsernameType
    , userStatus : Maybe UserStatusType
    , userMfasettingList : Maybe UserMfasettingListType
    , userLastModifiedDate : Maybe DateType
    , userCreateDate : Maybe DateType
    , userAttributes : Maybe AttributeListType
    , preferredMfaSetting : Maybe String
    , mfaoptions : Maybe MfaoptionListType
    , enabled : Maybe Bool
    }


{-| The AdminInitiateAuthRequest data model.
-}
type alias AdminInitiateAuthRequest =
    { userPoolId : UserPoolIdType
    , contextData : Maybe ContextDataType
    , clientMetadata : Maybe ClientMetadataType
    , clientId : ClientIdType
    , authParameters : Maybe AuthParametersType
    , authFlow : AuthFlowType
    , analyticsMetadata : Maybe AnalyticsMetadataType
    }


{-| The AdminInitiateAuthResponse data model.
-}
type alias AdminInitiateAuthResponse =
    { session : Maybe SessionType
    , challengeParameters : Maybe ChallengeParametersType
    , challengeName : Maybe ChallengeNameType
    , authenticationResult : Maybe AuthenticationResultType
    }


{-| The AdminLinkProviderForUserRequest data model.
-}
type alias AdminLinkProviderForUserRequest =
    { userPoolId : String, sourceUser : ProviderUserIdentifierType, destinationUser : ProviderUserIdentifierType }


{-| The AdminLinkProviderForUserResponse data model.
-}
type alias AdminLinkProviderForUserResponse =
    {}


{-| The AdminListDevicesRequest data model.
-}
type alias AdminListDevicesRequest =
    { username : UsernameType
    , userPoolId : UserPoolIdType
    , paginationToken : Maybe SearchPaginationTokenType
    , limit : Maybe QueryLimitType
    }


{-| The AdminListDevicesResponse data model.
-}
type alias AdminListDevicesResponse =
    { paginationToken : Maybe SearchPaginationTokenType, devices : Maybe DeviceListType }


{-| The AdminListGroupsForUserRequest data model.
-}
type alias AdminListGroupsForUserRequest =
    { username : UsernameType
    , userPoolId : UserPoolIdType
    , nextToken : Maybe PaginationKey
    , limit : Maybe QueryLimitType
    }


{-| The AdminListGroupsForUserResponse data model.
-}
type alias AdminListGroupsForUserResponse =
    { nextToken : Maybe PaginationKey, groups : Maybe GroupListType }


{-| The AdminListUserAuthEventsRequest data model.
-}
type alias AdminListUserAuthEventsRequest =
    { username : UsernameType
    , userPoolId : UserPoolIdType
    , nextToken : Maybe PaginationKey
    , maxResults : Maybe QueryLimitType
    }


{-| The AdminListUserAuthEventsResponse data model.
-}
type alias AdminListUserAuthEventsResponse =
    { nextToken : Maybe PaginationKey, authEvents : Maybe AuthEventsType }


{-| The AdminRemoveUserFromGroupRequest data model.
-}
type alias AdminRemoveUserFromGroupRequest =
    { username : UsernameType, userPoolId : UserPoolIdType, groupName : GroupNameType }


{-| The AdminResetUserPasswordRequest data model.
-}
type alias AdminResetUserPasswordRequest =
    { username : UsernameType, userPoolId : UserPoolIdType }


{-| The AdminResetUserPasswordResponse data model.
-}
type alias AdminResetUserPasswordResponse =
    {}


{-| The AdminRespondToAuthChallengeRequest data model.
-}
type alias AdminRespondToAuthChallengeRequest =
    { userPoolId : UserPoolIdType
    , session : Maybe SessionType
    , contextData : Maybe ContextDataType
    , clientId : ClientIdType
    , challengeResponses : Maybe ChallengeResponsesType
    , challengeName : ChallengeNameType
    , analyticsMetadata : Maybe AnalyticsMetadataType
    }


{-| The AdminRespondToAuthChallengeResponse data model.
-}
type alias AdminRespondToAuthChallengeResponse =
    { session : Maybe SessionType
    , challengeParameters : Maybe ChallengeParametersType
    , challengeName : Maybe ChallengeNameType
    , authenticationResult : Maybe AuthenticationResultType
    }


{-| The AdminSetUserMfapreferenceRequest data model.
-}
type alias AdminSetUserMfapreferenceRequest =
    { username : UsernameType
    , userPoolId : UserPoolIdType
    , softwareTokenMfaSettings : Maybe SoftwareTokenMfaSettingsType
    , smsmfaSettings : Maybe SmsmfaSettingsType
    }


{-| The AdminSetUserMfapreferenceResponse data model.
-}
type alias AdminSetUserMfapreferenceResponse =
    {}


{-| The AdminSetUserPasswordRequest data model.
-}
type alias AdminSetUserPasswordRequest =
    { username : UsernameType, userPoolId : UserPoolIdType, permanent : Maybe Bool, password : PasswordType }


{-| The AdminSetUserPasswordResponse data model.
-}
type alias AdminSetUserPasswordResponse =
    {}


{-| The AdminSetUserSettingsRequest data model.
-}
type alias AdminSetUserSettingsRequest =
    { username : UsernameType, userPoolId : UserPoolIdType, mfaoptions : MfaoptionListType }


{-| The AdminSetUserSettingsResponse data model.
-}
type alias AdminSetUserSettingsResponse =
    {}


{-| The AdminUpdateAuthEventFeedbackRequest data model.
-}
type alias AdminUpdateAuthEventFeedbackRequest =
    { username : UsernameType, userPoolId : UserPoolIdType, feedbackValue : FeedbackValueType, eventId : EventIdType }


{-| The AdminUpdateAuthEventFeedbackResponse data model.
-}
type alias AdminUpdateAuthEventFeedbackResponse =
    {}


{-| The AdminUpdateDeviceStatusRequest data model.
-}
type alias AdminUpdateDeviceStatusRequest =
    { username : UsernameType
    , userPoolId : UserPoolIdType
    , deviceRememberedStatus : Maybe DeviceRememberedStatusType
    , deviceKey : DeviceKeyType
    }


{-| The AdminUpdateDeviceStatusResponse data model.
-}
type alias AdminUpdateDeviceStatusResponse =
    {}


{-| The AdminUpdateUserAttributesRequest data model.
-}
type alias AdminUpdateUserAttributesRequest =
    { username : UsernameType, userPoolId : UserPoolIdType, userAttributes : AttributeListType }


{-| The AdminUpdateUserAttributesResponse data model.
-}
type alias AdminUpdateUserAttributesResponse =
    {}


{-| The AdminUserGlobalSignOutRequest data model.
-}
type alias AdminUserGlobalSignOutRequest =
    { username : UsernameType, userPoolId : UserPoolIdType }


{-| The AdminUserGlobalSignOutResponse data model.
-}
type alias AdminUserGlobalSignOutResponse =
    {}


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


{-| The AliasAttributesListType data model.
-}
type alias AliasAttributesListType =
    List AliasAttributeType


{-| The AnalyticsConfigurationType data model.
-}
type alias AnalyticsConfigurationType =
    { userDataShared : Maybe Bool, roleArn : ArnType, externalId : String, applicationId : HexStringType }


{-| The AnalyticsMetadataType data model.
-}
type alias AnalyticsMetadataType =
    { analyticsEndpointId : Maybe String }


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


{-| The AssociateSoftwareTokenRequest data model.
-}
type alias AssociateSoftwareTokenRequest =
    { session : Maybe SessionType, accessToken : Maybe TokenModelType }


{-| The AssociateSoftwareTokenResponse data model.
-}
type alias AssociateSoftwareTokenResponse =
    { session : Maybe SessionType, secretCode : Maybe SecretCodeType }


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


{-| The AttributeListType data model.
-}
type alias AttributeListType =
    List AttributeType


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


{-| The AttributeMappingType data model.
-}
type alias AttributeMappingType =
    Dict.Refined.Dict String AttributeMappingKeyType String


{-| The AttributeNameListType data model.
-}
type alias AttributeNameListType =
    List AttributeNameType


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


{-| The AttributeType data model.
-}
type alias AttributeType =
    { value : Maybe AttributeValueType, name : AttributeNameType }


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


{-| The AuthEventType data model.
-}
type alias AuthEventType =
    { eventType : Maybe EventType
    , eventRisk : Maybe EventRiskType
    , eventResponse : Maybe EventResponseType
    , eventId : Maybe String
    , eventFeedback : Maybe EventFeedbackType
    , eventContextData : Maybe EventContextDataType
    , creationDate : Maybe DateType
    , challengeResponses : Maybe ChallengeResponseListType
    }


{-| The AuthEventsType data model.
-}
type alias AuthEventsType =
    List AuthEventType


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


{-| The AuthParametersType data model.
-}
type alias AuthParametersType =
    Dict String String


{-| The AuthenticationResultType data model.
-}
type alias AuthenticationResultType =
    { tokenType : Maybe String
    , refreshToken : Maybe TokenModelType
    , newDeviceMetadata : Maybe NewDeviceMetadataType
    , idToken : Maybe TokenModelType
    , expiresIn : Maybe Int
    , accessToken : Maybe TokenModelType
    }


{-| The BlockedIprangeListType data model.
-}
type alias BlockedIprangeListType =
    List String


{-| The BooleanType data model.
-}
type alias BooleanType =
    Bool


{-| The Csstype data model.
-}
type alias Csstype =
    String


{-| The CssversionType data model.
-}
type alias CssversionType =
    String


{-| The CallbackUrlsListType data model.
-}
type alias CallbackUrlsListType =
    List RedirectUrlType


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


{-| The ChallengeParametersType data model.
-}
type alias ChallengeParametersType =
    Dict String String


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


{-| The ChallengeResponseListType data model.
-}
type alias ChallengeResponseListType =
    List ChallengeResponseType


{-| The ChallengeResponseType data model.
-}
type alias ChallengeResponseType =
    { challengeResponse : Maybe ChallengeResponse, challengeName : Maybe ChallengeName }


{-| The ChallengeResponsesType data model.
-}
type alias ChallengeResponsesType =
    Dict String String


{-| The ChangePasswordRequest data model.
-}
type alias ChangePasswordRequest =
    { proposedPassword : PasswordType, previousPassword : PasswordType, accessToken : TokenModelType }


{-| The ChangePasswordResponse data model.
-}
type alias ChangePasswordResponse =
    {}


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


{-| The ClientMetadataType data model.
-}
type alias ClientMetadataType =
    Dict String String


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


{-| The ClientPermissionListType data model.
-}
type alias ClientPermissionListType =
    List ClientPermissionType


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


{-| The CodeDeliveryDetailsListType data model.
-}
type alias CodeDeliveryDetailsListType =
    List CodeDeliveryDetailsType


{-| The CodeDeliveryDetailsType data model.
-}
type alias CodeDeliveryDetailsType =
    { destination : Maybe String, deliveryMedium : Maybe DeliveryMediumType, attributeName : Maybe AttributeNameType }


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


{-| The CompromisedCredentialsActionsType data model.
-}
type alias CompromisedCredentialsActionsType =
    { eventAction : CompromisedCredentialsEventActionType }


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


{-| The CompromisedCredentialsRiskConfigurationType data model.
-}
type alias CompromisedCredentialsRiskConfigurationType =
    { eventFilter : Maybe EventFiltersType, actions : CompromisedCredentialsActionsType }


{-| The ConfirmDeviceRequest data model.
-}
type alias ConfirmDeviceRequest =
    { deviceSecretVerifierConfig : Maybe DeviceSecretVerifierConfigType
    , deviceName : Maybe DeviceNameType
    , deviceKey : DeviceKeyType
    , accessToken : TokenModelType
    }


{-| The ConfirmDeviceResponse data model.
-}
type alias ConfirmDeviceResponse =
    { userConfirmationNecessary : Maybe Bool }


{-| The ConfirmForgotPasswordRequest data model.
-}
type alias ConfirmForgotPasswordRequest =
    { username : UsernameType
    , userContextData : Maybe UserContextDataType
    , secretHash : Maybe SecretHashType
    , password : PasswordType
    , confirmationCode : ConfirmationCodeType
    , clientId : ClientIdType
    , analyticsMetadata : Maybe AnalyticsMetadataType
    }


{-| The ConfirmForgotPasswordResponse data model.
-}
type alias ConfirmForgotPasswordResponse =
    {}


{-| The ConfirmSignUpRequest data model.
-}
type alias ConfirmSignUpRequest =
    { username : UsernameType
    , userContextData : Maybe UserContextDataType
    , secretHash : Maybe SecretHashType
    , forceAliasCreation : Maybe Bool
    , confirmationCode : ConfirmationCodeType
    , clientId : ClientIdType
    , analyticsMetadata : Maybe AnalyticsMetadataType
    }


{-| The ConfirmSignUpResponse data model.
-}
type alias ConfirmSignUpResponse =
    {}


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


{-| The ContextDataType data model.
-}
type alias ContextDataType =
    { serverPath : String
    , serverName : String
    , ipAddress : String
    , httpHeaders : HttpHeaderList
    , encodedData : Maybe String
    }


{-| The CreateGroupRequest data model.
-}
type alias CreateGroupRequest =
    { userPoolId : UserPoolIdType
    , roleArn : Maybe ArnType
    , precedence : Maybe PrecedenceType
    , groupName : GroupNameType
    , description : Maybe DescriptionType
    }


{-| The CreateGroupResponse data model.
-}
type alias CreateGroupResponse =
    { group : Maybe GroupType }


{-| The CreateIdentityProviderRequest data model.
-}
type alias CreateIdentityProviderRequest =
    { userPoolId : UserPoolIdType
    , providerType : IdentityProviderTypeType
    , providerName : ProviderNameTypeV1
    , providerDetails : ProviderDetailsType
    , idpIdentifiers : Maybe IdpIdentifiersListType
    , attributeMapping : Maybe AttributeMappingType
    }


{-| The CreateIdentityProviderResponse data model.
-}
type alias CreateIdentityProviderResponse =
    { identityProvider : IdentityProviderType }


{-| The CreateResourceServerRequest data model.
-}
type alias CreateResourceServerRequest =
    { userPoolId : UserPoolIdType
    , scopes : Maybe ResourceServerScopeListType
    , name : ResourceServerNameType
    , identifier : ResourceServerIdentifierType
    }


{-| The CreateResourceServerResponse data model.
-}
type alias CreateResourceServerResponse =
    { resourceServer : ResourceServerType }


{-| The CreateUserImportJobRequest data model.
-}
type alias CreateUserImportJobRequest =
    { userPoolId : UserPoolIdType, jobName : UserImportJobNameType, cloudWatchLogsRoleArn : ArnType }


{-| The CreateUserImportJobResponse data model.
-}
type alias CreateUserImportJobResponse =
    { userImportJob : Maybe UserImportJobType }


{-| The CreateUserPoolClientRequest data model.
-}
type alias CreateUserPoolClientRequest =
    { writeAttributes : Maybe ClientPermissionListType
    , userPoolId : UserPoolIdType
    , supportedIdentityProviders : Maybe SupportedIdentityProvidersListType
    , refreshTokenValidity : Maybe RefreshTokenValidityType
    , readAttributes : Maybe ClientPermissionListType
    , logoutUrls : Maybe LogoutUrlsListType
    , generateSecret : Maybe Bool
    , explicitAuthFlows : Maybe ExplicitAuthFlowsListType
    , defaultRedirectUri : Maybe RedirectUrlType
    , clientName : ClientNameType
    , callbackUrls : Maybe CallbackUrlsListType
    , analyticsConfiguration : Maybe AnalyticsConfigurationType
    , allowedOauthScopes : Maybe ScopeListType
    , allowedOauthFlowsUserPoolClient : Maybe Bool
    , allowedOauthFlows : Maybe OauthFlowsType
    }


{-| The CreateUserPoolClientResponse data model.
-}
type alias CreateUserPoolClientResponse =
    { userPoolClient : Maybe UserPoolClientType }


{-| The CreateUserPoolDomainRequest data model.
-}
type alias CreateUserPoolDomainRequest =
    { userPoolId : UserPoolIdType, domain : DomainType, customDomainConfig : Maybe CustomDomainConfigType }


{-| The CreateUserPoolDomainResponse data model.
-}
type alias CreateUserPoolDomainResponse =
    { cloudFrontDomain : Maybe DomainType }


{-| The CreateUserPoolRequest data model.
-}
type alias CreateUserPoolRequest =
    { verificationMessageTemplate : Maybe VerificationMessageTemplateType
    , usernameAttributes : Maybe UsernameAttributesListType
    , userPoolTags : Maybe UserPoolTagsType
    , userPoolAddOns : Maybe UserPoolAddOnsType
    , smsVerificationMessage : Maybe SmsVerificationMessageType
    , smsConfiguration : Maybe SmsConfigurationType
    , smsAuthenticationMessage : Maybe SmsVerificationMessageType
    , schema : Maybe SchemaAttributesListType
    , poolName : UserPoolNameType
    , policies : Maybe UserPoolPolicyType
    , mfaConfiguration : Maybe UserPoolMfaType
    , lambdaConfig : Maybe LambdaConfigType
    , emailVerificationSubject : Maybe EmailVerificationSubjectType
    , emailVerificationMessage : Maybe EmailVerificationMessageType
    , emailConfiguration : Maybe EmailConfigurationType
    , deviceConfiguration : Maybe DeviceConfigurationType
    , autoVerifiedAttributes : Maybe VerifiedAttributesListType
    , aliasAttributes : Maybe AliasAttributesListType
    , adminCreateUserConfig : Maybe AdminCreateUserConfigType
    }


{-| The CreateUserPoolResponse data model.
-}
type alias CreateUserPoolResponse =
    { userPool : Maybe UserPoolType }


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


{-| The CustomAttributesListType data model.
-}
type alias CustomAttributesListType =
    List SchemaAttributeType


{-| The CustomDomainConfigType data model.
-}
type alias CustomDomainConfigType =
    { certificateArn : ArnType }


{-| The DateType data model.
-}
type alias DateType =
    String


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


{-| The DeleteGroupRequest data model.
-}
type alias DeleteGroupRequest =
    { userPoolId : UserPoolIdType, groupName : GroupNameType }


{-| The DeleteIdentityProviderRequest data model.
-}
type alias DeleteIdentityProviderRequest =
    { userPoolId : UserPoolIdType, providerName : ProviderNameType }


{-| The DeleteResourceServerRequest data model.
-}
type alias DeleteResourceServerRequest =
    { userPoolId : UserPoolIdType, identifier : ResourceServerIdentifierType }


{-| The DeleteUserAttributesRequest data model.
-}
type alias DeleteUserAttributesRequest =
    { userAttributeNames : AttributeNameListType, accessToken : TokenModelType }


{-| The DeleteUserAttributesResponse data model.
-}
type alias DeleteUserAttributesResponse =
    {}


{-| The DeleteUserPoolClientRequest data model.
-}
type alias DeleteUserPoolClientRequest =
    { userPoolId : UserPoolIdType, clientId : ClientIdType }


{-| The DeleteUserPoolDomainRequest data model.
-}
type alias DeleteUserPoolDomainRequest =
    { userPoolId : UserPoolIdType, domain : DomainType }


{-| The DeleteUserPoolDomainResponse data model.
-}
type alias DeleteUserPoolDomainResponse =
    {}


{-| The DeleteUserPoolRequest data model.
-}
type alias DeleteUserPoolRequest =
    { userPoolId : UserPoolIdType }


{-| The DeleteUserRequest data model.
-}
type alias DeleteUserRequest =
    { accessToken : TokenModelType }


{-| The DeliveryMediumListType data model.
-}
type alias DeliveryMediumListType =
    List DeliveryMediumType


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


{-| The DescribeIdentityProviderRequest data model.
-}
type alias DescribeIdentityProviderRequest =
    { userPoolId : UserPoolIdType, providerName : ProviderNameType }


{-| The DescribeIdentityProviderResponse data model.
-}
type alias DescribeIdentityProviderResponse =
    { identityProvider : IdentityProviderType }


{-| The DescribeResourceServerRequest data model.
-}
type alias DescribeResourceServerRequest =
    { userPoolId : UserPoolIdType, identifier : ResourceServerIdentifierType }


{-| The DescribeResourceServerResponse data model.
-}
type alias DescribeResourceServerResponse =
    { resourceServer : ResourceServerType }


{-| The DescribeRiskConfigurationRequest data model.
-}
type alias DescribeRiskConfigurationRequest =
    { userPoolId : UserPoolIdType, clientId : Maybe ClientIdType }


{-| The DescribeRiskConfigurationResponse data model.
-}
type alias DescribeRiskConfigurationResponse =
    { riskConfiguration : RiskConfigurationType }


{-| The DescribeUserImportJobRequest data model.
-}
type alias DescribeUserImportJobRequest =
    { userPoolId : UserPoolIdType, jobId : UserImportJobIdType }


{-| The DescribeUserImportJobResponse data model.
-}
type alias DescribeUserImportJobResponse =
    { userImportJob : Maybe UserImportJobType }


{-| The DescribeUserPoolClientRequest data model.
-}
type alias DescribeUserPoolClientRequest =
    { userPoolId : UserPoolIdType, clientId : ClientIdType }


{-| The DescribeUserPoolClientResponse data model.
-}
type alias DescribeUserPoolClientResponse =
    { userPoolClient : Maybe UserPoolClientType }


{-| The DescribeUserPoolDomainRequest data model.
-}
type alias DescribeUserPoolDomainRequest =
    { domain : DomainType }


{-| The DescribeUserPoolDomainResponse data model.
-}
type alias DescribeUserPoolDomainResponse =
    { domainDescription : Maybe DomainDescriptionType }


{-| The DescribeUserPoolRequest data model.
-}
type alias DescribeUserPoolRequest =
    { userPoolId : UserPoolIdType }


{-| The DescribeUserPoolResponse data model.
-}
type alias DescribeUserPoolResponse =
    { userPool : Maybe UserPoolType }


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


{-| The DeviceConfigurationType data model.
-}
type alias DeviceConfigurationType =
    { deviceOnlyRememberedOnUserPrompt : Maybe Bool, challengeRequiredOnNewDevice : Maybe Bool }


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


{-| The DeviceListType data model.
-}
type alias DeviceListType =
    List DeviceType


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


{-| The DeviceSecretVerifierConfigType data model.
-}
type alias DeviceSecretVerifierConfigType =
    { salt : Maybe String, passwordVerifier : Maybe String }


{-| The DeviceType data model.
-}
type alias DeviceType =
    { deviceLastModifiedDate : Maybe DateType
    , deviceLastAuthenticatedDate : Maybe DateType
    , deviceKey : Maybe DeviceKeyType
    , deviceCreateDate : Maybe DateType
    , deviceAttributes : Maybe AttributeListType
    }


{-| The DomainDescriptionType data model.
-}
type alias DomainDescriptionType =
    { version : Maybe DomainVersionType
    , userPoolId : Maybe UserPoolIdType
    , status : Maybe DomainStatusType
    , s3Bucket : Maybe S3BucketType
    , domain : Maybe DomainType
    , customDomainConfig : Maybe CustomDomainConfigType
    , cloudFrontDistribution : Maybe String
    , awsaccountId : Maybe String
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


{-| The EmailConfigurationType data model.
-}
type alias EmailConfigurationType =
    { sourceArn : Maybe ArnType
    , replyToEmailAddress : Maybe EmailAddressType
    , emailSendingAccount : Maybe EmailSendingAccountType
    }


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


{-| The EventContextDataType data model.
-}
type alias EventContextDataType =
    { timezone : Maybe String
    , ipAddress : Maybe String
    , deviceName : Maybe String
    , country : Maybe String
    , city : Maybe String
    }


{-| The EventFeedbackType data model.
-}
type alias EventFeedbackType =
    { provider : String, feedbackValue : FeedbackValueType, feedbackDate : Maybe DateType }


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


{-| The EventFiltersType data model.
-}
type alias EventFiltersType =
    List EventFilterType


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


{-| The EventRiskType data model.
-}
type alias EventRiskType =
    { riskLevel : Maybe RiskLevelType, riskDecision : Maybe RiskDecisionType }


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


{-| The ExplicitAuthFlowsListType data model.
-}
type alias ExplicitAuthFlowsListType =
    List ExplicitAuthFlowsType


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


{-| The ForceAliasCreation data model.
-}
type alias ForceAliasCreation =
    Bool


{-| The ForgetDeviceRequest data model.
-}
type alias ForgetDeviceRequest =
    { deviceKey : DeviceKeyType, accessToken : Maybe TokenModelType }


{-| The ForgotPasswordRequest data model.
-}
type alias ForgotPasswordRequest =
    { username : UsernameType
    , userContextData : Maybe UserContextDataType
    , secretHash : Maybe SecretHashType
    , clientId : ClientIdType
    , analyticsMetadata : Maybe AnalyticsMetadataType
    }


{-| The ForgotPasswordResponse data model.
-}
type alias ForgotPasswordResponse =
    { codeDeliveryDetails : Maybe CodeDeliveryDetailsType }


{-| The GenerateSecret data model.
-}
type alias GenerateSecret =
    Bool


{-| The GetCsvheaderRequest data model.
-}
type alias GetCsvheaderRequest =
    { userPoolId : UserPoolIdType }


{-| The GetCsvheaderResponse data model.
-}
type alias GetCsvheaderResponse =
    { userPoolId : Maybe UserPoolIdType, csvheader : Maybe ListOfStringTypes }


{-| The GetDeviceRequest data model.
-}
type alias GetDeviceRequest =
    { deviceKey : DeviceKeyType, accessToken : Maybe TokenModelType }


{-| The GetDeviceResponse data model.
-}
type alias GetDeviceResponse =
    { device : DeviceType }


{-| The GetGroupRequest data model.
-}
type alias GetGroupRequest =
    { userPoolId : UserPoolIdType, groupName : GroupNameType }


{-| The GetGroupResponse data model.
-}
type alias GetGroupResponse =
    { group : Maybe GroupType }


{-| The GetIdentityProviderByIdentifierRequest data model.
-}
type alias GetIdentityProviderByIdentifierRequest =
    { userPoolId : UserPoolIdType, idpIdentifier : IdpIdentifierType }


{-| The GetIdentityProviderByIdentifierResponse data model.
-}
type alias GetIdentityProviderByIdentifierResponse =
    { identityProvider : IdentityProviderType }


{-| The GetSigningCertificateRequest data model.
-}
type alias GetSigningCertificateRequest =
    { userPoolId : UserPoolIdType }


{-| The GetSigningCertificateResponse data model.
-}
type alias GetSigningCertificateResponse =
    { certificate : Maybe String }


{-| The GetUicustomizationRequest data model.
-}
type alias GetUicustomizationRequest =
    { userPoolId : UserPoolIdType, clientId : Maybe ClientIdType }


{-| The GetUicustomizationResponse data model.
-}
type alias GetUicustomizationResponse =
    { uicustomization : UicustomizationType }


{-| The GetUserAttributeVerificationCodeRequest data model.
-}
type alias GetUserAttributeVerificationCodeRequest =
    { attributeName : AttributeNameType, accessToken : TokenModelType }


{-| The GetUserAttributeVerificationCodeResponse data model.
-}
type alias GetUserAttributeVerificationCodeResponse =
    { codeDeliveryDetails : Maybe CodeDeliveryDetailsType }


{-| The GetUserPoolMfaConfigRequest data model.
-}
type alias GetUserPoolMfaConfigRequest =
    { userPoolId : UserPoolIdType }


{-| The GetUserPoolMfaConfigResponse data model.
-}
type alias GetUserPoolMfaConfigResponse =
    { softwareTokenMfaConfiguration : Maybe SoftwareTokenMfaConfigType
    , smsMfaConfiguration : Maybe SmsMfaConfigType
    , mfaConfiguration : Maybe UserPoolMfaType
    }


{-| The GetUserRequest data model.
-}
type alias GetUserRequest =
    { accessToken : TokenModelType }


{-| The GetUserResponse data model.
-}
type alias GetUserResponse =
    { username : UsernameType
    , userMfasettingList : Maybe UserMfasettingListType
    , userAttributes : AttributeListType
    , preferredMfaSetting : Maybe String
    , mfaoptions : Maybe MfaoptionListType
    }


{-| The GlobalSignOutRequest data model.
-}
type alias GlobalSignOutRequest =
    { accessToken : TokenModelType }


{-| The GlobalSignOutResponse data model.
-}
type alias GlobalSignOutResponse =
    {}


{-| The GroupListType data model.
-}
type alias GroupListType =
    List GroupType


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


{-| The GroupType data model.
-}
type alias GroupType =
    { userPoolId : Maybe UserPoolIdType
    , roleArn : Maybe ArnType
    , precedence : Maybe PrecedenceType
    , lastModifiedDate : Maybe DateType
    , groupName : Maybe GroupNameType
    , description : Maybe DescriptionType
    , creationDate : Maybe DateType
    }


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


{-| The HttpHeader data model.
-}
type alias HttpHeader =
    { headerValue : Maybe String, headerName : Maybe String }


{-| The HttpHeaderList data model.
-}
type alias HttpHeaderList =
    List HttpHeader


{-| The IdentityProviderType data model.
-}
type alias IdentityProviderType =
    { userPoolId : Maybe UserPoolIdType
    , providerType : Maybe IdentityProviderTypeType
    , providerName : Maybe ProviderNameType
    , providerDetails : Maybe ProviderDetailsType
    , lastModifiedDate : Maybe DateType
    , idpIdentifiers : Maybe IdpIdentifiersListType
    , creationDate : Maybe DateType
    , attributeMapping : Maybe AttributeMappingType
    }


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


{-| The IdpIdentifiersListType data model.
-}
type alias IdpIdentifiersListType =
    List IdpIdentifierType


{-| The ImageFileType data model.
-}
type alias ImageFileType =
    String


{-| The ImageUrlType data model.
-}
type alias ImageUrlType =
    String


{-| The InitiateAuthRequest data model.
-}
type alias InitiateAuthRequest =
    { userContextData : Maybe UserContextDataType
    , clientMetadata : Maybe ClientMetadataType
    , clientId : ClientIdType
    , authParameters : Maybe AuthParametersType
    , authFlow : AuthFlowType
    , analyticsMetadata : Maybe AnalyticsMetadataType
    }


{-| The InitiateAuthResponse data model.
-}
type alias InitiateAuthResponse =
    { session : Maybe SessionType
    , challengeParameters : Maybe ChallengeParametersType
    , challengeName : Maybe ChallengeNameType
    , authenticationResult : Maybe AuthenticationResultType
    }


{-| The IntegerType data model.
-}
type alias IntegerType =
    Int


{-| The LambdaConfigType data model.
-}
type alias LambdaConfigType =
    { verifyAuthChallengeResponse : Maybe ArnType
    , userMigration : Maybe ArnType
    , preTokenGeneration : Maybe ArnType
    , preSignUp : Maybe ArnType
    , preAuthentication : Maybe ArnType
    , postConfirmation : Maybe ArnType
    , postAuthentication : Maybe ArnType
    , defineAuthChallenge : Maybe ArnType
    , customMessage : Maybe ArnType
    , createAuthChallenge : Maybe ArnType
    }


{-| The ListDevicesRequest data model.
-}
type alias ListDevicesRequest =
    { paginationToken : Maybe SearchPaginationTokenType, limit : Maybe QueryLimitType, accessToken : TokenModelType }


{-| The ListDevicesResponse data model.
-}
type alias ListDevicesResponse =
    { paginationToken : Maybe SearchPaginationTokenType, devices : Maybe DeviceListType }


{-| The ListGroupsRequest data model.
-}
type alias ListGroupsRequest =
    { userPoolId : UserPoolIdType, nextToken : Maybe PaginationKey, limit : Maybe QueryLimitType }


{-| The ListGroupsResponse data model.
-}
type alias ListGroupsResponse =
    { nextToken : Maybe PaginationKey, groups : Maybe GroupListType }


{-| The ListIdentityProvidersRequest data model.
-}
type alias ListIdentityProvidersRequest =
    { userPoolId : UserPoolIdType, nextToken : Maybe PaginationKeyType, maxResults : Maybe ListProvidersLimitType }


{-| The ListIdentityProvidersResponse data model.
-}
type alias ListIdentityProvidersResponse =
    { providers : ProvidersListType, nextToken : Maybe PaginationKeyType }


{-| The ListOfStringTypes data model.
-}
type alias ListOfStringTypes =
    List String


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


{-| The ListResourceServersRequest data model.
-}
type alias ListResourceServersRequest =
    { userPoolId : UserPoolIdType
    , nextToken : Maybe PaginationKeyType
    , maxResults : Maybe ListResourceServersLimitType
    }


{-| The ListResourceServersResponse data model.
-}
type alias ListResourceServersResponse =
    { resourceServers : ResourceServersListType, nextToken : Maybe PaginationKeyType }


{-| The ListTagsForResourceRequest data model.
-}
type alias ListTagsForResourceRequest =
    { resourceArn : ArnType }


{-| The ListTagsForResourceResponse data model.
-}
type alias ListTagsForResourceResponse =
    { tags : Maybe UserPoolTagsType }


{-| The ListUserImportJobsRequest data model.
-}
type alias ListUserImportJobsRequest =
    { userPoolId : UserPoolIdType, paginationToken : Maybe PaginationKeyType, maxResults : PoolQueryLimitType }


{-| The ListUserImportJobsResponse data model.
-}
type alias ListUserImportJobsResponse =
    { userImportJobs : Maybe UserImportJobsListType, paginationToken : Maybe PaginationKeyType }


{-| The ListUserPoolClientsRequest data model.
-}
type alias ListUserPoolClientsRequest =
    { userPoolId : UserPoolIdType, nextToken : Maybe PaginationKey, maxResults : Maybe QueryLimit }


{-| The ListUserPoolClientsResponse data model.
-}
type alias ListUserPoolClientsResponse =
    { userPoolClients : Maybe UserPoolClientListType, nextToken : Maybe PaginationKey }


{-| The ListUserPoolsRequest data model.
-}
type alias ListUserPoolsRequest =
    { nextToken : Maybe PaginationKeyType, maxResults : PoolQueryLimitType }


{-| The ListUserPoolsResponse data model.
-}
type alias ListUserPoolsResponse =
    { userPools : Maybe UserPoolListType, nextToken : Maybe PaginationKeyType }


{-| The ListUsersInGroupRequest data model.
-}
type alias ListUsersInGroupRequest =
    { userPoolId : UserPoolIdType
    , nextToken : Maybe PaginationKey
    , limit : Maybe QueryLimitType
    , groupName : GroupNameType
    }


{-| The ListUsersInGroupResponse data model.
-}
type alias ListUsersInGroupResponse =
    { users : Maybe UsersListType, nextToken : Maybe PaginationKey }


{-| The ListUsersRequest data model.
-}
type alias ListUsersRequest =
    { userPoolId : UserPoolIdType
    , paginationToken : Maybe SearchPaginationTokenType
    , limit : Maybe QueryLimitType
    , filter : Maybe UserFilterType
    , attributesToGet : Maybe SearchedAttributeNamesListType
    }


{-| The ListUsersResponse data model.
-}
type alias ListUsersResponse =
    { users : Maybe UsersListType, paginationToken : Maybe SearchPaginationTokenType }


{-| The LogoutUrlsListType data model.
-}
type alias LogoutUrlsListType =
    List RedirectUrlType


{-| The LongType data model.
-}
type alias LongType =
    Int


{-| The MfaoptionListType data model.
-}
type alias MfaoptionListType =
    List MfaoptionType


{-| The MfaoptionType data model.
-}
type alias MfaoptionType =
    { deliveryMedium : Maybe DeliveryMediumType, attributeName : Maybe AttributeNameType }


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


{-| The MessageTemplateType data model.
-}
type alias MessageTemplateType =
    { smsmessage : Maybe SmsVerificationMessageType
    , emailSubject : Maybe EmailVerificationSubjectType
    , emailMessage : Maybe EmailVerificationMessageType
    }


{-| The NewDeviceMetadataType data model.
-}
type alias NewDeviceMetadataType =
    { deviceKey : Maybe DeviceKeyType, deviceGroupKey : Maybe String }


{-| The NotifyConfigurationType data model.
-}
type alias NotifyConfigurationType =
    { sourceArn : ArnType
    , replyTo : Maybe String
    , noActionEmail : Maybe NotifyEmailType
    , mfaEmail : Maybe NotifyEmailType
    , from : Maybe String
    , blockEmail : Maybe NotifyEmailType
    }


{-| The NotifyEmailType data model.
-}
type alias NotifyEmailType =
    { textBody : Maybe EmailNotificationBodyType
    , subject : EmailNotificationSubjectType
    , htmlBody : Maybe EmailNotificationBodyType
    }


{-| The NumberAttributeConstraintsType data model.
-}
type alias NumberAttributeConstraintsType =
    { minValue : Maybe String, maxValue : Maybe String }


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


{-| The OauthFlowsType data model.
-}
type alias OauthFlowsType =
    List OauthFlowType


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


{-| The PasswordPolicyType data model.
-}
type alias PasswordPolicyType =
    { temporaryPasswordValidityDays : Maybe TemporaryPasswordValidityDaysType
    , requireUppercase : Maybe Bool
    , requireSymbols : Maybe Bool
    , requireNumbers : Maybe Bool
    , requireLowercase : Maybe Bool
    , minimumLength : Maybe PasswordPolicyMinLengthType
    }


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


{-| The ProviderDescription data model.
-}
type alias ProviderDescription =
    { providerType : Maybe IdentityProviderTypeType
    , providerName : Maybe ProviderNameType
    , lastModifiedDate : Maybe DateType
    , creationDate : Maybe DateType
    }


{-| The ProviderDetailsType data model.
-}
type alias ProviderDetailsType =
    Dict String String


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


{-| The ProviderUserIdentifierType data model.
-}
type alias ProviderUserIdentifierType =
    { providerName : Maybe ProviderNameType
    , providerAttributeValue : Maybe String
    , providerAttributeName : Maybe String
    }


{-| The ProvidersListType data model.
-}
type alias ProvidersListType =
    List ProviderDescription


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


{-| The ResendConfirmationCodeRequest data model.
-}
type alias ResendConfirmationCodeRequest =
    { username : UsernameType
    , userContextData : Maybe UserContextDataType
    , secretHash : Maybe SecretHashType
    , clientId : ClientIdType
    , analyticsMetadata : Maybe AnalyticsMetadataType
    }


{-| The ResendConfirmationCodeResponse data model.
-}
type alias ResendConfirmationCodeResponse =
    { codeDeliveryDetails : Maybe CodeDeliveryDetailsType }


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


{-| The ResourceServerScopeListType data model.
-}
type alias ResourceServerScopeListType =
    List ResourceServerScopeType


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


{-| The ResourceServerScopeType data model.
-}
type alias ResourceServerScopeType =
    { scopeName : ResourceServerScopeNameType, scopeDescription : ResourceServerScopeDescriptionType }


{-| The ResourceServerType data model.
-}
type alias ResourceServerType =
    { userPoolId : Maybe UserPoolIdType
    , scopes : Maybe ResourceServerScopeListType
    , name : Maybe ResourceServerNameType
    , identifier : Maybe ResourceServerIdentifierType
    }


{-| The ResourceServersListType data model.
-}
type alias ResourceServersListType =
    List ResourceServerType


{-| The RespondToAuthChallengeRequest data model.
-}
type alias RespondToAuthChallengeRequest =
    { userContextData : Maybe UserContextDataType
    , session : Maybe SessionType
    , clientId : ClientIdType
    , challengeResponses : Maybe ChallengeResponsesType
    , challengeName : ChallengeNameType
    , analyticsMetadata : Maybe AnalyticsMetadataType
    }


{-| The RespondToAuthChallengeResponse data model.
-}
type alias RespondToAuthChallengeResponse =
    { session : Maybe SessionType
    , challengeParameters : Maybe ChallengeParametersType
    , challengeName : Maybe ChallengeNameType
    , authenticationResult : Maybe AuthenticationResultType
    }


{-| The RiskConfigurationType data model.
-}
type alias RiskConfigurationType =
    { userPoolId : Maybe UserPoolIdType
    , riskExceptionConfiguration : Maybe RiskExceptionConfigurationType
    , lastModifiedDate : Maybe DateType
    , compromisedCredentialsRiskConfiguration : Maybe CompromisedCredentialsRiskConfigurationType
    , clientId : Maybe ClientIdType
    , accountTakeoverRiskConfiguration : Maybe AccountTakeoverRiskConfigurationType
    }


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


{-| The RiskExceptionConfigurationType data model.
-}
type alias RiskExceptionConfigurationType =
    { skippedIprangeList : Maybe SkippedIprangeListType, blockedIprangeList : Maybe BlockedIprangeListType }


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


{-| The SmsmfaSettingsType data model.
-}
type alias SmsmfaSettingsType =
    { preferredMfa : Maybe Bool, enabled : Maybe Bool }


{-| The SchemaAttributeType data model.
-}
type alias SchemaAttributeType =
    { stringAttributeConstraints : Maybe StringAttributeConstraintsType
    , required : Maybe Bool
    , numberAttributeConstraints : Maybe NumberAttributeConstraintsType
    , name : Maybe CustomAttributeNameType
    , mutable : Maybe Bool
    , developerOnlyAttribute : Maybe Bool
    , attributeDataType : Maybe AttributeDataType
    }


{-| The SchemaAttributesListType data model.
-}
type alias SchemaAttributesListType =
    List SchemaAttributeType


{-| The ScopeListType data model.
-}
type alias ScopeListType =
    List ScopeType


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


{-| The SearchedAttributeNamesListType data model.
-}
type alias SearchedAttributeNamesListType =
    List AttributeNameType


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


{-| The SetRiskConfigurationRequest data model.
-}
type alias SetRiskConfigurationRequest =
    { userPoolId : UserPoolIdType
    , riskExceptionConfiguration : Maybe RiskExceptionConfigurationType
    , compromisedCredentialsRiskConfiguration : Maybe CompromisedCredentialsRiskConfigurationType
    , clientId : Maybe ClientIdType
    , accountTakeoverRiskConfiguration : Maybe AccountTakeoverRiskConfigurationType
    }


{-| The SetRiskConfigurationResponse data model.
-}
type alias SetRiskConfigurationResponse =
    { riskConfiguration : RiskConfigurationType }


{-| The SetUicustomizationRequest data model.
-}
type alias SetUicustomizationRequest =
    { userPoolId : UserPoolIdType, imageFile : Maybe String, clientId : Maybe ClientIdType, css : Maybe String }


{-| The SetUicustomizationResponse data model.
-}
type alias SetUicustomizationResponse =
    { uicustomization : UicustomizationType }


{-| The SetUserMfapreferenceRequest data model.
-}
type alias SetUserMfapreferenceRequest =
    { softwareTokenMfaSettings : Maybe SoftwareTokenMfaSettingsType
    , smsmfaSettings : Maybe SmsmfaSettingsType
    , accessToken : TokenModelType
    }


{-| The SetUserMfapreferenceResponse data model.
-}
type alias SetUserMfapreferenceResponse =
    {}


{-| The SetUserPoolMfaConfigRequest data model.
-}
type alias SetUserPoolMfaConfigRequest =
    { userPoolId : UserPoolIdType
    , softwareTokenMfaConfiguration : Maybe SoftwareTokenMfaConfigType
    , smsMfaConfiguration : Maybe SmsMfaConfigType
    , mfaConfiguration : Maybe UserPoolMfaType
    }


{-| The SetUserPoolMfaConfigResponse data model.
-}
type alias SetUserPoolMfaConfigResponse =
    { softwareTokenMfaConfiguration : Maybe SoftwareTokenMfaConfigType
    , smsMfaConfiguration : Maybe SmsMfaConfigType
    , mfaConfiguration : Maybe UserPoolMfaType
    }


{-| The SetUserSettingsRequest data model.
-}
type alias SetUserSettingsRequest =
    { mfaoptions : MfaoptionListType, accessToken : TokenModelType }


{-| The SetUserSettingsResponse data model.
-}
type alias SetUserSettingsResponse =
    {}


{-| The SignUpRequest data model.
-}
type alias SignUpRequest =
    { validationData : Maybe AttributeListType
    , username : UsernameType
    , userContextData : Maybe UserContextDataType
    , userAttributes : Maybe AttributeListType
    , secretHash : Maybe SecretHashType
    , password : PasswordType
    , clientId : ClientIdType
    , analyticsMetadata : Maybe AnalyticsMetadataType
    }


{-| The SignUpResponse data model.
-}
type alias SignUpResponse =
    { userSub : String, userConfirmed : Bool, codeDeliveryDetails : Maybe CodeDeliveryDetailsType }


{-| The SkippedIprangeListType data model.
-}
type alias SkippedIprangeListType =
    List String


{-| The SmsConfigurationType data model.
-}
type alias SmsConfigurationType =
    { snsCallerArn : ArnType, externalId : Maybe String }


{-| The SmsMfaConfigType data model.
-}
type alias SmsMfaConfigType =
    { smsConfiguration : Maybe SmsConfigurationType, smsAuthenticationMessage : Maybe SmsVerificationMessageType }


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


{-| The SoftwareTokenMfaConfigType data model.
-}
type alias SoftwareTokenMfaConfigType =
    { enabled : Maybe Bool }


{-| The SoftwareTokenMfaSettingsType data model.
-}
type alias SoftwareTokenMfaSettingsType =
    { preferredMfa : Maybe Bool, enabled : Maybe Bool }


{-| The StartUserImportJobRequest data model.
-}
type alias StartUserImportJobRequest =
    { userPoolId : UserPoolIdType, jobId : UserImportJobIdType }


{-| The StartUserImportJobResponse data model.
-}
type alias StartUserImportJobResponse =
    { userImportJob : Maybe UserImportJobType }


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


{-| The StopUserImportJobRequest data model.
-}
type alias StopUserImportJobRequest =
    { userPoolId : UserPoolIdType, jobId : UserImportJobIdType }


{-| The StopUserImportJobResponse data model.
-}
type alias StopUserImportJobResponse =
    { userImportJob : Maybe UserImportJobType }


{-| The StringAttributeConstraintsType data model.
-}
type alias StringAttributeConstraintsType =
    { minLength : Maybe String, maxLength : Maybe String }


{-| The StringType data model.
-}
type alias StringType =
    String


{-| The SupportedIdentityProvidersListType data model.
-}
type alias SupportedIdentityProvidersListType =
    List ProviderNameType


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


{-| The TagResourceRequest data model.
-}
type alias TagResourceRequest =
    { tags : Maybe UserPoolTagsType, resourceArn : ArnType }


{-| The TagResourceResponse data model.
-}
type alias TagResourceResponse =
    {}


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


{-| The UicustomizationType data model.
-}
type alias UicustomizationType =
    { userPoolId : Maybe UserPoolIdType
    , lastModifiedDate : Maybe DateType
    , imageUrl : Maybe String
    , creationDate : Maybe DateType
    , clientId : Maybe ClientIdType
    , cssversion : Maybe String
    , css : Maybe String
    }


{-| The UntagResourceRequest data model.
-}
type alias UntagResourceRequest =
    { tagKeys : Maybe UserPoolTagsListType, resourceArn : ArnType }


{-| The UntagResourceResponse data model.
-}
type alias UntagResourceResponse =
    {}


{-| The UpdateAuthEventFeedbackRequest data model.
-}
type alias UpdateAuthEventFeedbackRequest =
    { username : UsernameType
    , userPoolId : UserPoolIdType
    , feedbackValue : FeedbackValueType
    , feedbackToken : TokenModelType
    , eventId : EventIdType
    }


{-| The UpdateAuthEventFeedbackResponse data model.
-}
type alias UpdateAuthEventFeedbackResponse =
    {}


{-| The UpdateDeviceStatusRequest data model.
-}
type alias UpdateDeviceStatusRequest =
    { deviceRememberedStatus : Maybe DeviceRememberedStatusType
    , deviceKey : DeviceKeyType
    , accessToken : TokenModelType
    }


{-| The UpdateDeviceStatusResponse data model.
-}
type alias UpdateDeviceStatusResponse =
    {}


{-| The UpdateGroupRequest data model.
-}
type alias UpdateGroupRequest =
    { userPoolId : UserPoolIdType
    , roleArn : Maybe ArnType
    , precedence : Maybe PrecedenceType
    , groupName : GroupNameType
    , description : Maybe DescriptionType
    }


{-| The UpdateGroupResponse data model.
-}
type alias UpdateGroupResponse =
    { group : Maybe GroupType }


{-| The UpdateIdentityProviderRequest data model.
-}
type alias UpdateIdentityProviderRequest =
    { userPoolId : UserPoolIdType
    , providerName : ProviderNameType
    , providerDetails : Maybe ProviderDetailsType
    , idpIdentifiers : Maybe IdpIdentifiersListType
    , attributeMapping : Maybe AttributeMappingType
    }


{-| The UpdateIdentityProviderResponse data model.
-}
type alias UpdateIdentityProviderResponse =
    { identityProvider : IdentityProviderType }


{-| The UpdateResourceServerRequest data model.
-}
type alias UpdateResourceServerRequest =
    { userPoolId : UserPoolIdType
    , scopes : Maybe ResourceServerScopeListType
    , name : ResourceServerNameType
    , identifier : ResourceServerIdentifierType
    }


{-| The UpdateResourceServerResponse data model.
-}
type alias UpdateResourceServerResponse =
    { resourceServer : ResourceServerType }


{-| The UpdateUserAttributesRequest data model.
-}
type alias UpdateUserAttributesRequest =
    { userAttributes : AttributeListType, accessToken : TokenModelType }


{-| The UpdateUserAttributesResponse data model.
-}
type alias UpdateUserAttributesResponse =
    { codeDeliveryDetailsList : Maybe CodeDeliveryDetailsListType }


{-| The UpdateUserPoolClientRequest data model.
-}
type alias UpdateUserPoolClientRequest =
    { writeAttributes : Maybe ClientPermissionListType
    , userPoolId : UserPoolIdType
    , supportedIdentityProviders : Maybe SupportedIdentityProvidersListType
    , refreshTokenValidity : Maybe RefreshTokenValidityType
    , readAttributes : Maybe ClientPermissionListType
    , logoutUrls : Maybe LogoutUrlsListType
    , explicitAuthFlows : Maybe ExplicitAuthFlowsListType
    , defaultRedirectUri : Maybe RedirectUrlType
    , clientName : Maybe ClientNameType
    , clientId : ClientIdType
    , callbackUrls : Maybe CallbackUrlsListType
    , analyticsConfiguration : Maybe AnalyticsConfigurationType
    , allowedOauthScopes : Maybe ScopeListType
    , allowedOauthFlowsUserPoolClient : Maybe Bool
    , allowedOauthFlows : Maybe OauthFlowsType
    }


{-| The UpdateUserPoolClientResponse data model.
-}
type alias UpdateUserPoolClientResponse =
    { userPoolClient : Maybe UserPoolClientType }


{-| The UpdateUserPoolDomainRequest data model.
-}
type alias UpdateUserPoolDomainRequest =
    { userPoolId : UserPoolIdType, domain : DomainType, customDomainConfig : CustomDomainConfigType }


{-| The UpdateUserPoolDomainResponse data model.
-}
type alias UpdateUserPoolDomainResponse =
    { cloudFrontDomain : Maybe DomainType }


{-| The UpdateUserPoolRequest data model.
-}
type alias UpdateUserPoolRequest =
    { verificationMessageTemplate : Maybe VerificationMessageTemplateType
    , userPoolTags : Maybe UserPoolTagsType
    , userPoolId : UserPoolIdType
    , userPoolAddOns : Maybe UserPoolAddOnsType
    , smsVerificationMessage : Maybe SmsVerificationMessageType
    , smsConfiguration : Maybe SmsConfigurationType
    , smsAuthenticationMessage : Maybe SmsVerificationMessageType
    , policies : Maybe UserPoolPolicyType
    , mfaConfiguration : Maybe UserPoolMfaType
    , lambdaConfig : Maybe LambdaConfigType
    , emailVerificationSubject : Maybe EmailVerificationSubjectType
    , emailVerificationMessage : Maybe EmailVerificationMessageType
    , emailConfiguration : Maybe EmailConfigurationType
    , deviceConfiguration : Maybe DeviceConfigurationType
    , autoVerifiedAttributes : Maybe VerifiedAttributesListType
    , adminCreateUserConfig : Maybe AdminCreateUserConfigType
    }


{-| The UpdateUserPoolResponse data model.
-}
type alias UpdateUserPoolResponse =
    {}


{-| The UserContextDataType data model.
-}
type alias UserContextDataType =
    { encodedData : Maybe String }


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


{-| The UserImportJobType data model.
-}
type alias UserImportJobType =
    { userPoolId : Maybe UserPoolIdType
    , status : Maybe UserImportJobStatusType
    , startDate : Maybe DateType
    , skippedUsers : Maybe Int
    , preSignedUrl : Maybe PreSignedUrlType
    , jobName : Maybe UserImportJobNameType
    , jobId : Maybe UserImportJobIdType
    , importedUsers : Maybe Int
    , failedUsers : Maybe Int
    , creationDate : Maybe DateType
    , completionMessage : Maybe CompletionMessageType
    , completionDate : Maybe DateType
    , cloudWatchLogsRoleArn : Maybe ArnType
    }


{-| The UserImportJobsListType data model.
-}
type alias UserImportJobsListType =
    List UserImportJobType


{-| The UserMfasettingListType data model.
-}
type alias UserMfasettingListType =
    List String


{-| The UserPoolAddOnsType data model.
-}
type alias UserPoolAddOnsType =
    { advancedSecurityMode : AdvancedSecurityModeType }


{-| The UserPoolClientDescription data model.
-}
type alias UserPoolClientDescription =
    { userPoolId : Maybe UserPoolIdType, clientName : Maybe ClientNameType, clientId : Maybe ClientIdType }


{-| The UserPoolClientListType data model.
-}
type alias UserPoolClientListType =
    List UserPoolClientDescription


{-| The UserPoolClientType data model.
-}
type alias UserPoolClientType =
    { writeAttributes : Maybe ClientPermissionListType
    , userPoolId : Maybe UserPoolIdType
    , supportedIdentityProviders : Maybe SupportedIdentityProvidersListType
    , refreshTokenValidity : Maybe RefreshTokenValidityType
    , readAttributes : Maybe ClientPermissionListType
    , logoutUrls : Maybe LogoutUrlsListType
    , lastModifiedDate : Maybe DateType
    , explicitAuthFlows : Maybe ExplicitAuthFlowsListType
    , defaultRedirectUri : Maybe RedirectUrlType
    , creationDate : Maybe DateType
    , clientSecret : Maybe ClientSecretType
    , clientName : Maybe ClientNameType
    , clientId : Maybe ClientIdType
    , callbackUrls : Maybe CallbackUrlsListType
    , analyticsConfiguration : Maybe AnalyticsConfigurationType
    , allowedOauthScopes : Maybe ScopeListType
    , allowedOauthFlowsUserPoolClient : Maybe Bool
    , allowedOauthFlows : Maybe OauthFlowsType
    }


{-| The UserPoolDescriptionType data model.
-}
type alias UserPoolDescriptionType =
    { status : Maybe StatusType
    , name : Maybe UserPoolNameType
    , lastModifiedDate : Maybe DateType
    , lambdaConfig : Maybe LambdaConfigType
    , id : Maybe UserPoolIdType
    , creationDate : Maybe DateType
    }


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


{-| The UserPoolListType data model.
-}
type alias UserPoolListType =
    List UserPoolDescriptionType


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


{-| The UserPoolPolicyType data model.
-}
type alias UserPoolPolicyType =
    { passwordPolicy : Maybe PasswordPolicyType }


{-| The UserPoolTagsListType data model.
-}
type alias UserPoolTagsListType =
    List TagKeysType


{-| The UserPoolTagsType data model.
-}
type alias UserPoolTagsType =
    Dict.Refined.Dict String TagKeysType TagValueType


{-| The UserPoolType data model.
-}
type alias UserPoolType =
    { verificationMessageTemplate : Maybe VerificationMessageTemplateType
    , usernameAttributes : Maybe UsernameAttributesListType
    , userPoolTags : Maybe UserPoolTagsType
    , userPoolAddOns : Maybe UserPoolAddOnsType
    , status : Maybe StatusType
    , smsVerificationMessage : Maybe SmsVerificationMessageType
    , smsConfigurationFailure : Maybe String
    , smsConfiguration : Maybe SmsConfigurationType
    , smsAuthenticationMessage : Maybe SmsVerificationMessageType
    , schemaAttributes : Maybe SchemaAttributesListType
    , policies : Maybe UserPoolPolicyType
    , name : Maybe UserPoolNameType
    , mfaConfiguration : Maybe UserPoolMfaType
    , lastModifiedDate : Maybe DateType
    , lambdaConfig : Maybe LambdaConfigType
    , id : Maybe UserPoolIdType
    , estimatedNumberOfUsers : Maybe Int
    , emailVerificationSubject : Maybe EmailVerificationSubjectType
    , emailVerificationMessage : Maybe EmailVerificationMessageType
    , emailConfigurationFailure : Maybe String
    , emailConfiguration : Maybe EmailConfigurationType
    , domain : Maybe DomainType
    , deviceConfiguration : Maybe DeviceConfigurationType
    , customDomain : Maybe DomainType
    , creationDate : Maybe DateType
    , autoVerifiedAttributes : Maybe VerifiedAttributesListType
    , arn : Maybe ArnType
    , aliasAttributes : Maybe AliasAttributesListType
    , adminCreateUserConfig : Maybe AdminCreateUserConfigType
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


{-| The UserType data model.
-}
type alias UserType =
    { username : Maybe UsernameType
    , userStatus : Maybe UserStatusType
    , userLastModifiedDate : Maybe DateType
    , userCreateDate : Maybe DateType
    , mfaoptions : Maybe MfaoptionListType
    , enabled : Maybe Bool
    , attributes : Maybe AttributeListType
    }


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


{-| The UsernameAttributesListType data model.
-}
type alias UsernameAttributesListType =
    List UsernameAttributeType


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


{-| The UsersListType data model.
-}
type alias UsersListType =
    List UserType


{-| The VerificationMessageTemplateType data model.
-}
type alias VerificationMessageTemplateType =
    { smsMessage : Maybe SmsVerificationMessageType
    , emailSubjectByLink : Maybe EmailVerificationSubjectByLinkType
    , emailSubject : Maybe EmailVerificationSubjectType
    , emailMessageByLink : Maybe EmailVerificationMessageByLinkType
    , emailMessage : Maybe EmailVerificationMessageType
    , defaultEmailOption : Maybe DefaultEmailOptionType
    }


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


{-| The VerifiedAttributesListType data model.
-}
type alias VerifiedAttributesListType =
    List VerifiedAttributeType


{-| The VerifySoftwareTokenRequest data model.
-}
type alias VerifySoftwareTokenRequest =
    { userCode : SoftwareTokenMfauserCodeType
    , session : Maybe SessionType
    , friendlyDeviceName : Maybe String
    , accessToken : Maybe TokenModelType
    }


{-| The VerifySoftwareTokenResponse data model.
-}
type alias VerifySoftwareTokenResponse =
    { status : Maybe VerifySoftwareTokenResponseType, session : Maybe SessionType }


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


{-| The VerifyUserAttributeRequest data model.
-}
type alias VerifyUserAttributeRequest =
    { code : ConfirmationCodeType, attributeName : AttributeNameType, accessToken : TokenModelType }


{-| The VerifyUserAttributeResponse data model.
-}
type alias VerifyUserAttributeResponse =
    {}


{-| Codec for VerifyUserAttributeResponse.
-}
verifyUserAttributeResponseCodec : Codec VerifyUserAttributeResponse
verifyUserAttributeResponseCodec =
    Codec.object VerifyUserAttributeResponse |> Codec.buildObject


{-| Codec for VerifyUserAttributeRequest.
-}
verifyUserAttributeRequestCodec : Codec VerifyUserAttributeRequest
verifyUserAttributeRequestCodec =
    Codec.object VerifyUserAttributeRequest
        |> Codec.field "Code" .code confirmationCodeTypeCodec
        |> Codec.field "AttributeName" .attributeName attributeNameTypeCodec
        |> Codec.field "AccessToken" .accessToken tokenModelTypeCodec
        |> Codec.buildObject


{-| Codec for VerifySoftwareTokenResponseType.
-}
verifySoftwareTokenResponseTypeCodec : Codec VerifySoftwareTokenResponseType
verifySoftwareTokenResponseTypeCodec =
    Codec.build (Enum.encoder verifySoftwareTokenResponseType) (Enum.decoder verifySoftwareTokenResponseType)


{-| Codec for VerifySoftwareTokenResponse.
-}
verifySoftwareTokenResponseCodec : Codec VerifySoftwareTokenResponse
verifySoftwareTokenResponseCodec =
    Codec.object VerifySoftwareTokenResponse
        |> Codec.optionalField "Status" .status verifySoftwareTokenResponseTypeCodec
        |> Codec.optionalField "Session" .session sessionTypeCodec
        |> Codec.buildObject


{-| Codec for VerifySoftwareTokenRequest.
-}
verifySoftwareTokenRequestCodec : Codec VerifySoftwareTokenRequest
verifySoftwareTokenRequestCodec =
    Codec.object VerifySoftwareTokenRequest
        |> Codec.field "UserCode" .userCode softwareTokenMfauserCodeTypeCodec
        |> Codec.optionalField "Session" .session sessionTypeCodec
        |> Codec.optionalField "FriendlyDeviceName" .friendlyDeviceName Codec.string
        |> Codec.optionalField "AccessToken" .accessToken tokenModelTypeCodec
        |> Codec.buildObject


{-| Codec for VerifiedAttributesListType.
-}
verifiedAttributesListTypeCodec : Codec VerifiedAttributesListType
verifiedAttributesListTypeCodec =
    Codec.list verifiedAttributeTypeCodec


{-| Codec for VerifiedAttributeType.
-}
verifiedAttributeTypeCodec : Codec VerifiedAttributeType
verifiedAttributeTypeCodec =
    Codec.build (Enum.encoder verifiedAttributeType) (Enum.decoder verifiedAttributeType)


{-| Codec for VerificationMessageTemplateType.
-}
verificationMessageTemplateTypeCodec : Codec VerificationMessageTemplateType
verificationMessageTemplateTypeCodec =
    Codec.object VerificationMessageTemplateType
        |> Codec.optionalField "SmsMessage" .smsMessage smsVerificationMessageTypeCodec
        |> Codec.optionalField "EmailSubjectByLink" .emailSubjectByLink emailVerificationSubjectByLinkTypeCodec
        |> Codec.optionalField "EmailSubject" .emailSubject emailVerificationSubjectTypeCodec
        |> Codec.optionalField "EmailMessageByLink" .emailMessageByLink emailVerificationMessageByLinkTypeCodec
        |> Codec.optionalField "EmailMessage" .emailMessage emailVerificationMessageTypeCodec
        |> Codec.optionalField "DefaultEmailOption" .defaultEmailOption defaultEmailOptionTypeCodec
        |> Codec.buildObject


{-| Codec for UsersListType.
-}
usersListTypeCodec : Codec UsersListType
usersListTypeCodec =
    Codec.list userTypeCodec


{-| Codec for UsernameType.
-}
usernameTypeCodec : Codec UsernameType
usernameTypeCodec =
    Codec.build (Refined.encoder usernameType) (Refined.decoder usernameType)


{-| Codec for UsernameAttributesListType.
-}
usernameAttributesListTypeCodec : Codec UsernameAttributesListType
usernameAttributesListTypeCodec =
    Codec.list usernameAttributeTypeCodec


{-| Codec for UsernameAttributeType.
-}
usernameAttributeTypeCodec : Codec UsernameAttributeType
usernameAttributeTypeCodec =
    Codec.build (Enum.encoder usernameAttributeType) (Enum.decoder usernameAttributeType)


{-| Codec for UserType.
-}
userTypeCodec : Codec UserType
userTypeCodec =
    Codec.object UserType
        |> Codec.optionalField "Username" .username usernameTypeCodec
        |> Codec.optionalField "UserStatus" .userStatus userStatusTypeCodec
        |> Codec.optionalField "UserLastModifiedDate" .userLastModifiedDate dateTypeCodec
        |> Codec.optionalField "UserCreateDate" .userCreateDate dateTypeCodec
        |> Codec.optionalField "MFAOptions" .mfaoptions mfaoptionListTypeCodec
        |> Codec.optionalField "Enabled" .enabled Codec.bool
        |> Codec.optionalField "Attributes" .attributes attributeListTypeCodec
        |> Codec.buildObject


{-| Codec for UserStatusType.
-}
userStatusTypeCodec : Codec UserStatusType
userStatusTypeCodec =
    Codec.build (Enum.encoder userStatusType) (Enum.decoder userStatusType)


{-| Codec for UserPoolType.
-}
userPoolTypeCodec : Codec UserPoolType
userPoolTypeCodec =
    Codec.object UserPoolType
        |> Codec.optionalField
            "VerificationMessageTemplate"
            .verificationMessageTemplate
            verificationMessageTemplateTypeCodec
        |> Codec.optionalField "UsernameAttributes" .usernameAttributes usernameAttributesListTypeCodec
        |> Codec.optionalField "UserPoolTags" .userPoolTags userPoolTagsTypeCodec
        |> Codec.optionalField "UserPoolAddOns" .userPoolAddOns userPoolAddOnsTypeCodec
        |> Codec.optionalField "Status" .status statusTypeCodec
        |> Codec.optionalField "SmsVerificationMessage" .smsVerificationMessage smsVerificationMessageTypeCodec
        |> Codec.optionalField "SmsConfigurationFailure" .smsConfigurationFailure Codec.string
        |> Codec.optionalField "SmsConfiguration" .smsConfiguration smsConfigurationTypeCodec
        |> Codec.optionalField "SmsAuthenticationMessage" .smsAuthenticationMessage smsVerificationMessageTypeCodec
        |> Codec.optionalField "SchemaAttributes" .schemaAttributes schemaAttributesListTypeCodec
        |> Codec.optionalField "Policies" .policies userPoolPolicyTypeCodec
        |> Codec.optionalField "Name" .name userPoolNameTypeCodec
        |> Codec.optionalField "MfaConfiguration" .mfaConfiguration userPoolMfaTypeCodec
        |> Codec.optionalField "LastModifiedDate" .lastModifiedDate dateTypeCodec
        |> Codec.optionalField "LambdaConfig" .lambdaConfig lambdaConfigTypeCodec
        |> Codec.optionalField "Id" .id userPoolIdTypeCodec
        |> Codec.optionalField "EstimatedNumberOfUsers" .estimatedNumberOfUsers Codec.int
        |> Codec.optionalField "EmailVerificationSubject" .emailVerificationSubject emailVerificationSubjectTypeCodec
        |> Codec.optionalField "EmailVerificationMessage" .emailVerificationMessage emailVerificationMessageTypeCodec
        |> Codec.optionalField "EmailConfigurationFailure" .emailConfigurationFailure Codec.string
        |> Codec.optionalField "EmailConfiguration" .emailConfiguration emailConfigurationTypeCodec
        |> Codec.optionalField "Domain" .domain domainTypeCodec
        |> Codec.optionalField "DeviceConfiguration" .deviceConfiguration deviceConfigurationTypeCodec
        |> Codec.optionalField "CustomDomain" .customDomain domainTypeCodec
        |> Codec.optionalField "CreationDate" .creationDate dateTypeCodec
        |> Codec.optionalField "AutoVerifiedAttributes" .autoVerifiedAttributes verifiedAttributesListTypeCodec
        |> Codec.optionalField "Arn" .arn arnTypeCodec
        |> Codec.optionalField "AliasAttributes" .aliasAttributes aliasAttributesListTypeCodec
        |> Codec.optionalField "AdminCreateUserConfig" .adminCreateUserConfig adminCreateUserConfigTypeCodec
        |> Codec.buildObject


{-| Codec for UserPoolTagsType.
-}
userPoolTagsTypeCodec : Codec UserPoolTagsType
userPoolTagsTypeCodec =
    Codec.build
        (Refined.dictEncoder tagKeysType (Codec.encoder tagValueTypeCodec))
        (Refined.dictDecoder tagKeysType (Codec.decoder tagValueTypeCodec))


{-| Codec for UserPoolTagsListType.
-}
userPoolTagsListTypeCodec : Codec UserPoolTagsListType
userPoolTagsListTypeCodec =
    Codec.list tagKeysTypeCodec


{-| Codec for UserPoolPolicyType.
-}
userPoolPolicyTypeCodec : Codec UserPoolPolicyType
userPoolPolicyTypeCodec =
    Codec.object UserPoolPolicyType
        |> Codec.optionalField "PasswordPolicy" .passwordPolicy passwordPolicyTypeCodec
        |> Codec.buildObject


{-| Codec for UserPoolNameType.
-}
userPoolNameTypeCodec : Codec UserPoolNameType
userPoolNameTypeCodec =
    Codec.build (Refined.encoder userPoolNameType) (Refined.decoder userPoolNameType)


{-| Codec for UserPoolMfaType.
-}
userPoolMfaTypeCodec : Codec UserPoolMfaType
userPoolMfaTypeCodec =
    Codec.build (Enum.encoder userPoolMfaType) (Enum.decoder userPoolMfaType)


{-| Codec for UserPoolListType.
-}
userPoolListTypeCodec : Codec UserPoolListType
userPoolListTypeCodec =
    Codec.list userPoolDescriptionTypeCodec


{-| Codec for UserPoolIdType.
-}
userPoolIdTypeCodec : Codec UserPoolIdType
userPoolIdTypeCodec =
    Codec.build (Refined.encoder userPoolIdType) (Refined.decoder userPoolIdType)


{-| Codec for UserPoolDescriptionType.
-}
userPoolDescriptionTypeCodec : Codec UserPoolDescriptionType
userPoolDescriptionTypeCodec =
    Codec.object UserPoolDescriptionType
        |> Codec.optionalField "Status" .status statusTypeCodec
        |> Codec.optionalField "Name" .name userPoolNameTypeCodec
        |> Codec.optionalField "LastModifiedDate" .lastModifiedDate dateTypeCodec
        |> Codec.optionalField "LambdaConfig" .lambdaConfig lambdaConfigTypeCodec
        |> Codec.optionalField "Id" .id userPoolIdTypeCodec
        |> Codec.optionalField "CreationDate" .creationDate dateTypeCodec
        |> Codec.buildObject


{-| Codec for UserPoolClientType.
-}
userPoolClientTypeCodec : Codec UserPoolClientType
userPoolClientTypeCodec =
    Codec.object UserPoolClientType
        |> Codec.optionalField "WriteAttributes" .writeAttributes clientPermissionListTypeCodec
        |> Codec.optionalField "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.optionalField
            "SupportedIdentityProviders"
            .supportedIdentityProviders
            supportedIdentityProvidersListTypeCodec
        |> Codec.optionalField "RefreshTokenValidity" .refreshTokenValidity refreshTokenValidityTypeCodec
        |> Codec.optionalField "ReadAttributes" .readAttributes clientPermissionListTypeCodec
        |> Codec.optionalField "LogoutURLs" .logoutUrls logoutUrlsListTypeCodec
        |> Codec.optionalField "LastModifiedDate" .lastModifiedDate dateTypeCodec
        |> Codec.optionalField "ExplicitAuthFlows" .explicitAuthFlows explicitAuthFlowsListTypeCodec
        |> Codec.optionalField "DefaultRedirectURI" .defaultRedirectUri redirectUrlTypeCodec
        |> Codec.optionalField "CreationDate" .creationDate dateTypeCodec
        |> Codec.optionalField "ClientSecret" .clientSecret clientSecretTypeCodec
        |> Codec.optionalField "ClientName" .clientName clientNameTypeCodec
        |> Codec.optionalField "ClientId" .clientId clientIdTypeCodec
        |> Codec.optionalField "CallbackURLs" .callbackUrls callbackUrlsListTypeCodec
        |> Codec.optionalField "AnalyticsConfiguration" .analyticsConfiguration analyticsConfigurationTypeCodec
        |> Codec.optionalField "AllowedOAuthScopes" .allowedOauthScopes scopeListTypeCodec
        |> Codec.optionalField "AllowedOAuthFlowsUserPoolClient" .allowedOauthFlowsUserPoolClient Codec.bool
        |> Codec.optionalField "AllowedOAuthFlows" .allowedOauthFlows oauthFlowsTypeCodec
        |> Codec.buildObject


{-| Codec for UserPoolClientListType.
-}
userPoolClientListTypeCodec : Codec UserPoolClientListType
userPoolClientListTypeCodec =
    Codec.list userPoolClientDescriptionCodec


{-| Codec for UserPoolClientDescription.
-}
userPoolClientDescriptionCodec : Codec UserPoolClientDescription
userPoolClientDescriptionCodec =
    Codec.object UserPoolClientDescription
        |> Codec.optionalField "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.optionalField "ClientName" .clientName clientNameTypeCodec
        |> Codec.optionalField "ClientId" .clientId clientIdTypeCodec
        |> Codec.buildObject


{-| Codec for UserPoolAddOnsType.
-}
userPoolAddOnsTypeCodec : Codec UserPoolAddOnsType
userPoolAddOnsTypeCodec =
    Codec.object UserPoolAddOnsType
        |> Codec.field "AdvancedSecurityMode" .advancedSecurityMode advancedSecurityModeTypeCodec
        |> Codec.buildObject


{-| Codec for UserMfasettingListType.
-}
userMfasettingListTypeCodec : Codec UserMfasettingListType
userMfasettingListTypeCodec =
    Codec.list Codec.string


{-| Codec for UserImportJobsListType.
-}
userImportJobsListTypeCodec : Codec UserImportJobsListType
userImportJobsListTypeCodec =
    Codec.list userImportJobTypeCodec


{-| Codec for UserImportJobType.
-}
userImportJobTypeCodec : Codec UserImportJobType
userImportJobTypeCodec =
    Codec.object UserImportJobType
        |> Codec.optionalField "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.optionalField "Status" .status userImportJobStatusTypeCodec
        |> Codec.optionalField "StartDate" .startDate dateTypeCodec
        |> Codec.optionalField "SkippedUsers" .skippedUsers Codec.int
        |> Codec.optionalField "PreSignedUrl" .preSignedUrl preSignedUrlTypeCodec
        |> Codec.optionalField "JobName" .jobName userImportJobNameTypeCodec
        |> Codec.optionalField "JobId" .jobId userImportJobIdTypeCodec
        |> Codec.optionalField "ImportedUsers" .importedUsers Codec.int
        |> Codec.optionalField "FailedUsers" .failedUsers Codec.int
        |> Codec.optionalField "CreationDate" .creationDate dateTypeCodec
        |> Codec.optionalField "CompletionMessage" .completionMessage completionMessageTypeCodec
        |> Codec.optionalField "CompletionDate" .completionDate dateTypeCodec
        |> Codec.optionalField "CloudWatchLogsRoleArn" .cloudWatchLogsRoleArn arnTypeCodec
        |> Codec.buildObject


{-| Codec for UserImportJobStatusType.
-}
userImportJobStatusTypeCodec : Codec UserImportJobStatusType
userImportJobStatusTypeCodec =
    Codec.build (Enum.encoder userImportJobStatusType) (Enum.decoder userImportJobStatusType)


{-| Codec for UserImportJobNameType.
-}
userImportJobNameTypeCodec : Codec UserImportJobNameType
userImportJobNameTypeCodec =
    Codec.build (Refined.encoder userImportJobNameType) (Refined.decoder userImportJobNameType)


{-| Codec for UserImportJobIdType.
-}
userImportJobIdTypeCodec : Codec UserImportJobIdType
userImportJobIdTypeCodec =
    Codec.build (Refined.encoder userImportJobIdType) (Refined.decoder userImportJobIdType)


{-| Codec for UserFilterType.
-}
userFilterTypeCodec : Codec UserFilterType
userFilterTypeCodec =
    Codec.build (Refined.encoder userFilterType) (Refined.decoder userFilterType)


{-| Codec for UserContextDataType.
-}
userContextDataTypeCodec : Codec UserContextDataType
userContextDataTypeCodec =
    Codec.object UserContextDataType |> Codec.optionalField "EncodedData" .encodedData Codec.string |> Codec.buildObject


{-| Codec for UpdateUserPoolResponse.
-}
updateUserPoolResponseCodec : Codec UpdateUserPoolResponse
updateUserPoolResponseCodec =
    Codec.object UpdateUserPoolResponse |> Codec.buildObject


{-| Codec for UpdateUserPoolRequest.
-}
updateUserPoolRequestCodec : Codec UpdateUserPoolRequest
updateUserPoolRequestCodec =
    Codec.object UpdateUserPoolRequest
        |> Codec.optionalField
            "VerificationMessageTemplate"
            .verificationMessageTemplate
            verificationMessageTemplateTypeCodec
        |> Codec.optionalField "UserPoolTags" .userPoolTags userPoolTagsTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.optionalField "UserPoolAddOns" .userPoolAddOns userPoolAddOnsTypeCodec
        |> Codec.optionalField "SmsVerificationMessage" .smsVerificationMessage smsVerificationMessageTypeCodec
        |> Codec.optionalField "SmsConfiguration" .smsConfiguration smsConfigurationTypeCodec
        |> Codec.optionalField "SmsAuthenticationMessage" .smsAuthenticationMessage smsVerificationMessageTypeCodec
        |> Codec.optionalField "Policies" .policies userPoolPolicyTypeCodec
        |> Codec.optionalField "MfaConfiguration" .mfaConfiguration userPoolMfaTypeCodec
        |> Codec.optionalField "LambdaConfig" .lambdaConfig lambdaConfigTypeCodec
        |> Codec.optionalField "EmailVerificationSubject" .emailVerificationSubject emailVerificationSubjectTypeCodec
        |> Codec.optionalField "EmailVerificationMessage" .emailVerificationMessage emailVerificationMessageTypeCodec
        |> Codec.optionalField "EmailConfiguration" .emailConfiguration emailConfigurationTypeCodec
        |> Codec.optionalField "DeviceConfiguration" .deviceConfiguration deviceConfigurationTypeCodec
        |> Codec.optionalField "AutoVerifiedAttributes" .autoVerifiedAttributes verifiedAttributesListTypeCodec
        |> Codec.optionalField "AdminCreateUserConfig" .adminCreateUserConfig adminCreateUserConfigTypeCodec
        |> Codec.buildObject


{-| Codec for UpdateUserPoolDomainResponse.
-}
updateUserPoolDomainResponseCodec : Codec UpdateUserPoolDomainResponse
updateUserPoolDomainResponseCodec =
    Codec.object UpdateUserPoolDomainResponse
        |> Codec.optionalField "CloudFrontDomain" .cloudFrontDomain domainTypeCodec
        |> Codec.buildObject


{-| Codec for UpdateUserPoolDomainRequest.
-}
updateUserPoolDomainRequestCodec : Codec UpdateUserPoolDomainRequest
updateUserPoolDomainRequestCodec =
    Codec.object UpdateUserPoolDomainRequest
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "Domain" .domain domainTypeCodec
        |> Codec.field "CustomDomainConfig" .customDomainConfig customDomainConfigTypeCodec
        |> Codec.buildObject


{-| Codec for UpdateUserPoolClientResponse.
-}
updateUserPoolClientResponseCodec : Codec UpdateUserPoolClientResponse
updateUserPoolClientResponseCodec =
    Codec.object UpdateUserPoolClientResponse
        |> Codec.optionalField "UserPoolClient" .userPoolClient userPoolClientTypeCodec
        |> Codec.buildObject


{-| Codec for UpdateUserPoolClientRequest.
-}
updateUserPoolClientRequestCodec : Codec UpdateUserPoolClientRequest
updateUserPoolClientRequestCodec =
    Codec.object UpdateUserPoolClientRequest
        |> Codec.optionalField "WriteAttributes" .writeAttributes clientPermissionListTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.optionalField
            "SupportedIdentityProviders"
            .supportedIdentityProviders
            supportedIdentityProvidersListTypeCodec
        |> Codec.optionalField "RefreshTokenValidity" .refreshTokenValidity refreshTokenValidityTypeCodec
        |> Codec.optionalField "ReadAttributes" .readAttributes clientPermissionListTypeCodec
        |> Codec.optionalField "LogoutURLs" .logoutUrls logoutUrlsListTypeCodec
        |> Codec.optionalField "ExplicitAuthFlows" .explicitAuthFlows explicitAuthFlowsListTypeCodec
        |> Codec.optionalField "DefaultRedirectURI" .defaultRedirectUri redirectUrlTypeCodec
        |> Codec.optionalField "ClientName" .clientName clientNameTypeCodec
        |> Codec.field "ClientId" .clientId clientIdTypeCodec
        |> Codec.optionalField "CallbackURLs" .callbackUrls callbackUrlsListTypeCodec
        |> Codec.optionalField "AnalyticsConfiguration" .analyticsConfiguration analyticsConfigurationTypeCodec
        |> Codec.optionalField "AllowedOAuthScopes" .allowedOauthScopes scopeListTypeCodec
        |> Codec.optionalField "AllowedOAuthFlowsUserPoolClient" .allowedOauthFlowsUserPoolClient Codec.bool
        |> Codec.optionalField "AllowedOAuthFlows" .allowedOauthFlows oauthFlowsTypeCodec
        |> Codec.buildObject


{-| Codec for UpdateUserAttributesResponse.
-}
updateUserAttributesResponseCodec : Codec UpdateUserAttributesResponse
updateUserAttributesResponseCodec =
    Codec.object UpdateUserAttributesResponse
        |> Codec.optionalField "CodeDeliveryDetailsList" .codeDeliveryDetailsList codeDeliveryDetailsListTypeCodec
        |> Codec.buildObject


{-| Codec for UpdateUserAttributesRequest.
-}
updateUserAttributesRequestCodec : Codec UpdateUserAttributesRequest
updateUserAttributesRequestCodec =
    Codec.object UpdateUserAttributesRequest
        |> Codec.field "UserAttributes" .userAttributes attributeListTypeCodec
        |> Codec.field "AccessToken" .accessToken tokenModelTypeCodec
        |> Codec.buildObject


{-| Codec for UpdateResourceServerResponse.
-}
updateResourceServerResponseCodec : Codec UpdateResourceServerResponse
updateResourceServerResponseCodec =
    Codec.object UpdateResourceServerResponse
        |> Codec.field "ResourceServer" .resourceServer resourceServerTypeCodec
        |> Codec.buildObject


{-| Codec for UpdateResourceServerRequest.
-}
updateResourceServerRequestCodec : Codec UpdateResourceServerRequest
updateResourceServerRequestCodec =
    Codec.object UpdateResourceServerRequest
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.optionalField "Scopes" .scopes resourceServerScopeListTypeCodec
        |> Codec.field "Name" .name resourceServerNameTypeCodec
        |> Codec.field "Identifier" .identifier resourceServerIdentifierTypeCodec
        |> Codec.buildObject


{-| Codec for UpdateIdentityProviderResponse.
-}
updateIdentityProviderResponseCodec : Codec UpdateIdentityProviderResponse
updateIdentityProviderResponseCodec =
    Codec.object UpdateIdentityProviderResponse
        |> Codec.field "IdentityProvider" .identityProvider identityProviderTypeCodec
        |> Codec.buildObject


{-| Codec for UpdateIdentityProviderRequest.
-}
updateIdentityProviderRequestCodec : Codec UpdateIdentityProviderRequest
updateIdentityProviderRequestCodec =
    Codec.object UpdateIdentityProviderRequest
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "ProviderName" .providerName providerNameTypeCodec
        |> Codec.optionalField "ProviderDetails" .providerDetails providerDetailsTypeCodec
        |> Codec.optionalField "IdpIdentifiers" .idpIdentifiers idpIdentifiersListTypeCodec
        |> Codec.optionalField "AttributeMapping" .attributeMapping attributeMappingTypeCodec
        |> Codec.buildObject


{-| Codec for UpdateGroupResponse.
-}
updateGroupResponseCodec : Codec UpdateGroupResponse
updateGroupResponseCodec =
    Codec.object UpdateGroupResponse |> Codec.optionalField "Group" .group groupTypeCodec |> Codec.buildObject


{-| Codec for UpdateGroupRequest.
-}
updateGroupRequestCodec : Codec UpdateGroupRequest
updateGroupRequestCodec =
    Codec.object UpdateGroupRequest
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.optionalField "RoleArn" .roleArn arnTypeCodec
        |> Codec.optionalField "Precedence" .precedence precedenceTypeCodec
        |> Codec.field "GroupName" .groupName groupNameTypeCodec
        |> Codec.optionalField "Description" .description descriptionTypeCodec
        |> Codec.buildObject


{-| Codec for UpdateDeviceStatusResponse.
-}
updateDeviceStatusResponseCodec : Codec UpdateDeviceStatusResponse
updateDeviceStatusResponseCodec =
    Codec.object UpdateDeviceStatusResponse |> Codec.buildObject


{-| Codec for UpdateDeviceStatusRequest.
-}
updateDeviceStatusRequestCodec : Codec UpdateDeviceStatusRequest
updateDeviceStatusRequestCodec =
    Codec.object UpdateDeviceStatusRequest
        |> Codec.optionalField "DeviceRememberedStatus" .deviceRememberedStatus deviceRememberedStatusTypeCodec
        |> Codec.field "DeviceKey" .deviceKey deviceKeyTypeCodec
        |> Codec.field "AccessToken" .accessToken tokenModelTypeCodec
        |> Codec.buildObject


{-| Codec for UpdateAuthEventFeedbackResponse.
-}
updateAuthEventFeedbackResponseCodec : Codec UpdateAuthEventFeedbackResponse
updateAuthEventFeedbackResponseCodec =
    Codec.object UpdateAuthEventFeedbackResponse |> Codec.buildObject


{-| Codec for UpdateAuthEventFeedbackRequest.
-}
updateAuthEventFeedbackRequestCodec : Codec UpdateAuthEventFeedbackRequest
updateAuthEventFeedbackRequestCodec =
    Codec.object UpdateAuthEventFeedbackRequest
        |> Codec.field "Username" .username usernameTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "FeedbackValue" .feedbackValue feedbackValueTypeCodec
        |> Codec.field "FeedbackToken" .feedbackToken tokenModelTypeCodec
        |> Codec.field "EventId" .eventId eventIdTypeCodec
        |> Codec.buildObject


{-| Codec for UntagResourceResponse.
-}
untagResourceResponseCodec : Codec UntagResourceResponse
untagResourceResponseCodec =
    Codec.object UntagResourceResponse |> Codec.buildObject


{-| Codec for UntagResourceRequest.
-}
untagResourceRequestCodec : Codec UntagResourceRequest
untagResourceRequestCodec =
    Codec.object UntagResourceRequest
        |> Codec.optionalField "TagKeys" .tagKeys userPoolTagsListTypeCodec
        |> Codec.field "ResourceArn" .resourceArn arnTypeCodec
        |> Codec.buildObject


{-| Codec for UicustomizationType.
-}
uicustomizationTypeCodec : Codec UicustomizationType
uicustomizationTypeCodec =
    Codec.object UicustomizationType
        |> Codec.optionalField "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.optionalField "LastModifiedDate" .lastModifiedDate dateTypeCodec
        |> Codec.optionalField "ImageUrl" .imageUrl Codec.string
        |> Codec.optionalField "CreationDate" .creationDate dateTypeCodec
        |> Codec.optionalField "ClientId" .clientId clientIdTypeCodec
        |> Codec.optionalField "CSSVersion" .cssversion Codec.string
        |> Codec.optionalField "CSS" .css Codec.string
        |> Codec.buildObject


{-| Codec for TokenModelType.
-}
tokenModelTypeCodec : Codec TokenModelType
tokenModelTypeCodec =
    Codec.build (Refined.encoder tokenModelType) (Refined.decoder tokenModelType)


{-| Codec for TemporaryPasswordValidityDaysType.
-}
temporaryPasswordValidityDaysTypeCodec : Codec TemporaryPasswordValidityDaysType
temporaryPasswordValidityDaysTypeCodec =
    Codec.build (Refined.encoder temporaryPasswordValidityDaysType) (Refined.decoder temporaryPasswordValidityDaysType)


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


{-| Codec for TagResourceRequest.
-}
tagResourceRequestCodec : Codec TagResourceRequest
tagResourceRequestCodec =
    Codec.object TagResourceRequest
        |> Codec.optionalField "Tags" .tags userPoolTagsTypeCodec
        |> Codec.field "ResourceArn" .resourceArn arnTypeCodec
        |> Codec.buildObject


{-| Codec for TagKeysType.
-}
tagKeysTypeCodec : Codec TagKeysType
tagKeysTypeCodec =
    Codec.build (Refined.encoder tagKeysType) (Refined.decoder tagKeysType)


{-| Codec for SupportedIdentityProvidersListType.
-}
supportedIdentityProvidersListTypeCodec : Codec SupportedIdentityProvidersListType
supportedIdentityProvidersListTypeCodec =
    Codec.list providerNameTypeCodec


{-| Codec for StringType.
-}
stringTypeCodec : Codec StringType
stringTypeCodec =
    Codec.string


{-| Codec for StringAttributeConstraintsType.
-}
stringAttributeConstraintsTypeCodec : Codec StringAttributeConstraintsType
stringAttributeConstraintsTypeCodec =
    Codec.object StringAttributeConstraintsType
        |> Codec.optionalField "MinLength" .minLength Codec.string
        |> Codec.optionalField "MaxLength" .maxLength Codec.string
        |> Codec.buildObject


{-| Codec for StopUserImportJobResponse.
-}
stopUserImportJobResponseCodec : Codec StopUserImportJobResponse
stopUserImportJobResponseCodec =
    Codec.object StopUserImportJobResponse
        |> Codec.optionalField "UserImportJob" .userImportJob userImportJobTypeCodec
        |> Codec.buildObject


{-| Codec for StopUserImportJobRequest.
-}
stopUserImportJobRequestCodec : Codec StopUserImportJobRequest
stopUserImportJobRequestCodec =
    Codec.object StopUserImportJobRequest
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "JobId" .jobId userImportJobIdTypeCodec
        |> Codec.buildObject


{-| Codec for StatusType.
-}
statusTypeCodec : Codec StatusType
statusTypeCodec =
    Codec.build (Enum.encoder statusType) (Enum.decoder statusType)


{-| Codec for StartUserImportJobResponse.
-}
startUserImportJobResponseCodec : Codec StartUserImportJobResponse
startUserImportJobResponseCodec =
    Codec.object StartUserImportJobResponse
        |> Codec.optionalField "UserImportJob" .userImportJob userImportJobTypeCodec
        |> Codec.buildObject


{-| Codec for StartUserImportJobRequest.
-}
startUserImportJobRequestCodec : Codec StartUserImportJobRequest
startUserImportJobRequestCodec =
    Codec.object StartUserImportJobRequest
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "JobId" .jobId userImportJobIdTypeCodec
        |> Codec.buildObject


{-| Codec for SoftwareTokenMfaSettingsType.
-}
softwareTokenMfaSettingsTypeCodec : Codec SoftwareTokenMfaSettingsType
softwareTokenMfaSettingsTypeCodec =
    Codec.object SoftwareTokenMfaSettingsType
        |> Codec.optionalField "PreferredMfa" .preferredMfa Codec.bool
        |> Codec.optionalField "Enabled" .enabled Codec.bool
        |> Codec.buildObject


{-| Codec for SoftwareTokenMfaConfigType.
-}
softwareTokenMfaConfigTypeCodec : Codec SoftwareTokenMfaConfigType
softwareTokenMfaConfigTypeCodec =
    Codec.object SoftwareTokenMfaConfigType |> Codec.optionalField "Enabled" .enabled Codec.bool |> Codec.buildObject


{-| Codec for SoftwareTokenMfauserCodeType.
-}
softwareTokenMfauserCodeTypeCodec : Codec SoftwareTokenMfauserCodeType
softwareTokenMfauserCodeTypeCodec =
    Codec.build (Refined.encoder softwareTokenMfauserCodeType) (Refined.decoder softwareTokenMfauserCodeType)


{-| Codec for SmsVerificationMessageType.
-}
smsVerificationMessageTypeCodec : Codec SmsVerificationMessageType
smsVerificationMessageTypeCodec =
    Codec.build (Refined.encoder smsVerificationMessageType) (Refined.decoder smsVerificationMessageType)


{-| Codec for SmsMfaConfigType.
-}
smsMfaConfigTypeCodec : Codec SmsMfaConfigType
smsMfaConfigTypeCodec =
    Codec.object SmsMfaConfigType
        |> Codec.optionalField "SmsConfiguration" .smsConfiguration smsConfigurationTypeCodec
        |> Codec.optionalField "SmsAuthenticationMessage" .smsAuthenticationMessage smsVerificationMessageTypeCodec
        |> Codec.buildObject


{-| Codec for SmsConfigurationType.
-}
smsConfigurationTypeCodec : Codec SmsConfigurationType
smsConfigurationTypeCodec =
    Codec.object SmsConfigurationType
        |> Codec.field "SnsCallerArn" .snsCallerArn arnTypeCodec
        |> Codec.optionalField "ExternalId" .externalId Codec.string
        |> Codec.buildObject


{-| Codec for SkippedIprangeListType.
-}
skippedIprangeListTypeCodec : Codec SkippedIprangeListType
skippedIprangeListTypeCodec =
    Codec.list Codec.string


{-| Codec for SignUpResponse.
-}
signUpResponseCodec : Codec SignUpResponse
signUpResponseCodec =
    Codec.object SignUpResponse
        |> Codec.field "UserSub" .userSub Codec.string
        |> Codec.field "UserConfirmed" .userConfirmed Codec.bool
        |> Codec.optionalField "CodeDeliveryDetails" .codeDeliveryDetails codeDeliveryDetailsTypeCodec
        |> Codec.buildObject


{-| Codec for SignUpRequest.
-}
signUpRequestCodec : Codec SignUpRequest
signUpRequestCodec =
    Codec.object SignUpRequest
        |> Codec.optionalField "ValidationData" .validationData attributeListTypeCodec
        |> Codec.field "Username" .username usernameTypeCodec
        |> Codec.optionalField "UserContextData" .userContextData userContextDataTypeCodec
        |> Codec.optionalField "UserAttributes" .userAttributes attributeListTypeCodec
        |> Codec.optionalField "SecretHash" .secretHash secretHashTypeCodec
        |> Codec.field "Password" .password passwordTypeCodec
        |> Codec.field "ClientId" .clientId clientIdTypeCodec
        |> Codec.optionalField "AnalyticsMetadata" .analyticsMetadata analyticsMetadataTypeCodec
        |> Codec.buildObject


{-| Codec for SetUserSettingsResponse.
-}
setUserSettingsResponseCodec : Codec SetUserSettingsResponse
setUserSettingsResponseCodec =
    Codec.object SetUserSettingsResponse |> Codec.buildObject


{-| Codec for SetUserSettingsRequest.
-}
setUserSettingsRequestCodec : Codec SetUserSettingsRequest
setUserSettingsRequestCodec =
    Codec.object SetUserSettingsRequest
        |> Codec.field "MFAOptions" .mfaoptions mfaoptionListTypeCodec
        |> Codec.field "AccessToken" .accessToken tokenModelTypeCodec
        |> Codec.buildObject


{-| Codec for SetUserPoolMfaConfigResponse.
-}
setUserPoolMfaConfigResponseCodec : Codec SetUserPoolMfaConfigResponse
setUserPoolMfaConfigResponseCodec =
    Codec.object SetUserPoolMfaConfigResponse
        |> Codec.optionalField
            "SoftwareTokenMfaConfiguration"
            .softwareTokenMfaConfiguration
            softwareTokenMfaConfigTypeCodec
        |> Codec.optionalField "SmsMfaConfiguration" .smsMfaConfiguration smsMfaConfigTypeCodec
        |> Codec.optionalField "MfaConfiguration" .mfaConfiguration userPoolMfaTypeCodec
        |> Codec.buildObject


{-| Codec for SetUserPoolMfaConfigRequest.
-}
setUserPoolMfaConfigRequestCodec : Codec SetUserPoolMfaConfigRequest
setUserPoolMfaConfigRequestCodec =
    Codec.object SetUserPoolMfaConfigRequest
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.optionalField
            "SoftwareTokenMfaConfiguration"
            .softwareTokenMfaConfiguration
            softwareTokenMfaConfigTypeCodec
        |> Codec.optionalField "SmsMfaConfiguration" .smsMfaConfiguration smsMfaConfigTypeCodec
        |> Codec.optionalField "MfaConfiguration" .mfaConfiguration userPoolMfaTypeCodec
        |> Codec.buildObject


{-| Codec for SetUserMfapreferenceResponse.
-}
setUserMfapreferenceResponseCodec : Codec SetUserMfapreferenceResponse
setUserMfapreferenceResponseCodec =
    Codec.object SetUserMfapreferenceResponse |> Codec.buildObject


{-| Codec for SetUserMfapreferenceRequest.
-}
setUserMfapreferenceRequestCodec : Codec SetUserMfapreferenceRequest
setUserMfapreferenceRequestCodec =
    Codec.object SetUserMfapreferenceRequest
        |> Codec.optionalField "SoftwareTokenMfaSettings" .softwareTokenMfaSettings softwareTokenMfaSettingsTypeCodec
        |> Codec.optionalField "SMSMfaSettings" .smsmfaSettings smsmfaSettingsTypeCodec
        |> Codec.field "AccessToken" .accessToken tokenModelTypeCodec
        |> Codec.buildObject


{-| Codec for SetUicustomizationResponse.
-}
setUicustomizationResponseCodec : Codec SetUicustomizationResponse
setUicustomizationResponseCodec =
    Codec.object SetUicustomizationResponse
        |> Codec.field "UICustomization" .uicustomization uicustomizationTypeCodec
        |> Codec.buildObject


{-| Codec for SetUicustomizationRequest.
-}
setUicustomizationRequestCodec : Codec SetUicustomizationRequest
setUicustomizationRequestCodec =
    Codec.object SetUicustomizationRequest
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.optionalField "ImageFile" .imageFile Codec.string
        |> Codec.optionalField "ClientId" .clientId clientIdTypeCodec
        |> Codec.optionalField "CSS" .css Codec.string
        |> Codec.buildObject


{-| Codec for SetRiskConfigurationResponse.
-}
setRiskConfigurationResponseCodec : Codec SetRiskConfigurationResponse
setRiskConfigurationResponseCodec =
    Codec.object SetRiskConfigurationResponse
        |> Codec.field "RiskConfiguration" .riskConfiguration riskConfigurationTypeCodec
        |> Codec.buildObject


{-| Codec for SetRiskConfigurationRequest.
-}
setRiskConfigurationRequestCodec : Codec SetRiskConfigurationRequest
setRiskConfigurationRequestCodec =
    Codec.object SetRiskConfigurationRequest
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.optionalField
            "RiskExceptionConfiguration"
            .riskExceptionConfiguration
            riskExceptionConfigurationTypeCodec
        |> Codec.optionalField
            "CompromisedCredentialsRiskConfiguration"
            .compromisedCredentialsRiskConfiguration
            compromisedCredentialsRiskConfigurationTypeCodec
        |> Codec.optionalField "ClientId" .clientId clientIdTypeCodec
        |> Codec.optionalField
            "AccountTakeoverRiskConfiguration"
            .accountTakeoverRiskConfiguration
            accountTakeoverRiskConfigurationTypeCodec
        |> Codec.buildObject


{-| Codec for SessionType.
-}
sessionTypeCodec : Codec SessionType
sessionTypeCodec =
    Codec.build (Refined.encoder sessionType) (Refined.decoder sessionType)


{-| Codec for SecretHashType.
-}
secretHashTypeCodec : Codec SecretHashType
secretHashTypeCodec =
    Codec.build (Refined.encoder secretHashType) (Refined.decoder secretHashType)


{-| Codec for SecretCodeType.
-}
secretCodeTypeCodec : Codec SecretCodeType
secretCodeTypeCodec =
    Codec.build (Refined.encoder secretCodeType) (Refined.decoder secretCodeType)


{-| Codec for SearchedAttributeNamesListType.
-}
searchedAttributeNamesListTypeCodec : Codec SearchedAttributeNamesListType
searchedAttributeNamesListTypeCodec =
    Codec.list attributeNameTypeCodec


{-| Codec for SearchPaginationTokenType.
-}
searchPaginationTokenTypeCodec : Codec SearchPaginationTokenType
searchPaginationTokenTypeCodec =
    Codec.build (Refined.encoder searchPaginationTokenType) (Refined.decoder searchPaginationTokenType)


{-| Codec for ScopeType.
-}
scopeTypeCodec : Codec ScopeType
scopeTypeCodec =
    Codec.build (Refined.encoder scopeType) (Refined.decoder scopeType)


{-| Codec for ScopeListType.
-}
scopeListTypeCodec : Codec ScopeListType
scopeListTypeCodec =
    Codec.list scopeTypeCodec


{-| Codec for SchemaAttributesListType.
-}
schemaAttributesListTypeCodec : Codec SchemaAttributesListType
schemaAttributesListTypeCodec =
    Codec.list schemaAttributeTypeCodec


{-| Codec for SchemaAttributeType.
-}
schemaAttributeTypeCodec : Codec SchemaAttributeType
schemaAttributeTypeCodec =
    Codec.object SchemaAttributeType
        |> Codec.optionalField
            "StringAttributeConstraints"
            .stringAttributeConstraints
            stringAttributeConstraintsTypeCodec
        |> Codec.optionalField "Required" .required Codec.bool
        |> Codec.optionalField
            "NumberAttributeConstraints"
            .numberAttributeConstraints
            numberAttributeConstraintsTypeCodec
        |> Codec.optionalField "Name" .name customAttributeNameTypeCodec
        |> Codec.optionalField "Mutable" .mutable Codec.bool
        |> Codec.optionalField "DeveloperOnlyAttribute" .developerOnlyAttribute Codec.bool
        |> Codec.optionalField "AttributeDataType" .attributeDataType attributeDataTypeCodec
        |> Codec.buildObject


{-| Codec for SmsmfaSettingsType.
-}
smsmfaSettingsTypeCodec : Codec SmsmfaSettingsType
smsmfaSettingsTypeCodec =
    Codec.object SmsmfaSettingsType
        |> Codec.optionalField "PreferredMfa" .preferredMfa Codec.bool
        |> Codec.optionalField "Enabled" .enabled Codec.bool
        |> Codec.buildObject


{-| Codec for S3BucketType.
-}
s3BucketTypeCodec : Codec S3BucketType
s3BucketTypeCodec =
    Codec.build (Refined.encoder s3BucketType) (Refined.decoder s3BucketType)


{-| Codec for RiskLevelType.
-}
riskLevelTypeCodec : Codec RiskLevelType
riskLevelTypeCodec =
    Codec.build (Enum.encoder riskLevelType) (Enum.decoder riskLevelType)


{-| Codec for RiskExceptionConfigurationType.
-}
riskExceptionConfigurationTypeCodec : Codec RiskExceptionConfigurationType
riskExceptionConfigurationTypeCodec =
    Codec.object RiskExceptionConfigurationType
        |> Codec.optionalField "SkippedIPRangeList" .skippedIprangeList skippedIprangeListTypeCodec
        |> Codec.optionalField "BlockedIPRangeList" .blockedIprangeList blockedIprangeListTypeCodec
        |> Codec.buildObject


{-| Codec for RiskDecisionType.
-}
riskDecisionTypeCodec : Codec RiskDecisionType
riskDecisionTypeCodec =
    Codec.build (Enum.encoder riskDecisionType) (Enum.decoder riskDecisionType)


{-| Codec for RiskConfigurationType.
-}
riskConfigurationTypeCodec : Codec RiskConfigurationType
riskConfigurationTypeCodec =
    Codec.object RiskConfigurationType
        |> Codec.optionalField "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.optionalField
            "RiskExceptionConfiguration"
            .riskExceptionConfiguration
            riskExceptionConfigurationTypeCodec
        |> Codec.optionalField "LastModifiedDate" .lastModifiedDate dateTypeCodec
        |> Codec.optionalField
            "CompromisedCredentialsRiskConfiguration"
            .compromisedCredentialsRiskConfiguration
            compromisedCredentialsRiskConfigurationTypeCodec
        |> Codec.optionalField "ClientId" .clientId clientIdTypeCodec
        |> Codec.optionalField
            "AccountTakeoverRiskConfiguration"
            .accountTakeoverRiskConfiguration
            accountTakeoverRiskConfigurationTypeCodec
        |> Codec.buildObject


{-| Codec for RespondToAuthChallengeResponse.
-}
respondToAuthChallengeResponseCodec : Codec RespondToAuthChallengeResponse
respondToAuthChallengeResponseCodec =
    Codec.object RespondToAuthChallengeResponse
        |> Codec.optionalField "Session" .session sessionTypeCodec
        |> Codec.optionalField "ChallengeParameters" .challengeParameters challengeParametersTypeCodec
        |> Codec.optionalField "ChallengeName" .challengeName challengeNameTypeCodec
        |> Codec.optionalField "AuthenticationResult" .authenticationResult authenticationResultTypeCodec
        |> Codec.buildObject


{-| Codec for RespondToAuthChallengeRequest.
-}
respondToAuthChallengeRequestCodec : Codec RespondToAuthChallengeRequest
respondToAuthChallengeRequestCodec =
    Codec.object RespondToAuthChallengeRequest
        |> Codec.optionalField "UserContextData" .userContextData userContextDataTypeCodec
        |> Codec.optionalField "Session" .session sessionTypeCodec
        |> Codec.field "ClientId" .clientId clientIdTypeCodec
        |> Codec.optionalField "ChallengeResponses" .challengeResponses challengeResponsesTypeCodec
        |> Codec.field "ChallengeName" .challengeName challengeNameTypeCodec
        |> Codec.optionalField "AnalyticsMetadata" .analyticsMetadata analyticsMetadataTypeCodec
        |> Codec.buildObject


{-| Codec for ResourceServersListType.
-}
resourceServersListTypeCodec : Codec ResourceServersListType
resourceServersListTypeCodec =
    Codec.list resourceServerTypeCodec


{-| Codec for ResourceServerType.
-}
resourceServerTypeCodec : Codec ResourceServerType
resourceServerTypeCodec =
    Codec.object ResourceServerType
        |> Codec.optionalField "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.optionalField "Scopes" .scopes resourceServerScopeListTypeCodec
        |> Codec.optionalField "Name" .name resourceServerNameTypeCodec
        |> Codec.optionalField "Identifier" .identifier resourceServerIdentifierTypeCodec
        |> Codec.buildObject


{-| Codec for ResourceServerScopeType.
-}
resourceServerScopeTypeCodec : Codec ResourceServerScopeType
resourceServerScopeTypeCodec =
    Codec.object ResourceServerScopeType
        |> Codec.field "ScopeName" .scopeName resourceServerScopeNameTypeCodec
        |> Codec.field "ScopeDescription" .scopeDescription resourceServerScopeDescriptionTypeCodec
        |> Codec.buildObject


{-| Codec for ResourceServerScopeNameType.
-}
resourceServerScopeNameTypeCodec : Codec ResourceServerScopeNameType
resourceServerScopeNameTypeCodec =
    Codec.build (Refined.encoder resourceServerScopeNameType) (Refined.decoder resourceServerScopeNameType)


{-| Codec for ResourceServerScopeListType.
-}
resourceServerScopeListTypeCodec : Codec ResourceServerScopeListType
resourceServerScopeListTypeCodec =
    Codec.list resourceServerScopeTypeCodec


{-| Codec for ResourceServerScopeDescriptionType.
-}
resourceServerScopeDescriptionTypeCodec : Codec ResourceServerScopeDescriptionType
resourceServerScopeDescriptionTypeCodec =
    Codec.build
        (Refined.encoder resourceServerScopeDescriptionType)
        (Refined.decoder resourceServerScopeDescriptionType)


{-| Codec for ResourceServerNameType.
-}
resourceServerNameTypeCodec : Codec ResourceServerNameType
resourceServerNameTypeCodec =
    Codec.build (Refined.encoder resourceServerNameType) (Refined.decoder resourceServerNameType)


{-| Codec for ResourceServerIdentifierType.
-}
resourceServerIdentifierTypeCodec : Codec ResourceServerIdentifierType
resourceServerIdentifierTypeCodec =
    Codec.build (Refined.encoder resourceServerIdentifierType) (Refined.decoder resourceServerIdentifierType)


{-| Codec for ResendConfirmationCodeResponse.
-}
resendConfirmationCodeResponseCodec : Codec ResendConfirmationCodeResponse
resendConfirmationCodeResponseCodec =
    Codec.object ResendConfirmationCodeResponse
        |> Codec.optionalField "CodeDeliveryDetails" .codeDeliveryDetails codeDeliveryDetailsTypeCodec
        |> Codec.buildObject


{-| Codec for ResendConfirmationCodeRequest.
-}
resendConfirmationCodeRequestCodec : Codec ResendConfirmationCodeRequest
resendConfirmationCodeRequestCodec =
    Codec.object ResendConfirmationCodeRequest
        |> Codec.field "Username" .username usernameTypeCodec
        |> Codec.optionalField "UserContextData" .userContextData userContextDataTypeCodec
        |> Codec.optionalField "SecretHash" .secretHash secretHashTypeCodec
        |> Codec.field "ClientId" .clientId clientIdTypeCodec
        |> Codec.optionalField "AnalyticsMetadata" .analyticsMetadata analyticsMetadataTypeCodec
        |> Codec.buildObject


{-| Codec for RefreshTokenValidityType.
-}
refreshTokenValidityTypeCodec : Codec RefreshTokenValidityType
refreshTokenValidityTypeCodec =
    Codec.build (Refined.encoder refreshTokenValidityType) (Refined.decoder refreshTokenValidityType)


{-| Codec for RedirectUrlType.
-}
redirectUrlTypeCodec : Codec RedirectUrlType
redirectUrlTypeCodec =
    Codec.build (Refined.encoder redirectUrlType) (Refined.decoder redirectUrlType)


{-| Codec for QueryLimitType.
-}
queryLimitTypeCodec : Codec QueryLimitType
queryLimitTypeCodec =
    Codec.build (Refined.encoder queryLimitType) (Refined.decoder queryLimitType)


{-| Codec for QueryLimit.
-}
queryLimitCodec : Codec QueryLimit
queryLimitCodec =
    Codec.build (Refined.encoder queryLimit) (Refined.decoder queryLimit)


{-| Codec for ProvidersListType.
-}
providersListTypeCodec : Codec ProvidersListType
providersListTypeCodec =
    Codec.list providerDescriptionCodec


{-| Codec for ProviderUserIdentifierType.
-}
providerUserIdentifierTypeCodec : Codec ProviderUserIdentifierType
providerUserIdentifierTypeCodec =
    Codec.object ProviderUserIdentifierType
        |> Codec.optionalField "ProviderName" .providerName providerNameTypeCodec
        |> Codec.optionalField "ProviderAttributeValue" .providerAttributeValue Codec.string
        |> Codec.optionalField "ProviderAttributeName" .providerAttributeName Codec.string
        |> Codec.buildObject


{-| Codec for ProviderNameTypeV1.
-}
providerNameTypeV1Codec : Codec ProviderNameTypeV1
providerNameTypeV1Codec =
    Codec.build (Refined.encoder providerNameTypeV1) (Refined.decoder providerNameTypeV1)


{-| Codec for ProviderNameType.
-}
providerNameTypeCodec : Codec ProviderNameType
providerNameTypeCodec =
    Codec.build (Refined.encoder providerNameType) (Refined.decoder providerNameType)


{-| Codec for ProviderDetailsType.
-}
providerDetailsTypeCodec : Codec ProviderDetailsType
providerDetailsTypeCodec =
    Codec.dict Codec.string


{-| Codec for ProviderDescription.
-}
providerDescriptionCodec : Codec ProviderDescription
providerDescriptionCodec =
    Codec.object ProviderDescription
        |> Codec.optionalField "ProviderType" .providerType identityProviderTypeTypeCodec
        |> Codec.optionalField "ProviderName" .providerName providerNameTypeCodec
        |> Codec.optionalField "LastModifiedDate" .lastModifiedDate dateTypeCodec
        |> Codec.optionalField "CreationDate" .creationDate dateTypeCodec
        |> Codec.buildObject


{-| Codec for PrecedenceType.
-}
precedenceTypeCodec : Codec PrecedenceType
precedenceTypeCodec =
    Codec.build (Refined.encoder precedenceType) (Refined.decoder precedenceType)


{-| Codec for PreSignedUrlType.
-}
preSignedUrlTypeCodec : Codec PreSignedUrlType
preSignedUrlTypeCodec =
    Codec.build (Refined.encoder preSignedUrlType) (Refined.decoder preSignedUrlType)


{-| Codec for PoolQueryLimitType.
-}
poolQueryLimitTypeCodec : Codec PoolQueryLimitType
poolQueryLimitTypeCodec =
    Codec.build (Refined.encoder poolQueryLimitType) (Refined.decoder poolQueryLimitType)


{-| Codec for PasswordType.
-}
passwordTypeCodec : Codec PasswordType
passwordTypeCodec =
    Codec.build (Refined.encoder passwordType) (Refined.decoder passwordType)


{-| Codec for PasswordPolicyType.
-}
passwordPolicyTypeCodec : Codec PasswordPolicyType
passwordPolicyTypeCodec =
    Codec.object PasswordPolicyType
        |> Codec.optionalField
            "TemporaryPasswordValidityDays"
            .temporaryPasswordValidityDays
            temporaryPasswordValidityDaysTypeCodec
        |> Codec.optionalField "RequireUppercase" .requireUppercase Codec.bool
        |> Codec.optionalField "RequireSymbols" .requireSymbols Codec.bool
        |> Codec.optionalField "RequireNumbers" .requireNumbers Codec.bool
        |> Codec.optionalField "RequireLowercase" .requireLowercase Codec.bool
        |> Codec.optionalField "MinimumLength" .minimumLength passwordPolicyMinLengthTypeCodec
        |> Codec.buildObject


{-| Codec for PasswordPolicyMinLengthType.
-}
passwordPolicyMinLengthTypeCodec : Codec PasswordPolicyMinLengthType
passwordPolicyMinLengthTypeCodec =
    Codec.build (Refined.encoder passwordPolicyMinLengthType) (Refined.decoder passwordPolicyMinLengthType)


{-| Codec for PaginationKeyType.
-}
paginationKeyTypeCodec : Codec PaginationKeyType
paginationKeyTypeCodec =
    Codec.build (Refined.encoder paginationKeyType) (Refined.decoder paginationKeyType)


{-| Codec for PaginationKey.
-}
paginationKeyCodec : Codec PaginationKey
paginationKeyCodec =
    Codec.build (Refined.encoder paginationKey) (Refined.decoder paginationKey)


{-| Codec for OauthFlowsType.
-}
oauthFlowsTypeCodec : Codec OauthFlowsType
oauthFlowsTypeCodec =
    Codec.list oauthFlowTypeCodec


{-| Codec for OauthFlowType.
-}
oauthFlowTypeCodec : Codec OauthFlowType
oauthFlowTypeCodec =
    Codec.build (Enum.encoder oauthFlowType) (Enum.decoder oauthFlowType)


{-| Codec for NumberAttributeConstraintsType.
-}
numberAttributeConstraintsTypeCodec : Codec NumberAttributeConstraintsType
numberAttributeConstraintsTypeCodec =
    Codec.object NumberAttributeConstraintsType
        |> Codec.optionalField "MinValue" .minValue Codec.string
        |> Codec.optionalField "MaxValue" .maxValue Codec.string
        |> Codec.buildObject


{-| Codec for NotifyEmailType.
-}
notifyEmailTypeCodec : Codec NotifyEmailType
notifyEmailTypeCodec =
    Codec.object NotifyEmailType
        |> Codec.optionalField "TextBody" .textBody emailNotificationBodyTypeCodec
        |> Codec.field "Subject" .subject emailNotificationSubjectTypeCodec
        |> Codec.optionalField "HtmlBody" .htmlBody emailNotificationBodyTypeCodec
        |> Codec.buildObject


{-| Codec for NotifyConfigurationType.
-}
notifyConfigurationTypeCodec : Codec NotifyConfigurationType
notifyConfigurationTypeCodec =
    Codec.object NotifyConfigurationType
        |> Codec.field "SourceArn" .sourceArn arnTypeCodec
        |> Codec.optionalField "ReplyTo" .replyTo Codec.string
        |> Codec.optionalField "NoActionEmail" .noActionEmail notifyEmailTypeCodec
        |> Codec.optionalField "MfaEmail" .mfaEmail notifyEmailTypeCodec
        |> Codec.optionalField "From" .from Codec.string
        |> Codec.optionalField "BlockEmail" .blockEmail notifyEmailTypeCodec
        |> Codec.buildObject


{-| Codec for NewDeviceMetadataType.
-}
newDeviceMetadataTypeCodec : Codec NewDeviceMetadataType
newDeviceMetadataTypeCodec =
    Codec.object NewDeviceMetadataType
        |> Codec.optionalField "DeviceKey" .deviceKey deviceKeyTypeCodec
        |> Codec.optionalField "DeviceGroupKey" .deviceGroupKey Codec.string
        |> Codec.buildObject


{-| Codec for MessageTemplateType.
-}
messageTemplateTypeCodec : Codec MessageTemplateType
messageTemplateTypeCodec =
    Codec.object MessageTemplateType
        |> Codec.optionalField "SMSMessage" .smsmessage smsVerificationMessageTypeCodec
        |> Codec.optionalField "EmailSubject" .emailSubject emailVerificationSubjectTypeCodec
        |> Codec.optionalField "EmailMessage" .emailMessage emailVerificationMessageTypeCodec
        |> Codec.buildObject


{-| Codec for MessageActionType.
-}
messageActionTypeCodec : Codec MessageActionType
messageActionTypeCodec =
    Codec.build (Enum.encoder messageActionType) (Enum.decoder messageActionType)


{-| Codec for MfaoptionType.
-}
mfaoptionTypeCodec : Codec MfaoptionType
mfaoptionTypeCodec =
    Codec.object MfaoptionType
        |> Codec.optionalField "DeliveryMedium" .deliveryMedium deliveryMediumTypeCodec
        |> Codec.optionalField "AttributeName" .attributeName attributeNameTypeCodec
        |> Codec.buildObject


{-| Codec for MfaoptionListType.
-}
mfaoptionListTypeCodec : Codec MfaoptionListType
mfaoptionListTypeCodec =
    Codec.list mfaoptionTypeCodec


{-| Codec for LongType.
-}
longTypeCodec : Codec LongType
longTypeCodec =
    Codec.int


{-| Codec for LogoutUrlsListType.
-}
logoutUrlsListTypeCodec : Codec LogoutUrlsListType
logoutUrlsListTypeCodec =
    Codec.list redirectUrlTypeCodec


{-| Codec for ListUsersResponse.
-}
listUsersResponseCodec : Codec ListUsersResponse
listUsersResponseCodec =
    Codec.object ListUsersResponse
        |> Codec.optionalField "Users" .users usersListTypeCodec
        |> Codec.optionalField "PaginationToken" .paginationToken searchPaginationTokenTypeCodec
        |> Codec.buildObject


{-| Codec for ListUsersRequest.
-}
listUsersRequestCodec : Codec ListUsersRequest
listUsersRequestCodec =
    Codec.object ListUsersRequest
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.optionalField "PaginationToken" .paginationToken searchPaginationTokenTypeCodec
        |> Codec.optionalField "Limit" .limit queryLimitTypeCodec
        |> Codec.optionalField "Filter" .filter userFilterTypeCodec
        |> Codec.optionalField "AttributesToGet" .attributesToGet searchedAttributeNamesListTypeCodec
        |> Codec.buildObject


{-| Codec for ListUsersInGroupResponse.
-}
listUsersInGroupResponseCodec : Codec ListUsersInGroupResponse
listUsersInGroupResponseCodec =
    Codec.object ListUsersInGroupResponse
        |> Codec.optionalField "Users" .users usersListTypeCodec
        |> Codec.optionalField "NextToken" .nextToken paginationKeyCodec
        |> Codec.buildObject


{-| Codec for ListUsersInGroupRequest.
-}
listUsersInGroupRequestCodec : Codec ListUsersInGroupRequest
listUsersInGroupRequestCodec =
    Codec.object ListUsersInGroupRequest
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.optionalField "NextToken" .nextToken paginationKeyCodec
        |> Codec.optionalField "Limit" .limit queryLimitTypeCodec
        |> Codec.field "GroupName" .groupName groupNameTypeCodec
        |> Codec.buildObject


{-| Codec for ListUserPoolsResponse.
-}
listUserPoolsResponseCodec : Codec ListUserPoolsResponse
listUserPoolsResponseCodec =
    Codec.object ListUserPoolsResponse
        |> Codec.optionalField "UserPools" .userPools userPoolListTypeCodec
        |> Codec.optionalField "NextToken" .nextToken paginationKeyTypeCodec
        |> Codec.buildObject


{-| Codec for ListUserPoolsRequest.
-}
listUserPoolsRequestCodec : Codec ListUserPoolsRequest
listUserPoolsRequestCodec =
    Codec.object ListUserPoolsRequest
        |> Codec.optionalField "NextToken" .nextToken paginationKeyTypeCodec
        |> Codec.field "MaxResults" .maxResults poolQueryLimitTypeCodec
        |> Codec.buildObject


{-| Codec for ListUserPoolClientsResponse.
-}
listUserPoolClientsResponseCodec : Codec ListUserPoolClientsResponse
listUserPoolClientsResponseCodec =
    Codec.object ListUserPoolClientsResponse
        |> Codec.optionalField "UserPoolClients" .userPoolClients userPoolClientListTypeCodec
        |> Codec.optionalField "NextToken" .nextToken paginationKeyCodec
        |> Codec.buildObject


{-| Codec for ListUserPoolClientsRequest.
-}
listUserPoolClientsRequestCodec : Codec ListUserPoolClientsRequest
listUserPoolClientsRequestCodec =
    Codec.object ListUserPoolClientsRequest
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.optionalField "NextToken" .nextToken paginationKeyCodec
        |> Codec.optionalField "MaxResults" .maxResults queryLimitCodec
        |> Codec.buildObject


{-| Codec for ListUserImportJobsResponse.
-}
listUserImportJobsResponseCodec : Codec ListUserImportJobsResponse
listUserImportJobsResponseCodec =
    Codec.object ListUserImportJobsResponse
        |> Codec.optionalField "UserImportJobs" .userImportJobs userImportJobsListTypeCodec
        |> Codec.optionalField "PaginationToken" .paginationToken paginationKeyTypeCodec
        |> Codec.buildObject


{-| Codec for ListUserImportJobsRequest.
-}
listUserImportJobsRequestCodec : Codec ListUserImportJobsRequest
listUserImportJobsRequestCodec =
    Codec.object ListUserImportJobsRequest
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.optionalField "PaginationToken" .paginationToken paginationKeyTypeCodec
        |> Codec.field "MaxResults" .maxResults poolQueryLimitTypeCodec
        |> Codec.buildObject


{-| Codec for ListTagsForResourceResponse.
-}
listTagsForResourceResponseCodec : Codec ListTagsForResourceResponse
listTagsForResourceResponseCodec =
    Codec.object ListTagsForResourceResponse
        |> Codec.optionalField "Tags" .tags userPoolTagsTypeCodec
        |> Codec.buildObject


{-| Codec for ListTagsForResourceRequest.
-}
listTagsForResourceRequestCodec : Codec ListTagsForResourceRequest
listTagsForResourceRequestCodec =
    Codec.object ListTagsForResourceRequest |> Codec.field "ResourceArn" .resourceArn arnTypeCodec |> Codec.buildObject


{-| Codec for ListResourceServersResponse.
-}
listResourceServersResponseCodec : Codec ListResourceServersResponse
listResourceServersResponseCodec =
    Codec.object ListResourceServersResponse
        |> Codec.field "ResourceServers" .resourceServers resourceServersListTypeCodec
        |> Codec.optionalField "NextToken" .nextToken paginationKeyTypeCodec
        |> Codec.buildObject


{-| Codec for ListResourceServersRequest.
-}
listResourceServersRequestCodec : Codec ListResourceServersRequest
listResourceServersRequestCodec =
    Codec.object ListResourceServersRequest
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.optionalField "NextToken" .nextToken paginationKeyTypeCodec
        |> Codec.optionalField "MaxResults" .maxResults listResourceServersLimitTypeCodec
        |> Codec.buildObject


{-| Codec for ListResourceServersLimitType.
-}
listResourceServersLimitTypeCodec : Codec ListResourceServersLimitType
listResourceServersLimitTypeCodec =
    Codec.build (Refined.encoder listResourceServersLimitType) (Refined.decoder listResourceServersLimitType)


{-| Codec for ListProvidersLimitType.
-}
listProvidersLimitTypeCodec : Codec ListProvidersLimitType
listProvidersLimitTypeCodec =
    Codec.build (Refined.encoder listProvidersLimitType) (Refined.decoder listProvidersLimitType)


{-| Codec for ListOfStringTypes.
-}
listOfStringTypesCodec : Codec ListOfStringTypes
listOfStringTypesCodec =
    Codec.list Codec.string


{-| Codec for ListIdentityProvidersResponse.
-}
listIdentityProvidersResponseCodec : Codec ListIdentityProvidersResponse
listIdentityProvidersResponseCodec =
    Codec.object ListIdentityProvidersResponse
        |> Codec.field "Providers" .providers providersListTypeCodec
        |> Codec.optionalField "NextToken" .nextToken paginationKeyTypeCodec
        |> Codec.buildObject


{-| Codec for ListIdentityProvidersRequest.
-}
listIdentityProvidersRequestCodec : Codec ListIdentityProvidersRequest
listIdentityProvidersRequestCodec =
    Codec.object ListIdentityProvidersRequest
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.optionalField "NextToken" .nextToken paginationKeyTypeCodec
        |> Codec.optionalField "MaxResults" .maxResults listProvidersLimitTypeCodec
        |> Codec.buildObject


{-| Codec for ListGroupsResponse.
-}
listGroupsResponseCodec : Codec ListGroupsResponse
listGroupsResponseCodec =
    Codec.object ListGroupsResponse
        |> Codec.optionalField "NextToken" .nextToken paginationKeyCodec
        |> Codec.optionalField "Groups" .groups groupListTypeCodec
        |> Codec.buildObject


{-| Codec for ListGroupsRequest.
-}
listGroupsRequestCodec : Codec ListGroupsRequest
listGroupsRequestCodec =
    Codec.object ListGroupsRequest
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.optionalField "NextToken" .nextToken paginationKeyCodec
        |> Codec.optionalField "Limit" .limit queryLimitTypeCodec
        |> Codec.buildObject


{-| Codec for ListDevicesResponse.
-}
listDevicesResponseCodec : Codec ListDevicesResponse
listDevicesResponseCodec =
    Codec.object ListDevicesResponse
        |> Codec.optionalField "PaginationToken" .paginationToken searchPaginationTokenTypeCodec
        |> Codec.optionalField "Devices" .devices deviceListTypeCodec
        |> Codec.buildObject


{-| Codec for ListDevicesRequest.
-}
listDevicesRequestCodec : Codec ListDevicesRequest
listDevicesRequestCodec =
    Codec.object ListDevicesRequest
        |> Codec.optionalField "PaginationToken" .paginationToken searchPaginationTokenTypeCodec
        |> Codec.optionalField "Limit" .limit queryLimitTypeCodec
        |> Codec.field "AccessToken" .accessToken tokenModelTypeCodec
        |> Codec.buildObject


{-| Codec for LambdaConfigType.
-}
lambdaConfigTypeCodec : Codec LambdaConfigType
lambdaConfigTypeCodec =
    Codec.object LambdaConfigType
        |> Codec.optionalField "VerifyAuthChallengeResponse" .verifyAuthChallengeResponse arnTypeCodec
        |> Codec.optionalField "UserMigration" .userMigration arnTypeCodec
        |> Codec.optionalField "PreTokenGeneration" .preTokenGeneration arnTypeCodec
        |> Codec.optionalField "PreSignUp" .preSignUp arnTypeCodec
        |> Codec.optionalField "PreAuthentication" .preAuthentication arnTypeCodec
        |> Codec.optionalField "PostConfirmation" .postConfirmation arnTypeCodec
        |> Codec.optionalField "PostAuthentication" .postAuthentication arnTypeCodec
        |> Codec.optionalField "DefineAuthChallenge" .defineAuthChallenge arnTypeCodec
        |> Codec.optionalField "CustomMessage" .customMessage arnTypeCodec
        |> Codec.optionalField "CreateAuthChallenge" .createAuthChallenge arnTypeCodec
        |> Codec.buildObject


{-| Codec for IntegerType.
-}
integerTypeCodec : Codec IntegerType
integerTypeCodec =
    Codec.int


{-| Codec for InitiateAuthResponse.
-}
initiateAuthResponseCodec : Codec InitiateAuthResponse
initiateAuthResponseCodec =
    Codec.object InitiateAuthResponse
        |> Codec.optionalField "Session" .session sessionTypeCodec
        |> Codec.optionalField "ChallengeParameters" .challengeParameters challengeParametersTypeCodec
        |> Codec.optionalField "ChallengeName" .challengeName challengeNameTypeCodec
        |> Codec.optionalField "AuthenticationResult" .authenticationResult authenticationResultTypeCodec
        |> Codec.buildObject


{-| Codec for InitiateAuthRequest.
-}
initiateAuthRequestCodec : Codec InitiateAuthRequest
initiateAuthRequestCodec =
    Codec.object InitiateAuthRequest
        |> Codec.optionalField "UserContextData" .userContextData userContextDataTypeCodec
        |> Codec.optionalField "ClientMetadata" .clientMetadata clientMetadataTypeCodec
        |> Codec.field "ClientId" .clientId clientIdTypeCodec
        |> Codec.optionalField "AuthParameters" .authParameters authParametersTypeCodec
        |> Codec.field "AuthFlow" .authFlow authFlowTypeCodec
        |> Codec.optionalField "AnalyticsMetadata" .analyticsMetadata analyticsMetadataTypeCodec
        |> Codec.buildObject


{-| Codec for ImageUrlType.
-}
imageUrlTypeCodec : Codec ImageUrlType
imageUrlTypeCodec =
    Codec.string


{-| Codec for ImageFileType.
-}
imageFileTypeCodec : Codec ImageFileType
imageFileTypeCodec =
    Codec.string


{-| Codec for IdpIdentifiersListType.
-}
idpIdentifiersListTypeCodec : Codec IdpIdentifiersListType
idpIdentifiersListTypeCodec =
    Codec.list idpIdentifierTypeCodec


{-| Codec for IdpIdentifierType.
-}
idpIdentifierTypeCodec : Codec IdpIdentifierType
idpIdentifierTypeCodec =
    Codec.build (Refined.encoder idpIdentifierType) (Refined.decoder idpIdentifierType)


{-| Codec for IdentityProviderTypeType.
-}
identityProviderTypeTypeCodec : Codec IdentityProviderTypeType
identityProviderTypeTypeCodec =
    Codec.build (Enum.encoder identityProviderTypeType) (Enum.decoder identityProviderTypeType)


{-| Codec for IdentityProviderType.
-}
identityProviderTypeCodec : Codec IdentityProviderType
identityProviderTypeCodec =
    Codec.object IdentityProviderType
        |> Codec.optionalField "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.optionalField "ProviderType" .providerType identityProviderTypeTypeCodec
        |> Codec.optionalField "ProviderName" .providerName providerNameTypeCodec
        |> Codec.optionalField "ProviderDetails" .providerDetails providerDetailsTypeCodec
        |> Codec.optionalField "LastModifiedDate" .lastModifiedDate dateTypeCodec
        |> Codec.optionalField "IdpIdentifiers" .idpIdentifiers idpIdentifiersListTypeCodec
        |> Codec.optionalField "CreationDate" .creationDate dateTypeCodec
        |> Codec.optionalField "AttributeMapping" .attributeMapping attributeMappingTypeCodec
        |> Codec.buildObject


{-| Codec for HttpHeaderList.
-}
httpHeaderListCodec : Codec HttpHeaderList
httpHeaderListCodec =
    Codec.list httpHeaderCodec


{-| Codec for HttpHeader.
-}
httpHeaderCodec : Codec HttpHeader
httpHeaderCodec =
    Codec.object HttpHeader
        |> Codec.optionalField "headerValue" .headerValue Codec.string
        |> Codec.optionalField "headerName" .headerName Codec.string
        |> Codec.buildObject


{-| Codec for HexStringType.
-}
hexStringTypeCodec : Codec HexStringType
hexStringTypeCodec =
    Codec.build (Refined.encoder hexStringType) (Refined.decoder hexStringType)


{-| Codec for GroupType.
-}
groupTypeCodec : Codec GroupType
groupTypeCodec =
    Codec.object GroupType
        |> Codec.optionalField "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.optionalField "RoleArn" .roleArn arnTypeCodec
        |> Codec.optionalField "Precedence" .precedence precedenceTypeCodec
        |> Codec.optionalField "LastModifiedDate" .lastModifiedDate dateTypeCodec
        |> Codec.optionalField "GroupName" .groupName groupNameTypeCodec
        |> Codec.optionalField "Description" .description descriptionTypeCodec
        |> Codec.optionalField "CreationDate" .creationDate dateTypeCodec
        |> Codec.buildObject


{-| Codec for GroupNameType.
-}
groupNameTypeCodec : Codec GroupNameType
groupNameTypeCodec =
    Codec.build (Refined.encoder groupNameType) (Refined.decoder groupNameType)


{-| Codec for GroupListType.
-}
groupListTypeCodec : Codec GroupListType
groupListTypeCodec =
    Codec.list groupTypeCodec


{-| Codec for GlobalSignOutResponse.
-}
globalSignOutResponseCodec : Codec GlobalSignOutResponse
globalSignOutResponseCodec =
    Codec.object GlobalSignOutResponse |> Codec.buildObject


{-| Codec for GlobalSignOutRequest.
-}
globalSignOutRequestCodec : Codec GlobalSignOutRequest
globalSignOutRequestCodec =
    Codec.object GlobalSignOutRequest |> Codec.field "AccessToken" .accessToken tokenModelTypeCodec |> Codec.buildObject


{-| Codec for GetUserResponse.
-}
getUserResponseCodec : Codec GetUserResponse
getUserResponseCodec =
    Codec.object GetUserResponse
        |> Codec.field "Username" .username usernameTypeCodec
        |> Codec.optionalField "UserMFASettingList" .userMfasettingList userMfasettingListTypeCodec
        |> Codec.field "UserAttributes" .userAttributes attributeListTypeCodec
        |> Codec.optionalField "PreferredMfaSetting" .preferredMfaSetting Codec.string
        |> Codec.optionalField "MFAOptions" .mfaoptions mfaoptionListTypeCodec
        |> Codec.buildObject


{-| Codec for GetUserRequest.
-}
getUserRequestCodec : Codec GetUserRequest
getUserRequestCodec =
    Codec.object GetUserRequest |> Codec.field "AccessToken" .accessToken tokenModelTypeCodec |> Codec.buildObject


{-| Codec for GetUserPoolMfaConfigResponse.
-}
getUserPoolMfaConfigResponseCodec : Codec GetUserPoolMfaConfigResponse
getUserPoolMfaConfigResponseCodec =
    Codec.object GetUserPoolMfaConfigResponse
        |> Codec.optionalField
            "SoftwareTokenMfaConfiguration"
            .softwareTokenMfaConfiguration
            softwareTokenMfaConfigTypeCodec
        |> Codec.optionalField "SmsMfaConfiguration" .smsMfaConfiguration smsMfaConfigTypeCodec
        |> Codec.optionalField "MfaConfiguration" .mfaConfiguration userPoolMfaTypeCodec
        |> Codec.buildObject


{-| Codec for GetUserPoolMfaConfigRequest.
-}
getUserPoolMfaConfigRequestCodec : Codec GetUserPoolMfaConfigRequest
getUserPoolMfaConfigRequestCodec =
    Codec.object GetUserPoolMfaConfigRequest
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.buildObject


{-| Codec for GetUserAttributeVerificationCodeResponse.
-}
getUserAttributeVerificationCodeResponseCodec : Codec GetUserAttributeVerificationCodeResponse
getUserAttributeVerificationCodeResponseCodec =
    Codec.object GetUserAttributeVerificationCodeResponse
        |> Codec.optionalField "CodeDeliveryDetails" .codeDeliveryDetails codeDeliveryDetailsTypeCodec
        |> Codec.buildObject


{-| Codec for GetUserAttributeVerificationCodeRequest.
-}
getUserAttributeVerificationCodeRequestCodec : Codec GetUserAttributeVerificationCodeRequest
getUserAttributeVerificationCodeRequestCodec =
    Codec.object GetUserAttributeVerificationCodeRequest
        |> Codec.field "AttributeName" .attributeName attributeNameTypeCodec
        |> Codec.field "AccessToken" .accessToken tokenModelTypeCodec
        |> Codec.buildObject


{-| Codec for GetUicustomizationResponse.
-}
getUicustomizationResponseCodec : Codec GetUicustomizationResponse
getUicustomizationResponseCodec =
    Codec.object GetUicustomizationResponse
        |> Codec.field "UICustomization" .uicustomization uicustomizationTypeCodec
        |> Codec.buildObject


{-| Codec for GetUicustomizationRequest.
-}
getUicustomizationRequestCodec : Codec GetUicustomizationRequest
getUicustomizationRequestCodec =
    Codec.object GetUicustomizationRequest
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.optionalField "ClientId" .clientId clientIdTypeCodec
        |> Codec.buildObject


{-| Codec for GetSigningCertificateResponse.
-}
getSigningCertificateResponseCodec : Codec GetSigningCertificateResponse
getSigningCertificateResponseCodec =
    Codec.object GetSigningCertificateResponse
        |> Codec.optionalField "Certificate" .certificate Codec.string
        |> Codec.buildObject


{-| Codec for GetSigningCertificateRequest.
-}
getSigningCertificateRequestCodec : Codec GetSigningCertificateRequest
getSigningCertificateRequestCodec =
    Codec.object GetSigningCertificateRequest
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.buildObject


{-| Codec for GetIdentityProviderByIdentifierResponse.
-}
getIdentityProviderByIdentifierResponseCodec : Codec GetIdentityProviderByIdentifierResponse
getIdentityProviderByIdentifierResponseCodec =
    Codec.object GetIdentityProviderByIdentifierResponse
        |> Codec.field "IdentityProvider" .identityProvider identityProviderTypeCodec
        |> Codec.buildObject


{-| Codec for GetIdentityProviderByIdentifierRequest.
-}
getIdentityProviderByIdentifierRequestCodec : Codec GetIdentityProviderByIdentifierRequest
getIdentityProviderByIdentifierRequestCodec =
    Codec.object GetIdentityProviderByIdentifierRequest
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "IdpIdentifier" .idpIdentifier idpIdentifierTypeCodec
        |> Codec.buildObject


{-| Codec for GetGroupResponse.
-}
getGroupResponseCodec : Codec GetGroupResponse
getGroupResponseCodec =
    Codec.object GetGroupResponse |> Codec.optionalField "Group" .group groupTypeCodec |> Codec.buildObject


{-| Codec for GetGroupRequest.
-}
getGroupRequestCodec : Codec GetGroupRequest
getGroupRequestCodec =
    Codec.object GetGroupRequest
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "GroupName" .groupName groupNameTypeCodec
        |> Codec.buildObject


{-| Codec for GetDeviceResponse.
-}
getDeviceResponseCodec : Codec GetDeviceResponse
getDeviceResponseCodec =
    Codec.object GetDeviceResponse |> Codec.field "Device" .device deviceTypeCodec |> Codec.buildObject


{-| Codec for GetDeviceRequest.
-}
getDeviceRequestCodec : Codec GetDeviceRequest
getDeviceRequestCodec =
    Codec.object GetDeviceRequest
        |> Codec.field "DeviceKey" .deviceKey deviceKeyTypeCodec
        |> Codec.optionalField "AccessToken" .accessToken tokenModelTypeCodec
        |> Codec.buildObject


{-| Codec for GetCsvheaderResponse.
-}
getCsvheaderResponseCodec : Codec GetCsvheaderResponse
getCsvheaderResponseCodec =
    Codec.object GetCsvheaderResponse
        |> Codec.optionalField "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.optionalField "CSVHeader" .csvheader listOfStringTypesCodec
        |> Codec.buildObject


{-| Codec for GetCsvheaderRequest.
-}
getCsvheaderRequestCodec : Codec GetCsvheaderRequest
getCsvheaderRequestCodec =
    Codec.object GetCsvheaderRequest |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec |> Codec.buildObject


{-| Codec for GenerateSecret.
-}
generateSecretCodec : Codec GenerateSecret
generateSecretCodec =
    Codec.bool


{-| Codec for ForgotPasswordResponse.
-}
forgotPasswordResponseCodec : Codec ForgotPasswordResponse
forgotPasswordResponseCodec =
    Codec.object ForgotPasswordResponse
        |> Codec.optionalField "CodeDeliveryDetails" .codeDeliveryDetails codeDeliveryDetailsTypeCodec
        |> Codec.buildObject


{-| Codec for ForgotPasswordRequest.
-}
forgotPasswordRequestCodec : Codec ForgotPasswordRequest
forgotPasswordRequestCodec =
    Codec.object ForgotPasswordRequest
        |> Codec.field "Username" .username usernameTypeCodec
        |> Codec.optionalField "UserContextData" .userContextData userContextDataTypeCodec
        |> Codec.optionalField "SecretHash" .secretHash secretHashTypeCodec
        |> Codec.field "ClientId" .clientId clientIdTypeCodec
        |> Codec.optionalField "AnalyticsMetadata" .analyticsMetadata analyticsMetadataTypeCodec
        |> Codec.buildObject


{-| Codec for ForgetDeviceRequest.
-}
forgetDeviceRequestCodec : Codec ForgetDeviceRequest
forgetDeviceRequestCodec =
    Codec.object ForgetDeviceRequest
        |> Codec.field "DeviceKey" .deviceKey deviceKeyTypeCodec
        |> Codec.optionalField "AccessToken" .accessToken tokenModelTypeCodec
        |> Codec.buildObject


{-| Codec for ForceAliasCreation.
-}
forceAliasCreationCodec : Codec ForceAliasCreation
forceAliasCreationCodec =
    Codec.bool


{-| Codec for FeedbackValueType.
-}
feedbackValueTypeCodec : Codec FeedbackValueType
feedbackValueTypeCodec =
    Codec.build (Enum.encoder feedbackValueType) (Enum.decoder feedbackValueType)


{-| Codec for ExplicitAuthFlowsType.
-}
explicitAuthFlowsTypeCodec : Codec ExplicitAuthFlowsType
explicitAuthFlowsTypeCodec =
    Codec.build (Enum.encoder explicitAuthFlowsType) (Enum.decoder explicitAuthFlowsType)


{-| Codec for ExplicitAuthFlowsListType.
-}
explicitAuthFlowsListTypeCodec : Codec ExplicitAuthFlowsListType
explicitAuthFlowsListTypeCodec =
    Codec.list explicitAuthFlowsTypeCodec


{-| Codec for EventType.
-}
eventTypeCodec : Codec EventType
eventTypeCodec =
    Codec.build (Enum.encoder eventType) (Enum.decoder eventType)


{-| Codec for EventRiskType.
-}
eventRiskTypeCodec : Codec EventRiskType
eventRiskTypeCodec =
    Codec.object EventRiskType
        |> Codec.optionalField "RiskLevel" .riskLevel riskLevelTypeCodec
        |> Codec.optionalField "RiskDecision" .riskDecision riskDecisionTypeCodec
        |> Codec.buildObject


{-| Codec for EventResponseType.
-}
eventResponseTypeCodec : Codec EventResponseType
eventResponseTypeCodec =
    Codec.build (Enum.encoder eventResponseType) (Enum.decoder eventResponseType)


{-| Codec for EventIdType.
-}
eventIdTypeCodec : Codec EventIdType
eventIdTypeCodec =
    Codec.build (Refined.encoder eventIdType) (Refined.decoder eventIdType)


{-| Codec for EventFiltersType.
-}
eventFiltersTypeCodec : Codec EventFiltersType
eventFiltersTypeCodec =
    Codec.list eventFilterTypeCodec


{-| Codec for EventFilterType.
-}
eventFilterTypeCodec : Codec EventFilterType
eventFilterTypeCodec =
    Codec.build (Enum.encoder eventFilterType) (Enum.decoder eventFilterType)


{-| Codec for EventFeedbackType.
-}
eventFeedbackTypeCodec : Codec EventFeedbackType
eventFeedbackTypeCodec =
    Codec.object EventFeedbackType
        |> Codec.field "Provider" .provider Codec.string
        |> Codec.field "FeedbackValue" .feedbackValue feedbackValueTypeCodec
        |> Codec.optionalField "FeedbackDate" .feedbackDate dateTypeCodec
        |> Codec.buildObject


{-| Codec for EventContextDataType.
-}
eventContextDataTypeCodec : Codec EventContextDataType
eventContextDataTypeCodec =
    Codec.object EventContextDataType
        |> Codec.optionalField "Timezone" .timezone Codec.string
        |> Codec.optionalField "IpAddress" .ipAddress Codec.string
        |> Codec.optionalField "DeviceName" .deviceName Codec.string
        |> Codec.optionalField "Country" .country Codec.string
        |> Codec.optionalField "City" .city Codec.string
        |> Codec.buildObject


{-| Codec for EmailVerificationSubjectType.
-}
emailVerificationSubjectTypeCodec : Codec EmailVerificationSubjectType
emailVerificationSubjectTypeCodec =
    Codec.build (Refined.encoder emailVerificationSubjectType) (Refined.decoder emailVerificationSubjectType)


{-| Codec for EmailVerificationSubjectByLinkType.
-}
emailVerificationSubjectByLinkTypeCodec : Codec EmailVerificationSubjectByLinkType
emailVerificationSubjectByLinkTypeCodec =
    Codec.build
        (Refined.encoder emailVerificationSubjectByLinkType)
        (Refined.decoder emailVerificationSubjectByLinkType)


{-| Codec for EmailVerificationMessageType.
-}
emailVerificationMessageTypeCodec : Codec EmailVerificationMessageType
emailVerificationMessageTypeCodec =
    Codec.build (Refined.encoder emailVerificationMessageType) (Refined.decoder emailVerificationMessageType)


{-| Codec for EmailVerificationMessageByLinkType.
-}
emailVerificationMessageByLinkTypeCodec : Codec EmailVerificationMessageByLinkType
emailVerificationMessageByLinkTypeCodec =
    Codec.build
        (Refined.encoder emailVerificationMessageByLinkType)
        (Refined.decoder emailVerificationMessageByLinkType)


{-| Codec for EmailSendingAccountType.
-}
emailSendingAccountTypeCodec : Codec EmailSendingAccountType
emailSendingAccountTypeCodec =
    Codec.build (Enum.encoder emailSendingAccountType) (Enum.decoder emailSendingAccountType)


{-| Codec for EmailNotificationSubjectType.
-}
emailNotificationSubjectTypeCodec : Codec EmailNotificationSubjectType
emailNotificationSubjectTypeCodec =
    Codec.build (Refined.encoder emailNotificationSubjectType) (Refined.decoder emailNotificationSubjectType)


{-| Codec for EmailNotificationBodyType.
-}
emailNotificationBodyTypeCodec : Codec EmailNotificationBodyType
emailNotificationBodyTypeCodec =
    Codec.build (Refined.encoder emailNotificationBodyType) (Refined.decoder emailNotificationBodyType)


{-| Codec for EmailConfigurationType.
-}
emailConfigurationTypeCodec : Codec EmailConfigurationType
emailConfigurationTypeCodec =
    Codec.object EmailConfigurationType
        |> Codec.optionalField "SourceArn" .sourceArn arnTypeCodec
        |> Codec.optionalField "ReplyToEmailAddress" .replyToEmailAddress emailAddressTypeCodec
        |> Codec.optionalField "EmailSendingAccount" .emailSendingAccount emailSendingAccountTypeCodec
        |> Codec.buildObject


{-| Codec for EmailAddressType.
-}
emailAddressTypeCodec : Codec EmailAddressType
emailAddressTypeCodec =
    Codec.build (Refined.encoder emailAddressType) (Refined.decoder emailAddressType)


{-| Codec for DomainVersionType.
-}
domainVersionTypeCodec : Codec DomainVersionType
domainVersionTypeCodec =
    Codec.build (Refined.encoder domainVersionType) (Refined.decoder domainVersionType)


{-| Codec for DomainType.
-}
domainTypeCodec : Codec DomainType
domainTypeCodec =
    Codec.build (Refined.encoder domainType) (Refined.decoder domainType)


{-| Codec for DomainStatusType.
-}
domainStatusTypeCodec : Codec DomainStatusType
domainStatusTypeCodec =
    Codec.build (Enum.encoder domainStatusType) (Enum.decoder domainStatusType)


{-| Codec for DomainDescriptionType.
-}
domainDescriptionTypeCodec : Codec DomainDescriptionType
domainDescriptionTypeCodec =
    Codec.object DomainDescriptionType
        |> Codec.optionalField "Version" .version domainVersionTypeCodec
        |> Codec.optionalField "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.optionalField "Status" .status domainStatusTypeCodec
        |> Codec.optionalField "S3Bucket" .s3Bucket s3BucketTypeCodec
        |> Codec.optionalField "Domain" .domain domainTypeCodec
        |> Codec.optionalField "CustomDomainConfig" .customDomainConfig customDomainConfigTypeCodec
        |> Codec.optionalField "CloudFrontDistribution" .cloudFrontDistribution Codec.string
        |> Codec.optionalField "AWSAccountId" .awsaccountId Codec.string
        |> Codec.buildObject


{-| Codec for DeviceType.
-}
deviceTypeCodec : Codec DeviceType
deviceTypeCodec =
    Codec.object DeviceType
        |> Codec.optionalField "DeviceLastModifiedDate" .deviceLastModifiedDate dateTypeCodec
        |> Codec.optionalField "DeviceLastAuthenticatedDate" .deviceLastAuthenticatedDate dateTypeCodec
        |> Codec.optionalField "DeviceKey" .deviceKey deviceKeyTypeCodec
        |> Codec.optionalField "DeviceCreateDate" .deviceCreateDate dateTypeCodec
        |> Codec.optionalField "DeviceAttributes" .deviceAttributes attributeListTypeCodec
        |> Codec.buildObject


{-| Codec for DeviceSecretVerifierConfigType.
-}
deviceSecretVerifierConfigTypeCodec : Codec DeviceSecretVerifierConfigType
deviceSecretVerifierConfigTypeCodec =
    Codec.object DeviceSecretVerifierConfigType
        |> Codec.optionalField "Salt" .salt Codec.string
        |> Codec.optionalField "PasswordVerifier" .passwordVerifier Codec.string
        |> Codec.buildObject


{-| Codec for DeviceRememberedStatusType.
-}
deviceRememberedStatusTypeCodec : Codec DeviceRememberedStatusType
deviceRememberedStatusTypeCodec =
    Codec.build (Enum.encoder deviceRememberedStatusType) (Enum.decoder deviceRememberedStatusType)


{-| Codec for DeviceNameType.
-}
deviceNameTypeCodec : Codec DeviceNameType
deviceNameTypeCodec =
    Codec.build (Refined.encoder deviceNameType) (Refined.decoder deviceNameType)


{-| Codec for DeviceListType.
-}
deviceListTypeCodec : Codec DeviceListType
deviceListTypeCodec =
    Codec.list deviceTypeCodec


{-| Codec for DeviceKeyType.
-}
deviceKeyTypeCodec : Codec DeviceKeyType
deviceKeyTypeCodec =
    Codec.build (Refined.encoder deviceKeyType) (Refined.decoder deviceKeyType)


{-| Codec for DeviceConfigurationType.
-}
deviceConfigurationTypeCodec : Codec DeviceConfigurationType
deviceConfigurationTypeCodec =
    Codec.object DeviceConfigurationType
        |> Codec.optionalField "DeviceOnlyRememberedOnUserPrompt" .deviceOnlyRememberedOnUserPrompt Codec.bool
        |> Codec.optionalField "ChallengeRequiredOnNewDevice" .challengeRequiredOnNewDevice Codec.bool
        |> Codec.buildObject


{-| Codec for DescriptionType.
-}
descriptionTypeCodec : Codec DescriptionType
descriptionTypeCodec =
    Codec.build (Refined.encoder descriptionType) (Refined.decoder descriptionType)


{-| Codec for DescribeUserPoolResponse.
-}
describeUserPoolResponseCodec : Codec DescribeUserPoolResponse
describeUserPoolResponseCodec =
    Codec.object DescribeUserPoolResponse
        |> Codec.optionalField "UserPool" .userPool userPoolTypeCodec
        |> Codec.buildObject


{-| Codec for DescribeUserPoolRequest.
-}
describeUserPoolRequestCodec : Codec DescribeUserPoolRequest
describeUserPoolRequestCodec =
    Codec.object DescribeUserPoolRequest
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.buildObject


{-| Codec for DescribeUserPoolDomainResponse.
-}
describeUserPoolDomainResponseCodec : Codec DescribeUserPoolDomainResponse
describeUserPoolDomainResponseCodec =
    Codec.object DescribeUserPoolDomainResponse
        |> Codec.optionalField "DomainDescription" .domainDescription domainDescriptionTypeCodec
        |> Codec.buildObject


{-| Codec for DescribeUserPoolDomainRequest.
-}
describeUserPoolDomainRequestCodec : Codec DescribeUserPoolDomainRequest
describeUserPoolDomainRequestCodec =
    Codec.object DescribeUserPoolDomainRequest |> Codec.field "Domain" .domain domainTypeCodec |> Codec.buildObject


{-| Codec for DescribeUserPoolClientResponse.
-}
describeUserPoolClientResponseCodec : Codec DescribeUserPoolClientResponse
describeUserPoolClientResponseCodec =
    Codec.object DescribeUserPoolClientResponse
        |> Codec.optionalField "UserPoolClient" .userPoolClient userPoolClientTypeCodec
        |> Codec.buildObject


{-| Codec for DescribeUserPoolClientRequest.
-}
describeUserPoolClientRequestCodec : Codec DescribeUserPoolClientRequest
describeUserPoolClientRequestCodec =
    Codec.object DescribeUserPoolClientRequest
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "ClientId" .clientId clientIdTypeCodec
        |> Codec.buildObject


{-| Codec for DescribeUserImportJobResponse.
-}
describeUserImportJobResponseCodec : Codec DescribeUserImportJobResponse
describeUserImportJobResponseCodec =
    Codec.object DescribeUserImportJobResponse
        |> Codec.optionalField "UserImportJob" .userImportJob userImportJobTypeCodec
        |> Codec.buildObject


{-| Codec for DescribeUserImportJobRequest.
-}
describeUserImportJobRequestCodec : Codec DescribeUserImportJobRequest
describeUserImportJobRequestCodec =
    Codec.object DescribeUserImportJobRequest
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "JobId" .jobId userImportJobIdTypeCodec
        |> Codec.buildObject


{-| Codec for DescribeRiskConfigurationResponse.
-}
describeRiskConfigurationResponseCodec : Codec DescribeRiskConfigurationResponse
describeRiskConfigurationResponseCodec =
    Codec.object DescribeRiskConfigurationResponse
        |> Codec.field "RiskConfiguration" .riskConfiguration riskConfigurationTypeCodec
        |> Codec.buildObject


{-| Codec for DescribeRiskConfigurationRequest.
-}
describeRiskConfigurationRequestCodec : Codec DescribeRiskConfigurationRequest
describeRiskConfigurationRequestCodec =
    Codec.object DescribeRiskConfigurationRequest
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.optionalField "ClientId" .clientId clientIdTypeCodec
        |> Codec.buildObject


{-| Codec for DescribeResourceServerResponse.
-}
describeResourceServerResponseCodec : Codec DescribeResourceServerResponse
describeResourceServerResponseCodec =
    Codec.object DescribeResourceServerResponse
        |> Codec.field "ResourceServer" .resourceServer resourceServerTypeCodec
        |> Codec.buildObject


{-| Codec for DescribeResourceServerRequest.
-}
describeResourceServerRequestCodec : Codec DescribeResourceServerRequest
describeResourceServerRequestCodec =
    Codec.object DescribeResourceServerRequest
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "Identifier" .identifier resourceServerIdentifierTypeCodec
        |> Codec.buildObject


{-| Codec for DescribeIdentityProviderResponse.
-}
describeIdentityProviderResponseCodec : Codec DescribeIdentityProviderResponse
describeIdentityProviderResponseCodec =
    Codec.object DescribeIdentityProviderResponse
        |> Codec.field "IdentityProvider" .identityProvider identityProviderTypeCodec
        |> Codec.buildObject


{-| Codec for DescribeIdentityProviderRequest.
-}
describeIdentityProviderRequestCodec : Codec DescribeIdentityProviderRequest
describeIdentityProviderRequestCodec =
    Codec.object DescribeIdentityProviderRequest
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "ProviderName" .providerName providerNameTypeCodec
        |> Codec.buildObject


{-| Codec for DeliveryMediumType.
-}
deliveryMediumTypeCodec : Codec DeliveryMediumType
deliveryMediumTypeCodec =
    Codec.build (Enum.encoder deliveryMediumType) (Enum.decoder deliveryMediumType)


{-| Codec for DeliveryMediumListType.
-}
deliveryMediumListTypeCodec : Codec DeliveryMediumListType
deliveryMediumListTypeCodec =
    Codec.list deliveryMediumTypeCodec


{-| Codec for DeleteUserRequest.
-}
deleteUserRequestCodec : Codec DeleteUserRequest
deleteUserRequestCodec =
    Codec.object DeleteUserRequest |> Codec.field "AccessToken" .accessToken tokenModelTypeCodec |> Codec.buildObject


{-| Codec for DeleteUserPoolRequest.
-}
deleteUserPoolRequestCodec : Codec DeleteUserPoolRequest
deleteUserPoolRequestCodec =
    Codec.object DeleteUserPoolRequest |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec |> Codec.buildObject


{-| Codec for DeleteUserPoolDomainResponse.
-}
deleteUserPoolDomainResponseCodec : Codec DeleteUserPoolDomainResponse
deleteUserPoolDomainResponseCodec =
    Codec.object DeleteUserPoolDomainResponse |> Codec.buildObject


{-| Codec for DeleteUserPoolDomainRequest.
-}
deleteUserPoolDomainRequestCodec : Codec DeleteUserPoolDomainRequest
deleteUserPoolDomainRequestCodec =
    Codec.object DeleteUserPoolDomainRequest
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "Domain" .domain domainTypeCodec
        |> Codec.buildObject


{-| Codec for DeleteUserPoolClientRequest.
-}
deleteUserPoolClientRequestCodec : Codec DeleteUserPoolClientRequest
deleteUserPoolClientRequestCodec =
    Codec.object DeleteUserPoolClientRequest
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "ClientId" .clientId clientIdTypeCodec
        |> Codec.buildObject


{-| Codec for DeleteUserAttributesResponse.
-}
deleteUserAttributesResponseCodec : Codec DeleteUserAttributesResponse
deleteUserAttributesResponseCodec =
    Codec.object DeleteUserAttributesResponse |> Codec.buildObject


{-| Codec for DeleteUserAttributesRequest.
-}
deleteUserAttributesRequestCodec : Codec DeleteUserAttributesRequest
deleteUserAttributesRequestCodec =
    Codec.object DeleteUserAttributesRequest
        |> Codec.field "UserAttributeNames" .userAttributeNames attributeNameListTypeCodec
        |> Codec.field "AccessToken" .accessToken tokenModelTypeCodec
        |> Codec.buildObject


{-| Codec for DeleteResourceServerRequest.
-}
deleteResourceServerRequestCodec : Codec DeleteResourceServerRequest
deleteResourceServerRequestCodec =
    Codec.object DeleteResourceServerRequest
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "Identifier" .identifier resourceServerIdentifierTypeCodec
        |> Codec.buildObject


{-| Codec for DeleteIdentityProviderRequest.
-}
deleteIdentityProviderRequestCodec : Codec DeleteIdentityProviderRequest
deleteIdentityProviderRequestCodec =
    Codec.object DeleteIdentityProviderRequest
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "ProviderName" .providerName providerNameTypeCodec
        |> Codec.buildObject


{-| Codec for DeleteGroupRequest.
-}
deleteGroupRequestCodec : Codec DeleteGroupRequest
deleteGroupRequestCodec =
    Codec.object DeleteGroupRequest
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "GroupName" .groupName groupNameTypeCodec
        |> Codec.buildObject


{-| Codec for DefaultEmailOptionType.
-}
defaultEmailOptionTypeCodec : Codec DefaultEmailOptionType
defaultEmailOptionTypeCodec =
    Codec.build (Enum.encoder defaultEmailOptionType) (Enum.decoder defaultEmailOptionType)


{-| Codec for DateType.
-}
dateTypeCodec : Codec DateType
dateTypeCodec =
    Codec.string


{-| Codec for CustomDomainConfigType.
-}
customDomainConfigTypeCodec : Codec CustomDomainConfigType
customDomainConfigTypeCodec =
    Codec.object CustomDomainConfigType
        |> Codec.field "CertificateArn" .certificateArn arnTypeCodec
        |> Codec.buildObject


{-| Codec for CustomAttributesListType.
-}
customAttributesListTypeCodec : Codec CustomAttributesListType
customAttributesListTypeCodec =
    Codec.list schemaAttributeTypeCodec


{-| Codec for CustomAttributeNameType.
-}
customAttributeNameTypeCodec : Codec CustomAttributeNameType
customAttributeNameTypeCodec =
    Codec.build (Refined.encoder customAttributeNameType) (Refined.decoder customAttributeNameType)


{-| Codec for CreateUserPoolResponse.
-}
createUserPoolResponseCodec : Codec CreateUserPoolResponse
createUserPoolResponseCodec =
    Codec.object CreateUserPoolResponse
        |> Codec.optionalField "UserPool" .userPool userPoolTypeCodec
        |> Codec.buildObject


{-| Codec for CreateUserPoolRequest.
-}
createUserPoolRequestCodec : Codec CreateUserPoolRequest
createUserPoolRequestCodec =
    Codec.object CreateUserPoolRequest
        |> Codec.optionalField
            "VerificationMessageTemplate"
            .verificationMessageTemplate
            verificationMessageTemplateTypeCodec
        |> Codec.optionalField "UsernameAttributes" .usernameAttributes usernameAttributesListTypeCodec
        |> Codec.optionalField "UserPoolTags" .userPoolTags userPoolTagsTypeCodec
        |> Codec.optionalField "UserPoolAddOns" .userPoolAddOns userPoolAddOnsTypeCodec
        |> Codec.optionalField "SmsVerificationMessage" .smsVerificationMessage smsVerificationMessageTypeCodec
        |> Codec.optionalField "SmsConfiguration" .smsConfiguration smsConfigurationTypeCodec
        |> Codec.optionalField "SmsAuthenticationMessage" .smsAuthenticationMessage smsVerificationMessageTypeCodec
        |> Codec.optionalField "Schema" .schema schemaAttributesListTypeCodec
        |> Codec.field "PoolName" .poolName userPoolNameTypeCodec
        |> Codec.optionalField "Policies" .policies userPoolPolicyTypeCodec
        |> Codec.optionalField "MfaConfiguration" .mfaConfiguration userPoolMfaTypeCodec
        |> Codec.optionalField "LambdaConfig" .lambdaConfig lambdaConfigTypeCodec
        |> Codec.optionalField "EmailVerificationSubject" .emailVerificationSubject emailVerificationSubjectTypeCodec
        |> Codec.optionalField "EmailVerificationMessage" .emailVerificationMessage emailVerificationMessageTypeCodec
        |> Codec.optionalField "EmailConfiguration" .emailConfiguration emailConfigurationTypeCodec
        |> Codec.optionalField "DeviceConfiguration" .deviceConfiguration deviceConfigurationTypeCodec
        |> Codec.optionalField "AutoVerifiedAttributes" .autoVerifiedAttributes verifiedAttributesListTypeCodec
        |> Codec.optionalField "AliasAttributes" .aliasAttributes aliasAttributesListTypeCodec
        |> Codec.optionalField "AdminCreateUserConfig" .adminCreateUserConfig adminCreateUserConfigTypeCodec
        |> Codec.buildObject


{-| Codec for CreateUserPoolDomainResponse.
-}
createUserPoolDomainResponseCodec : Codec CreateUserPoolDomainResponse
createUserPoolDomainResponseCodec =
    Codec.object CreateUserPoolDomainResponse
        |> Codec.optionalField "CloudFrontDomain" .cloudFrontDomain domainTypeCodec
        |> Codec.buildObject


{-| Codec for CreateUserPoolDomainRequest.
-}
createUserPoolDomainRequestCodec : Codec CreateUserPoolDomainRequest
createUserPoolDomainRequestCodec =
    Codec.object CreateUserPoolDomainRequest
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "Domain" .domain domainTypeCodec
        |> Codec.optionalField "CustomDomainConfig" .customDomainConfig customDomainConfigTypeCodec
        |> Codec.buildObject


{-| Codec for CreateUserPoolClientResponse.
-}
createUserPoolClientResponseCodec : Codec CreateUserPoolClientResponse
createUserPoolClientResponseCodec =
    Codec.object CreateUserPoolClientResponse
        |> Codec.optionalField "UserPoolClient" .userPoolClient userPoolClientTypeCodec
        |> Codec.buildObject


{-| Codec for CreateUserPoolClientRequest.
-}
createUserPoolClientRequestCodec : Codec CreateUserPoolClientRequest
createUserPoolClientRequestCodec =
    Codec.object CreateUserPoolClientRequest
        |> Codec.optionalField "WriteAttributes" .writeAttributes clientPermissionListTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.optionalField
            "SupportedIdentityProviders"
            .supportedIdentityProviders
            supportedIdentityProvidersListTypeCodec
        |> Codec.optionalField "RefreshTokenValidity" .refreshTokenValidity refreshTokenValidityTypeCodec
        |> Codec.optionalField "ReadAttributes" .readAttributes clientPermissionListTypeCodec
        |> Codec.optionalField "LogoutURLs" .logoutUrls logoutUrlsListTypeCodec
        |> Codec.optionalField "GenerateSecret" .generateSecret Codec.bool
        |> Codec.optionalField "ExplicitAuthFlows" .explicitAuthFlows explicitAuthFlowsListTypeCodec
        |> Codec.optionalField "DefaultRedirectURI" .defaultRedirectUri redirectUrlTypeCodec
        |> Codec.field "ClientName" .clientName clientNameTypeCodec
        |> Codec.optionalField "CallbackURLs" .callbackUrls callbackUrlsListTypeCodec
        |> Codec.optionalField "AnalyticsConfiguration" .analyticsConfiguration analyticsConfigurationTypeCodec
        |> Codec.optionalField "AllowedOAuthScopes" .allowedOauthScopes scopeListTypeCodec
        |> Codec.optionalField "AllowedOAuthFlowsUserPoolClient" .allowedOauthFlowsUserPoolClient Codec.bool
        |> Codec.optionalField "AllowedOAuthFlows" .allowedOauthFlows oauthFlowsTypeCodec
        |> Codec.buildObject


{-| Codec for CreateUserImportJobResponse.
-}
createUserImportJobResponseCodec : Codec CreateUserImportJobResponse
createUserImportJobResponseCodec =
    Codec.object CreateUserImportJobResponse
        |> Codec.optionalField "UserImportJob" .userImportJob userImportJobTypeCodec
        |> Codec.buildObject


{-| Codec for CreateUserImportJobRequest.
-}
createUserImportJobRequestCodec : Codec CreateUserImportJobRequest
createUserImportJobRequestCodec =
    Codec.object CreateUserImportJobRequest
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "JobName" .jobName userImportJobNameTypeCodec
        |> Codec.field "CloudWatchLogsRoleArn" .cloudWatchLogsRoleArn arnTypeCodec
        |> Codec.buildObject


{-| Codec for CreateResourceServerResponse.
-}
createResourceServerResponseCodec : Codec CreateResourceServerResponse
createResourceServerResponseCodec =
    Codec.object CreateResourceServerResponse
        |> Codec.field "ResourceServer" .resourceServer resourceServerTypeCodec
        |> Codec.buildObject


{-| Codec for CreateResourceServerRequest.
-}
createResourceServerRequestCodec : Codec CreateResourceServerRequest
createResourceServerRequestCodec =
    Codec.object CreateResourceServerRequest
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.optionalField "Scopes" .scopes resourceServerScopeListTypeCodec
        |> Codec.field "Name" .name resourceServerNameTypeCodec
        |> Codec.field "Identifier" .identifier resourceServerIdentifierTypeCodec
        |> Codec.buildObject


{-| Codec for CreateIdentityProviderResponse.
-}
createIdentityProviderResponseCodec : Codec CreateIdentityProviderResponse
createIdentityProviderResponseCodec =
    Codec.object CreateIdentityProviderResponse
        |> Codec.field "IdentityProvider" .identityProvider identityProviderTypeCodec
        |> Codec.buildObject


{-| Codec for CreateIdentityProviderRequest.
-}
createIdentityProviderRequestCodec : Codec CreateIdentityProviderRequest
createIdentityProviderRequestCodec =
    Codec.object CreateIdentityProviderRequest
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "ProviderType" .providerType identityProviderTypeTypeCodec
        |> Codec.field "ProviderName" .providerName providerNameTypeV1Codec
        |> Codec.field "ProviderDetails" .providerDetails providerDetailsTypeCodec
        |> Codec.optionalField "IdpIdentifiers" .idpIdentifiers idpIdentifiersListTypeCodec
        |> Codec.optionalField "AttributeMapping" .attributeMapping attributeMappingTypeCodec
        |> Codec.buildObject


{-| Codec for CreateGroupResponse.
-}
createGroupResponseCodec : Codec CreateGroupResponse
createGroupResponseCodec =
    Codec.object CreateGroupResponse |> Codec.optionalField "Group" .group groupTypeCodec |> Codec.buildObject


{-| Codec for CreateGroupRequest.
-}
createGroupRequestCodec : Codec CreateGroupRequest
createGroupRequestCodec =
    Codec.object CreateGroupRequest
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.optionalField "RoleArn" .roleArn arnTypeCodec
        |> Codec.optionalField "Precedence" .precedence precedenceTypeCodec
        |> Codec.field "GroupName" .groupName groupNameTypeCodec
        |> Codec.optionalField "Description" .description descriptionTypeCodec
        |> Codec.buildObject


{-| Codec for ContextDataType.
-}
contextDataTypeCodec : Codec ContextDataType
contextDataTypeCodec =
    Codec.object ContextDataType
        |> Codec.field "ServerPath" .serverPath Codec.string
        |> Codec.field "ServerName" .serverName Codec.string
        |> Codec.field "IpAddress" .ipAddress Codec.string
        |> Codec.field "HttpHeaders" .httpHeaders httpHeaderListCodec
        |> Codec.optionalField "EncodedData" .encodedData Codec.string
        |> Codec.buildObject


{-| Codec for ConfirmationCodeType.
-}
confirmationCodeTypeCodec : Codec ConfirmationCodeType
confirmationCodeTypeCodec =
    Codec.build (Refined.encoder confirmationCodeType) (Refined.decoder confirmationCodeType)


{-| Codec for ConfirmSignUpResponse.
-}
confirmSignUpResponseCodec : Codec ConfirmSignUpResponse
confirmSignUpResponseCodec =
    Codec.object ConfirmSignUpResponse |> Codec.buildObject


{-| Codec for ConfirmSignUpRequest.
-}
confirmSignUpRequestCodec : Codec ConfirmSignUpRequest
confirmSignUpRequestCodec =
    Codec.object ConfirmSignUpRequest
        |> Codec.field "Username" .username usernameTypeCodec
        |> Codec.optionalField "UserContextData" .userContextData userContextDataTypeCodec
        |> Codec.optionalField "SecretHash" .secretHash secretHashTypeCodec
        |> Codec.optionalField "ForceAliasCreation" .forceAliasCreation Codec.bool
        |> Codec.field "ConfirmationCode" .confirmationCode confirmationCodeTypeCodec
        |> Codec.field "ClientId" .clientId clientIdTypeCodec
        |> Codec.optionalField "AnalyticsMetadata" .analyticsMetadata analyticsMetadataTypeCodec
        |> Codec.buildObject


{-| Codec for ConfirmForgotPasswordResponse.
-}
confirmForgotPasswordResponseCodec : Codec ConfirmForgotPasswordResponse
confirmForgotPasswordResponseCodec =
    Codec.object ConfirmForgotPasswordResponse |> Codec.buildObject


{-| Codec for ConfirmForgotPasswordRequest.
-}
confirmForgotPasswordRequestCodec : Codec ConfirmForgotPasswordRequest
confirmForgotPasswordRequestCodec =
    Codec.object ConfirmForgotPasswordRequest
        |> Codec.field "Username" .username usernameTypeCodec
        |> Codec.optionalField "UserContextData" .userContextData userContextDataTypeCodec
        |> Codec.optionalField "SecretHash" .secretHash secretHashTypeCodec
        |> Codec.field "Password" .password passwordTypeCodec
        |> Codec.field "ConfirmationCode" .confirmationCode confirmationCodeTypeCodec
        |> Codec.field "ClientId" .clientId clientIdTypeCodec
        |> Codec.optionalField "AnalyticsMetadata" .analyticsMetadata analyticsMetadataTypeCodec
        |> Codec.buildObject


{-| Codec for ConfirmDeviceResponse.
-}
confirmDeviceResponseCodec : Codec ConfirmDeviceResponse
confirmDeviceResponseCodec =
    Codec.object ConfirmDeviceResponse
        |> Codec.optionalField "UserConfirmationNecessary" .userConfirmationNecessary Codec.bool
        |> Codec.buildObject


{-| Codec for ConfirmDeviceRequest.
-}
confirmDeviceRequestCodec : Codec ConfirmDeviceRequest
confirmDeviceRequestCodec =
    Codec.object ConfirmDeviceRequest
        |> Codec.optionalField
            "DeviceSecretVerifierConfig"
            .deviceSecretVerifierConfig
            deviceSecretVerifierConfigTypeCodec
        |> Codec.optionalField "DeviceName" .deviceName deviceNameTypeCodec
        |> Codec.field "DeviceKey" .deviceKey deviceKeyTypeCodec
        |> Codec.field "AccessToken" .accessToken tokenModelTypeCodec
        |> Codec.buildObject


{-| Codec for CompromisedCredentialsRiskConfigurationType.
-}
compromisedCredentialsRiskConfigurationTypeCodec : Codec CompromisedCredentialsRiskConfigurationType
compromisedCredentialsRiskConfigurationTypeCodec =
    Codec.object CompromisedCredentialsRiskConfigurationType
        |> Codec.optionalField "EventFilter" .eventFilter eventFiltersTypeCodec
        |> Codec.field "Actions" .actions compromisedCredentialsActionsTypeCodec
        |> Codec.buildObject


{-| Codec for CompromisedCredentialsEventActionType.
-}
compromisedCredentialsEventActionTypeCodec : Codec CompromisedCredentialsEventActionType
compromisedCredentialsEventActionTypeCodec =
    Codec.build
        (Enum.encoder compromisedCredentialsEventActionType)
        (Enum.decoder compromisedCredentialsEventActionType)


{-| Codec for CompromisedCredentialsActionsType.
-}
compromisedCredentialsActionsTypeCodec : Codec CompromisedCredentialsActionsType
compromisedCredentialsActionsTypeCodec =
    Codec.object CompromisedCredentialsActionsType
        |> Codec.field "EventAction" .eventAction compromisedCredentialsEventActionTypeCodec
        |> Codec.buildObject


{-| Codec for CompletionMessageType.
-}
completionMessageTypeCodec : Codec CompletionMessageType
completionMessageTypeCodec =
    Codec.build (Refined.encoder completionMessageType) (Refined.decoder completionMessageType)


{-| Codec for CodeDeliveryDetailsType.
-}
codeDeliveryDetailsTypeCodec : Codec CodeDeliveryDetailsType
codeDeliveryDetailsTypeCodec =
    Codec.object CodeDeliveryDetailsType
        |> Codec.optionalField "Destination" .destination Codec.string
        |> Codec.optionalField "DeliveryMedium" .deliveryMedium deliveryMediumTypeCodec
        |> Codec.optionalField "AttributeName" .attributeName attributeNameTypeCodec
        |> Codec.buildObject


{-| Codec for CodeDeliveryDetailsListType.
-}
codeDeliveryDetailsListTypeCodec : Codec CodeDeliveryDetailsListType
codeDeliveryDetailsListTypeCodec =
    Codec.list codeDeliveryDetailsTypeCodec


{-| Codec for ClientSecretType.
-}
clientSecretTypeCodec : Codec ClientSecretType
clientSecretTypeCodec =
    Codec.build (Refined.encoder clientSecretType) (Refined.decoder clientSecretType)


{-| Codec for ClientPermissionType.
-}
clientPermissionTypeCodec : Codec ClientPermissionType
clientPermissionTypeCodec =
    Codec.build (Refined.encoder clientPermissionType) (Refined.decoder clientPermissionType)


{-| Codec for ClientPermissionListType.
-}
clientPermissionListTypeCodec : Codec ClientPermissionListType
clientPermissionListTypeCodec =
    Codec.list clientPermissionTypeCodec


{-| Codec for ClientNameType.
-}
clientNameTypeCodec : Codec ClientNameType
clientNameTypeCodec =
    Codec.build (Refined.encoder clientNameType) (Refined.decoder clientNameType)


{-| Codec for ClientMetadataType.
-}
clientMetadataTypeCodec : Codec ClientMetadataType
clientMetadataTypeCodec =
    Codec.dict Codec.string


{-| Codec for ClientIdType.
-}
clientIdTypeCodec : Codec ClientIdType
clientIdTypeCodec =
    Codec.build (Refined.encoder clientIdType) (Refined.decoder clientIdType)


{-| Codec for ChangePasswordResponse.
-}
changePasswordResponseCodec : Codec ChangePasswordResponse
changePasswordResponseCodec =
    Codec.object ChangePasswordResponse |> Codec.buildObject


{-| Codec for ChangePasswordRequest.
-}
changePasswordRequestCodec : Codec ChangePasswordRequest
changePasswordRequestCodec =
    Codec.object ChangePasswordRequest
        |> Codec.field "ProposedPassword" .proposedPassword passwordTypeCodec
        |> Codec.field "PreviousPassword" .previousPassword passwordTypeCodec
        |> Codec.field "AccessToken" .accessToken tokenModelTypeCodec
        |> Codec.buildObject


{-| Codec for ChallengeResponsesType.
-}
challengeResponsesTypeCodec : Codec ChallengeResponsesType
challengeResponsesTypeCodec =
    Codec.dict Codec.string


{-| Codec for ChallengeResponseType.
-}
challengeResponseTypeCodec : Codec ChallengeResponseType
challengeResponseTypeCodec =
    Codec.object ChallengeResponseType
        |> Codec.optionalField "ChallengeResponse" .challengeResponse challengeResponseCodec
        |> Codec.optionalField "ChallengeName" .challengeName challengeNameCodec
        |> Codec.buildObject


{-| Codec for ChallengeResponseListType.
-}
challengeResponseListTypeCodec : Codec ChallengeResponseListType
challengeResponseListTypeCodec =
    Codec.list challengeResponseTypeCodec


{-| Codec for ChallengeResponse.
-}
challengeResponseCodec : Codec ChallengeResponse
challengeResponseCodec =
    Codec.build (Enum.encoder challengeResponse) (Enum.decoder challengeResponse)


{-| Codec for ChallengeParametersType.
-}
challengeParametersTypeCodec : Codec ChallengeParametersType
challengeParametersTypeCodec =
    Codec.dict Codec.string


{-| Codec for ChallengeNameType.
-}
challengeNameTypeCodec : Codec ChallengeNameType
challengeNameTypeCodec =
    Codec.build (Enum.encoder challengeNameType) (Enum.decoder challengeNameType)


{-| Codec for ChallengeName.
-}
challengeNameCodec : Codec ChallengeName
challengeNameCodec =
    Codec.build (Enum.encoder challengeName) (Enum.decoder challengeName)


{-| Codec for CallbackUrlsListType.
-}
callbackUrlsListTypeCodec : Codec CallbackUrlsListType
callbackUrlsListTypeCodec =
    Codec.list redirectUrlTypeCodec


{-| Codec for CssversionType.
-}
cssversionTypeCodec : Codec CssversionType
cssversionTypeCodec =
    Codec.string


{-| Codec for Csstype.
-}
csstypeCodec : Codec Csstype
csstypeCodec =
    Codec.string


{-| Codec for BooleanType.
-}
booleanTypeCodec : Codec BooleanType
booleanTypeCodec =
    Codec.bool


{-| Codec for BlockedIprangeListType.
-}
blockedIprangeListTypeCodec : Codec BlockedIprangeListType
blockedIprangeListTypeCodec =
    Codec.list Codec.string


{-| Codec for AuthenticationResultType.
-}
authenticationResultTypeCodec : Codec AuthenticationResultType
authenticationResultTypeCodec =
    Codec.object AuthenticationResultType
        |> Codec.optionalField "TokenType" .tokenType Codec.string
        |> Codec.optionalField "RefreshToken" .refreshToken tokenModelTypeCodec
        |> Codec.optionalField "NewDeviceMetadata" .newDeviceMetadata newDeviceMetadataTypeCodec
        |> Codec.optionalField "IdToken" .idToken tokenModelTypeCodec
        |> Codec.optionalField "ExpiresIn" .expiresIn Codec.int
        |> Codec.optionalField "AccessToken" .accessToken tokenModelTypeCodec
        |> Codec.buildObject


{-| Codec for AuthParametersType.
-}
authParametersTypeCodec : Codec AuthParametersType
authParametersTypeCodec =
    Codec.dict Codec.string


{-| Codec for AuthFlowType.
-}
authFlowTypeCodec : Codec AuthFlowType
authFlowTypeCodec =
    Codec.build (Enum.encoder authFlowType) (Enum.decoder authFlowType)


{-| Codec for AuthEventsType.
-}
authEventsTypeCodec : Codec AuthEventsType
authEventsTypeCodec =
    Codec.list authEventTypeCodec


{-| Codec for AuthEventType.
-}
authEventTypeCodec : Codec AuthEventType
authEventTypeCodec =
    Codec.object AuthEventType
        |> Codec.optionalField "EventType" .eventType eventTypeCodec
        |> Codec.optionalField "EventRisk" .eventRisk eventRiskTypeCodec
        |> Codec.optionalField "EventResponse" .eventResponse eventResponseTypeCodec
        |> Codec.optionalField "EventId" .eventId Codec.string
        |> Codec.optionalField "EventFeedback" .eventFeedback eventFeedbackTypeCodec
        |> Codec.optionalField "EventContextData" .eventContextData eventContextDataTypeCodec
        |> Codec.optionalField "CreationDate" .creationDate dateTypeCodec
        |> Codec.optionalField "ChallengeResponses" .challengeResponses challengeResponseListTypeCodec
        |> Codec.buildObject


{-| Codec for AttributeValueType.
-}
attributeValueTypeCodec : Codec AttributeValueType
attributeValueTypeCodec =
    Codec.build (Refined.encoder attributeValueType) (Refined.decoder attributeValueType)


{-| Codec for AttributeType.
-}
attributeTypeCodec : Codec AttributeType
attributeTypeCodec =
    Codec.object AttributeType
        |> Codec.optionalField "Value" .value attributeValueTypeCodec
        |> Codec.field "Name" .name attributeNameTypeCodec
        |> Codec.buildObject


{-| Codec for AttributeNameType.
-}
attributeNameTypeCodec : Codec AttributeNameType
attributeNameTypeCodec =
    Codec.build (Refined.encoder attributeNameType) (Refined.decoder attributeNameType)


{-| Codec for AttributeNameListType.
-}
attributeNameListTypeCodec : Codec AttributeNameListType
attributeNameListTypeCodec =
    Codec.list attributeNameTypeCodec


{-| Codec for AttributeMappingType.
-}
attributeMappingTypeCodec : Codec AttributeMappingType
attributeMappingTypeCodec =
    Codec.build
        (Refined.dictEncoder attributeMappingKeyType (Codec.encoder Codec.string))
        (Refined.dictDecoder attributeMappingKeyType (Codec.decoder Codec.string))


{-| Codec for AttributeMappingKeyType.
-}
attributeMappingKeyTypeCodec : Codec AttributeMappingKeyType
attributeMappingKeyTypeCodec =
    Codec.build (Refined.encoder attributeMappingKeyType) (Refined.decoder attributeMappingKeyType)


{-| Codec for AttributeListType.
-}
attributeListTypeCodec : Codec AttributeListType
attributeListTypeCodec =
    Codec.list attributeTypeCodec


{-| Codec for AttributeDataType.
-}
attributeDataTypeCodec : Codec AttributeDataType
attributeDataTypeCodec =
    Codec.build (Enum.encoder attributeDataType) (Enum.decoder attributeDataType)


{-| Codec for AssociateSoftwareTokenResponse.
-}
associateSoftwareTokenResponseCodec : Codec AssociateSoftwareTokenResponse
associateSoftwareTokenResponseCodec =
    Codec.object AssociateSoftwareTokenResponse
        |> Codec.optionalField "Session" .session sessionTypeCodec
        |> Codec.optionalField "SecretCode" .secretCode secretCodeTypeCodec
        |> Codec.buildObject


{-| Codec for AssociateSoftwareTokenRequest.
-}
associateSoftwareTokenRequestCodec : Codec AssociateSoftwareTokenRequest
associateSoftwareTokenRequestCodec =
    Codec.object AssociateSoftwareTokenRequest
        |> Codec.optionalField "Session" .session sessionTypeCodec
        |> Codec.optionalField "AccessToken" .accessToken tokenModelTypeCodec
        |> Codec.buildObject


{-| Codec for ArnType.
-}
arnTypeCodec : Codec ArnType
arnTypeCodec =
    Codec.build (Refined.encoder arnType) (Refined.decoder arnType)


{-| Codec for AnalyticsMetadataType.
-}
analyticsMetadataTypeCodec : Codec AnalyticsMetadataType
analyticsMetadataTypeCodec =
    Codec.object AnalyticsMetadataType
        |> Codec.optionalField "AnalyticsEndpointId" .analyticsEndpointId Codec.string
        |> Codec.buildObject


{-| Codec for AnalyticsConfigurationType.
-}
analyticsConfigurationTypeCodec : Codec AnalyticsConfigurationType
analyticsConfigurationTypeCodec =
    Codec.object AnalyticsConfigurationType
        |> Codec.optionalField "UserDataShared" .userDataShared Codec.bool
        |> Codec.field "RoleArn" .roleArn arnTypeCodec
        |> Codec.field "ExternalId" .externalId Codec.string
        |> Codec.field "ApplicationId" .applicationId hexStringTypeCodec
        |> Codec.buildObject


{-| Codec for AliasAttributesListType.
-}
aliasAttributesListTypeCodec : Codec AliasAttributesListType
aliasAttributesListTypeCodec =
    Codec.list aliasAttributeTypeCodec


{-| Codec for AliasAttributeType.
-}
aliasAttributeTypeCodec : Codec AliasAttributeType
aliasAttributeTypeCodec =
    Codec.build (Enum.encoder aliasAttributeType) (Enum.decoder aliasAttributeType)


{-| Codec for AdvancedSecurityModeType.
-}
advancedSecurityModeTypeCodec : Codec AdvancedSecurityModeType
advancedSecurityModeTypeCodec =
    Codec.build (Enum.encoder advancedSecurityModeType) (Enum.decoder advancedSecurityModeType)


{-| Codec for AdminUserGlobalSignOutResponse.
-}
adminUserGlobalSignOutResponseCodec : Codec AdminUserGlobalSignOutResponse
adminUserGlobalSignOutResponseCodec =
    Codec.object AdminUserGlobalSignOutResponse |> Codec.buildObject


{-| Codec for AdminUserGlobalSignOutRequest.
-}
adminUserGlobalSignOutRequestCodec : Codec AdminUserGlobalSignOutRequest
adminUserGlobalSignOutRequestCodec =
    Codec.object AdminUserGlobalSignOutRequest
        |> Codec.field "Username" .username usernameTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.buildObject


{-| Codec for AdminUpdateUserAttributesResponse.
-}
adminUpdateUserAttributesResponseCodec : Codec AdminUpdateUserAttributesResponse
adminUpdateUserAttributesResponseCodec =
    Codec.object AdminUpdateUserAttributesResponse |> Codec.buildObject


{-| Codec for AdminUpdateUserAttributesRequest.
-}
adminUpdateUserAttributesRequestCodec : Codec AdminUpdateUserAttributesRequest
adminUpdateUserAttributesRequestCodec =
    Codec.object AdminUpdateUserAttributesRequest
        |> Codec.field "Username" .username usernameTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "UserAttributes" .userAttributes attributeListTypeCodec
        |> Codec.buildObject


{-| Codec for AdminUpdateDeviceStatusResponse.
-}
adminUpdateDeviceStatusResponseCodec : Codec AdminUpdateDeviceStatusResponse
adminUpdateDeviceStatusResponseCodec =
    Codec.object AdminUpdateDeviceStatusResponse |> Codec.buildObject


{-| Codec for AdminUpdateDeviceStatusRequest.
-}
adminUpdateDeviceStatusRequestCodec : Codec AdminUpdateDeviceStatusRequest
adminUpdateDeviceStatusRequestCodec =
    Codec.object AdminUpdateDeviceStatusRequest
        |> Codec.field "Username" .username usernameTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.optionalField "DeviceRememberedStatus" .deviceRememberedStatus deviceRememberedStatusTypeCodec
        |> Codec.field "DeviceKey" .deviceKey deviceKeyTypeCodec
        |> Codec.buildObject


{-| Codec for AdminUpdateAuthEventFeedbackResponse.
-}
adminUpdateAuthEventFeedbackResponseCodec : Codec AdminUpdateAuthEventFeedbackResponse
adminUpdateAuthEventFeedbackResponseCodec =
    Codec.object AdminUpdateAuthEventFeedbackResponse |> Codec.buildObject


{-| Codec for AdminUpdateAuthEventFeedbackRequest.
-}
adminUpdateAuthEventFeedbackRequestCodec : Codec AdminUpdateAuthEventFeedbackRequest
adminUpdateAuthEventFeedbackRequestCodec =
    Codec.object AdminUpdateAuthEventFeedbackRequest
        |> Codec.field "Username" .username usernameTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "FeedbackValue" .feedbackValue feedbackValueTypeCodec
        |> Codec.field "EventId" .eventId eventIdTypeCodec
        |> Codec.buildObject


{-| Codec for AdminSetUserSettingsResponse.
-}
adminSetUserSettingsResponseCodec : Codec AdminSetUserSettingsResponse
adminSetUserSettingsResponseCodec =
    Codec.object AdminSetUserSettingsResponse |> Codec.buildObject


{-| Codec for AdminSetUserSettingsRequest.
-}
adminSetUserSettingsRequestCodec : Codec AdminSetUserSettingsRequest
adminSetUserSettingsRequestCodec =
    Codec.object AdminSetUserSettingsRequest
        |> Codec.field "Username" .username usernameTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "MFAOptions" .mfaoptions mfaoptionListTypeCodec
        |> Codec.buildObject


{-| Codec for AdminSetUserPasswordResponse.
-}
adminSetUserPasswordResponseCodec : Codec AdminSetUserPasswordResponse
adminSetUserPasswordResponseCodec =
    Codec.object AdminSetUserPasswordResponse |> Codec.buildObject


{-| Codec for AdminSetUserPasswordRequest.
-}
adminSetUserPasswordRequestCodec : Codec AdminSetUserPasswordRequest
adminSetUserPasswordRequestCodec =
    Codec.object AdminSetUserPasswordRequest
        |> Codec.field "Username" .username usernameTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.optionalField "Permanent" .permanent Codec.bool
        |> Codec.field "Password" .password passwordTypeCodec
        |> Codec.buildObject


{-| Codec for AdminSetUserMfapreferenceResponse.
-}
adminSetUserMfapreferenceResponseCodec : Codec AdminSetUserMfapreferenceResponse
adminSetUserMfapreferenceResponseCodec =
    Codec.object AdminSetUserMfapreferenceResponse |> Codec.buildObject


{-| Codec for AdminSetUserMfapreferenceRequest.
-}
adminSetUserMfapreferenceRequestCodec : Codec AdminSetUserMfapreferenceRequest
adminSetUserMfapreferenceRequestCodec =
    Codec.object AdminSetUserMfapreferenceRequest
        |> Codec.field "Username" .username usernameTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.optionalField "SoftwareTokenMfaSettings" .softwareTokenMfaSettings softwareTokenMfaSettingsTypeCodec
        |> Codec.optionalField "SMSMfaSettings" .smsmfaSettings smsmfaSettingsTypeCodec
        |> Codec.buildObject


{-| Codec for AdminRespondToAuthChallengeResponse.
-}
adminRespondToAuthChallengeResponseCodec : Codec AdminRespondToAuthChallengeResponse
adminRespondToAuthChallengeResponseCodec =
    Codec.object AdminRespondToAuthChallengeResponse
        |> Codec.optionalField "Session" .session sessionTypeCodec
        |> Codec.optionalField "ChallengeParameters" .challengeParameters challengeParametersTypeCodec
        |> Codec.optionalField "ChallengeName" .challengeName challengeNameTypeCodec
        |> Codec.optionalField "AuthenticationResult" .authenticationResult authenticationResultTypeCodec
        |> Codec.buildObject


{-| Codec for AdminRespondToAuthChallengeRequest.
-}
adminRespondToAuthChallengeRequestCodec : Codec AdminRespondToAuthChallengeRequest
adminRespondToAuthChallengeRequestCodec =
    Codec.object AdminRespondToAuthChallengeRequest
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.optionalField "Session" .session sessionTypeCodec
        |> Codec.optionalField "ContextData" .contextData contextDataTypeCodec
        |> Codec.field "ClientId" .clientId clientIdTypeCodec
        |> Codec.optionalField "ChallengeResponses" .challengeResponses challengeResponsesTypeCodec
        |> Codec.field "ChallengeName" .challengeName challengeNameTypeCodec
        |> Codec.optionalField "AnalyticsMetadata" .analyticsMetadata analyticsMetadataTypeCodec
        |> Codec.buildObject


{-| Codec for AdminResetUserPasswordResponse.
-}
adminResetUserPasswordResponseCodec : Codec AdminResetUserPasswordResponse
adminResetUserPasswordResponseCodec =
    Codec.object AdminResetUserPasswordResponse |> Codec.buildObject


{-| Codec for AdminResetUserPasswordRequest.
-}
adminResetUserPasswordRequestCodec : Codec AdminResetUserPasswordRequest
adminResetUserPasswordRequestCodec =
    Codec.object AdminResetUserPasswordRequest
        |> Codec.field "Username" .username usernameTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.buildObject


{-| Codec for AdminRemoveUserFromGroupRequest.
-}
adminRemoveUserFromGroupRequestCodec : Codec AdminRemoveUserFromGroupRequest
adminRemoveUserFromGroupRequestCodec =
    Codec.object AdminRemoveUserFromGroupRequest
        |> Codec.field "Username" .username usernameTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "GroupName" .groupName groupNameTypeCodec
        |> Codec.buildObject


{-| Codec for AdminListUserAuthEventsResponse.
-}
adminListUserAuthEventsResponseCodec : Codec AdminListUserAuthEventsResponse
adminListUserAuthEventsResponseCodec =
    Codec.object AdminListUserAuthEventsResponse
        |> Codec.optionalField "NextToken" .nextToken paginationKeyCodec
        |> Codec.optionalField "AuthEvents" .authEvents authEventsTypeCodec
        |> Codec.buildObject


{-| Codec for AdminListUserAuthEventsRequest.
-}
adminListUserAuthEventsRequestCodec : Codec AdminListUserAuthEventsRequest
adminListUserAuthEventsRequestCodec =
    Codec.object AdminListUserAuthEventsRequest
        |> Codec.field "Username" .username usernameTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.optionalField "NextToken" .nextToken paginationKeyCodec
        |> Codec.optionalField "MaxResults" .maxResults queryLimitTypeCodec
        |> Codec.buildObject


{-| Codec for AdminListGroupsForUserResponse.
-}
adminListGroupsForUserResponseCodec : Codec AdminListGroupsForUserResponse
adminListGroupsForUserResponseCodec =
    Codec.object AdminListGroupsForUserResponse
        |> Codec.optionalField "NextToken" .nextToken paginationKeyCodec
        |> Codec.optionalField "Groups" .groups groupListTypeCodec
        |> Codec.buildObject


{-| Codec for AdminListGroupsForUserRequest.
-}
adminListGroupsForUserRequestCodec : Codec AdminListGroupsForUserRequest
adminListGroupsForUserRequestCodec =
    Codec.object AdminListGroupsForUserRequest
        |> Codec.field "Username" .username usernameTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.optionalField "NextToken" .nextToken paginationKeyCodec
        |> Codec.optionalField "Limit" .limit queryLimitTypeCodec
        |> Codec.buildObject


{-| Codec for AdminListDevicesResponse.
-}
adminListDevicesResponseCodec : Codec AdminListDevicesResponse
adminListDevicesResponseCodec =
    Codec.object AdminListDevicesResponse
        |> Codec.optionalField "PaginationToken" .paginationToken searchPaginationTokenTypeCodec
        |> Codec.optionalField "Devices" .devices deviceListTypeCodec
        |> Codec.buildObject


{-| Codec for AdminListDevicesRequest.
-}
adminListDevicesRequestCodec : Codec AdminListDevicesRequest
adminListDevicesRequestCodec =
    Codec.object AdminListDevicesRequest
        |> Codec.field "Username" .username usernameTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.optionalField "PaginationToken" .paginationToken searchPaginationTokenTypeCodec
        |> Codec.optionalField "Limit" .limit queryLimitTypeCodec
        |> Codec.buildObject


{-| Codec for AdminLinkProviderForUserResponse.
-}
adminLinkProviderForUserResponseCodec : Codec AdminLinkProviderForUserResponse
adminLinkProviderForUserResponseCodec =
    Codec.object AdminLinkProviderForUserResponse |> Codec.buildObject


{-| Codec for AdminLinkProviderForUserRequest.
-}
adminLinkProviderForUserRequestCodec : Codec AdminLinkProviderForUserRequest
adminLinkProviderForUserRequestCodec =
    Codec.object AdminLinkProviderForUserRequest
        |> Codec.field "UserPoolId" .userPoolId Codec.string
        |> Codec.field "SourceUser" .sourceUser providerUserIdentifierTypeCodec
        |> Codec.field "DestinationUser" .destinationUser providerUserIdentifierTypeCodec
        |> Codec.buildObject


{-| Codec for AdminInitiateAuthResponse.
-}
adminInitiateAuthResponseCodec : Codec AdminInitiateAuthResponse
adminInitiateAuthResponseCodec =
    Codec.object AdminInitiateAuthResponse
        |> Codec.optionalField "Session" .session sessionTypeCodec
        |> Codec.optionalField "ChallengeParameters" .challengeParameters challengeParametersTypeCodec
        |> Codec.optionalField "ChallengeName" .challengeName challengeNameTypeCodec
        |> Codec.optionalField "AuthenticationResult" .authenticationResult authenticationResultTypeCodec
        |> Codec.buildObject


{-| Codec for AdminInitiateAuthRequest.
-}
adminInitiateAuthRequestCodec : Codec AdminInitiateAuthRequest
adminInitiateAuthRequestCodec =
    Codec.object AdminInitiateAuthRequest
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.optionalField "ContextData" .contextData contextDataTypeCodec
        |> Codec.optionalField "ClientMetadata" .clientMetadata clientMetadataTypeCodec
        |> Codec.field "ClientId" .clientId clientIdTypeCodec
        |> Codec.optionalField "AuthParameters" .authParameters authParametersTypeCodec
        |> Codec.field "AuthFlow" .authFlow authFlowTypeCodec
        |> Codec.optionalField "AnalyticsMetadata" .analyticsMetadata analyticsMetadataTypeCodec
        |> Codec.buildObject


{-| Codec for AdminGetUserResponse.
-}
adminGetUserResponseCodec : Codec AdminGetUserResponse
adminGetUserResponseCodec =
    Codec.object AdminGetUserResponse
        |> Codec.field "Username" .username usernameTypeCodec
        |> Codec.optionalField "UserStatus" .userStatus userStatusTypeCodec
        |> Codec.optionalField "UserMFASettingList" .userMfasettingList userMfasettingListTypeCodec
        |> Codec.optionalField "UserLastModifiedDate" .userLastModifiedDate dateTypeCodec
        |> Codec.optionalField "UserCreateDate" .userCreateDate dateTypeCodec
        |> Codec.optionalField "UserAttributes" .userAttributes attributeListTypeCodec
        |> Codec.optionalField "PreferredMfaSetting" .preferredMfaSetting Codec.string
        |> Codec.optionalField "MFAOptions" .mfaoptions mfaoptionListTypeCodec
        |> Codec.optionalField "Enabled" .enabled Codec.bool
        |> Codec.buildObject


{-| Codec for AdminGetUserRequest.
-}
adminGetUserRequestCodec : Codec AdminGetUserRequest
adminGetUserRequestCodec =
    Codec.object AdminGetUserRequest
        |> Codec.field "Username" .username usernameTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.buildObject


{-| Codec for AdminGetDeviceResponse.
-}
adminGetDeviceResponseCodec : Codec AdminGetDeviceResponse
adminGetDeviceResponseCodec =
    Codec.object AdminGetDeviceResponse |> Codec.field "Device" .device deviceTypeCodec |> Codec.buildObject


{-| Codec for AdminGetDeviceRequest.
-}
adminGetDeviceRequestCodec : Codec AdminGetDeviceRequest
adminGetDeviceRequestCodec =
    Codec.object AdminGetDeviceRequest
        |> Codec.field "Username" .username usernameTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "DeviceKey" .deviceKey deviceKeyTypeCodec
        |> Codec.buildObject


{-| Codec for AdminForgetDeviceRequest.
-}
adminForgetDeviceRequestCodec : Codec AdminForgetDeviceRequest
adminForgetDeviceRequestCodec =
    Codec.object AdminForgetDeviceRequest
        |> Codec.field "Username" .username usernameTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "DeviceKey" .deviceKey deviceKeyTypeCodec
        |> Codec.buildObject


{-| Codec for AdminEnableUserResponse.
-}
adminEnableUserResponseCodec : Codec AdminEnableUserResponse
adminEnableUserResponseCodec =
    Codec.object AdminEnableUserResponse |> Codec.buildObject


{-| Codec for AdminEnableUserRequest.
-}
adminEnableUserRequestCodec : Codec AdminEnableUserRequest
adminEnableUserRequestCodec =
    Codec.object AdminEnableUserRequest
        |> Codec.field "Username" .username usernameTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.buildObject


{-| Codec for AdminDisableUserResponse.
-}
adminDisableUserResponseCodec : Codec AdminDisableUserResponse
adminDisableUserResponseCodec =
    Codec.object AdminDisableUserResponse |> Codec.buildObject


{-| Codec for AdminDisableUserRequest.
-}
adminDisableUserRequestCodec : Codec AdminDisableUserRequest
adminDisableUserRequestCodec =
    Codec.object AdminDisableUserRequest
        |> Codec.field "Username" .username usernameTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.buildObject


{-| Codec for AdminDisableProviderForUserResponse.
-}
adminDisableProviderForUserResponseCodec : Codec AdminDisableProviderForUserResponse
adminDisableProviderForUserResponseCodec =
    Codec.object AdminDisableProviderForUserResponse |> Codec.buildObject


{-| Codec for AdminDisableProviderForUserRequest.
-}
adminDisableProviderForUserRequestCodec : Codec AdminDisableProviderForUserRequest
adminDisableProviderForUserRequestCodec =
    Codec.object AdminDisableProviderForUserRequest
        |> Codec.field "UserPoolId" .userPoolId Codec.string
        |> Codec.field "User" .user providerUserIdentifierTypeCodec
        |> Codec.buildObject


{-| Codec for AdminDeleteUserRequest.
-}
adminDeleteUserRequestCodec : Codec AdminDeleteUserRequest
adminDeleteUserRequestCodec =
    Codec.object AdminDeleteUserRequest
        |> Codec.field "Username" .username usernameTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.buildObject


{-| Codec for AdminDeleteUserAttributesResponse.
-}
adminDeleteUserAttributesResponseCodec : Codec AdminDeleteUserAttributesResponse
adminDeleteUserAttributesResponseCodec =
    Codec.object AdminDeleteUserAttributesResponse |> Codec.buildObject


{-| Codec for AdminDeleteUserAttributesRequest.
-}
adminDeleteUserAttributesRequestCodec : Codec AdminDeleteUserAttributesRequest
adminDeleteUserAttributesRequestCodec =
    Codec.object AdminDeleteUserAttributesRequest
        |> Codec.field "Username" .username usernameTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "UserAttributeNames" .userAttributeNames attributeNameListTypeCodec
        |> Codec.buildObject


{-| Codec for AdminCreateUserUnusedAccountValidityDaysType.
-}
adminCreateUserUnusedAccountValidityDaysTypeCodec : Codec AdminCreateUserUnusedAccountValidityDaysType
adminCreateUserUnusedAccountValidityDaysTypeCodec =
    Codec.build
        (Refined.encoder adminCreateUserUnusedAccountValidityDaysType)
        (Refined.decoder adminCreateUserUnusedAccountValidityDaysType)


{-| Codec for AdminCreateUserResponse.
-}
adminCreateUserResponseCodec : Codec AdminCreateUserResponse
adminCreateUserResponseCodec =
    Codec.object AdminCreateUserResponse |> Codec.optionalField "User" .user userTypeCodec |> Codec.buildObject


{-| Codec for AdminCreateUserRequest.
-}
adminCreateUserRequestCodec : Codec AdminCreateUserRequest
adminCreateUserRequestCodec =
    Codec.object AdminCreateUserRequest
        |> Codec.optionalField "ValidationData" .validationData attributeListTypeCodec
        |> Codec.field "Username" .username usernameTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.optionalField "UserAttributes" .userAttributes attributeListTypeCodec
        |> Codec.optionalField "TemporaryPassword" .temporaryPassword passwordTypeCodec
        |> Codec.optionalField "MessageAction" .messageAction messageActionTypeCodec
        |> Codec.optionalField "ForceAliasCreation" .forceAliasCreation Codec.bool
        |> Codec.optionalField "DesiredDeliveryMediums" .desiredDeliveryMediums deliveryMediumListTypeCodec
        |> Codec.buildObject


{-| Codec for AdminCreateUserConfigType.
-}
adminCreateUserConfigTypeCodec : Codec AdminCreateUserConfigType
adminCreateUserConfigTypeCodec =
    Codec.object AdminCreateUserConfigType
        |> Codec.optionalField
            "UnusedAccountValidityDays"
            .unusedAccountValidityDays
            adminCreateUserUnusedAccountValidityDaysTypeCodec
        |> Codec.optionalField "InviteMessageTemplate" .inviteMessageTemplate messageTemplateTypeCodec
        |> Codec.optionalField "AllowAdminCreateUserOnly" .allowAdminCreateUserOnly Codec.bool
        |> Codec.buildObject


{-| Codec for AdminConfirmSignUpResponse.
-}
adminConfirmSignUpResponseCodec : Codec AdminConfirmSignUpResponse
adminConfirmSignUpResponseCodec =
    Codec.object AdminConfirmSignUpResponse |> Codec.buildObject


{-| Codec for AdminConfirmSignUpRequest.
-}
adminConfirmSignUpRequestCodec : Codec AdminConfirmSignUpRequest
adminConfirmSignUpRequestCodec =
    Codec.object AdminConfirmSignUpRequest
        |> Codec.field "Username" .username usernameTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.buildObject


{-| Codec for AdminAddUserToGroupRequest.
-}
adminAddUserToGroupRequestCodec : Codec AdminAddUserToGroupRequest
adminAddUserToGroupRequestCodec =
    Codec.object AdminAddUserToGroupRequest
        |> Codec.field "Username" .username usernameTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "GroupName" .groupName groupNameTypeCodec
        |> Codec.buildObject


{-| Codec for AddCustomAttributesResponse.
-}
addCustomAttributesResponseCodec : Codec AddCustomAttributesResponse
addCustomAttributesResponseCodec =
    Codec.object AddCustomAttributesResponse |> Codec.buildObject


{-| Codec for AddCustomAttributesRequest.
-}
addCustomAttributesRequestCodec : Codec AddCustomAttributesRequest
addCustomAttributesRequestCodec =
    Codec.object AddCustomAttributesRequest
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "CustomAttributes" .customAttributes customAttributesListTypeCodec
        |> Codec.buildObject


{-| Codec for AccountTakeoverRiskConfigurationType.
-}
accountTakeoverRiskConfigurationTypeCodec : Codec AccountTakeoverRiskConfigurationType
accountTakeoverRiskConfigurationTypeCodec =
    Codec.object AccountTakeoverRiskConfigurationType
        |> Codec.optionalField "NotifyConfiguration" .notifyConfiguration notifyConfigurationTypeCodec
        |> Codec.field "Actions" .actions accountTakeoverActionsTypeCodec
        |> Codec.buildObject


{-| Codec for AccountTakeoverEventActionType.
-}
accountTakeoverEventActionTypeCodec : Codec AccountTakeoverEventActionType
accountTakeoverEventActionTypeCodec =
    Codec.build (Enum.encoder accountTakeoverEventActionType) (Enum.decoder accountTakeoverEventActionType)


{-| Codec for AccountTakeoverActionsType.
-}
accountTakeoverActionsTypeCodec : Codec AccountTakeoverActionsType
accountTakeoverActionsTypeCodec =
    Codec.object AccountTakeoverActionsType
        |> Codec.optionalField "MediumAction" .mediumAction accountTakeoverActionTypeCodec
        |> Codec.optionalField "LowAction" .lowAction accountTakeoverActionTypeCodec
        |> Codec.optionalField "HighAction" .highAction accountTakeoverActionTypeCodec
        |> Codec.buildObject


{-| Codec for AccountTakeoverActionType.
-}
accountTakeoverActionTypeCodec : Codec AccountTakeoverActionType
accountTakeoverActionTypeCodec =
    Codec.object AccountTakeoverActionType
        |> Codec.field "Notify" .notify Codec.bool
        |> Codec.field "EventAction" .eventAction accountTakeoverEventActionTypeCodec
        |> Codec.buildObject


{-| Codec for AccountTakeoverActionNotifyType.
-}
accountTakeoverActionNotifyTypeCodec : Codec AccountTakeoverActionNotifyType
accountTakeoverActionNotifyTypeCodec =
    Codec.bool


{-| Codec for AwsaccountIdType.
-}
awsaccountIdTypeCodec : Codec AwsaccountIdType
awsaccountIdTypeCodec =
    Codec.string
