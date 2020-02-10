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
    { eventAction : AccountTakeoverEventActionType, notify : AccountTakeoverActionNotifyType }


{-| The AccountTakeoverActionsType data model.
-}
type alias AccountTakeoverActionsType =
    { highAction : Maybe AccountTakeoverActionType
    , lowAction : Maybe AccountTakeoverActionType
    , mediumAction : Maybe AccountTakeoverActionType
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
    { actions : AccountTakeoverActionsType, notifyConfiguration : Maybe NotifyConfigurationType }


{-| The AddCustomAttributesRequest data model.
-}
type alias AddCustomAttributesRequest =
    { customAttributes : CustomAttributesListType, userPoolId : UserPoolIdType }


{-| The AddCustomAttributesResponse data model.
-}
type alias AddCustomAttributesResponse =
    {}


{-| The AdminAddUserToGroupRequest data model.
-}
type alias AdminAddUserToGroupRequest =
    { groupName : GroupNameType, userPoolId : UserPoolIdType, username : UsernameType }


{-| The AdminConfirmSignUpRequest data model.
-}
type alias AdminConfirmSignUpRequest =
    { userPoolId : UserPoolIdType, username : UsernameType }


{-| The AdminConfirmSignUpResponse data model.
-}
type alias AdminConfirmSignUpResponse =
    {}


{-| The AdminCreateUserConfigType data model.
-}
type alias AdminCreateUserConfigType =
    { allowAdminCreateUserOnly : Maybe BooleanType
    , inviteMessageTemplate : Maybe MessageTemplateType
    , unusedAccountValidityDays : Maybe AdminCreateUserUnusedAccountValidityDaysType
    }


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


{-| The AdminCreateUserResponse data model.
-}
type alias AdminCreateUserResponse =
    { user : Maybe UserType }


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


{-| The AdminDeleteUserAttributesRequest data model.
-}
type alias AdminDeleteUserAttributesRequest =
    { userAttributeNames : AttributeNameListType, userPoolId : UserPoolIdType, username : UsernameType }


{-| The AdminDeleteUserAttributesResponse data model.
-}
type alias AdminDeleteUserAttributesResponse =
    {}


{-| The AdminDeleteUserRequest data model.
-}
type alias AdminDeleteUserRequest =
    { userPoolId : UserPoolIdType, username : UsernameType }


{-| The AdminDisableProviderForUserRequest data model.
-}
type alias AdminDisableProviderForUserRequest =
    { user : ProviderUserIdentifierType, userPoolId : StringType }


{-| The AdminDisableProviderForUserResponse data model.
-}
type alias AdminDisableProviderForUserResponse =
    {}


{-| The AdminDisableUserRequest data model.
-}
type alias AdminDisableUserRequest =
    { userPoolId : UserPoolIdType, username : UsernameType }


{-| The AdminDisableUserResponse data model.
-}
type alias AdminDisableUserResponse =
    {}


{-| The AdminEnableUserRequest data model.
-}
type alias AdminEnableUserRequest =
    { userPoolId : UserPoolIdType, username : UsernameType }


{-| The AdminEnableUserResponse data model.
-}
type alias AdminEnableUserResponse =
    {}


{-| The AdminForgetDeviceRequest data model.
-}
type alias AdminForgetDeviceRequest =
    { deviceKey : DeviceKeyType, userPoolId : UserPoolIdType, username : UsernameType }


{-| The AdminGetDeviceRequest data model.
-}
type alias AdminGetDeviceRequest =
    { deviceKey : DeviceKeyType, userPoolId : UserPoolIdType, username : UsernameType }


{-| The AdminGetDeviceResponse data model.
-}
type alias AdminGetDeviceResponse =
    { device : DeviceType }


{-| The AdminGetUserRequest data model.
-}
type alias AdminGetUserRequest =
    { userPoolId : UserPoolIdType, username : UsernameType }


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


{-| The AdminInitiateAuthResponse data model.
-}
type alias AdminInitiateAuthResponse =
    { authenticationResult : Maybe AuthenticationResultType
    , challengeName : Maybe ChallengeNameType
    , challengeParameters : Maybe ChallengeParametersType
    , session : Maybe SessionType
    }


{-| The AdminLinkProviderForUserRequest data model.
-}
type alias AdminLinkProviderForUserRequest =
    { destinationUser : ProviderUserIdentifierType, sourceUser : ProviderUserIdentifierType, userPoolId : StringType }


{-| The AdminLinkProviderForUserResponse data model.
-}
type alias AdminLinkProviderForUserResponse =
    {}


{-| The AdminListDevicesRequest data model.
-}
type alias AdminListDevicesRequest =
    { limit : Maybe QueryLimitType
    , paginationToken : Maybe SearchPaginationTokenType
    , userPoolId : UserPoolIdType
    , username : UsernameType
    }


{-| The AdminListDevicesResponse data model.
-}
type alias AdminListDevicesResponse =
    { devices : Maybe DeviceListType, paginationToken : Maybe SearchPaginationTokenType }


{-| The AdminListGroupsForUserRequest data model.
-}
type alias AdminListGroupsForUserRequest =
    { limit : Maybe QueryLimitType
    , nextToken : Maybe PaginationKey
    , userPoolId : UserPoolIdType
    , username : UsernameType
    }


{-| The AdminListGroupsForUserResponse data model.
-}
type alias AdminListGroupsForUserResponse =
    { groups : Maybe GroupListType, nextToken : Maybe PaginationKey }


{-| The AdminListUserAuthEventsRequest data model.
-}
type alias AdminListUserAuthEventsRequest =
    { maxResults : Maybe QueryLimitType
    , nextToken : Maybe PaginationKey
    , userPoolId : UserPoolIdType
    , username : UsernameType
    }


{-| The AdminListUserAuthEventsResponse data model.
-}
type alias AdminListUserAuthEventsResponse =
    { authEvents : Maybe AuthEventsType, nextToken : Maybe PaginationKey }


{-| The AdminRemoveUserFromGroupRequest data model.
-}
type alias AdminRemoveUserFromGroupRequest =
    { groupName : GroupNameType, userPoolId : UserPoolIdType, username : UsernameType }


{-| The AdminResetUserPasswordRequest data model.
-}
type alias AdminResetUserPasswordRequest =
    { userPoolId : UserPoolIdType, username : UsernameType }


{-| The AdminResetUserPasswordResponse data model.
-}
type alias AdminResetUserPasswordResponse =
    {}


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


{-| The AdminRespondToAuthChallengeResponse data model.
-}
type alias AdminRespondToAuthChallengeResponse =
    { authenticationResult : Maybe AuthenticationResultType
    , challengeName : Maybe ChallengeNameType
    , challengeParameters : Maybe ChallengeParametersType
    , session : Maybe SessionType
    }


{-| The AdminSetUserMfapreferenceRequest data model.
-}
type alias AdminSetUserMfapreferenceRequest =
    { smsmfaSettings : Maybe SmsmfaSettingsType
    , softwareTokenMfaSettings : Maybe SoftwareTokenMfaSettingsType
    , userPoolId : UserPoolIdType
    , username : UsernameType
    }


{-| The AdminSetUserMfapreferenceResponse data model.
-}
type alias AdminSetUserMfapreferenceResponse =
    {}


{-| The AdminSetUserPasswordRequest data model.
-}
type alias AdminSetUserPasswordRequest =
    { password : PasswordType, permanent : Maybe BooleanType, userPoolId : UserPoolIdType, username : UsernameType }


{-| The AdminSetUserPasswordResponse data model.
-}
type alias AdminSetUserPasswordResponse =
    {}


{-| The AdminSetUserSettingsRequest data model.
-}
type alias AdminSetUserSettingsRequest =
    { mfaoptions : MfaoptionListType, userPoolId : UserPoolIdType, username : UsernameType }


{-| The AdminSetUserSettingsResponse data model.
-}
type alias AdminSetUserSettingsResponse =
    {}


{-| The AdminUpdateAuthEventFeedbackRequest data model.
-}
type alias AdminUpdateAuthEventFeedbackRequest =
    { eventId : EventIdType, feedbackValue : FeedbackValueType, userPoolId : UserPoolIdType, username : UsernameType }


{-| The AdminUpdateAuthEventFeedbackResponse data model.
-}
type alias AdminUpdateAuthEventFeedbackResponse =
    {}


{-| The AdminUpdateDeviceStatusRequest data model.
-}
type alias AdminUpdateDeviceStatusRequest =
    { deviceKey : DeviceKeyType
    , deviceRememberedStatus : Maybe DeviceRememberedStatusType
    , userPoolId : UserPoolIdType
    , username : UsernameType
    }


{-| The AdminUpdateDeviceStatusResponse data model.
-}
type alias AdminUpdateDeviceStatusResponse =
    {}


{-| The AdminUpdateUserAttributesRequest data model.
-}
type alias AdminUpdateUserAttributesRequest =
    { userAttributes : AttributeListType, userPoolId : UserPoolIdType, username : UsernameType }


{-| The AdminUpdateUserAttributesResponse data model.
-}
type alias AdminUpdateUserAttributesResponse =
    {}


{-| The AdminUserGlobalSignOutRequest data model.
-}
type alias AdminUserGlobalSignOutRequest =
    { userPoolId : UserPoolIdType, username : UsernameType }


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
    { applicationId : HexStringType, externalId : StringType, roleArn : ArnType, userDataShared : Maybe BooleanType }


{-| The AnalyticsMetadataType data model.
-}
type alias AnalyticsMetadataType =
    { analyticsEndpointId : Maybe StringType }


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


{-| The AssociateSoftwareTokenRequest data model.
-}
type alias AssociateSoftwareTokenRequest =
    { accessToken : Maybe TokenModelType, session : Maybe SessionType }


{-| The AssociateSoftwareTokenResponse data model.
-}
type alias AssociateSoftwareTokenResponse =
    { secretCode : Maybe SecretCodeType, session : Maybe SessionType }


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


{-| The AttributeMappingType data model.
-}
type alias AttributeMappingType =
    Dict.Refined.Dict String AttributeMappingKeyType StringType


{-| The AttributeNameListType data model.
-}
type alias AttributeNameListType =
    List AttributeNameType


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


{-| The AttributeType data model.
-}
type alias AttributeType =
    { name : AttributeNameType, value : Maybe AttributeValueType }


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
    Dict StringType StringType


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


{-| The BlockedIprangeListType data model.
-}
type alias BlockedIprangeListType =
    List StringType


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
    Dict StringType StringType


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
    { challengeName : Maybe ChallengeName, challengeResponse : Maybe ChallengeResponse }


{-| The ChallengeResponsesType data model.
-}
type alias ChallengeResponsesType =
    Dict StringType StringType


{-| The ChangePasswordRequest data model.
-}
type alias ChangePasswordRequest =
    { accessToken : TokenModelType, previousPassword : PasswordType, proposedPassword : PasswordType }


{-| The ChangePasswordResponse data model.
-}
type alias ChangePasswordResponse =
    {}


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


{-| The ClientMetadataType data model.
-}
type alias ClientMetadataType =
    Dict StringType StringType


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


{-| The ClientPermissionListType data model.
-}
type alias ClientPermissionListType =
    List ClientPermissionType


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


{-| The CodeDeliveryDetailsListType data model.
-}
type alias CodeDeliveryDetailsListType =
    List CodeDeliveryDetailsType


{-| The CodeDeliveryDetailsType data model.
-}
type alias CodeDeliveryDetailsType =
    { attributeName : Maybe AttributeNameType
    , deliveryMedium : Maybe DeliveryMediumType
    , destination : Maybe StringType
    }


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
    { actions : CompromisedCredentialsActionsType, eventFilter : Maybe EventFiltersType }


{-| The ConfirmDeviceRequest data model.
-}
type alias ConfirmDeviceRequest =
    { accessToken : TokenModelType
    , deviceKey : DeviceKeyType
    , deviceName : Maybe DeviceNameType
    , deviceSecretVerifierConfig : Maybe DeviceSecretVerifierConfigType
    }


{-| The ConfirmDeviceResponse data model.
-}
type alias ConfirmDeviceResponse =
    { userConfirmationNecessary : Maybe BooleanType }


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


{-| The ConfirmForgotPasswordResponse data model.
-}
type alias ConfirmForgotPasswordResponse =
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


{-| The ConfirmSignUpResponse data model.
-}
type alias ConfirmSignUpResponse =
    {}


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


{-| The ContextDataType data model.
-}
type alias ContextDataType =
    { encodedData : Maybe StringType
    , httpHeaders : HttpHeaderList
    , ipAddress : StringType
    , serverName : StringType
    , serverPath : StringType
    }


{-| The CreateGroupRequest data model.
-}
type alias CreateGroupRequest =
    { description : Maybe DescriptionType
    , groupName : GroupNameType
    , precedence : Maybe PrecedenceType
    , roleArn : Maybe ArnType
    , userPoolId : UserPoolIdType
    }


{-| The CreateGroupResponse data model.
-}
type alias CreateGroupResponse =
    { group : Maybe GroupType }


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


{-| The CreateIdentityProviderResponse data model.
-}
type alias CreateIdentityProviderResponse =
    { identityProvider : IdentityProviderType }


{-| The CreateResourceServerRequest data model.
-}
type alias CreateResourceServerRequest =
    { identifier : ResourceServerIdentifierType
    , name : ResourceServerNameType
    , scopes : Maybe ResourceServerScopeListType
    , userPoolId : UserPoolIdType
    }


{-| The CreateResourceServerResponse data model.
-}
type alias CreateResourceServerResponse =
    { resourceServer : ResourceServerType }


{-| The CreateUserImportJobRequest data model.
-}
type alias CreateUserImportJobRequest =
    { cloudWatchLogsRoleArn : ArnType, jobName : UserImportJobNameType, userPoolId : UserPoolIdType }


{-| The CreateUserImportJobResponse data model.
-}
type alias CreateUserImportJobResponse =
    { userImportJob : Maybe UserImportJobType }


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


{-| The CreateUserPoolClientResponse data model.
-}
type alias CreateUserPoolClientResponse =
    { userPoolClient : Maybe UserPoolClientType }


{-| The CreateUserPoolDomainRequest data model.
-}
type alias CreateUserPoolDomainRequest =
    { customDomainConfig : Maybe CustomDomainConfigType, domain : DomainType, userPoolId : UserPoolIdType }


{-| The CreateUserPoolDomainResponse data model.
-}
type alias CreateUserPoolDomainResponse =
    { cloudFrontDomain : Maybe DomainType }


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


{-| The CreateUserPoolResponse data model.
-}
type alias CreateUserPoolResponse =
    { userPool : Maybe UserPoolType }


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
    { groupName : GroupNameType, userPoolId : UserPoolIdType }


{-| The DeleteIdentityProviderRequest data model.
-}
type alias DeleteIdentityProviderRequest =
    { providerName : ProviderNameType, userPoolId : UserPoolIdType }


{-| The DeleteResourceServerRequest data model.
-}
type alias DeleteResourceServerRequest =
    { identifier : ResourceServerIdentifierType, userPoolId : UserPoolIdType }


{-| The DeleteUserAttributesRequest data model.
-}
type alias DeleteUserAttributesRequest =
    { accessToken : TokenModelType, userAttributeNames : AttributeNameListType }


{-| The DeleteUserAttributesResponse data model.
-}
type alias DeleteUserAttributesResponse =
    {}


{-| The DeleteUserPoolClientRequest data model.
-}
type alias DeleteUserPoolClientRequest =
    { clientId : ClientIdType, userPoolId : UserPoolIdType }


{-| The DeleteUserPoolDomainRequest data model.
-}
type alias DeleteUserPoolDomainRequest =
    { domain : DomainType, userPoolId : UserPoolIdType }


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
    { providerName : ProviderNameType, userPoolId : UserPoolIdType }


{-| The DescribeIdentityProviderResponse data model.
-}
type alias DescribeIdentityProviderResponse =
    { identityProvider : IdentityProviderType }


{-| The DescribeResourceServerRequest data model.
-}
type alias DescribeResourceServerRequest =
    { identifier : ResourceServerIdentifierType, userPoolId : UserPoolIdType }


{-| The DescribeResourceServerResponse data model.
-}
type alias DescribeResourceServerResponse =
    { resourceServer : ResourceServerType }


{-| The DescribeRiskConfigurationRequest data model.
-}
type alias DescribeRiskConfigurationRequest =
    { clientId : Maybe ClientIdType, userPoolId : UserPoolIdType }


{-| The DescribeRiskConfigurationResponse data model.
-}
type alias DescribeRiskConfigurationResponse =
    { riskConfiguration : RiskConfigurationType }


{-| The DescribeUserImportJobRequest data model.
-}
type alias DescribeUserImportJobRequest =
    { jobId : UserImportJobIdType, userPoolId : UserPoolIdType }


{-| The DescribeUserImportJobResponse data model.
-}
type alias DescribeUserImportJobResponse =
    { userImportJob : Maybe UserImportJobType }


{-| The DescribeUserPoolClientRequest data model.
-}
type alias DescribeUserPoolClientRequest =
    { clientId : ClientIdType, userPoolId : UserPoolIdType }


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


{-| The DeviceConfigurationType data model.
-}
type alias DeviceConfigurationType =
    { challengeRequiredOnNewDevice : Maybe BooleanType, deviceOnlyRememberedOnUserPrompt : Maybe BooleanType }


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


{-| The DeviceListType data model.
-}
type alias DeviceListType =
    List DeviceType


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
    { passwordVerifier : Maybe StringType, salt : Maybe StringType }


{-| The DeviceType data model.
-}
type alias DeviceType =
    { deviceAttributes : Maybe AttributeListType
    , deviceCreateDate : Maybe DateType
    , deviceKey : Maybe DeviceKeyType
    , deviceLastAuthenticatedDate : Maybe DateType
    , deviceLastModifiedDate : Maybe DateType
    }


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


{-| The EmailConfigurationType data model.
-}
type alias EmailConfigurationType =
    { emailSendingAccount : Maybe EmailSendingAccountType
    , replyToEmailAddress : Maybe EmailAddressType
    , sourceArn : Maybe ArnType
    }


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


{-| The EventContextDataType data model.
-}
type alias EventContextDataType =
    { city : Maybe StringType
    , country : Maybe StringType
    , deviceName : Maybe StringType
    , ipAddress : Maybe StringType
    , timezone : Maybe StringType
    }


{-| The EventFeedbackType data model.
-}
type alias EventFeedbackType =
    { feedbackDate : Maybe DateType, feedbackValue : FeedbackValueType, provider : StringType }


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
    { riskDecision : Maybe RiskDecisionType, riskLevel : Maybe RiskLevelType }


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
    { accessToken : Maybe TokenModelType, deviceKey : DeviceKeyType }


{-| The ForgotPasswordRequest data model.
-}
type alias ForgotPasswordRequest =
    { analyticsMetadata : Maybe AnalyticsMetadataType
    , clientId : ClientIdType
    , secretHash : Maybe SecretHashType
    , userContextData : Maybe UserContextDataType
    , username : UsernameType
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
    { csvheader : Maybe ListOfStringTypes, userPoolId : Maybe UserPoolIdType }


{-| The GetDeviceRequest data model.
-}
type alias GetDeviceRequest =
    { accessToken : Maybe TokenModelType, deviceKey : DeviceKeyType }


{-| The GetDeviceResponse data model.
-}
type alias GetDeviceResponse =
    { device : DeviceType }


{-| The GetGroupRequest data model.
-}
type alias GetGroupRequest =
    { groupName : GroupNameType, userPoolId : UserPoolIdType }


{-| The GetGroupResponse data model.
-}
type alias GetGroupResponse =
    { group : Maybe GroupType }


{-| The GetIdentityProviderByIdentifierRequest data model.
-}
type alias GetIdentityProviderByIdentifierRequest =
    { idpIdentifier : IdpIdentifierType, userPoolId : UserPoolIdType }


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
    { certificate : Maybe StringType }


{-| The GetUicustomizationRequest data model.
-}
type alias GetUicustomizationRequest =
    { clientId : Maybe ClientIdType, userPoolId : UserPoolIdType }


{-| The GetUicustomizationResponse data model.
-}
type alias GetUicustomizationResponse =
    { uicustomization : UicustomizationType }


{-| The GetUserAttributeVerificationCodeRequest data model.
-}
type alias GetUserAttributeVerificationCodeRequest =
    { accessToken : TokenModelType, attributeName : AttributeNameType }


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
    { mfaConfiguration : Maybe UserPoolMfaType
    , smsMfaConfiguration : Maybe SmsMfaConfigType
    , softwareTokenMfaConfiguration : Maybe SoftwareTokenMfaConfigType
    }


{-| The GetUserRequest data model.
-}
type alias GetUserRequest =
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


{-| The HttpHeader data model.
-}
type alias HttpHeader =
    { headerName : Maybe StringType, headerValue : Maybe StringType }


{-| The HttpHeaderList data model.
-}
type alias HttpHeaderList =
    List HttpHeader


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
    { analyticsMetadata : Maybe AnalyticsMetadataType
    , authFlow : AuthFlowType
    , authParameters : Maybe AuthParametersType
    , clientId : ClientIdType
    , clientMetadata : Maybe ClientMetadataType
    , userContextData : Maybe UserContextDataType
    }


{-| The InitiateAuthResponse data model.
-}
type alias InitiateAuthResponse =
    { authenticationResult : Maybe AuthenticationResultType
    , challengeName : Maybe ChallengeNameType
    , challengeParameters : Maybe ChallengeParametersType
    , session : Maybe SessionType
    }


{-| The IntegerType data model.
-}
type alias IntegerType =
    Int


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


{-| The ListDevicesRequest data model.
-}
type alias ListDevicesRequest =
    { accessToken : TokenModelType, limit : Maybe QueryLimitType, paginationToken : Maybe SearchPaginationTokenType }


{-| The ListDevicesResponse data model.
-}
type alias ListDevicesResponse =
    { devices : Maybe DeviceListType, paginationToken : Maybe SearchPaginationTokenType }


{-| The ListGroupsRequest data model.
-}
type alias ListGroupsRequest =
    { limit : Maybe QueryLimitType, nextToken : Maybe PaginationKey, userPoolId : UserPoolIdType }


{-| The ListGroupsResponse data model.
-}
type alias ListGroupsResponse =
    { groups : Maybe GroupListType, nextToken : Maybe PaginationKey }


{-| The ListIdentityProvidersRequest data model.
-}
type alias ListIdentityProvidersRequest =
    { maxResults : Maybe ListProvidersLimitType, nextToken : Maybe PaginationKeyType, userPoolId : UserPoolIdType }


{-| The ListIdentityProvidersResponse data model.
-}
type alias ListIdentityProvidersResponse =
    { nextToken : Maybe PaginationKeyType, providers : ProvidersListType }


{-| The ListOfStringTypes data model.
-}
type alias ListOfStringTypes =
    List StringType


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


{-| The ListResourceServersRequest data model.
-}
type alias ListResourceServersRequest =
    { maxResults : Maybe ListResourceServersLimitType
    , nextToken : Maybe PaginationKeyType
    , userPoolId : UserPoolIdType
    }


{-| The ListResourceServersResponse data model.
-}
type alias ListResourceServersResponse =
    { nextToken : Maybe PaginationKeyType, resourceServers : ResourceServersListType }


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
    { maxResults : PoolQueryLimitType, paginationToken : Maybe PaginationKeyType, userPoolId : UserPoolIdType }


{-| The ListUserImportJobsResponse data model.
-}
type alias ListUserImportJobsResponse =
    { paginationToken : Maybe PaginationKeyType, userImportJobs : Maybe UserImportJobsListType }


{-| The ListUserPoolClientsRequest data model.
-}
type alias ListUserPoolClientsRequest =
    { maxResults : Maybe QueryLimit, nextToken : Maybe PaginationKey, userPoolId : UserPoolIdType }


{-| The ListUserPoolClientsResponse data model.
-}
type alias ListUserPoolClientsResponse =
    { nextToken : Maybe PaginationKey, userPoolClients : Maybe UserPoolClientListType }


{-| The ListUserPoolsRequest data model.
-}
type alias ListUserPoolsRequest =
    { maxResults : PoolQueryLimitType, nextToken : Maybe PaginationKeyType }


{-| The ListUserPoolsResponse data model.
-}
type alias ListUserPoolsResponse =
    { nextToken : Maybe PaginationKeyType, userPools : Maybe UserPoolListType }


{-| The ListUsersInGroupRequest data model.
-}
type alias ListUsersInGroupRequest =
    { groupName : GroupNameType
    , limit : Maybe QueryLimitType
    , nextToken : Maybe PaginationKey
    , userPoolId : UserPoolIdType
    }


{-| The ListUsersInGroupResponse data model.
-}
type alias ListUsersInGroupResponse =
    { nextToken : Maybe PaginationKey, users : Maybe UsersListType }


{-| The ListUsersRequest data model.
-}
type alias ListUsersRequest =
    { attributesToGet : Maybe SearchedAttributeNamesListType
    , filter : Maybe UserFilterType
    , limit : Maybe QueryLimitType
    , paginationToken : Maybe SearchPaginationTokenType
    , userPoolId : UserPoolIdType
    }


{-| The ListUsersResponse data model.
-}
type alias ListUsersResponse =
    { paginationToken : Maybe SearchPaginationTokenType, users : Maybe UsersListType }


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
    { attributeName : Maybe AttributeNameType, deliveryMedium : Maybe DeliveryMediumType }


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
    { emailMessage : Maybe EmailVerificationMessageType
    , emailSubject : Maybe EmailVerificationSubjectType
    , smsmessage : Maybe SmsVerificationMessageType
    }


{-| The NewDeviceMetadataType data model.
-}
type alias NewDeviceMetadataType =
    { deviceGroupKey : Maybe StringType, deviceKey : Maybe DeviceKeyType }


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


{-| The NotifyEmailType data model.
-}
type alias NotifyEmailType =
    { htmlBody : Maybe EmailNotificationBodyType
    , subject : EmailNotificationSubjectType
    , textBody : Maybe EmailNotificationBodyType
    }


{-| The NumberAttributeConstraintsType data model.
-}
type alias NumberAttributeConstraintsType =
    { maxValue : Maybe StringType, minValue : Maybe StringType }


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


{-| The ProviderDescription data model.
-}
type alias ProviderDescription =
    { creationDate : Maybe DateType
    , lastModifiedDate : Maybe DateType
    , providerName : Maybe ProviderNameType
    , providerType : Maybe IdentityProviderTypeType
    }


{-| The ProviderDetailsType data model.
-}
type alias ProviderDetailsType =
    Dict StringType StringType


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


{-| The ProviderUserIdentifierType data model.
-}
type alias ProviderUserIdentifierType =
    { providerAttributeName : Maybe StringType
    , providerAttributeValue : Maybe StringType
    , providerName : Maybe ProviderNameType
    }


{-| The ProvidersListType data model.
-}
type alias ProvidersListType =
    List ProviderDescription


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


{-| The ResendConfirmationCodeRequest data model.
-}
type alias ResendConfirmationCodeRequest =
    { analyticsMetadata : Maybe AnalyticsMetadataType
    , clientId : ClientIdType
    , secretHash : Maybe SecretHashType
    , userContextData : Maybe UserContextDataType
    , username : UsernameType
    }


{-| The ResendConfirmationCodeResponse data model.
-}
type alias ResendConfirmationCodeResponse =
    { codeDeliveryDetails : Maybe CodeDeliveryDetailsType }


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


{-| The ResourceServerScopeListType data model.
-}
type alias ResourceServerScopeListType =
    List ResourceServerScopeType


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


{-| The ResourceServerScopeType data model.
-}
type alias ResourceServerScopeType =
    { scopeDescription : ResourceServerScopeDescriptionType, scopeName : ResourceServerScopeNameType }


{-| The ResourceServerType data model.
-}
type alias ResourceServerType =
    { identifier : Maybe ResourceServerIdentifierType
    , name : Maybe ResourceServerNameType
    , scopes : Maybe ResourceServerScopeListType
    , userPoolId : Maybe UserPoolIdType
    }


{-| The ResourceServersListType data model.
-}
type alias ResourceServersListType =
    List ResourceServerType


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


{-| The RespondToAuthChallengeResponse data model.
-}
type alias RespondToAuthChallengeResponse =
    { authenticationResult : Maybe AuthenticationResultType
    , challengeName : Maybe ChallengeNameType
    , challengeParameters : Maybe ChallengeParametersType
    , session : Maybe SessionType
    }


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
    { blockedIprangeList : Maybe BlockedIprangeListType, skippedIprangeList : Maybe SkippedIprangeListType }


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


{-| The SmsmfaSettingsType data model.
-}
type alias SmsmfaSettingsType =
    { enabled : Maybe BooleanType, preferredMfa : Maybe BooleanType }


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


{-| The SchemaAttributesListType data model.
-}
type alias SchemaAttributesListType =
    List SchemaAttributeType


{-| The ScopeListType data model.
-}
type alias ScopeListType =
    List ScopeType


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


{-| The SearchedAttributeNamesListType data model.
-}
type alias SearchedAttributeNamesListType =
    List AttributeNameType


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


{-| The SetRiskConfigurationRequest data model.
-}
type alias SetRiskConfigurationRequest =
    { accountTakeoverRiskConfiguration : Maybe AccountTakeoverRiskConfigurationType
    , clientId : Maybe ClientIdType
    , compromisedCredentialsRiskConfiguration : Maybe CompromisedCredentialsRiskConfigurationType
    , riskExceptionConfiguration : Maybe RiskExceptionConfigurationType
    , userPoolId : UserPoolIdType
    }


{-| The SetRiskConfigurationResponse data model.
-}
type alias SetRiskConfigurationResponse =
    { riskConfiguration : RiskConfigurationType }


{-| The SetUicustomizationRequest data model.
-}
type alias SetUicustomizationRequest =
    { css : Maybe Csstype, clientId : Maybe ClientIdType, imageFile : Maybe ImageFileType, userPoolId : UserPoolIdType }


{-| The SetUicustomizationResponse data model.
-}
type alias SetUicustomizationResponse =
    { uicustomization : UicustomizationType }


{-| The SetUserMfapreferenceRequest data model.
-}
type alias SetUserMfapreferenceRequest =
    { accessToken : TokenModelType
    , smsmfaSettings : Maybe SmsmfaSettingsType
    , softwareTokenMfaSettings : Maybe SoftwareTokenMfaSettingsType
    }


{-| The SetUserMfapreferenceResponse data model.
-}
type alias SetUserMfapreferenceResponse =
    {}


{-| The SetUserPoolMfaConfigRequest data model.
-}
type alias SetUserPoolMfaConfigRequest =
    { mfaConfiguration : Maybe UserPoolMfaType
    , smsMfaConfiguration : Maybe SmsMfaConfigType
    , softwareTokenMfaConfiguration : Maybe SoftwareTokenMfaConfigType
    , userPoolId : UserPoolIdType
    }


{-| The SetUserPoolMfaConfigResponse data model.
-}
type alias SetUserPoolMfaConfigResponse =
    { mfaConfiguration : Maybe UserPoolMfaType
    , smsMfaConfiguration : Maybe SmsMfaConfigType
    , softwareTokenMfaConfiguration : Maybe SoftwareTokenMfaConfigType
    }


{-| The SetUserSettingsRequest data model.
-}
type alias SetUserSettingsRequest =
    { accessToken : TokenModelType, mfaoptions : MfaoptionListType }


{-| The SetUserSettingsResponse data model.
-}
type alias SetUserSettingsResponse =
    {}


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


{-| The SignUpResponse data model.
-}
type alias SignUpResponse =
    { codeDeliveryDetails : Maybe CodeDeliveryDetailsType, userConfirmed : BooleanType, userSub : StringType }


{-| The SkippedIprangeListType data model.
-}
type alias SkippedIprangeListType =
    List StringType


{-| The SmsConfigurationType data model.
-}
type alias SmsConfigurationType =
    { externalId : Maybe StringType, snsCallerArn : ArnType }


{-| The SmsMfaConfigType data model.
-}
type alias SmsMfaConfigType =
    { smsAuthenticationMessage : Maybe SmsVerificationMessageType, smsConfiguration : Maybe SmsConfigurationType }


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


{-| The SoftwareTokenMfaConfigType data model.
-}
type alias SoftwareTokenMfaConfigType =
    { enabled : Maybe BooleanType }


{-| The SoftwareTokenMfaSettingsType data model.
-}
type alias SoftwareTokenMfaSettingsType =
    { enabled : Maybe BooleanType, preferredMfa : Maybe BooleanType }


{-| The StartUserImportJobRequest data model.
-}
type alias StartUserImportJobRequest =
    { jobId : UserImportJobIdType, userPoolId : UserPoolIdType }


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
    { jobId : UserImportJobIdType, userPoolId : UserPoolIdType }


{-| The StopUserImportJobResponse data model.
-}
type alias StopUserImportJobResponse =
    { userImportJob : Maybe UserImportJobType }


{-| The StringAttributeConstraintsType data model.
-}
type alias StringAttributeConstraintsType =
    { maxLength : Maybe StringType, minLength : Maybe StringType }


{-| The StringType data model.
-}
type alias StringType =
    String


{-| The SupportedIdentityProvidersListType data model.
-}
type alias SupportedIdentityProvidersListType =
    List ProviderNameType


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


{-| The TagResourceRequest data model.
-}
type alias TagResourceRequest =
    { resourceArn : ArnType, tags : Maybe UserPoolTagsType }


{-| The TagResourceResponse data model.
-}
type alias TagResourceResponse =
    {}


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


{-| The UntagResourceRequest data model.
-}
type alias UntagResourceRequest =
    { resourceArn : ArnType, tagKeys : Maybe UserPoolTagsListType }


{-| The UntagResourceResponse data model.
-}
type alias UntagResourceResponse =
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


{-| The UpdateAuthEventFeedbackResponse data model.
-}
type alias UpdateAuthEventFeedbackResponse =
    {}


{-| The UpdateDeviceStatusRequest data model.
-}
type alias UpdateDeviceStatusRequest =
    { accessToken : TokenModelType
    , deviceKey : DeviceKeyType
    , deviceRememberedStatus : Maybe DeviceRememberedStatusType
    }


{-| The UpdateDeviceStatusResponse data model.
-}
type alias UpdateDeviceStatusResponse =
    {}


{-| The UpdateGroupRequest data model.
-}
type alias UpdateGroupRequest =
    { description : Maybe DescriptionType
    , groupName : GroupNameType
    , precedence : Maybe PrecedenceType
    , roleArn : Maybe ArnType
    , userPoolId : UserPoolIdType
    }


{-| The UpdateGroupResponse data model.
-}
type alias UpdateGroupResponse =
    { group : Maybe GroupType }


{-| The UpdateIdentityProviderRequest data model.
-}
type alias UpdateIdentityProviderRequest =
    { attributeMapping : Maybe AttributeMappingType
    , idpIdentifiers : Maybe IdpIdentifiersListType
    , providerDetails : Maybe ProviderDetailsType
    , providerName : ProviderNameType
    , userPoolId : UserPoolIdType
    }


{-| The UpdateIdentityProviderResponse data model.
-}
type alias UpdateIdentityProviderResponse =
    { identityProvider : IdentityProviderType }


{-| The UpdateResourceServerRequest data model.
-}
type alias UpdateResourceServerRequest =
    { identifier : ResourceServerIdentifierType
    , name : ResourceServerNameType
    , scopes : Maybe ResourceServerScopeListType
    , userPoolId : UserPoolIdType
    }


{-| The UpdateResourceServerResponse data model.
-}
type alias UpdateResourceServerResponse =
    { resourceServer : ResourceServerType }


{-| The UpdateUserAttributesRequest data model.
-}
type alias UpdateUserAttributesRequest =
    { accessToken : TokenModelType, userAttributes : AttributeListType }


{-| The UpdateUserAttributesResponse data model.
-}
type alias UpdateUserAttributesResponse =
    { codeDeliveryDetailsList : Maybe CodeDeliveryDetailsListType }


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


{-| The UpdateUserPoolClientResponse data model.
-}
type alias UpdateUserPoolClientResponse =
    { userPoolClient : Maybe UserPoolClientType }


{-| The UpdateUserPoolDomainRequest data model.
-}
type alias UpdateUserPoolDomainRequest =
    { customDomainConfig : CustomDomainConfigType, domain : DomainType, userPoolId : UserPoolIdType }


{-| The UpdateUserPoolDomainResponse data model.
-}
type alias UpdateUserPoolDomainResponse =
    { cloudFrontDomain : Maybe DomainType }


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


{-| The UpdateUserPoolResponse data model.
-}
type alias UpdateUserPoolResponse =
    {}


{-| The UserContextDataType data model.
-}
type alias UserContextDataType =
    { encodedData : Maybe StringType }


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


{-| The UserImportJobsListType data model.
-}
type alias UserImportJobsListType =
    List UserImportJobType


{-| The UserMfasettingListType data model.
-}
type alias UserMfasettingListType =
    List StringType


{-| The UserPoolAddOnsType data model.
-}
type alias UserPoolAddOnsType =
    { advancedSecurityMode : AdvancedSecurityModeType }


{-| The UserPoolClientDescription data model.
-}
type alias UserPoolClientDescription =
    { clientId : Maybe ClientIdType, clientName : Maybe ClientNameType, userPoolId : Maybe UserPoolIdType }


{-| The UserPoolClientListType data model.
-}
type alias UserPoolClientListType =
    List UserPoolClientDescription


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
    { attributes : Maybe AttributeListType
    , enabled : Maybe BooleanType
    , mfaoptions : Maybe MfaoptionListType
    , userCreateDate : Maybe DateType
    , userLastModifiedDate : Maybe DateType
    , userStatus : Maybe UserStatusType
    , username : Maybe UsernameType
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


{-| The UsersListType data model.
-}
type alias UsersListType =
    List UserType


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
    { accessToken : Maybe TokenModelType
    , friendlyDeviceName : Maybe StringType
    , session : Maybe SessionType
    , userCode : SoftwareTokenMfauserCodeType
    }


{-| The VerifySoftwareTokenResponse data model.
-}
type alias VerifySoftwareTokenResponse =
    { session : Maybe SessionType, status : Maybe VerifySoftwareTokenResponseType }


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
    { accessToken : TokenModelType, attributeName : AttributeNameType, code : ConfirmationCodeType }


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
        |> Codec.field "AccessToken" .accessToken tokenModelTypeCodec
        |> Codec.field "AttributeName" .attributeName attributeNameTypeCodec
        |> Codec.field "Code" .code confirmationCodeTypeCodec
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
        |> Codec.optionalField "Session" .session sessionTypeCodec
        |> Codec.optionalField "Status" .status verifySoftwareTokenResponseTypeCodec
        |> Codec.buildObject


{-| Codec for VerifySoftwareTokenRequest.
-}
verifySoftwareTokenRequestCodec : Codec VerifySoftwareTokenRequest
verifySoftwareTokenRequestCodec =
    Codec.object VerifySoftwareTokenRequest
        |> Codec.optionalField "AccessToken" .accessToken tokenModelTypeCodec
        |> Codec.optionalField "FriendlyDeviceName" .friendlyDeviceName stringTypeCodec
        |> Codec.optionalField "Session" .session sessionTypeCodec
        |> Codec.field "UserCode" .userCode softwareTokenMfauserCodeTypeCodec
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
        |> Codec.optionalField "DefaultEmailOption" .defaultEmailOption defaultEmailOptionTypeCodec
        |> Codec.optionalField "EmailMessage" .emailMessage emailVerificationMessageTypeCodec
        |> Codec.optionalField "EmailMessageByLink" .emailMessageByLink emailVerificationMessageByLinkTypeCodec
        |> Codec.optionalField "EmailSubject" .emailSubject emailVerificationSubjectTypeCodec
        |> Codec.optionalField "EmailSubjectByLink" .emailSubjectByLink emailVerificationSubjectByLinkTypeCodec
        |> Codec.optionalField "SmsMessage" .smsMessage smsVerificationMessageTypeCodec
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
        |> Codec.optionalField "Attributes" .attributes attributeListTypeCodec
        |> Codec.optionalField "Enabled" .enabled booleanTypeCodec
        |> Codec.optionalField "MFAOptions" .mfaoptions mfaoptionListTypeCodec
        |> Codec.optionalField "UserCreateDate" .userCreateDate dateTypeCodec
        |> Codec.optionalField "UserLastModifiedDate" .userLastModifiedDate dateTypeCodec
        |> Codec.optionalField "UserStatus" .userStatus userStatusTypeCodec
        |> Codec.optionalField "Username" .username usernameTypeCodec
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
        |> Codec.optionalField "AdminCreateUserConfig" .adminCreateUserConfig adminCreateUserConfigTypeCodec
        |> Codec.optionalField "AliasAttributes" .aliasAttributes aliasAttributesListTypeCodec
        |> Codec.optionalField "Arn" .arn arnTypeCodec
        |> Codec.optionalField "AutoVerifiedAttributes" .autoVerifiedAttributes verifiedAttributesListTypeCodec
        |> Codec.optionalField "CreationDate" .creationDate dateTypeCodec
        |> Codec.optionalField "CustomDomain" .customDomain domainTypeCodec
        |> Codec.optionalField "DeviceConfiguration" .deviceConfiguration deviceConfigurationTypeCodec
        |> Codec.optionalField "Domain" .domain domainTypeCodec
        |> Codec.optionalField "EmailConfiguration" .emailConfiguration emailConfigurationTypeCodec
        |> Codec.optionalField "EmailConfigurationFailure" .emailConfigurationFailure stringTypeCodec
        |> Codec.optionalField "EmailVerificationMessage" .emailVerificationMessage emailVerificationMessageTypeCodec
        |> Codec.optionalField "EmailVerificationSubject" .emailVerificationSubject emailVerificationSubjectTypeCodec
        |> Codec.optionalField "EstimatedNumberOfUsers" .estimatedNumberOfUsers integerTypeCodec
        |> Codec.optionalField "Id" .id userPoolIdTypeCodec
        |> Codec.optionalField "LambdaConfig" .lambdaConfig lambdaConfigTypeCodec
        |> Codec.optionalField "LastModifiedDate" .lastModifiedDate dateTypeCodec
        |> Codec.optionalField "MfaConfiguration" .mfaConfiguration userPoolMfaTypeCodec
        |> Codec.optionalField "Name" .name userPoolNameTypeCodec
        |> Codec.optionalField "Policies" .policies userPoolPolicyTypeCodec
        |> Codec.optionalField "SchemaAttributes" .schemaAttributes schemaAttributesListTypeCodec
        |> Codec.optionalField "SmsAuthenticationMessage" .smsAuthenticationMessage smsVerificationMessageTypeCodec
        |> Codec.optionalField "SmsConfiguration" .smsConfiguration smsConfigurationTypeCodec
        |> Codec.optionalField "SmsConfigurationFailure" .smsConfigurationFailure stringTypeCodec
        |> Codec.optionalField "SmsVerificationMessage" .smsVerificationMessage smsVerificationMessageTypeCodec
        |> Codec.optionalField "Status" .status statusTypeCodec
        |> Codec.optionalField "UserPoolAddOns" .userPoolAddOns userPoolAddOnsTypeCodec
        |> Codec.optionalField "UserPoolTags" .userPoolTags userPoolTagsTypeCodec
        |> Codec.optionalField "UsernameAttributes" .usernameAttributes usernameAttributesListTypeCodec
        |> Codec.optionalField
            "VerificationMessageTemplate"
            .verificationMessageTemplate
            verificationMessageTemplateTypeCodec
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
        |> Codec.optionalField "CreationDate" .creationDate dateTypeCodec
        |> Codec.optionalField "Id" .id userPoolIdTypeCodec
        |> Codec.optionalField "LambdaConfig" .lambdaConfig lambdaConfigTypeCodec
        |> Codec.optionalField "LastModifiedDate" .lastModifiedDate dateTypeCodec
        |> Codec.optionalField "Name" .name userPoolNameTypeCodec
        |> Codec.optionalField "Status" .status statusTypeCodec
        |> Codec.buildObject


{-| Codec for UserPoolClientType.
-}
userPoolClientTypeCodec : Codec UserPoolClientType
userPoolClientTypeCodec =
    Codec.object UserPoolClientType
        |> Codec.optionalField "AllowedOAuthFlows" .allowedOauthFlows oauthFlowsTypeCodec
        |> Codec.optionalField "AllowedOAuthFlowsUserPoolClient" .allowedOauthFlowsUserPoolClient booleanTypeCodec
        |> Codec.optionalField "AllowedOAuthScopes" .allowedOauthScopes scopeListTypeCodec
        |> Codec.optionalField "AnalyticsConfiguration" .analyticsConfiguration analyticsConfigurationTypeCodec
        |> Codec.optionalField "CallbackURLs" .callbackUrls callbackUrlsListTypeCodec
        |> Codec.optionalField "ClientId" .clientId clientIdTypeCodec
        |> Codec.optionalField "ClientName" .clientName clientNameTypeCodec
        |> Codec.optionalField "ClientSecret" .clientSecret clientSecretTypeCodec
        |> Codec.optionalField "CreationDate" .creationDate dateTypeCodec
        |> Codec.optionalField "DefaultRedirectURI" .defaultRedirectUri redirectUrlTypeCodec
        |> Codec.optionalField "ExplicitAuthFlows" .explicitAuthFlows explicitAuthFlowsListTypeCodec
        |> Codec.optionalField "LastModifiedDate" .lastModifiedDate dateTypeCodec
        |> Codec.optionalField "LogoutURLs" .logoutUrls logoutUrlsListTypeCodec
        |> Codec.optionalField "ReadAttributes" .readAttributes clientPermissionListTypeCodec
        |> Codec.optionalField "RefreshTokenValidity" .refreshTokenValidity refreshTokenValidityTypeCodec
        |> Codec.optionalField
            "SupportedIdentityProviders"
            .supportedIdentityProviders
            supportedIdentityProvidersListTypeCodec
        |> Codec.optionalField "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.optionalField "WriteAttributes" .writeAttributes clientPermissionListTypeCodec
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
        |> Codec.optionalField "ClientId" .clientId clientIdTypeCodec
        |> Codec.optionalField "ClientName" .clientName clientNameTypeCodec
        |> Codec.optionalField "UserPoolId" .userPoolId userPoolIdTypeCodec
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
    Codec.list stringTypeCodec


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
        |> Codec.optionalField "CloudWatchLogsRoleArn" .cloudWatchLogsRoleArn arnTypeCodec
        |> Codec.optionalField "CompletionDate" .completionDate dateTypeCodec
        |> Codec.optionalField "CompletionMessage" .completionMessage completionMessageTypeCodec
        |> Codec.optionalField "CreationDate" .creationDate dateTypeCodec
        |> Codec.optionalField "FailedUsers" .failedUsers longTypeCodec
        |> Codec.optionalField "ImportedUsers" .importedUsers longTypeCodec
        |> Codec.optionalField "JobId" .jobId userImportJobIdTypeCodec
        |> Codec.optionalField "JobName" .jobName userImportJobNameTypeCodec
        |> Codec.optionalField "PreSignedUrl" .preSignedUrl preSignedUrlTypeCodec
        |> Codec.optionalField "SkippedUsers" .skippedUsers longTypeCodec
        |> Codec.optionalField "StartDate" .startDate dateTypeCodec
        |> Codec.optionalField "Status" .status userImportJobStatusTypeCodec
        |> Codec.optionalField "UserPoolId" .userPoolId userPoolIdTypeCodec
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
    Codec.object UserContextDataType
        |> Codec.optionalField "EncodedData" .encodedData stringTypeCodec
        |> Codec.buildObject


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
        |> Codec.optionalField "AdminCreateUserConfig" .adminCreateUserConfig adminCreateUserConfigTypeCodec
        |> Codec.optionalField "AutoVerifiedAttributes" .autoVerifiedAttributes verifiedAttributesListTypeCodec
        |> Codec.optionalField "DeviceConfiguration" .deviceConfiguration deviceConfigurationTypeCodec
        |> Codec.optionalField "EmailConfiguration" .emailConfiguration emailConfigurationTypeCodec
        |> Codec.optionalField "EmailVerificationMessage" .emailVerificationMessage emailVerificationMessageTypeCodec
        |> Codec.optionalField "EmailVerificationSubject" .emailVerificationSubject emailVerificationSubjectTypeCodec
        |> Codec.optionalField "LambdaConfig" .lambdaConfig lambdaConfigTypeCodec
        |> Codec.optionalField "MfaConfiguration" .mfaConfiguration userPoolMfaTypeCodec
        |> Codec.optionalField "Policies" .policies userPoolPolicyTypeCodec
        |> Codec.optionalField "SmsAuthenticationMessage" .smsAuthenticationMessage smsVerificationMessageTypeCodec
        |> Codec.optionalField "SmsConfiguration" .smsConfiguration smsConfigurationTypeCodec
        |> Codec.optionalField "SmsVerificationMessage" .smsVerificationMessage smsVerificationMessageTypeCodec
        |> Codec.optionalField "UserPoolAddOns" .userPoolAddOns userPoolAddOnsTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.optionalField "UserPoolTags" .userPoolTags userPoolTagsTypeCodec
        |> Codec.optionalField
            "VerificationMessageTemplate"
            .verificationMessageTemplate
            verificationMessageTemplateTypeCodec
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
        |> Codec.field "CustomDomainConfig" .customDomainConfig customDomainConfigTypeCodec
        |> Codec.field "Domain" .domain domainTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
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
        |> Codec.optionalField "AllowedOAuthFlows" .allowedOauthFlows oauthFlowsTypeCodec
        |> Codec.optionalField "AllowedOAuthFlowsUserPoolClient" .allowedOauthFlowsUserPoolClient booleanTypeCodec
        |> Codec.optionalField "AllowedOAuthScopes" .allowedOauthScopes scopeListTypeCodec
        |> Codec.optionalField "AnalyticsConfiguration" .analyticsConfiguration analyticsConfigurationTypeCodec
        |> Codec.optionalField "CallbackURLs" .callbackUrls callbackUrlsListTypeCodec
        |> Codec.field "ClientId" .clientId clientIdTypeCodec
        |> Codec.optionalField "ClientName" .clientName clientNameTypeCodec
        |> Codec.optionalField "DefaultRedirectURI" .defaultRedirectUri redirectUrlTypeCodec
        |> Codec.optionalField "ExplicitAuthFlows" .explicitAuthFlows explicitAuthFlowsListTypeCodec
        |> Codec.optionalField "LogoutURLs" .logoutUrls logoutUrlsListTypeCodec
        |> Codec.optionalField "ReadAttributes" .readAttributes clientPermissionListTypeCodec
        |> Codec.optionalField "RefreshTokenValidity" .refreshTokenValidity refreshTokenValidityTypeCodec
        |> Codec.optionalField
            "SupportedIdentityProviders"
            .supportedIdentityProviders
            supportedIdentityProvidersListTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.optionalField "WriteAttributes" .writeAttributes clientPermissionListTypeCodec
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
        |> Codec.field "AccessToken" .accessToken tokenModelTypeCodec
        |> Codec.field "UserAttributes" .userAttributes attributeListTypeCodec
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
        |> Codec.field "Identifier" .identifier resourceServerIdentifierTypeCodec
        |> Codec.field "Name" .name resourceServerNameTypeCodec
        |> Codec.optionalField "Scopes" .scopes resourceServerScopeListTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
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
        |> Codec.optionalField "AttributeMapping" .attributeMapping attributeMappingTypeCodec
        |> Codec.optionalField "IdpIdentifiers" .idpIdentifiers idpIdentifiersListTypeCodec
        |> Codec.optionalField "ProviderDetails" .providerDetails providerDetailsTypeCodec
        |> Codec.field "ProviderName" .providerName providerNameTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
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
        |> Codec.optionalField "Description" .description descriptionTypeCodec
        |> Codec.field "GroupName" .groupName groupNameTypeCodec
        |> Codec.optionalField "Precedence" .precedence precedenceTypeCodec
        |> Codec.optionalField "RoleArn" .roleArn arnTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
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
        |> Codec.field "AccessToken" .accessToken tokenModelTypeCodec
        |> Codec.field "DeviceKey" .deviceKey deviceKeyTypeCodec
        |> Codec.optionalField "DeviceRememberedStatus" .deviceRememberedStatus deviceRememberedStatusTypeCodec
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
        |> Codec.field "EventId" .eventId eventIdTypeCodec
        |> Codec.field "FeedbackToken" .feedbackToken tokenModelTypeCodec
        |> Codec.field "FeedbackValue" .feedbackValue feedbackValueTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "Username" .username usernameTypeCodec
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
        |> Codec.field "ResourceArn" .resourceArn arnTypeCodec
        |> Codec.optionalField "TagKeys" .tagKeys userPoolTagsListTypeCodec
        |> Codec.buildObject


{-| Codec for UicustomizationType.
-}
uicustomizationTypeCodec : Codec UicustomizationType
uicustomizationTypeCodec =
    Codec.object UicustomizationType
        |> Codec.optionalField "CSS" .css csstypeCodec
        |> Codec.optionalField "CSSVersion" .cssversion cssversionTypeCodec
        |> Codec.optionalField "ClientId" .clientId clientIdTypeCodec
        |> Codec.optionalField "CreationDate" .creationDate dateTypeCodec
        |> Codec.optionalField "ImageUrl" .imageUrl imageUrlTypeCodec
        |> Codec.optionalField "LastModifiedDate" .lastModifiedDate dateTypeCodec
        |> Codec.optionalField "UserPoolId" .userPoolId userPoolIdTypeCodec
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
        |> Codec.field "ResourceArn" .resourceArn arnTypeCodec
        |> Codec.optionalField "Tags" .tags userPoolTagsTypeCodec
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
        |> Codec.optionalField "MaxLength" .maxLength stringTypeCodec
        |> Codec.optionalField "MinLength" .minLength stringTypeCodec
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
        |> Codec.field "JobId" .jobId userImportJobIdTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
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
        |> Codec.field "JobId" .jobId userImportJobIdTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.buildObject


{-| Codec for SoftwareTokenMfaSettingsType.
-}
softwareTokenMfaSettingsTypeCodec : Codec SoftwareTokenMfaSettingsType
softwareTokenMfaSettingsTypeCodec =
    Codec.object SoftwareTokenMfaSettingsType
        |> Codec.optionalField "Enabled" .enabled booleanTypeCodec
        |> Codec.optionalField "PreferredMfa" .preferredMfa booleanTypeCodec
        |> Codec.buildObject


{-| Codec for SoftwareTokenMfaConfigType.
-}
softwareTokenMfaConfigTypeCodec : Codec SoftwareTokenMfaConfigType
softwareTokenMfaConfigTypeCodec =
    Codec.object SoftwareTokenMfaConfigType
        |> Codec.optionalField "Enabled" .enabled booleanTypeCodec
        |> Codec.buildObject


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
        |> Codec.optionalField "SmsAuthenticationMessage" .smsAuthenticationMessage smsVerificationMessageTypeCodec
        |> Codec.optionalField "SmsConfiguration" .smsConfiguration smsConfigurationTypeCodec
        |> Codec.buildObject


{-| Codec for SmsConfigurationType.
-}
smsConfigurationTypeCodec : Codec SmsConfigurationType
smsConfigurationTypeCodec =
    Codec.object SmsConfigurationType
        |> Codec.optionalField "ExternalId" .externalId stringTypeCodec
        |> Codec.field "SnsCallerArn" .snsCallerArn arnTypeCodec
        |> Codec.buildObject


{-| Codec for SkippedIprangeListType.
-}
skippedIprangeListTypeCodec : Codec SkippedIprangeListType
skippedIprangeListTypeCodec =
    Codec.list stringTypeCodec


{-| Codec for SignUpResponse.
-}
signUpResponseCodec : Codec SignUpResponse
signUpResponseCodec =
    Codec.object SignUpResponse
        |> Codec.optionalField "CodeDeliveryDetails" .codeDeliveryDetails codeDeliveryDetailsTypeCodec
        |> Codec.field "UserConfirmed" .userConfirmed booleanTypeCodec
        |> Codec.field "UserSub" .userSub stringTypeCodec
        |> Codec.buildObject


{-| Codec for SignUpRequest.
-}
signUpRequestCodec : Codec SignUpRequest
signUpRequestCodec =
    Codec.object SignUpRequest
        |> Codec.optionalField "AnalyticsMetadata" .analyticsMetadata analyticsMetadataTypeCodec
        |> Codec.field "ClientId" .clientId clientIdTypeCodec
        |> Codec.field "Password" .password passwordTypeCodec
        |> Codec.optionalField "SecretHash" .secretHash secretHashTypeCodec
        |> Codec.optionalField "UserAttributes" .userAttributes attributeListTypeCodec
        |> Codec.optionalField "UserContextData" .userContextData userContextDataTypeCodec
        |> Codec.field "Username" .username usernameTypeCodec
        |> Codec.optionalField "ValidationData" .validationData attributeListTypeCodec
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
        |> Codec.field "AccessToken" .accessToken tokenModelTypeCodec
        |> Codec.field "MFAOptions" .mfaoptions mfaoptionListTypeCodec
        |> Codec.buildObject


{-| Codec for SetUserPoolMfaConfigResponse.
-}
setUserPoolMfaConfigResponseCodec : Codec SetUserPoolMfaConfigResponse
setUserPoolMfaConfigResponseCodec =
    Codec.object SetUserPoolMfaConfigResponse
        |> Codec.optionalField "MfaConfiguration" .mfaConfiguration userPoolMfaTypeCodec
        |> Codec.optionalField "SmsMfaConfiguration" .smsMfaConfiguration smsMfaConfigTypeCodec
        |> Codec.optionalField
            "SoftwareTokenMfaConfiguration"
            .softwareTokenMfaConfiguration
            softwareTokenMfaConfigTypeCodec
        |> Codec.buildObject


{-| Codec for SetUserPoolMfaConfigRequest.
-}
setUserPoolMfaConfigRequestCodec : Codec SetUserPoolMfaConfigRequest
setUserPoolMfaConfigRequestCodec =
    Codec.object SetUserPoolMfaConfigRequest
        |> Codec.optionalField "MfaConfiguration" .mfaConfiguration userPoolMfaTypeCodec
        |> Codec.optionalField "SmsMfaConfiguration" .smsMfaConfiguration smsMfaConfigTypeCodec
        |> Codec.optionalField
            "SoftwareTokenMfaConfiguration"
            .softwareTokenMfaConfiguration
            softwareTokenMfaConfigTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
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
        |> Codec.field "AccessToken" .accessToken tokenModelTypeCodec
        |> Codec.optionalField "SMSMfaSettings" .smsmfaSettings smsmfaSettingsTypeCodec
        |> Codec.optionalField "SoftwareTokenMfaSettings" .softwareTokenMfaSettings softwareTokenMfaSettingsTypeCodec
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
        |> Codec.optionalField "CSS" .css csstypeCodec
        |> Codec.optionalField "ClientId" .clientId clientIdTypeCodec
        |> Codec.optionalField "ImageFile" .imageFile imageFileTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
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
        |> Codec.optionalField
            "AccountTakeoverRiskConfiguration"
            .accountTakeoverRiskConfiguration
            accountTakeoverRiskConfigurationTypeCodec
        |> Codec.optionalField "ClientId" .clientId clientIdTypeCodec
        |> Codec.optionalField
            "CompromisedCredentialsRiskConfiguration"
            .compromisedCredentialsRiskConfiguration
            compromisedCredentialsRiskConfigurationTypeCodec
        |> Codec.optionalField
            "RiskExceptionConfiguration"
            .riskExceptionConfiguration
            riskExceptionConfigurationTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
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


{-| Codec for SmsmfaSettingsType.
-}
smsmfaSettingsTypeCodec : Codec SmsmfaSettingsType
smsmfaSettingsTypeCodec =
    Codec.object SmsmfaSettingsType
        |> Codec.optionalField "Enabled" .enabled booleanTypeCodec
        |> Codec.optionalField "PreferredMfa" .preferredMfa booleanTypeCodec
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
        |> Codec.optionalField "BlockedIPRangeList" .blockedIprangeList blockedIprangeListTypeCodec
        |> Codec.optionalField "SkippedIPRangeList" .skippedIprangeList skippedIprangeListTypeCodec
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
        |> Codec.optionalField
            "AccountTakeoverRiskConfiguration"
            .accountTakeoverRiskConfiguration
            accountTakeoverRiskConfigurationTypeCodec
        |> Codec.optionalField "ClientId" .clientId clientIdTypeCodec
        |> Codec.optionalField
            "CompromisedCredentialsRiskConfiguration"
            .compromisedCredentialsRiskConfiguration
            compromisedCredentialsRiskConfigurationTypeCodec
        |> Codec.optionalField "LastModifiedDate" .lastModifiedDate dateTypeCodec
        |> Codec.optionalField
            "RiskExceptionConfiguration"
            .riskExceptionConfiguration
            riskExceptionConfigurationTypeCodec
        |> Codec.optionalField "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.buildObject


{-| Codec for RespondToAuthChallengeResponse.
-}
respondToAuthChallengeResponseCodec : Codec RespondToAuthChallengeResponse
respondToAuthChallengeResponseCodec =
    Codec.object RespondToAuthChallengeResponse
        |> Codec.optionalField "AuthenticationResult" .authenticationResult authenticationResultTypeCodec
        |> Codec.optionalField "ChallengeName" .challengeName challengeNameTypeCodec
        |> Codec.optionalField "ChallengeParameters" .challengeParameters challengeParametersTypeCodec
        |> Codec.optionalField "Session" .session sessionTypeCodec
        |> Codec.buildObject


{-| Codec for RespondToAuthChallengeRequest.
-}
respondToAuthChallengeRequestCodec : Codec RespondToAuthChallengeRequest
respondToAuthChallengeRequestCodec =
    Codec.object RespondToAuthChallengeRequest
        |> Codec.optionalField "AnalyticsMetadata" .analyticsMetadata analyticsMetadataTypeCodec
        |> Codec.field "ChallengeName" .challengeName challengeNameTypeCodec
        |> Codec.optionalField "ChallengeResponses" .challengeResponses challengeResponsesTypeCodec
        |> Codec.field "ClientId" .clientId clientIdTypeCodec
        |> Codec.optionalField "Session" .session sessionTypeCodec
        |> Codec.optionalField "UserContextData" .userContextData userContextDataTypeCodec
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
        |> Codec.optionalField "Identifier" .identifier resourceServerIdentifierTypeCodec
        |> Codec.optionalField "Name" .name resourceServerNameTypeCodec
        |> Codec.optionalField "Scopes" .scopes resourceServerScopeListTypeCodec
        |> Codec.optionalField "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.buildObject


{-| Codec for ResourceServerScopeType.
-}
resourceServerScopeTypeCodec : Codec ResourceServerScopeType
resourceServerScopeTypeCodec =
    Codec.object ResourceServerScopeType
        |> Codec.field "ScopeDescription" .scopeDescription resourceServerScopeDescriptionTypeCodec
        |> Codec.field "ScopeName" .scopeName resourceServerScopeNameTypeCodec
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
        |> Codec.optionalField "AnalyticsMetadata" .analyticsMetadata analyticsMetadataTypeCodec
        |> Codec.field "ClientId" .clientId clientIdTypeCodec
        |> Codec.optionalField "SecretHash" .secretHash secretHashTypeCodec
        |> Codec.optionalField "UserContextData" .userContextData userContextDataTypeCodec
        |> Codec.field "Username" .username usernameTypeCodec
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
        |> Codec.optionalField "ProviderAttributeName" .providerAttributeName stringTypeCodec
        |> Codec.optionalField "ProviderAttributeValue" .providerAttributeValue stringTypeCodec
        |> Codec.optionalField "ProviderName" .providerName providerNameTypeCodec
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
    Codec.dict stringTypeCodec


{-| Codec for ProviderDescription.
-}
providerDescriptionCodec : Codec ProviderDescription
providerDescriptionCodec =
    Codec.object ProviderDescription
        |> Codec.optionalField "CreationDate" .creationDate dateTypeCodec
        |> Codec.optionalField "LastModifiedDate" .lastModifiedDate dateTypeCodec
        |> Codec.optionalField "ProviderName" .providerName providerNameTypeCodec
        |> Codec.optionalField "ProviderType" .providerType identityProviderTypeTypeCodec
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
        |> Codec.optionalField "MaxValue" .maxValue stringTypeCodec
        |> Codec.optionalField "MinValue" .minValue stringTypeCodec
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


{-| Codec for NewDeviceMetadataType.
-}
newDeviceMetadataTypeCodec : Codec NewDeviceMetadataType
newDeviceMetadataTypeCodec =
    Codec.object NewDeviceMetadataType
        |> Codec.optionalField "DeviceGroupKey" .deviceGroupKey stringTypeCodec
        |> Codec.optionalField "DeviceKey" .deviceKey deviceKeyTypeCodec
        |> Codec.buildObject


{-| Codec for MessageTemplateType.
-}
messageTemplateTypeCodec : Codec MessageTemplateType
messageTemplateTypeCodec =
    Codec.object MessageTemplateType
        |> Codec.optionalField "EmailMessage" .emailMessage emailVerificationMessageTypeCodec
        |> Codec.optionalField "EmailSubject" .emailSubject emailVerificationSubjectTypeCodec
        |> Codec.optionalField "SMSMessage" .smsmessage smsVerificationMessageTypeCodec
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
        |> Codec.optionalField "AttributeName" .attributeName attributeNameTypeCodec
        |> Codec.optionalField "DeliveryMedium" .deliveryMedium deliveryMediumTypeCodec
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
        |> Codec.optionalField "PaginationToken" .paginationToken searchPaginationTokenTypeCodec
        |> Codec.optionalField "Users" .users usersListTypeCodec
        |> Codec.buildObject


{-| Codec for ListUsersRequest.
-}
listUsersRequestCodec : Codec ListUsersRequest
listUsersRequestCodec =
    Codec.object ListUsersRequest
        |> Codec.optionalField "AttributesToGet" .attributesToGet searchedAttributeNamesListTypeCodec
        |> Codec.optionalField "Filter" .filter userFilterTypeCodec
        |> Codec.optionalField "Limit" .limit queryLimitTypeCodec
        |> Codec.optionalField "PaginationToken" .paginationToken searchPaginationTokenTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.buildObject


{-| Codec for ListUsersInGroupResponse.
-}
listUsersInGroupResponseCodec : Codec ListUsersInGroupResponse
listUsersInGroupResponseCodec =
    Codec.object ListUsersInGroupResponse
        |> Codec.optionalField "NextToken" .nextToken paginationKeyCodec
        |> Codec.optionalField "Users" .users usersListTypeCodec
        |> Codec.buildObject


{-| Codec for ListUsersInGroupRequest.
-}
listUsersInGroupRequestCodec : Codec ListUsersInGroupRequest
listUsersInGroupRequestCodec =
    Codec.object ListUsersInGroupRequest
        |> Codec.field "GroupName" .groupName groupNameTypeCodec
        |> Codec.optionalField "Limit" .limit queryLimitTypeCodec
        |> Codec.optionalField "NextToken" .nextToken paginationKeyCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.buildObject


{-| Codec for ListUserPoolsResponse.
-}
listUserPoolsResponseCodec : Codec ListUserPoolsResponse
listUserPoolsResponseCodec =
    Codec.object ListUserPoolsResponse
        |> Codec.optionalField "NextToken" .nextToken paginationKeyTypeCodec
        |> Codec.optionalField "UserPools" .userPools userPoolListTypeCodec
        |> Codec.buildObject


{-| Codec for ListUserPoolsRequest.
-}
listUserPoolsRequestCodec : Codec ListUserPoolsRequest
listUserPoolsRequestCodec =
    Codec.object ListUserPoolsRequest
        |> Codec.field "MaxResults" .maxResults poolQueryLimitTypeCodec
        |> Codec.optionalField "NextToken" .nextToken paginationKeyTypeCodec
        |> Codec.buildObject


{-| Codec for ListUserPoolClientsResponse.
-}
listUserPoolClientsResponseCodec : Codec ListUserPoolClientsResponse
listUserPoolClientsResponseCodec =
    Codec.object ListUserPoolClientsResponse
        |> Codec.optionalField "NextToken" .nextToken paginationKeyCodec
        |> Codec.optionalField "UserPoolClients" .userPoolClients userPoolClientListTypeCodec
        |> Codec.buildObject


{-| Codec for ListUserPoolClientsRequest.
-}
listUserPoolClientsRequestCodec : Codec ListUserPoolClientsRequest
listUserPoolClientsRequestCodec =
    Codec.object ListUserPoolClientsRequest
        |> Codec.optionalField "MaxResults" .maxResults queryLimitCodec
        |> Codec.optionalField "NextToken" .nextToken paginationKeyCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.buildObject


{-| Codec for ListUserImportJobsResponse.
-}
listUserImportJobsResponseCodec : Codec ListUserImportJobsResponse
listUserImportJobsResponseCodec =
    Codec.object ListUserImportJobsResponse
        |> Codec.optionalField "PaginationToken" .paginationToken paginationKeyTypeCodec
        |> Codec.optionalField "UserImportJobs" .userImportJobs userImportJobsListTypeCodec
        |> Codec.buildObject


{-| Codec for ListUserImportJobsRequest.
-}
listUserImportJobsRequestCodec : Codec ListUserImportJobsRequest
listUserImportJobsRequestCodec =
    Codec.object ListUserImportJobsRequest
        |> Codec.field "MaxResults" .maxResults poolQueryLimitTypeCodec
        |> Codec.optionalField "PaginationToken" .paginationToken paginationKeyTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
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
        |> Codec.optionalField "NextToken" .nextToken paginationKeyTypeCodec
        |> Codec.field "ResourceServers" .resourceServers resourceServersListTypeCodec
        |> Codec.buildObject


{-| Codec for ListResourceServersRequest.
-}
listResourceServersRequestCodec : Codec ListResourceServersRequest
listResourceServersRequestCodec =
    Codec.object ListResourceServersRequest
        |> Codec.optionalField "MaxResults" .maxResults listResourceServersLimitTypeCodec
        |> Codec.optionalField "NextToken" .nextToken paginationKeyTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
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
    Codec.list stringTypeCodec


{-| Codec for ListIdentityProvidersResponse.
-}
listIdentityProvidersResponseCodec : Codec ListIdentityProvidersResponse
listIdentityProvidersResponseCodec =
    Codec.object ListIdentityProvidersResponse
        |> Codec.optionalField "NextToken" .nextToken paginationKeyTypeCodec
        |> Codec.field "Providers" .providers providersListTypeCodec
        |> Codec.buildObject


{-| Codec for ListIdentityProvidersRequest.
-}
listIdentityProvidersRequestCodec : Codec ListIdentityProvidersRequest
listIdentityProvidersRequestCodec =
    Codec.object ListIdentityProvidersRequest
        |> Codec.optionalField "MaxResults" .maxResults listProvidersLimitTypeCodec
        |> Codec.optionalField "NextToken" .nextToken paginationKeyTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.buildObject


{-| Codec for ListGroupsResponse.
-}
listGroupsResponseCodec : Codec ListGroupsResponse
listGroupsResponseCodec =
    Codec.object ListGroupsResponse
        |> Codec.optionalField "Groups" .groups groupListTypeCodec
        |> Codec.optionalField "NextToken" .nextToken paginationKeyCodec
        |> Codec.buildObject


{-| Codec for ListGroupsRequest.
-}
listGroupsRequestCodec : Codec ListGroupsRequest
listGroupsRequestCodec =
    Codec.object ListGroupsRequest
        |> Codec.optionalField "Limit" .limit queryLimitTypeCodec
        |> Codec.optionalField "NextToken" .nextToken paginationKeyCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.buildObject


{-| Codec for ListDevicesResponse.
-}
listDevicesResponseCodec : Codec ListDevicesResponse
listDevicesResponseCodec =
    Codec.object ListDevicesResponse
        |> Codec.optionalField "Devices" .devices deviceListTypeCodec
        |> Codec.optionalField "PaginationToken" .paginationToken searchPaginationTokenTypeCodec
        |> Codec.buildObject


{-| Codec for ListDevicesRequest.
-}
listDevicesRequestCodec : Codec ListDevicesRequest
listDevicesRequestCodec =
    Codec.object ListDevicesRequest
        |> Codec.field "AccessToken" .accessToken tokenModelTypeCodec
        |> Codec.optionalField "Limit" .limit queryLimitTypeCodec
        |> Codec.optionalField "PaginationToken" .paginationToken searchPaginationTokenTypeCodec
        |> Codec.buildObject


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
        |> Codec.optionalField "AuthenticationResult" .authenticationResult authenticationResultTypeCodec
        |> Codec.optionalField "ChallengeName" .challengeName challengeNameTypeCodec
        |> Codec.optionalField "ChallengeParameters" .challengeParameters challengeParametersTypeCodec
        |> Codec.optionalField "Session" .session sessionTypeCodec
        |> Codec.buildObject


{-| Codec for InitiateAuthRequest.
-}
initiateAuthRequestCodec : Codec InitiateAuthRequest
initiateAuthRequestCodec =
    Codec.object InitiateAuthRequest
        |> Codec.optionalField "AnalyticsMetadata" .analyticsMetadata analyticsMetadataTypeCodec
        |> Codec.field "AuthFlow" .authFlow authFlowTypeCodec
        |> Codec.optionalField "AuthParameters" .authParameters authParametersTypeCodec
        |> Codec.field "ClientId" .clientId clientIdTypeCodec
        |> Codec.optionalField "ClientMetadata" .clientMetadata clientMetadataTypeCodec
        |> Codec.optionalField "UserContextData" .userContextData userContextDataTypeCodec
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
        |> Codec.optionalField "AttributeMapping" .attributeMapping attributeMappingTypeCodec
        |> Codec.optionalField "CreationDate" .creationDate dateTypeCodec
        |> Codec.optionalField "IdpIdentifiers" .idpIdentifiers idpIdentifiersListTypeCodec
        |> Codec.optionalField "LastModifiedDate" .lastModifiedDate dateTypeCodec
        |> Codec.optionalField "ProviderDetails" .providerDetails providerDetailsTypeCodec
        |> Codec.optionalField "ProviderName" .providerName providerNameTypeCodec
        |> Codec.optionalField "ProviderType" .providerType identityProviderTypeTypeCodec
        |> Codec.optionalField "UserPoolId" .userPoolId userPoolIdTypeCodec
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
        |> Codec.optionalField "headerName" .headerName stringTypeCodec
        |> Codec.optionalField "headerValue" .headerValue stringTypeCodec
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
        |> Codec.optionalField "CreationDate" .creationDate dateTypeCodec
        |> Codec.optionalField "Description" .description descriptionTypeCodec
        |> Codec.optionalField "GroupName" .groupName groupNameTypeCodec
        |> Codec.optionalField "LastModifiedDate" .lastModifiedDate dateTypeCodec
        |> Codec.optionalField "Precedence" .precedence precedenceTypeCodec
        |> Codec.optionalField "RoleArn" .roleArn arnTypeCodec
        |> Codec.optionalField "UserPoolId" .userPoolId userPoolIdTypeCodec
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
        |> Codec.optionalField "MFAOptions" .mfaoptions mfaoptionListTypeCodec
        |> Codec.optionalField "PreferredMfaSetting" .preferredMfaSetting stringTypeCodec
        |> Codec.field "UserAttributes" .userAttributes attributeListTypeCodec
        |> Codec.optionalField "UserMFASettingList" .userMfasettingList userMfasettingListTypeCodec
        |> Codec.field "Username" .username usernameTypeCodec
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
        |> Codec.optionalField "MfaConfiguration" .mfaConfiguration userPoolMfaTypeCodec
        |> Codec.optionalField "SmsMfaConfiguration" .smsMfaConfiguration smsMfaConfigTypeCodec
        |> Codec.optionalField
            "SoftwareTokenMfaConfiguration"
            .softwareTokenMfaConfiguration
            softwareTokenMfaConfigTypeCodec
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
        |> Codec.field "AccessToken" .accessToken tokenModelTypeCodec
        |> Codec.field "AttributeName" .attributeName attributeNameTypeCodec
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
        |> Codec.optionalField "ClientId" .clientId clientIdTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.buildObject


{-| Codec for GetSigningCertificateResponse.
-}
getSigningCertificateResponseCodec : Codec GetSigningCertificateResponse
getSigningCertificateResponseCodec =
    Codec.object GetSigningCertificateResponse
        |> Codec.optionalField "Certificate" .certificate stringTypeCodec
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
        |> Codec.field "IdpIdentifier" .idpIdentifier idpIdentifierTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
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
        |> Codec.field "GroupName" .groupName groupNameTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
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
        |> Codec.optionalField "AccessToken" .accessToken tokenModelTypeCodec
        |> Codec.field "DeviceKey" .deviceKey deviceKeyTypeCodec
        |> Codec.buildObject


{-| Codec for GetCsvheaderResponse.
-}
getCsvheaderResponseCodec : Codec GetCsvheaderResponse
getCsvheaderResponseCodec =
    Codec.object GetCsvheaderResponse
        |> Codec.optionalField "CSVHeader" .csvheader listOfStringTypesCodec
        |> Codec.optionalField "UserPoolId" .userPoolId userPoolIdTypeCodec
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
        |> Codec.optionalField "AnalyticsMetadata" .analyticsMetadata analyticsMetadataTypeCodec
        |> Codec.field "ClientId" .clientId clientIdTypeCodec
        |> Codec.optionalField "SecretHash" .secretHash secretHashTypeCodec
        |> Codec.optionalField "UserContextData" .userContextData userContextDataTypeCodec
        |> Codec.field "Username" .username usernameTypeCodec
        |> Codec.buildObject


{-| Codec for ForgetDeviceRequest.
-}
forgetDeviceRequestCodec : Codec ForgetDeviceRequest
forgetDeviceRequestCodec =
    Codec.object ForgetDeviceRequest
        |> Codec.optionalField "AccessToken" .accessToken tokenModelTypeCodec
        |> Codec.field "DeviceKey" .deviceKey deviceKeyTypeCodec
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
        |> Codec.optionalField "RiskDecision" .riskDecision riskDecisionTypeCodec
        |> Codec.optionalField "RiskLevel" .riskLevel riskLevelTypeCodec
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
        |> Codec.optionalField "FeedbackDate" .feedbackDate dateTypeCodec
        |> Codec.field "FeedbackValue" .feedbackValue feedbackValueTypeCodec
        |> Codec.field "Provider" .provider stringTypeCodec
        |> Codec.buildObject


{-| Codec for EventContextDataType.
-}
eventContextDataTypeCodec : Codec EventContextDataType
eventContextDataTypeCodec =
    Codec.object EventContextDataType
        |> Codec.optionalField "City" .city stringTypeCodec
        |> Codec.optionalField "Country" .country stringTypeCodec
        |> Codec.optionalField "DeviceName" .deviceName stringTypeCodec
        |> Codec.optionalField "IpAddress" .ipAddress stringTypeCodec
        |> Codec.optionalField "Timezone" .timezone stringTypeCodec
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
        |> Codec.optionalField "EmailSendingAccount" .emailSendingAccount emailSendingAccountTypeCodec
        |> Codec.optionalField "ReplyToEmailAddress" .replyToEmailAddress emailAddressTypeCodec
        |> Codec.optionalField "SourceArn" .sourceArn arnTypeCodec
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
        |> Codec.optionalField "AWSAccountId" .awsaccountId awsaccountIdTypeCodec
        |> Codec.optionalField "CloudFrontDistribution" .cloudFrontDistribution stringTypeCodec
        |> Codec.optionalField "CustomDomainConfig" .customDomainConfig customDomainConfigTypeCodec
        |> Codec.optionalField "Domain" .domain domainTypeCodec
        |> Codec.optionalField "S3Bucket" .s3Bucket s3BucketTypeCodec
        |> Codec.optionalField "Status" .status domainStatusTypeCodec
        |> Codec.optionalField "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.optionalField "Version" .version domainVersionTypeCodec
        |> Codec.buildObject


{-| Codec for DeviceType.
-}
deviceTypeCodec : Codec DeviceType
deviceTypeCodec =
    Codec.object DeviceType
        |> Codec.optionalField "DeviceAttributes" .deviceAttributes attributeListTypeCodec
        |> Codec.optionalField "DeviceCreateDate" .deviceCreateDate dateTypeCodec
        |> Codec.optionalField "DeviceKey" .deviceKey deviceKeyTypeCodec
        |> Codec.optionalField "DeviceLastAuthenticatedDate" .deviceLastAuthenticatedDate dateTypeCodec
        |> Codec.optionalField "DeviceLastModifiedDate" .deviceLastModifiedDate dateTypeCodec
        |> Codec.buildObject


{-| Codec for DeviceSecretVerifierConfigType.
-}
deviceSecretVerifierConfigTypeCodec : Codec DeviceSecretVerifierConfigType
deviceSecretVerifierConfigTypeCodec =
    Codec.object DeviceSecretVerifierConfigType
        |> Codec.optionalField "PasswordVerifier" .passwordVerifier stringTypeCodec
        |> Codec.optionalField "Salt" .salt stringTypeCodec
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
        |> Codec.optionalField "ChallengeRequiredOnNewDevice" .challengeRequiredOnNewDevice booleanTypeCodec
        |> Codec.optionalField "DeviceOnlyRememberedOnUserPrompt" .deviceOnlyRememberedOnUserPrompt booleanTypeCodec
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
        |> Codec.field "ClientId" .clientId clientIdTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
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
        |> Codec.field "JobId" .jobId userImportJobIdTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
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
        |> Codec.optionalField "ClientId" .clientId clientIdTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
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
        |> Codec.field "Identifier" .identifier resourceServerIdentifierTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
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
        |> Codec.field "ProviderName" .providerName providerNameTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
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
        |> Codec.field "Domain" .domain domainTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.buildObject


{-| Codec for DeleteUserPoolClientRequest.
-}
deleteUserPoolClientRequestCodec : Codec DeleteUserPoolClientRequest
deleteUserPoolClientRequestCodec =
    Codec.object DeleteUserPoolClientRequest
        |> Codec.field "ClientId" .clientId clientIdTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
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
        |> Codec.field "AccessToken" .accessToken tokenModelTypeCodec
        |> Codec.field "UserAttributeNames" .userAttributeNames attributeNameListTypeCodec
        |> Codec.buildObject


{-| Codec for DeleteResourceServerRequest.
-}
deleteResourceServerRequestCodec : Codec DeleteResourceServerRequest
deleteResourceServerRequestCodec =
    Codec.object DeleteResourceServerRequest
        |> Codec.field "Identifier" .identifier resourceServerIdentifierTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.buildObject


{-| Codec for DeleteIdentityProviderRequest.
-}
deleteIdentityProviderRequestCodec : Codec DeleteIdentityProviderRequest
deleteIdentityProviderRequestCodec =
    Codec.object DeleteIdentityProviderRequest
        |> Codec.field "ProviderName" .providerName providerNameTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.buildObject


{-| Codec for DeleteGroupRequest.
-}
deleteGroupRequestCodec : Codec DeleteGroupRequest
deleteGroupRequestCodec =
    Codec.object DeleteGroupRequest
        |> Codec.field "GroupName" .groupName groupNameTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
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
        |> Codec.optionalField "AdminCreateUserConfig" .adminCreateUserConfig adminCreateUserConfigTypeCodec
        |> Codec.optionalField "AliasAttributes" .aliasAttributes aliasAttributesListTypeCodec
        |> Codec.optionalField "AutoVerifiedAttributes" .autoVerifiedAttributes verifiedAttributesListTypeCodec
        |> Codec.optionalField "DeviceConfiguration" .deviceConfiguration deviceConfigurationTypeCodec
        |> Codec.optionalField "EmailConfiguration" .emailConfiguration emailConfigurationTypeCodec
        |> Codec.optionalField "EmailVerificationMessage" .emailVerificationMessage emailVerificationMessageTypeCodec
        |> Codec.optionalField "EmailVerificationSubject" .emailVerificationSubject emailVerificationSubjectTypeCodec
        |> Codec.optionalField "LambdaConfig" .lambdaConfig lambdaConfigTypeCodec
        |> Codec.optionalField "MfaConfiguration" .mfaConfiguration userPoolMfaTypeCodec
        |> Codec.optionalField "Policies" .policies userPoolPolicyTypeCodec
        |> Codec.field "PoolName" .poolName userPoolNameTypeCodec
        |> Codec.optionalField "Schema" .schema schemaAttributesListTypeCodec
        |> Codec.optionalField "SmsAuthenticationMessage" .smsAuthenticationMessage smsVerificationMessageTypeCodec
        |> Codec.optionalField "SmsConfiguration" .smsConfiguration smsConfigurationTypeCodec
        |> Codec.optionalField "SmsVerificationMessage" .smsVerificationMessage smsVerificationMessageTypeCodec
        |> Codec.optionalField "UserPoolAddOns" .userPoolAddOns userPoolAddOnsTypeCodec
        |> Codec.optionalField "UserPoolTags" .userPoolTags userPoolTagsTypeCodec
        |> Codec.optionalField "UsernameAttributes" .usernameAttributes usernameAttributesListTypeCodec
        |> Codec.optionalField
            "VerificationMessageTemplate"
            .verificationMessageTemplate
            verificationMessageTemplateTypeCodec
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
        |> Codec.optionalField "CustomDomainConfig" .customDomainConfig customDomainConfigTypeCodec
        |> Codec.field "Domain" .domain domainTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
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
        |> Codec.optionalField "AllowedOAuthFlows" .allowedOauthFlows oauthFlowsTypeCodec
        |> Codec.optionalField "AllowedOAuthFlowsUserPoolClient" .allowedOauthFlowsUserPoolClient booleanTypeCodec
        |> Codec.optionalField "AllowedOAuthScopes" .allowedOauthScopes scopeListTypeCodec
        |> Codec.optionalField "AnalyticsConfiguration" .analyticsConfiguration analyticsConfigurationTypeCodec
        |> Codec.optionalField "CallbackURLs" .callbackUrls callbackUrlsListTypeCodec
        |> Codec.field "ClientName" .clientName clientNameTypeCodec
        |> Codec.optionalField "DefaultRedirectURI" .defaultRedirectUri redirectUrlTypeCodec
        |> Codec.optionalField "ExplicitAuthFlows" .explicitAuthFlows explicitAuthFlowsListTypeCodec
        |> Codec.optionalField "GenerateSecret" .generateSecret generateSecretCodec
        |> Codec.optionalField "LogoutURLs" .logoutUrls logoutUrlsListTypeCodec
        |> Codec.optionalField "ReadAttributes" .readAttributes clientPermissionListTypeCodec
        |> Codec.optionalField "RefreshTokenValidity" .refreshTokenValidity refreshTokenValidityTypeCodec
        |> Codec.optionalField
            "SupportedIdentityProviders"
            .supportedIdentityProviders
            supportedIdentityProvidersListTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.optionalField "WriteAttributes" .writeAttributes clientPermissionListTypeCodec
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
        |> Codec.field "CloudWatchLogsRoleArn" .cloudWatchLogsRoleArn arnTypeCodec
        |> Codec.field "JobName" .jobName userImportJobNameTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
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
        |> Codec.field "Identifier" .identifier resourceServerIdentifierTypeCodec
        |> Codec.field "Name" .name resourceServerNameTypeCodec
        |> Codec.optionalField "Scopes" .scopes resourceServerScopeListTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
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
        |> Codec.optionalField "AttributeMapping" .attributeMapping attributeMappingTypeCodec
        |> Codec.optionalField "IdpIdentifiers" .idpIdentifiers idpIdentifiersListTypeCodec
        |> Codec.field "ProviderDetails" .providerDetails providerDetailsTypeCodec
        |> Codec.field "ProviderName" .providerName providerNameTypeV1Codec
        |> Codec.field "ProviderType" .providerType identityProviderTypeTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
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
        |> Codec.optionalField "Description" .description descriptionTypeCodec
        |> Codec.field "GroupName" .groupName groupNameTypeCodec
        |> Codec.optionalField "Precedence" .precedence precedenceTypeCodec
        |> Codec.optionalField "RoleArn" .roleArn arnTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.buildObject


{-| Codec for ContextDataType.
-}
contextDataTypeCodec : Codec ContextDataType
contextDataTypeCodec =
    Codec.object ContextDataType
        |> Codec.optionalField "EncodedData" .encodedData stringTypeCodec
        |> Codec.field "HttpHeaders" .httpHeaders httpHeaderListCodec
        |> Codec.field "IpAddress" .ipAddress stringTypeCodec
        |> Codec.field "ServerName" .serverName stringTypeCodec
        |> Codec.field "ServerPath" .serverPath stringTypeCodec
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
        |> Codec.optionalField "AnalyticsMetadata" .analyticsMetadata analyticsMetadataTypeCodec
        |> Codec.field "ClientId" .clientId clientIdTypeCodec
        |> Codec.field "ConfirmationCode" .confirmationCode confirmationCodeTypeCodec
        |> Codec.optionalField "ForceAliasCreation" .forceAliasCreation forceAliasCreationCodec
        |> Codec.optionalField "SecretHash" .secretHash secretHashTypeCodec
        |> Codec.optionalField "UserContextData" .userContextData userContextDataTypeCodec
        |> Codec.field "Username" .username usernameTypeCodec
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
        |> Codec.optionalField "AnalyticsMetadata" .analyticsMetadata analyticsMetadataTypeCodec
        |> Codec.field "ClientId" .clientId clientIdTypeCodec
        |> Codec.field "ConfirmationCode" .confirmationCode confirmationCodeTypeCodec
        |> Codec.field "Password" .password passwordTypeCodec
        |> Codec.optionalField "SecretHash" .secretHash secretHashTypeCodec
        |> Codec.optionalField "UserContextData" .userContextData userContextDataTypeCodec
        |> Codec.field "Username" .username usernameTypeCodec
        |> Codec.buildObject


{-| Codec for ConfirmDeviceResponse.
-}
confirmDeviceResponseCodec : Codec ConfirmDeviceResponse
confirmDeviceResponseCodec =
    Codec.object ConfirmDeviceResponse
        |> Codec.optionalField "UserConfirmationNecessary" .userConfirmationNecessary booleanTypeCodec
        |> Codec.buildObject


{-| Codec for ConfirmDeviceRequest.
-}
confirmDeviceRequestCodec : Codec ConfirmDeviceRequest
confirmDeviceRequestCodec =
    Codec.object ConfirmDeviceRequest
        |> Codec.field "AccessToken" .accessToken tokenModelTypeCodec
        |> Codec.field "DeviceKey" .deviceKey deviceKeyTypeCodec
        |> Codec.optionalField "DeviceName" .deviceName deviceNameTypeCodec
        |> Codec.optionalField
            "DeviceSecretVerifierConfig"
            .deviceSecretVerifierConfig
            deviceSecretVerifierConfigTypeCodec
        |> Codec.buildObject


{-| Codec for CompromisedCredentialsRiskConfigurationType.
-}
compromisedCredentialsRiskConfigurationTypeCodec : Codec CompromisedCredentialsRiskConfigurationType
compromisedCredentialsRiskConfigurationTypeCodec =
    Codec.object CompromisedCredentialsRiskConfigurationType
        |> Codec.field "Actions" .actions compromisedCredentialsActionsTypeCodec
        |> Codec.optionalField "EventFilter" .eventFilter eventFiltersTypeCodec
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
        |> Codec.optionalField "AttributeName" .attributeName attributeNameTypeCodec
        |> Codec.optionalField "DeliveryMedium" .deliveryMedium deliveryMediumTypeCodec
        |> Codec.optionalField "Destination" .destination stringTypeCodec
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
    Codec.dict stringTypeCodec


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
        |> Codec.field "AccessToken" .accessToken tokenModelTypeCodec
        |> Codec.field "PreviousPassword" .previousPassword passwordTypeCodec
        |> Codec.field "ProposedPassword" .proposedPassword passwordTypeCodec
        |> Codec.buildObject


{-| Codec for ChallengeResponsesType.
-}
challengeResponsesTypeCodec : Codec ChallengeResponsesType
challengeResponsesTypeCodec =
    Codec.dict stringTypeCodec


{-| Codec for ChallengeResponseType.
-}
challengeResponseTypeCodec : Codec ChallengeResponseType
challengeResponseTypeCodec =
    Codec.object ChallengeResponseType
        |> Codec.optionalField "ChallengeName" .challengeName challengeNameCodec
        |> Codec.optionalField "ChallengeResponse" .challengeResponse challengeResponseCodec
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
    Codec.dict stringTypeCodec


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
    Codec.list stringTypeCodec


{-| Codec for AuthenticationResultType.
-}
authenticationResultTypeCodec : Codec AuthenticationResultType
authenticationResultTypeCodec =
    Codec.object AuthenticationResultType
        |> Codec.optionalField "AccessToken" .accessToken tokenModelTypeCodec
        |> Codec.optionalField "ExpiresIn" .expiresIn integerTypeCodec
        |> Codec.optionalField "IdToken" .idToken tokenModelTypeCodec
        |> Codec.optionalField "NewDeviceMetadata" .newDeviceMetadata newDeviceMetadataTypeCodec
        |> Codec.optionalField "RefreshToken" .refreshToken tokenModelTypeCodec
        |> Codec.optionalField "TokenType" .tokenType stringTypeCodec
        |> Codec.buildObject


{-| Codec for AuthParametersType.
-}
authParametersTypeCodec : Codec AuthParametersType
authParametersTypeCodec =
    Codec.dict stringTypeCodec


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
        |> Codec.optionalField "ChallengeResponses" .challengeResponses challengeResponseListTypeCodec
        |> Codec.optionalField "CreationDate" .creationDate dateTypeCodec
        |> Codec.optionalField "EventContextData" .eventContextData eventContextDataTypeCodec
        |> Codec.optionalField "EventFeedback" .eventFeedback eventFeedbackTypeCodec
        |> Codec.optionalField "EventId" .eventId stringTypeCodec
        |> Codec.optionalField "EventResponse" .eventResponse eventResponseTypeCodec
        |> Codec.optionalField "EventRisk" .eventRisk eventRiskTypeCodec
        |> Codec.optionalField "EventType" .eventType eventTypeCodec
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
        |> Codec.field "Name" .name attributeNameTypeCodec
        |> Codec.optionalField "Value" .value attributeValueTypeCodec
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
        (Refined.dictEncoder attributeMappingKeyType (Codec.encoder stringTypeCodec))
        (Refined.dictDecoder attributeMappingKeyType (Codec.decoder stringTypeCodec))


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
        |> Codec.optionalField "SecretCode" .secretCode secretCodeTypeCodec
        |> Codec.optionalField "Session" .session sessionTypeCodec
        |> Codec.buildObject


{-| Codec for AssociateSoftwareTokenRequest.
-}
associateSoftwareTokenRequestCodec : Codec AssociateSoftwareTokenRequest
associateSoftwareTokenRequestCodec =
    Codec.object AssociateSoftwareTokenRequest
        |> Codec.optionalField "AccessToken" .accessToken tokenModelTypeCodec
        |> Codec.optionalField "Session" .session sessionTypeCodec
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
        |> Codec.optionalField "AnalyticsEndpointId" .analyticsEndpointId stringTypeCodec
        |> Codec.buildObject


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
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "Username" .username usernameTypeCodec
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
        |> Codec.field "UserAttributes" .userAttributes attributeListTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "Username" .username usernameTypeCodec
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
        |> Codec.field "DeviceKey" .deviceKey deviceKeyTypeCodec
        |> Codec.optionalField "DeviceRememberedStatus" .deviceRememberedStatus deviceRememberedStatusTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "Username" .username usernameTypeCodec
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
        |> Codec.field "EventId" .eventId eventIdTypeCodec
        |> Codec.field "FeedbackValue" .feedbackValue feedbackValueTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "Username" .username usernameTypeCodec
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
        |> Codec.field "MFAOptions" .mfaoptions mfaoptionListTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "Username" .username usernameTypeCodec
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
        |> Codec.field "Password" .password passwordTypeCodec
        |> Codec.optionalField "Permanent" .permanent booleanTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "Username" .username usernameTypeCodec
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
        |> Codec.optionalField "SMSMfaSettings" .smsmfaSettings smsmfaSettingsTypeCodec
        |> Codec.optionalField "SoftwareTokenMfaSettings" .softwareTokenMfaSettings softwareTokenMfaSettingsTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "Username" .username usernameTypeCodec
        |> Codec.buildObject


{-| Codec for AdminRespondToAuthChallengeResponse.
-}
adminRespondToAuthChallengeResponseCodec : Codec AdminRespondToAuthChallengeResponse
adminRespondToAuthChallengeResponseCodec =
    Codec.object AdminRespondToAuthChallengeResponse
        |> Codec.optionalField "AuthenticationResult" .authenticationResult authenticationResultTypeCodec
        |> Codec.optionalField "ChallengeName" .challengeName challengeNameTypeCodec
        |> Codec.optionalField "ChallengeParameters" .challengeParameters challengeParametersTypeCodec
        |> Codec.optionalField "Session" .session sessionTypeCodec
        |> Codec.buildObject


{-| Codec for AdminRespondToAuthChallengeRequest.
-}
adminRespondToAuthChallengeRequestCodec : Codec AdminRespondToAuthChallengeRequest
adminRespondToAuthChallengeRequestCodec =
    Codec.object AdminRespondToAuthChallengeRequest
        |> Codec.optionalField "AnalyticsMetadata" .analyticsMetadata analyticsMetadataTypeCodec
        |> Codec.field "ChallengeName" .challengeName challengeNameTypeCodec
        |> Codec.optionalField "ChallengeResponses" .challengeResponses challengeResponsesTypeCodec
        |> Codec.field "ClientId" .clientId clientIdTypeCodec
        |> Codec.optionalField "ContextData" .contextData contextDataTypeCodec
        |> Codec.optionalField "Session" .session sessionTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
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
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "Username" .username usernameTypeCodec
        |> Codec.buildObject


{-| Codec for AdminRemoveUserFromGroupRequest.
-}
adminRemoveUserFromGroupRequestCodec : Codec AdminRemoveUserFromGroupRequest
adminRemoveUserFromGroupRequestCodec =
    Codec.object AdminRemoveUserFromGroupRequest
        |> Codec.field "GroupName" .groupName groupNameTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "Username" .username usernameTypeCodec
        |> Codec.buildObject


{-| Codec for AdminListUserAuthEventsResponse.
-}
adminListUserAuthEventsResponseCodec : Codec AdminListUserAuthEventsResponse
adminListUserAuthEventsResponseCodec =
    Codec.object AdminListUserAuthEventsResponse
        |> Codec.optionalField "AuthEvents" .authEvents authEventsTypeCodec
        |> Codec.optionalField "NextToken" .nextToken paginationKeyCodec
        |> Codec.buildObject


{-| Codec for AdminListUserAuthEventsRequest.
-}
adminListUserAuthEventsRequestCodec : Codec AdminListUserAuthEventsRequest
adminListUserAuthEventsRequestCodec =
    Codec.object AdminListUserAuthEventsRequest
        |> Codec.optionalField "MaxResults" .maxResults queryLimitTypeCodec
        |> Codec.optionalField "NextToken" .nextToken paginationKeyCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "Username" .username usernameTypeCodec
        |> Codec.buildObject


{-| Codec for AdminListGroupsForUserResponse.
-}
adminListGroupsForUserResponseCodec : Codec AdminListGroupsForUserResponse
adminListGroupsForUserResponseCodec =
    Codec.object AdminListGroupsForUserResponse
        |> Codec.optionalField "Groups" .groups groupListTypeCodec
        |> Codec.optionalField "NextToken" .nextToken paginationKeyCodec
        |> Codec.buildObject


{-| Codec for AdminListGroupsForUserRequest.
-}
adminListGroupsForUserRequestCodec : Codec AdminListGroupsForUserRequest
adminListGroupsForUserRequestCodec =
    Codec.object AdminListGroupsForUserRequest
        |> Codec.optionalField "Limit" .limit queryLimitTypeCodec
        |> Codec.optionalField "NextToken" .nextToken paginationKeyCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "Username" .username usernameTypeCodec
        |> Codec.buildObject


{-| Codec for AdminListDevicesResponse.
-}
adminListDevicesResponseCodec : Codec AdminListDevicesResponse
adminListDevicesResponseCodec =
    Codec.object AdminListDevicesResponse
        |> Codec.optionalField "Devices" .devices deviceListTypeCodec
        |> Codec.optionalField "PaginationToken" .paginationToken searchPaginationTokenTypeCodec
        |> Codec.buildObject


{-| Codec for AdminListDevicesRequest.
-}
adminListDevicesRequestCodec : Codec AdminListDevicesRequest
adminListDevicesRequestCodec =
    Codec.object AdminListDevicesRequest
        |> Codec.optionalField "Limit" .limit queryLimitTypeCodec
        |> Codec.optionalField "PaginationToken" .paginationToken searchPaginationTokenTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "Username" .username usernameTypeCodec
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
        |> Codec.field "DestinationUser" .destinationUser providerUserIdentifierTypeCodec
        |> Codec.field "SourceUser" .sourceUser providerUserIdentifierTypeCodec
        |> Codec.field "UserPoolId" .userPoolId stringTypeCodec
        |> Codec.buildObject


{-| Codec for AdminInitiateAuthResponse.
-}
adminInitiateAuthResponseCodec : Codec AdminInitiateAuthResponse
adminInitiateAuthResponseCodec =
    Codec.object AdminInitiateAuthResponse
        |> Codec.optionalField "AuthenticationResult" .authenticationResult authenticationResultTypeCodec
        |> Codec.optionalField "ChallengeName" .challengeName challengeNameTypeCodec
        |> Codec.optionalField "ChallengeParameters" .challengeParameters challengeParametersTypeCodec
        |> Codec.optionalField "Session" .session sessionTypeCodec
        |> Codec.buildObject


{-| Codec for AdminInitiateAuthRequest.
-}
adminInitiateAuthRequestCodec : Codec AdminInitiateAuthRequest
adminInitiateAuthRequestCodec =
    Codec.object AdminInitiateAuthRequest
        |> Codec.optionalField "AnalyticsMetadata" .analyticsMetadata analyticsMetadataTypeCodec
        |> Codec.field "AuthFlow" .authFlow authFlowTypeCodec
        |> Codec.optionalField "AuthParameters" .authParameters authParametersTypeCodec
        |> Codec.field "ClientId" .clientId clientIdTypeCodec
        |> Codec.optionalField "ClientMetadata" .clientMetadata clientMetadataTypeCodec
        |> Codec.optionalField "ContextData" .contextData contextDataTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.buildObject


{-| Codec for AdminGetUserResponse.
-}
adminGetUserResponseCodec : Codec AdminGetUserResponse
adminGetUserResponseCodec =
    Codec.object AdminGetUserResponse
        |> Codec.optionalField "Enabled" .enabled booleanTypeCodec
        |> Codec.optionalField "MFAOptions" .mfaoptions mfaoptionListTypeCodec
        |> Codec.optionalField "PreferredMfaSetting" .preferredMfaSetting stringTypeCodec
        |> Codec.optionalField "UserAttributes" .userAttributes attributeListTypeCodec
        |> Codec.optionalField "UserCreateDate" .userCreateDate dateTypeCodec
        |> Codec.optionalField "UserLastModifiedDate" .userLastModifiedDate dateTypeCodec
        |> Codec.optionalField "UserMFASettingList" .userMfasettingList userMfasettingListTypeCodec
        |> Codec.optionalField "UserStatus" .userStatus userStatusTypeCodec
        |> Codec.field "Username" .username usernameTypeCodec
        |> Codec.buildObject


{-| Codec for AdminGetUserRequest.
-}
adminGetUserRequestCodec : Codec AdminGetUserRequest
adminGetUserRequestCodec =
    Codec.object AdminGetUserRequest
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "Username" .username usernameTypeCodec
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
        |> Codec.field "DeviceKey" .deviceKey deviceKeyTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "Username" .username usernameTypeCodec
        |> Codec.buildObject


{-| Codec for AdminForgetDeviceRequest.
-}
adminForgetDeviceRequestCodec : Codec AdminForgetDeviceRequest
adminForgetDeviceRequestCodec =
    Codec.object AdminForgetDeviceRequest
        |> Codec.field "DeviceKey" .deviceKey deviceKeyTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "Username" .username usernameTypeCodec
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
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "Username" .username usernameTypeCodec
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
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "Username" .username usernameTypeCodec
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
        |> Codec.field "User" .user providerUserIdentifierTypeCodec
        |> Codec.field "UserPoolId" .userPoolId stringTypeCodec
        |> Codec.buildObject


{-| Codec for AdminDeleteUserRequest.
-}
adminDeleteUserRequestCodec : Codec AdminDeleteUserRequest
adminDeleteUserRequestCodec =
    Codec.object AdminDeleteUserRequest
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "Username" .username usernameTypeCodec
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
        |> Codec.field "UserAttributeNames" .userAttributeNames attributeNameListTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "Username" .username usernameTypeCodec
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
        |> Codec.optionalField "DesiredDeliveryMediums" .desiredDeliveryMediums deliveryMediumListTypeCodec
        |> Codec.optionalField "ForceAliasCreation" .forceAliasCreation forceAliasCreationCodec
        |> Codec.optionalField "MessageAction" .messageAction messageActionTypeCodec
        |> Codec.optionalField "TemporaryPassword" .temporaryPassword passwordTypeCodec
        |> Codec.optionalField "UserAttributes" .userAttributes attributeListTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "Username" .username usernameTypeCodec
        |> Codec.optionalField "ValidationData" .validationData attributeListTypeCodec
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
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "Username" .username usernameTypeCodec
        |> Codec.buildObject


{-| Codec for AdminAddUserToGroupRequest.
-}
adminAddUserToGroupRequestCodec : Codec AdminAddUserToGroupRequest
adminAddUserToGroupRequestCodec =
    Codec.object AdminAddUserToGroupRequest
        |> Codec.field "GroupName" .groupName groupNameTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.field "Username" .username usernameTypeCodec
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
        |> Codec.field "CustomAttributes" .customAttributes customAttributesListTypeCodec
        |> Codec.field "UserPoolId" .userPoolId userPoolIdTypeCodec
        |> Codec.buildObject


{-| Codec for AccountTakeoverRiskConfigurationType.
-}
accountTakeoverRiskConfigurationTypeCodec : Codec AccountTakeoverRiskConfigurationType
accountTakeoverRiskConfigurationTypeCodec =
    Codec.object AccountTakeoverRiskConfigurationType
        |> Codec.field "Actions" .actions accountTakeoverActionsTypeCodec
        |> Codec.optionalField "NotifyConfiguration" .notifyConfiguration notifyConfigurationTypeCodec
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
        |> Codec.optionalField "HighAction" .highAction accountTakeoverActionTypeCodec
        |> Codec.optionalField "LowAction" .lowAction accountTakeoverActionTypeCodec
        |> Codec.optionalField "MediumAction" .mediumAction accountTakeoverActionTypeCodec
        |> Codec.buildObject


{-| Codec for AccountTakeoverActionType.
-}
accountTakeoverActionTypeCodec : Codec AccountTakeoverActionType
accountTakeoverActionTypeCodec =
    Codec.object AccountTakeoverActionType
        |> Codec.field "EventAction" .eventAction accountTakeoverEventActionTypeCodec
        |> Codec.field "Notify" .notify accountTakeoverActionNotifyTypeCodec
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
