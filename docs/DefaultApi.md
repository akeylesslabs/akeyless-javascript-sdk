# AkeylessVaultApi.DefaultApi

All URIs are relative to *https://127.0.0.1:8080*

Method | HTTP request | Description
------------- | ------------- | -------------
[**assocRoleAm**](DefaultApi.md#assocRoleAm) | **POST** /assoc-role-am | Create an association between role and auth method
[**auth**](DefaultApi.md#auth) | **POST** /auth | Authenticate to the service and returns a token to be used as a profile to execute the CLI without the need for re-authentication
[**configure**](DefaultApi.md#configure) | **POST** /configure | Configure client profile.
[**createAuthMethod**](DefaultApi.md#createAuthMethod) | **POST** /create-auth-method | Create a new Auth Method in the account
[**createAuthMethodAwsIam**](DefaultApi.md#createAuthMethodAwsIam) | **POST** /create-auth-method-aws-iam | Create a new Auth Method that will be able to authenticate using AWS IAM credentials
[**createAuthMethodAzureAd**](DefaultApi.md#createAuthMethodAzureAd) | **POST** /create-auth-method-azure-ad | Create a new Auth Method that will be able to authenticate using Azure Active Directory credentials
[**createAuthMethodLdap**](DefaultApi.md#createAuthMethodLdap) | **POST** /create-auth-method-ldap | Create a new Auth Method that will be able to authenticate using LDAP
[**createAuthMethodOauth2**](DefaultApi.md#createAuthMethodOauth2) | **POST** /create-auth-method-oauth2 | Create a new Auth Method that will be able to authenticate using OpenId/OAuth2
[**createAuthMethodSaml**](DefaultApi.md#createAuthMethodSaml) | **POST** /create-auth-method-saml | Create a new Auth Method that will be able to authenticate using SAML
[**createDynamicSecret**](DefaultApi.md#createDynamicSecret) | **POST** /create-dynamic-secret | Creates a new dynamic secret item
[**createKey**](DefaultApi.md#createKey) | **POST** /create-key | Creates a new key
[**createPkiCertIssuer**](DefaultApi.md#createPkiCertIssuer) | **POST** /create-pki-cert-issuer | Creates a new PKI certificate issuer
[**createRole**](DefaultApi.md#createRole) | **POST** /create-role | Creates a new role
[**createSecret**](DefaultApi.md#createSecret) | **POST** /create-secret | Creates a new secret item
[**createSshCertIssuer**](DefaultApi.md#createSshCertIssuer) | **POST** /create-ssh-cert-issuer | Creates a new SSH certificate issuer
[**decrypt**](DefaultApi.md#decrypt) | **POST** /decrypt | Decrypts ciphertext into plaintext by using an AES key
[**decryptFile**](DefaultApi.md#decryptFile) | **POST** /decrypt-file | Decrypts a file by using an AES key
[**decryptPkcs1**](DefaultApi.md#decryptPkcs1) | **POST** /decrypt-pkcs1 | Decrypts a plaintext using RSA and the padding scheme from PKCS#1 v1.5
[**deleteAssoc**](DefaultApi.md#deleteAssoc) | **POST** /delete-assoc | Delete an association between role and auth method
[**deleteAuthMethod**](DefaultApi.md#deleteAuthMethod) | **POST** /delete-auth-method | Delete the Auth Method
[**deleteItem**](DefaultApi.md#deleteItem) | **POST** /delete-item | Delete an item or an item version
[**deleteRole**](DefaultApi.md#deleteRole) | **POST** /delete-role | Delete a role
[**deleteRoleRule**](DefaultApi.md#deleteRoleRule) | **POST** /delete-role-rule | Delete a rule from a role
[**describeItem**](DefaultApi.md#describeItem) | **POST** /describe-item | Returns the item details
[**encrypt**](DefaultApi.md#encrypt) | **POST** /encrypt | Encrypts plaintext into ciphertext by using an AES key
[**encryptFile**](DefaultApi.md#encryptFile) | **POST** /encrypt-file | Encrypts a file by using an AES key
[**encryptPkcs1**](DefaultApi.md#encryptPkcs1) | **POST** /encrypt-pkcs1 | Encrypts the given message with RSA and the padding scheme from PKCS#1 v1.5
[**getAuthMethod**](DefaultApi.md#getAuthMethod) | **POST** /get-auth-method | Returns an information about the Auth Method
[**getCloudIdentity**](DefaultApi.md#getCloudIdentity) | **POST** /get-cloud-identity | Get Cloud Identity Token (relevant only for access-type=azure_ad,aws_iam)
[**getDynamicSecretValue**](DefaultApi.md#getDynamicSecretValue) | **POST** /get-dynamic-secret-value | Get dynamic secret value
[**getKubeExecCreds**](DefaultApi.md#getKubeExecCreds) | **POST** /get-kube-exec-creds | Get credentials for authentication with Kubernetes cluster based on a PKI Cert Issuer
[**getPkiCertificate**](DefaultApi.md#getPkiCertificate) | **POST** /get-pki-certificate | Generates PKI certificate
[**getRole**](DefaultApi.md#getRole) | **POST** /get-role | Get role details
[**getRsaPublic**](DefaultApi.md#getRsaPublic) | **POST** /get-rsa-public | Obtain the public key from a specific RSA private key
[**getSecretValue**](DefaultApi.md#getSecretValue) | **POST** /get-secret-value | Get static secret value
[**getSshCertificate**](DefaultApi.md#getSshCertificate) | **POST** /get-ssh-certificate | Generates SSH certificate
[**help**](DefaultApi.md#help) | **POST** /help | help text
[**listAuthMethods**](DefaultApi.md#listAuthMethods) | **POST** /list-auth-methods | Returns a list of all the Auth Methods in the account
[**listItems**](DefaultApi.md#listItems) | **POST** /list-items | Returns a list of all accessible items
[**listRoles**](DefaultApi.md#listRoles) | **POST** /list-roles | Returns a list of all roles in the account
[**reverseRbac**](DefaultApi.md#reverseRbac) | **POST** /reverse-rbac | See which authentication methods have access to a particular object
[**setRoleRule**](DefaultApi.md#setRoleRule) | **POST** /set-role-rule | Set a rule to a role
[**signPkcs1**](DefaultApi.md#signPkcs1) | **POST** /sign-pkcs1 | Calculates the signature of hashed using RSASSA-PKCS1-V1_5-SIGN from RSA PKCS#1 v1.5
[**unconfigure**](DefaultApi.md#unconfigure) | **POST** /unconfigure | Remove Configuration of client profile.
[**update**](DefaultApi.md#update) | **POST** /update | Update a new AKEYLESS CLI version
[**updateItem**](DefaultApi.md#updateItem) | **POST** /update-item | Update item name and metadata
[**updateRole**](DefaultApi.md#updateRole) | **POST** /update-role | Update role details
[**updateSecretVal**](DefaultApi.md#updateSecretVal) | **POST** /update-secret-val | Update static secret value
[**uploadPkcs12**](DefaultApi.md#uploadPkcs12) | **POST** /upload-pkcs12 | Upload a PKCS#12 key and certificates
[**uploadRsa**](DefaultApi.md#uploadRsa) | **POST** /upload-rsa | Upload RSA key
[**verifyPkcs1**](DefaultApi.md#verifyPkcs1) | **POST** /verify-pkcs1 | Verifies an RSA PKCS#1 v1.5 signature


<a name="assocRoleAm"></a>
# **assocRoleAm**
> ReplyObj assocRoleAm(roleName, amName, token, opts)

Create an association between role and auth method

Create an association between role and auth method Options:   role-name -    The role name to associate   am-name -    The auth method name to associate   sub-claims -    key/val of sub claims, ex. group=admins,developers   token -    Access token

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var roleName = "roleName_example"; // String | The role name to associate

var amName = "amName_example"; // String | The auth method name to associate

var token = "token_example"; // String | Access token

var opts = { 
  'subClaims': "subClaims_example" // String | key/val of sub claims, ex. group=admins,developers
};

var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.assocRoleAm(roleName, amName, token, opts, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **roleName** | **String**| The role name to associate | 
 **amName** | **String**| The auth method name to associate | 
 **token** | **String**| Access token | 
 **subClaims** | **String**| key/val of sub claims, ex. group=admins,developers | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="auth"></a>
# **auth**
> ReplyObj auth(opts)

Authenticate to the service and returns a token to be used as a profile to execute the CLI without the need for re-authentication

Authenticate to the service and returns a token to be used as a profile to execute the CLI without the need for re-authentication Options:   access-id -    Access ID   access-type -    Access Type (access_key/password/saml/ldap/azure_ad/aws_iam/universal_identity)   access-key -    Access key (relevant only for access-type=access_key)   cloud-id -    The cloued identity (relevant only for access-type=azure_ad,awd_im)   uid_token -    The universal_identity token (relevant only for access-type=universal_identity)   admin-password -    Password (relevant only for access-type=password)   admin-email -    Email (relevant only for access-type=password)   ldap_proxy_url -    Address URL for LDAP proxy (relevant only for access-type=ldap)

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var opts = { 
  'accessId': "accessId_example", // String | Access ID
  'accessType': "accessType_example", // String | Access Type (access_key/password/saml/ldap/azure_ad/aws_iam/universal_identity)
  'accessKey': "accessKey_example", // String | Access key (relevant only for access-type=access_key)
  'cloudId': "cloudId_example", // String | The cloued identity (relevant only for access-type=azure_ad,awd_im)
  'uidToken': "uidToken_example", // String | The universal_identity token (relevant only for access-type=universal_identity)
  'adminPassword': "adminPassword_example", // String | Password (relevant only for access-type=password)
  'adminEmail': "adminEmail_example", // String | Email (relevant only for access-type=password)
  'ldapProxyUrl': "ldapProxyUrl_example" // String | Address URL for LDAP proxy (relevant only for access-type=ldap)
};

var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.auth(opts, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **accessId** | **String**| Access ID | [optional] 
 **accessType** | **String**| Access Type (access_key/password/saml/ldap/azure_ad/aws_iam/universal_identity) | [optional] 
 **accessKey** | **String**| Access key (relevant only for access-type=access_key) | [optional] 
 **cloudId** | **String**| The cloued identity (relevant only for access-type=azure_ad,awd_im) | [optional] 
 **uidToken** | **String**| The universal_identity token (relevant only for access-type=universal_identity) | [optional] 
 **adminPassword** | **String**| Password (relevant only for access-type=password) | [optional] 
 **adminEmail** | **String**| Email (relevant only for access-type=password) | [optional] 
 **ldapProxyUrl** | **String**| Address URL for LDAP proxy (relevant only for access-type=ldap) | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="configure"></a>
# **configure**
> ReplyObj configure(opts)

Configure client profile.

Configure client profile. Options:   access-id -    Access ID   access-key -    Access Key   access-type -    Access Type (access_key/password/azure_ad/saml/ldap/aws_iam/universal_identity)   admin-password -    Password (relevant only for access-type=password)   admin-email -    Email (relevant only for access-type=password)   uid_token -    The universal_identity token (relevant only for access-type=universal_identity)   ldap_proxy_url -    Address URL for ldap proxy (relevant only for access-type=ldap)   azure_ad_object_id -    Azure Active Directory ObjectId (relevant only for access-type=azure_ad)

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var opts = { 
  'accessId': "accessId_example", // String | Access ID
  'accessKey': "accessKey_example", // String | Access Key
  'accessType': "accessType_example", // String | Access Type (access_key/password/azure_ad/saml/ldap/aws_iam/universal_identity)
  'adminPassword': "adminPassword_example", // String | Password (relevant only for access-type=password)
  'adminEmail': "adminEmail_example", // String | Email (relevant only for access-type=password)
  'uidToken': "uidToken_example", // String | The universal_identity token (relevant only for access-type=universal_identity)
  'ldapProxyUrl': "ldapProxyUrl_example", // String | Address URL for ldap proxy (relevant only for access-type=ldap)
  'azureAdObjectId': "azureAdObjectId_example" // String | Azure Active Directory ObjectId (relevant only for access-type=azure_ad)
};

var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.configure(opts, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **accessId** | **String**| Access ID | [optional] 
 **accessKey** | **String**| Access Key | [optional] 
 **accessType** | **String**| Access Type (access_key/password/azure_ad/saml/ldap/aws_iam/universal_identity) | [optional] 
 **adminPassword** | **String**| Password (relevant only for access-type=password) | [optional] 
 **adminEmail** | **String**| Email (relevant only for access-type=password) | [optional] 
 **uidToken** | **String**| The universal_identity token (relevant only for access-type=universal_identity) | [optional] 
 **ldapProxyUrl** | **String**| Address URL for ldap proxy (relevant only for access-type=ldap) | [optional] 
 **azureAdObjectId** | **String**| Azure Active Directory ObjectId (relevant only for access-type=azure_ad) | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="createAuthMethod"></a>
# **createAuthMethod**
> ReplyObj createAuthMethod(name, token, opts)

Create a new Auth Method in the account

Create a new Auth Method in the account Options:   name -    Auth Method name   access-expires -    Access expiration date in Unix timestamp (select 0 for access without expiry date)   bound-ips -    A CIDR whitelist with the IPs that the access is restricted to   token -    Access token

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var name = "name_example"; // String | Auth Method name

var token = "token_example"; // String | Access token

var opts = { 
  'accessExpires': "accessExpires_example", // String | Access expiration date in Unix timestamp (select 0 for access without expiry date)
  'boundIps': "boundIps_example" // String | A CIDR whitelist with the IPs that the access is restricted to
};

var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.createAuthMethod(name, token, opts, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| Auth Method name | 
 **token** | **String**| Access token | 
 **accessExpires** | **String**| Access expiration date in Unix timestamp (select 0 for access without expiry date) | [optional] 
 **boundIps** | **String**| A CIDR whitelist with the IPs that the access is restricted to | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="createAuthMethodAwsIam"></a>
# **createAuthMethodAwsIam**
> ReplyObj createAuthMethodAwsIam(name, boundAWSAccountId, token, opts)

Create a new Auth Method that will be able to authenticate using AWS IAM credentials

Create a new Auth Method that will be able to authenticate using AWS IAM credentials Options:   name -    Auth Method name   access-expires -    Access expiration date in Unix timestamp (select 0 for access without expiry date)   bound-ips -    A CIDR whitelist of the IPs that the access is restricted to   sts-url -    sts URL   bound-AWS-account-id -    A list of AWS account-IDs that the access is restricted to   bound-arn -    A list of full arns that the access is restricted to   bound-role-name -    A list of full role-name that the access is restricted to   bound-role-id -    A list of full role ids that the access is restricted to   bound-resource-id -    A list of full resource ids that the access is restricted to   bound-user-name -    A list of full user-name that the access is restricted to   bound-user-id -    A list of full user ids that the access is restricted to   token -    Access token

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var name = "name_example"; // String | Auth Method name

var boundAWSAccountId = "boundAWSAccountId_example"; // String | A list of AWS account-IDs that the access is restricted to

var token = "token_example"; // String | Access token

var opts = { 
  'accessExpires': "accessExpires_example", // String | Access expiration date in Unix timestamp (select 0 for access without expiry date)
  'boundIps': "boundIps_example", // String | A CIDR whitelist of the IPs that the access is restricted to
  'stsUrl': "stsUrl_example", // String | sts URL
  'boundArn': "boundArn_example", // String | A list of full arns that the access is restricted to
  'boundRoleName': "boundRoleName_example", // String | A list of full role-name that the access is restricted to
  'boundRoleId': "boundRoleId_example", // String | A list of full role ids that the access is restricted to
  'boundResourceId': "boundResourceId_example", // String | A list of full resource ids that the access is restricted to
  'boundUserName': "boundUserName_example", // String | A list of full user-name that the access is restricted to
  'boundUserId': "boundUserId_example" // String | A list of full user ids that the access is restricted to
};

var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.createAuthMethodAwsIam(name, boundAWSAccountId, token, opts, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| Auth Method name | 
 **boundAWSAccountId** | **String**| A list of AWS account-IDs that the access is restricted to | 
 **token** | **String**| Access token | 
 **accessExpires** | **String**| Access expiration date in Unix timestamp (select 0 for access without expiry date) | [optional] 
 **boundIps** | **String**| A CIDR whitelist of the IPs that the access is restricted to | [optional] 
 **stsUrl** | **String**| sts URL | [optional] 
 **boundArn** | **String**| A list of full arns that the access is restricted to | [optional] 
 **boundRoleName** | **String**| A list of full role-name that the access is restricted to | [optional] 
 **boundRoleId** | **String**| A list of full role ids that the access is restricted to | [optional] 
 **boundResourceId** | **String**| A list of full resource ids that the access is restricted to | [optional] 
 **boundUserName** | **String**| A list of full user-name that the access is restricted to | [optional] 
 **boundUserId** | **String**| A list of full user ids that the access is restricted to | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="createAuthMethodAzureAd"></a>
# **createAuthMethodAzureAd**
> ReplyObj createAuthMethodAzureAd(name, boundTenantId, token, opts)

Create a new Auth Method that will be able to authenticate using Azure Active Directory credentials

Create a new Auth Method that will be able to authenticate using Azure Active Directory credentials Options:   name -    Auth Method name   access-expires -    Access expiration date in Unix timestamp (select 0 for access without expiry date)   bound-ips -    A CIDR whitelist of the IPs that the access is restricted to   bound-tenant-id -    The Azure tenant id that the access is restricted to   issuer -    Issuer URL   jwks-uri -    The URL to the JSON Web Key Set (JWKS) that containing the public keys that should be used to verify any JSON Web Token (JWT) issued by the authorization server.   audience -    The audience in the JWT   bound-spid -    A list of service principal IDs that the access is restricted to   bound-group-id -    A list of group ids that the access is restricted to   bound-sub-id -    A list of subscription ids that the access is restricted to   bound-rg-id -    A list of resource groups that the access is restricted to   bound-providers -    A list of resource providers that the access is restricted to (e.g, Microsoft.Compute, Microsoft.ManagedIdentity, etc)   bound-resource-types -    A list of resource types that the access is restricted to (e.g, virtualMachines, userAssignedIdentities, etc)   bound-resource-names -    A list of resource names that the access is restricted to (e.g, a virtual machine name, scale set name, etc).   bound-resource-id -    A list of full resource ids that the access is restricted to   token -    Access token

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var name = "name_example"; // String | Auth Method name

var boundTenantId = "boundTenantId_example"; // String | The Azure tenant id that the access is restricted to

var token = "token_example"; // String | Access token

var opts = { 
  'accessExpires': "accessExpires_example", // String | Access expiration date in Unix timestamp (select 0 for access without expiry date)
  'boundIps': "boundIps_example", // String | A CIDR whitelist of the IPs that the access is restricted to
  'issuer': "issuer_example", // String | Issuer URL
  'jwksUri': "jwksUri_example", // String | The URL to the JSON Web Key Set (JWKS) that containing the public keys that should be used to verify any JSON Web Token (JWT) issued by the authorization server.
  'audience': "audience_example", // String | The audience in the JWT
  'boundSpid': "boundSpid_example", // String | A list of service principal IDs that the access is restricted to
  'boundGroupId': "boundGroupId_example", // String | A list of group ids that the access is restricted to
  'boundSubId': "boundSubId_example", // String | A list of subscription ids that the access is restricted to
  'boundRgId': "boundRgId_example", // String | A list of resource groups that the access is restricted to
  'boundProviders': "boundProviders_example", // String | A list of resource providers that the access is restricted to (e.g, Microsoft.Compute, Microsoft.ManagedIdentity, etc)
  'boundResourceTypes': "boundResourceTypes_example", // String | A list of resource types that the access is restricted to (e.g, virtualMachines, userAssignedIdentities, etc)
  'boundResourceNames': "boundResourceNames_example", // String | A list of resource names that the access is restricted to (e.g, a virtual machine name, scale set name, etc).
  'boundResourceId': "boundResourceId_example" // String | A list of full resource ids that the access is restricted to
};

var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.createAuthMethodAzureAd(name, boundTenantId, token, opts, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| Auth Method name | 
 **boundTenantId** | **String**| The Azure tenant id that the access is restricted to | 
 **token** | **String**| Access token | 
 **accessExpires** | **String**| Access expiration date in Unix timestamp (select 0 for access without expiry date) | [optional] 
 **boundIps** | **String**| A CIDR whitelist of the IPs that the access is restricted to | [optional] 
 **issuer** | **String**| Issuer URL | [optional] 
 **jwksUri** | **String**| The URL to the JSON Web Key Set (JWKS) that containing the public keys that should be used to verify any JSON Web Token (JWT) issued by the authorization server. | [optional] 
 **audience** | **String**| The audience in the JWT | [optional] 
 **boundSpid** | **String**| A list of service principal IDs that the access is restricted to | [optional] 
 **boundGroupId** | **String**| A list of group ids that the access is restricted to | [optional] 
 **boundSubId** | **String**| A list of subscription ids that the access is restricted to | [optional] 
 **boundRgId** | **String**| A list of resource groups that the access is restricted to | [optional] 
 **boundProviders** | **String**| A list of resource providers that the access is restricted to (e.g, Microsoft.Compute, Microsoft.ManagedIdentity, etc) | [optional] 
 **boundResourceTypes** | **String**| A list of resource types that the access is restricted to (e.g, virtualMachines, userAssignedIdentities, etc) | [optional] 
 **boundResourceNames** | **String**| A list of resource names that the access is restricted to (e.g, a virtual machine name, scale set name, etc). | [optional] 
 **boundResourceId** | **String**| A list of full resource ids that the access is restricted to | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="createAuthMethodLdap"></a>
# **createAuthMethodLdap**
> ReplyObj createAuthMethodLdap(name, publicKeyFilePath, token, opts)

Create a new Auth Method that will be able to authenticate using LDAP

Create a new Auth Method that will be able to authenticate using LDAP Options:   name -    Auth Method name   access-expires -    Access expiration date in Unix timestamp (select 0 for access without expiry date)   bound-ips -    A CIDR whitelist of the IPs that the access is restricted to   public-key-file-path -    A public key generated for LDAP authentication method on Akeyless [RSA2048]   token -    Access token

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var name = "name_example"; // String | Auth Method name

var publicKeyFilePath = "publicKeyFilePath_example"; // String | A public key generated for LDAP authentication method on Akeyless [RSA2048]

var token = "token_example"; // String | Access token

var opts = { 
  'accessExpires': "accessExpires_example", // String | Access expiration date in Unix timestamp (select 0 for access without expiry date)
  'boundIps': "boundIps_example" // String | A CIDR whitelist of the IPs that the access is restricted to
};

var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.createAuthMethodLdap(name, publicKeyFilePath, token, opts, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| Auth Method name | 
 **publicKeyFilePath** | **String**| A public key generated for LDAP authentication method on Akeyless [RSA2048] | 
 **token** | **String**| Access token | 
 **accessExpires** | **String**| Access expiration date in Unix timestamp (select 0 for access without expiry date) | [optional] 
 **boundIps** | **String**| A CIDR whitelist of the IPs that the access is restricted to | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="createAuthMethodOauth2"></a>
# **createAuthMethodOauth2**
> ReplyObj createAuthMethodOauth2(name, boundClientsIds, issuer, jwksUri, audience, token, opts)

Create a new Auth Method that will be able to authenticate using OpenId/OAuth2

Create a new Auth Method that will be able to authenticate using OpenId/OAuth2 Options:   name -    Auth Method name   access-expires -    Access expiration date in Unix timestamp (select 0 for access without expiry date)   bound-ips -    A CIDR whitelist of the IPs that the access is restricted to   bound-clients-ids -    The clients ids that the access is restricted to   issuer -    Issuer URL   jwks-uri -    The URL to the JSON Web Key Set (JWKS) that containing the public keys that should be used to verify any JSON Web Token (JWT) issued by the authorization server.   audience -    The audience in the JWT   token -    Access token

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var name = "name_example"; // String | Auth Method name

var boundClientsIds = "boundClientsIds_example"; // String | The clients ids that the access is restricted to

var issuer = "issuer_example"; // String | Issuer URL

var jwksUri = "jwksUri_example"; // String | The URL to the JSON Web Key Set (JWKS) that containing the public keys that should be used to verify any JSON Web Token (JWT) issued by the authorization server.

var audience = "audience_example"; // String | The audience in the JWT

var token = "token_example"; // String | Access token

var opts = { 
  'accessExpires': "accessExpires_example", // String | Access expiration date in Unix timestamp (select 0 for access without expiry date)
  'boundIps': "boundIps_example" // String | A CIDR whitelist of the IPs that the access is restricted to
};

var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.createAuthMethodOauth2(name, boundClientsIds, issuer, jwksUri, audience, token, opts, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| Auth Method name | 
 **boundClientsIds** | **String**| The clients ids that the access is restricted to | 
 **issuer** | **String**| Issuer URL | 
 **jwksUri** | **String**| The URL to the JSON Web Key Set (JWKS) that containing the public keys that should be used to verify any JSON Web Token (JWT) issued by the authorization server. | 
 **audience** | **String**| The audience in the JWT | 
 **token** | **String**| Access token | 
 **accessExpires** | **String**| Access expiration date in Unix timestamp (select 0 for access without expiry date) | [optional] 
 **boundIps** | **String**| A CIDR whitelist of the IPs that the access is restricted to | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="createAuthMethodSaml"></a>
# **createAuthMethodSaml**
> ReplyObj createAuthMethodSaml(name, idpMetadataUrl, idpMetadataXml, token, opts)

Create a new Auth Method that will be able to authenticate using SAML

Create a new Auth Method that will be able to authenticate using SAML Options:   name -    Auth Method name   access-expires -    Access expiration date in Unix timestamp (select 0 for access without expiry date)   bound-ips -    A CIDR whitelist of the IPs that the access is restricted to   idp-metadata-url -    IDP metadata url   idp-metadata-xml -    IDP metadata xml   token -    Access token

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var name = "name_example"; // String | Auth Method name

var idpMetadataUrl = "idpMetadataUrl_example"; // String | IDP metadata url

var idpMetadataXml = "idpMetadataXml_example"; // String | IDP metadata xml

var token = "token_example"; // String | Access token

var opts = { 
  'accessExpires': "accessExpires_example", // String | Access expiration date in Unix timestamp (select 0 for access without expiry date)
  'boundIps': "boundIps_example" // String | A CIDR whitelist of the IPs that the access is restricted to
};

var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.createAuthMethodSaml(name, idpMetadataUrl, idpMetadataXml, token, opts, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| Auth Method name | 
 **idpMetadataUrl** | **String**| IDP metadata url | 
 **idpMetadataXml** | **String**| IDP metadata xml | 
 **token** | **String**| Access token | 
 **accessExpires** | **String**| Access expiration date in Unix timestamp (select 0 for access without expiry date) | [optional] 
 **boundIps** | **String**| A CIDR whitelist of the IPs that the access is restricted to | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="createDynamicSecret"></a>
# **createDynamicSecret**
> ReplyObj createDynamicSecret(name, token, opts)

Creates a new dynamic secret item

Creates a new dynamic secret item Options:   name -    Dynamic secret name   metadata -    Metadata about the dynamic secret   tag -    List of the tags attached to this secret. To specify multiple tags use argument multiple times- -t Tag1 -t Tag2   key -    The name of a key that used to encrypt the dynamic secret values (if empty, the account default protectionKey key will be used)   token -    Access token

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var name = "name_example"; // String | Dynamic secret name

var token = "token_example"; // String | Access token

var opts = { 
  'metadata': "metadata_example", // String | Metadata about the dynamic secret
  'tag': "tag_example", // String | List of the tags attached to this secret. To specify multiple tags use argument multiple times- -t Tag1 -t Tag2
  'key': "key_example" // String | The name of a key that used to encrypt the dynamic secret values (if empty, the account default protectionKey key will be used)
};

var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.createDynamicSecret(name, token, opts, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| Dynamic secret name | 
 **token** | **String**| Access token | 
 **metadata** | **String**| Metadata about the dynamic secret | [optional] 
 **tag** | **String**| List of the tags attached to this secret. To specify multiple tags use argument multiple times- -t Tag1 -t Tag2 | [optional] 
 **key** | **String**| The name of a key that used to encrypt the dynamic secret values (if empty, the account default protectionKey key will be used) | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="createKey"></a>
# **createKey**
> ReplyObj createKey(name, alg, token, opts)

Creates a new key

Creates a new key Options:   name -    Key name   alg -    Key type. options- [AES128GCM, AES256GCM, AES128SIV, AES256SIV, RSA1024, RSA2048]   metadata -    Metadata about the key   tag -    List of the tags attached to this key. To specify multiple tags use argument multiple times- -t Tag1 -t Tag2   split-level -    The number of fragments that the item will be split into (not includes customer fragment)   customer-frg-id -    The customer fragment ID that will be used to create the key (if empty, the key will be created independently of a customer fragment)   token -    Access token

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var name = "name_example"; // String | Key name

var alg = "alg_example"; // String | Key type. options- [AES128GCM, AES256GCM, AES128SIV, AES256SIV, RSA1024, RSA2048]

var token = "token_example"; // String | Access token

var opts = { 
  'metadata': "metadata_example", // String | Metadata about the key
  'tag': "tag_example", // String | List of the tags attached to this key. To specify multiple tags use argument multiple times- -t Tag1 -t Tag2
  'splitLevel': "splitLevel_example", // String | The number of fragments that the item will be split into (not includes customer fragment)
  'customerFrgId': "customerFrgId_example" // String | The customer fragment ID that will be used to create the key (if empty, the key will be created independently of a customer fragment)
};

var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.createKey(name, alg, token, opts, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| Key name | 
 **alg** | **String**| Key type. options- [AES128GCM, AES256GCM, AES128SIV, AES256SIV, RSA1024, RSA2048] | 
 **token** | **String**| Access token | 
 **metadata** | **String**| Metadata about the key | [optional] 
 **tag** | **String**| List of the tags attached to this key. To specify multiple tags use argument multiple times- -t Tag1 -t Tag2 | [optional] 
 **splitLevel** | **String**| The number of fragments that the item will be split into (not includes customer fragment) | [optional] 
 **customerFrgId** | **String**| The customer fragment ID that will be used to create the key (if empty, the key will be created independently of a customer fragment) | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="createPkiCertIssuer"></a>
# **createPkiCertIssuer**
> ReplyObj createPkiCertIssuer(name, signerKeyName, ttl, token, opts)

Creates a new PKI certificate issuer

Creates a new PKI certificate issuer Options:   name -    PKI certificate issuer name   signer-key-name -    A key to sign the certificate with   allowed-domains -    A list of the allowed domains that clients can request to be included in the certificate (in a comma-delimited list)   allowed-uri-sans -    A list of the allowed URIs that clients can request to be included in the certificate as part of the URI Subject Alternative Names (in a comma-delimited list)   allow-subdomains -    If set, clients can request certificates for subdomains and wildcard subdomains of the allowed domains   not-enforce-hostnames -    If set, any names are allowed for CN and SANs in the certificate and not only a valid host name   allow-any-name -    If set, clients can request certificates for any CN   not-require-cn -    If set, clients can request certificates without a CN   server-flag -    If set, certificates will be flagged for server auth use   client-flag -    If set, certificates will be flagged for client auth use   code-signing-flag -    If set, certificates will be flagged for code signing use   key-usage -    A comma-separated string or list of key usages   organization-units -    A comma-separated list of organizational units (OU) that will be set in the issued certificate   organizations -    A comma-separated list of organizations (O) that will be set in the issued certificate   country -    A comma-separated list of the country that will be set in the issued certificate   locality -    A comma-separated list of the locality that will be set in the issued certificate   province -    A comma-separated list of the province that will be set in the issued certificate   street-address -    A comma-separated list of the street address that will be set in the issued certificate   postal-code -    A comma-separated list of the postal code that will be set in the issued certificate   ttl -    The requested Time To Live for the certificate, use second units   metadata -    A metadata about the issuer   token -    Access token

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var name = "name_example"; // String | PKI certificate issuer name

var signerKeyName = "signerKeyName_example"; // String | A key to sign the certificate with

var ttl = "ttl_example"; // String | The requested Time To Live for the certificate, use second units

var token = "token_example"; // String | Access token

var opts = { 
  'allowedDomains': "allowedDomains_example", // String | A list of the allowed domains that clients can request to be included in the certificate (in a comma-delimited list)
  'allowedUriSans': "allowedUriSans_example", // String | A list of the allowed URIs that clients can request to be included in the certificate as part of the URI Subject Alternative Names (in a comma-delimited list)
  'allowSubdomains': "allowSubdomains_example", // String | If set, clients can request certificates for subdomains and wildcard subdomains of the allowed domains
  'notEnforceHostnames': "notEnforceHostnames_example", // String | If set, any names are allowed for CN and SANs in the certificate and not only a valid host name
  'allowAnyName': "allowAnyName_example", // String | If set, clients can request certificates for any CN
  'notRequireCn': "notRequireCn_example", // String | If set, clients can request certificates without a CN
  'serverFlag': "serverFlag_example", // String | If set, certificates will be flagged for server auth use
  'clientFlag': "clientFlag_example", // String | If set, certificates will be flagged for client auth use
  'codeSigningFlag': "codeSigningFlag_example", // String | If set, certificates will be flagged for code signing use
  'keyUsage': "keyUsage_example", // String | A comma-separated string or list of key usages
  'organizationUnits': "organizationUnits_example", // String | A comma-separated list of organizational units (OU) that will be set in the issued certificate
  'organizations': "organizations_example", // String | A comma-separated list of organizations (O) that will be set in the issued certificate
  'country': "country_example", // String | A comma-separated list of the country that will be set in the issued certificate
  'locality': "locality_example", // String | A comma-separated list of the locality that will be set in the issued certificate
  'province': "province_example", // String | A comma-separated list of the province that will be set in the issued certificate
  'streetAddress': "streetAddress_example", // String | A comma-separated list of the street address that will be set in the issued certificate
  'postalCode': "postalCode_example", // String | A comma-separated list of the postal code that will be set in the issued certificate
  'metadata': "metadata_example" // String | A metadata about the issuer
};

var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.createPkiCertIssuer(name, signerKeyName, ttl, token, opts, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| PKI certificate issuer name | 
 **signerKeyName** | **String**| A key to sign the certificate with | 
 **ttl** | **String**| The requested Time To Live for the certificate, use second units | 
 **token** | **String**| Access token | 
 **allowedDomains** | **String**| A list of the allowed domains that clients can request to be included in the certificate (in a comma-delimited list) | [optional] 
 **allowedUriSans** | **String**| A list of the allowed URIs that clients can request to be included in the certificate as part of the URI Subject Alternative Names (in a comma-delimited list) | [optional] 
 **allowSubdomains** | **String**| If set, clients can request certificates for subdomains and wildcard subdomains of the allowed domains | [optional] 
 **notEnforceHostnames** | **String**| If set, any names are allowed for CN and SANs in the certificate and not only a valid host name | [optional] 
 **allowAnyName** | **String**| If set, clients can request certificates for any CN | [optional] 
 **notRequireCn** | **String**| If set, clients can request certificates without a CN | [optional] 
 **serverFlag** | **String**| If set, certificates will be flagged for server auth use | [optional] 
 **clientFlag** | **String**| If set, certificates will be flagged for client auth use | [optional] 
 **codeSigningFlag** | **String**| If set, certificates will be flagged for code signing use | [optional] 
 **keyUsage** | **String**| A comma-separated string or list of key usages | [optional] 
 **organizationUnits** | **String**| A comma-separated list of organizational units (OU) that will be set in the issued certificate | [optional] 
 **organizations** | **String**| A comma-separated list of organizations (O) that will be set in the issued certificate | [optional] 
 **country** | **String**| A comma-separated list of the country that will be set in the issued certificate | [optional] 
 **locality** | **String**| A comma-separated list of the locality that will be set in the issued certificate | [optional] 
 **province** | **String**| A comma-separated list of the province that will be set in the issued certificate | [optional] 
 **streetAddress** | **String**| A comma-separated list of the street address that will be set in the issued certificate | [optional] 
 **postalCode** | **String**| A comma-separated list of the postal code that will be set in the issued certificate | [optional] 
 **metadata** | **String**| A metadata about the issuer | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="createRole"></a>
# **createRole**
> ReplyObj createRole(name, token, opts)

Creates a new role

Creates a new role Options:   name -    Role name   comment -    Comment about the role   token -    Access token

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var name = "name_example"; // String | Role name

var token = "token_example"; // String | Access token

var opts = { 
  'comment': "comment_example" // String | Comment about the role
};

var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.createRole(name, token, opts, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| Role name | 
 **token** | **String**| Access token | 
 **comment** | **String**| Comment about the role | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="createSecret"></a>
# **createSecret**
> ReplyObj createSecret(name, value, token, opts)

Creates a new secret item

Creates a new secret item Options:   name -    Secret name   value -    The secret value   metadata -    Metadata about the secret   tag -    List of the tags attached to this secret. To specify multiple tags use argument multiple times- -t Tag1 -t Tag2   key -    The name of a key that used to encrypt the secret value (if empty, the account default protectionKey key will be used)   multiline -    The provided value is a multiline value (separated by '\\n')   token -    Access token

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var name = "name_example"; // String | Secret name

var value = "value_example"; // String | The secret value

var token = "token_example"; // String | Access token

var opts = { 
  'metadata': "metadata_example", // String | Metadata about the secret
  'tag': "tag_example", // String | List of the tags attached to this secret. To specify multiple tags use argument multiple times- -t Tag1 -t Tag2
  'key': "key_example", // String | The name of a key that used to encrypt the secret value (if empty, the account default protectionKey key will be used)
  'multiline': true // Boolean | The provided value is a multiline value (separated by '\\n')
};

var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.createSecret(name, value, token, opts, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| Secret name | 
 **value** | **String**| The secret value | 
 **token** | **String**| Access token | 
 **metadata** | **String**| Metadata about the secret | [optional] 
 **tag** | **String**| List of the tags attached to this secret. To specify multiple tags use argument multiple times- -t Tag1 -t Tag2 | [optional] 
 **key** | **String**| The name of a key that used to encrypt the secret value (if empty, the account default protectionKey key will be used) | [optional] 
 **multiline** | **Boolean**| The provided value is a multiline value (separated by '\\n') | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="createSshCertIssuer"></a>
# **createSshCertIssuer**
> ReplyObj createSshCertIssuer(name, signerKeyName, allowedUsers, ttl, token, opts)

Creates a new SSH certificate issuer

Creates a new SSH certificate issuer Options:   name -    SSH certificate issuer name   signer-key-name -    A key to sign the certificate with   allowed-users -    Users allowed to fetch the certificate, ex. root,ubuntu   principals -    Signed certificates with principal, ex. example_role1,example_role2   extensions -    Signed certificates with extensions, ex. permit-port-forwarding=\"\"   ttl -    The requested Time To Live for the certificate, use second units   metadata -    A metadata about the issuer   token -    Access token

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var name = "name_example"; // String | SSH certificate issuer name

var signerKeyName = "signerKeyName_example"; // String | A key to sign the certificate with

var allowedUsers = "allowedUsers_example"; // String | Users allowed to fetch the certificate, ex. root,ubuntu

var ttl = "ttl_example"; // String | The requested Time To Live for the certificate, use second units

var token = "token_example"; // String | Access token

var opts = { 
  'principals': "principals_example", // String | Signed certificates with principal, ex. example_role1,example_role2
  'extensions': "extensions_example", // String | Signed certificates with extensions, ex. permit-port-forwarding=\"\"
  'metadata': "metadata_example" // String | A metadata about the issuer
};

var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.createSshCertIssuer(name, signerKeyName, allowedUsers, ttl, token, opts, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| SSH certificate issuer name | 
 **signerKeyName** | **String**| A key to sign the certificate with | 
 **allowedUsers** | **String**| Users allowed to fetch the certificate, ex. root,ubuntu | 
 **ttl** | **String**| The requested Time To Live for the certificate, use second units | 
 **token** | **String**| Access token | 
 **principals** | **String**| Signed certificates with principal, ex. example_role1,example_role2 | [optional] 
 **extensions** | **String**| Signed certificates with extensions, ex. permit-port-forwarding=\"\" | [optional] 
 **metadata** | **String**| A metadata about the issuer | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="decrypt"></a>
# **decrypt**
> ReplyObj decrypt(keyName, ciphertext, token, opts)

Decrypts ciphertext into plaintext by using an AES key

Decrypts ciphertext into plaintext by using an AES key Options:   key-name -    The name of the key to use in the decryption process   ciphertext -    Ciphertext to be decrypted in base64 encoded format   encryption-context -    The encryption context. If this was specified in the encrypt command, it must be specified here or the decryption operation will fail   token -    Access token

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var keyName = "keyName_example"; // String | The name of the key to use in the decryption process

var ciphertext = "ciphertext_example"; // String | Ciphertext to be decrypted in base64 encoded format

var token = "token_example"; // String | Access token

var opts = { 
  'encryptionContext': "encryptionContext_example" // String | The encryption context. If this was specified in the encrypt command, it must be specified here or the decryption operation will fail
};

var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.decrypt(keyName, ciphertext, token, opts, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **keyName** | **String**| The name of the key to use in the decryption process | 
 **ciphertext** | **String**| Ciphertext to be decrypted in base64 encoded format | 
 **token** | **String**| Access token | 
 **encryptionContext** | **String**| The encryption context. If this was specified in the encrypt command, it must be specified here or the decryption operation will fail | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="decryptFile"></a>
# **decryptFile**
> ReplyObj decryptFile(keyName, _in, token, opts)

Decrypts a file by using an AES key

Decrypts a file by using an AES key Options:   key-name -    The name of the key to use in the decryption process   in -    Path to the file to be decrypted. If not provided, the content will be taken from stdin   out -    Path to the output file. If not provided, the output will be sent to stdout   encryption-context -    The encryption context. If this was specified in the encrypt command, it must be specified here or the decryption operation will fail   token -    Access token

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var keyName = "keyName_example"; // String | The name of the key to use in the decryption process

var _in = "_in_example"; // String | Path to the file to be decrypted. If not provided, the content will be taken from stdin

var token = "token_example"; // String | Access token

var opts = { 
  'out': "out_example", // String | Path to the output file. If not provided, the output will be sent to stdout
  'encryptionContext': "encryptionContext_example" // String | The encryption context. If this was specified in the encrypt command, it must be specified here or the decryption operation will fail
};

var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.decryptFile(keyName, _in, token, opts, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **keyName** | **String**| The name of the key to use in the decryption process | 
 **_in** | **String**| Path to the file to be decrypted. If not provided, the content will be taken from stdin | 
 **token** | **String**| Access token | 
 **out** | **String**| Path to the output file. If not provided, the output will be sent to stdout | [optional] 
 **encryptionContext** | **String**| The encryption context. If this was specified in the encrypt command, it must be specified here or the decryption operation will fail | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="decryptPkcs1"></a>
# **decryptPkcs1**
> ReplyObj decryptPkcs1(keyName, ciphertext, token)

Decrypts a plaintext using RSA and the padding scheme from PKCS#1 v1.5

Decrypts a plaintext using RSA and the padding scheme from PKCS#1 v1.5 Options:   key-name -    The name of the RSA key to use in the decryption process   ciphertext -    Ciphertext to be decrypted in base64 encoded format   token -    Access token

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var keyName = "keyName_example"; // String | The name of the RSA key to use in the decryption process

var ciphertext = "ciphertext_example"; // String | Ciphertext to be decrypted in base64 encoded format

var token = "token_example"; // String | Access token


var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.decryptPkcs1(keyName, ciphertext, token, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **keyName** | **String**| The name of the RSA key to use in the decryption process | 
 **ciphertext** | **String**| Ciphertext to be decrypted in base64 encoded format | 
 **token** | **String**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="deleteAssoc"></a>
# **deleteAssoc**
> ReplyObj deleteAssoc(assocId, token)

Delete an association between role and auth method

Delete an association between role and auth method Options:   assoc-id -    The association id to be deleted   token -    Access token

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var assocId = "assocId_example"; // String | The association id to be deleted

var token = "token_example"; // String | Access token


var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.deleteAssoc(assocId, token, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **assocId** | **String**| The association id to be deleted | 
 **token** | **String**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="deleteAuthMethod"></a>
# **deleteAuthMethod**
> ReplyObj deleteAuthMethod(name, token)

Delete the Auth Method

Delete the Auth Method Options:   name -    Auth Method name   token -    Access token

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var name = "name_example"; // String | Auth Method name

var token = "token_example"; // String | Access token


var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.deleteAuthMethod(name, token, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| Auth Method name | 
 **token** | **String**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="deleteItem"></a>
# **deleteItem**
> ReplyObj deleteItem(name, token)

Delete an item or an item version

Delete an item or an item version Options:   name -    Item name   token -    Access token

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var name = "name_example"; // String | Item name

var token = "token_example"; // String | Access token


var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.deleteItem(name, token, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| Item name | 
 **token** | **String**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="deleteRole"></a>
# **deleteRole**
> ReplyObj deleteRole(name, token)

Delete a role

Delete a role Options:   name -    Role name   token -    Access token

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var name = "name_example"; // String | Role name

var token = "token_example"; // String | Access token


var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.deleteRole(name, token, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| Role name | 
 **token** | **String**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="deleteRoleRule"></a>
# **deleteRoleRule**
> ReplyObj deleteRoleRule(roleName, path, token)

Delete a rule from a role

Delete a rule from a role Options:   role-name -    The role name to be updated   path -    The path the rule refers to   token -    Access token

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var roleName = "roleName_example"; // String | The role name to be updated

var path = "path_example"; // String | The path the rule refers to

var token = "token_example"; // String | Access token


var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.deleteRoleRule(roleName, path, token, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **roleName** | **String**| The role name to be updated | 
 **path** | **String**| The path the rule refers to | 
 **token** | **String**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="describeItem"></a>
# **describeItem**
> ReplyObj describeItem(name, token)

Returns the item details

Returns the item details Options:   name -    Item name   token -    Access token

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var name = "name_example"; // String | Item name

var token = "token_example"; // String | Access token


var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.describeItem(name, token, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| Item name | 
 **token** | **String**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="encrypt"></a>
# **encrypt**
> ReplyObj encrypt(keyName, plaintext, token, opts)

Encrypts plaintext into ciphertext by using an AES key

Encrypts plaintext into ciphertext by using an AES key Options:   key-name -    The name of the key to use in the encryption process   plaintext -    Data to be encrypted   encryption-context -    name-value pair that specifies the encryption context to be used for authenticated encryption. If used here, the same value must be supplied to the decrypt command or decryption will fail   token -    Access token

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var keyName = "keyName_example"; // String | The name of the key to use in the encryption process

var plaintext = "plaintext_example"; // String | Data to be encrypted

var token = "token_example"; // String | Access token

var opts = { 
  'encryptionContext': "encryptionContext_example" // String | name-value pair that specifies the encryption context to be used for authenticated encryption. If used here, the same value must be supplied to the decrypt command or decryption will fail
};

var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.encrypt(keyName, plaintext, token, opts, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **keyName** | **String**| The name of the key to use in the encryption process | 
 **plaintext** | **String**| Data to be encrypted | 
 **token** | **String**| Access token | 
 **encryptionContext** | **String**| name-value pair that specifies the encryption context to be used for authenticated encryption. If used here, the same value must be supplied to the decrypt command or decryption will fail | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="encryptFile"></a>
# **encryptFile**
> ReplyObj encryptFile(keyName, _in, token, opts)

Encrypts a file by using an AES key

Encrypts a file by using an AES key Options:   key-name -    The name of the key to use in the encryption process   in -    Path to the file to be encrypted. If not provided, the content will be taken from stdin   out -    Path to the output file. If not provided, the output will be sent to stdout   encryption-context -    name-value pair that specifies the encryption context to be used for authenticated encryption. If used here, the same value must be supplied to the decrypt command or decryption will fail   token -    Access token

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var keyName = "keyName_example"; // String | The name of the key to use in the encryption process

var _in = "_in_example"; // String | Path to the file to be encrypted. If not provided, the content will be taken from stdin

var token = "token_example"; // String | Access token

var opts = { 
  'out': "out_example", // String | Path to the output file. If not provided, the output will be sent to stdout
  'encryptionContext': "encryptionContext_example" // String | name-value pair that specifies the encryption context to be used for authenticated encryption. If used here, the same value must be supplied to the decrypt command or decryption will fail
};

var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.encryptFile(keyName, _in, token, opts, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **keyName** | **String**| The name of the key to use in the encryption process | 
 **_in** | **String**| Path to the file to be encrypted. If not provided, the content will be taken from stdin | 
 **token** | **String**| Access token | 
 **out** | **String**| Path to the output file. If not provided, the output will be sent to stdout | [optional] 
 **encryptionContext** | **String**| name-value pair that specifies the encryption context to be used for authenticated encryption. If used here, the same value must be supplied to the decrypt command or decryption will fail | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="encryptPkcs1"></a>
# **encryptPkcs1**
> ReplyObj encryptPkcs1(keyName, plaintext, token)

Encrypts the given message with RSA and the padding scheme from PKCS#1 v1.5

Encrypts the given message with RSA and the padding scheme from PKCS#1 v1.5 Options:   key-name -    The name of the RSA key to use in the encryption process   plaintext -    Data to be encrypted   token -    Access token

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var keyName = "keyName_example"; // String | The name of the RSA key to use in the encryption process

var plaintext = "plaintext_example"; // String | Data to be encrypted

var token = "token_example"; // String | Access token


var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.encryptPkcs1(keyName, plaintext, token, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **keyName** | **String**| The name of the RSA key to use in the encryption process | 
 **plaintext** | **String**| Data to be encrypted | 
 **token** | **String**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="getAuthMethod"></a>
# **getAuthMethod**
> ReplyObj getAuthMethod(name, token)

Returns an information about the Auth Method

Returns an information about the Auth Method Options:   name -    Auth Method name   token -    Access token

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var name = "name_example"; // String | Auth Method name

var token = "token_example"; // String | Access token


var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.getAuthMethod(name, token, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| Auth Method name | 
 **token** | **String**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="getCloudIdentity"></a>
# **getCloudIdentity**
> ReplyObj getCloudIdentity(token, opts)

Get Cloud Identity Token (relevant only for access-type=azure_ad,aws_iam)

Get Cloud Identity Token (relevant only for access-type=azure_ad,aws_iam) Options:   azure_ad_object_id -    Azure Active Directory ObjectId (relevant only for access-type=azure_ad)   url_safe -    escapes the token so it can be safely placed inside a URL query   token -    Access token

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var token = "token_example"; // String | Access token

var opts = { 
  'azureAdObjectId': "azureAdObjectId_example", // String | Azure Active Directory ObjectId (relevant only for access-type=azure_ad)
  'urlSafe': "urlSafe_example" // String | escapes the token so it can be safely placed inside a URL query
};

var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.getCloudIdentity(token, opts, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **token** | **String**| Access token | 
 **azureAdObjectId** | **String**| Azure Active Directory ObjectId (relevant only for access-type=azure_ad) | [optional] 
 **urlSafe** | **String**| escapes the token so it can be safely placed inside a URL query | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="getDynamicSecretValue"></a>
# **getDynamicSecretValue**
> ReplyObj getDynamicSecretValue(name, token)

Get dynamic secret value

Get dynamic secret value Options:   name -    Dynamic secret name   token -    Access token

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var name = "name_example"; // String | Dynamic secret name

var token = "token_example"; // String | Access token


var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.getDynamicSecretValue(name, token, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| Dynamic secret name | 
 **token** | **String**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="getKubeExecCreds"></a>
# **getKubeExecCreds**
> ReplyObj getKubeExecCreds(certIssuerName, keyFilePath, token, opts)

Get credentials for authentication with Kubernetes cluster based on a PKI Cert Issuer

Get credentials for authentication with Kubernetes cluster based on a PKI Cert Issuer Options:   cert-issuer-name -    The name of the PKI certificate issuer   key-file-path -    The client public or private key file path (in case of a private key, it will be use to extract the public key)   common-name -    The common name to be included in the PKI certificate   alt-names -    The Subject Alternative Names to be included in the PKI certificate (in a comma-delimited list)   uri-sans -    The URI Subject Alternative Names to be included in the PKI certificate (in a comma-delimited list)   outfile -    Output file path with the certificate. If not provided, the file with the certificate will be created in the same location of the provided public key with the -cert extension   token -    Access token

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var certIssuerName = "certIssuerName_example"; // String | The name of the PKI certificate issuer

var keyFilePath = "keyFilePath_example"; // String | The client public or private key file path (in case of a private key, it will be use to extract the public key)

var token = "token_example"; // String | Access token

var opts = { 
  'commonName': "commonName_example", // String | The common name to be included in the PKI certificate
  'altNames': "altNames_example", // String | The Subject Alternative Names to be included in the PKI certificate (in a comma-delimited list)
  'uriSans': "uriSans_example", // String | The URI Subject Alternative Names to be included in the PKI certificate (in a comma-delimited list)
  'outfile': "outfile_example" // String | Output file path with the certificate. If not provided, the file with the certificate will be created in the same location of the provided public key with the -cert extension
};

var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.getKubeExecCreds(certIssuerName, keyFilePath, token, opts, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **certIssuerName** | **String**| The name of the PKI certificate issuer | 
 **keyFilePath** | **String**| The client public or private key file path (in case of a private key, it will be use to extract the public key) | 
 **token** | **String**| Access token | 
 **commonName** | **String**| The common name to be included in the PKI certificate | [optional] 
 **altNames** | **String**| The Subject Alternative Names to be included in the PKI certificate (in a comma-delimited list) | [optional] 
 **uriSans** | **String**| The URI Subject Alternative Names to be included in the PKI certificate (in a comma-delimited list) | [optional] 
 **outfile** | **String**| Output file path with the certificate. If not provided, the file with the certificate will be created in the same location of the provided public key with the -cert extension | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="getPkiCertificate"></a>
# **getPkiCertificate**
> ReplyObj getPkiCertificate(certIssuerName, keyFilePath, token, opts)

Generates PKI certificate

Generates PKI certificate Options:   cert-issuer-name -    The name of the PKI certificate issuer   key-file-path -    The client public or private key file path (in case of a private key, it will be use to extract the public key)   common-name -    The common name to be included in the PKI certificate   alt-names -    The Subject Alternative Names to be included in the PKI certificate (in a comma-delimited list)   uri-sans -    The URI Subject Alternative Names to be included in the PKI certificate (in a comma-delimited list)   outfile -    Output file path with the certificate. If not provided, the file with the certificate will be created in the same location of the provided public key with the -cert extension   token -    Access token

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var certIssuerName = "certIssuerName_example"; // String | The name of the PKI certificate issuer

var keyFilePath = "keyFilePath_example"; // String | The client public or private key file path (in case of a private key, it will be use to extract the public key)

var token = "token_example"; // String | Access token

var opts = { 
  'commonName': "commonName_example", // String | The common name to be included in the PKI certificate
  'altNames': "altNames_example", // String | The Subject Alternative Names to be included in the PKI certificate (in a comma-delimited list)
  'uriSans': "uriSans_example", // String | The URI Subject Alternative Names to be included in the PKI certificate (in a comma-delimited list)
  'outfile': "outfile_example" // String | Output file path with the certificate. If not provided, the file with the certificate will be created in the same location of the provided public key with the -cert extension
};

var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.getPkiCertificate(certIssuerName, keyFilePath, token, opts, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **certIssuerName** | **String**| The name of the PKI certificate issuer | 
 **keyFilePath** | **String**| The client public or private key file path (in case of a private key, it will be use to extract the public key) | 
 **token** | **String**| Access token | 
 **commonName** | **String**| The common name to be included in the PKI certificate | [optional] 
 **altNames** | **String**| The Subject Alternative Names to be included in the PKI certificate (in a comma-delimited list) | [optional] 
 **uriSans** | **String**| The URI Subject Alternative Names to be included in the PKI certificate (in a comma-delimited list) | [optional] 
 **outfile** | **String**| Output file path with the certificate. If not provided, the file with the certificate will be created in the same location of the provided public key with the -cert extension | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="getRole"></a>
# **getRole**
> ReplyObj getRole(name, token)

Get role details

Get role details Options:   name -    Role name   token -    Access token

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var name = "name_example"; // String | Role name

var token = "token_example"; // String | Access token


var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.getRole(name, token, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| Role name | 
 **token** | **String**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="getRsaPublic"></a>
# **getRsaPublic**
> ReplyObj getRsaPublic(name, token)

Obtain the public key from a specific RSA private key

Obtain the public key from a specific RSA private key Options:   name -    Name of key to be created   token -    Access token

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var name = "name_example"; // String | Name of key to be created

var token = "token_example"; // String | Access token


var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.getRsaPublic(name, token, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| Name of key to be created | 
 **token** | **String**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="getSecretValue"></a>
# **getSecretValue**
> ReplyObj getSecretValue(name, token)

Get static secret value

Get static secret value Options:   name -    Secret name   token -    Access token

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var name = "name_example"; // String | Secret name

var token = "token_example"; // String | Access token


var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.getSecretValue(name, token, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| Secret name | 
 **token** | **String**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="getSshCertificate"></a>
# **getSshCertificate**
> ReplyObj getSshCertificate(certUsername, certIssuerName, publicKeyFilePath, token, opts)

Generates SSH certificate

Generates SSH certificate Options:   cert-username -    The username to sign in the SSH certificate   cert-issuer-name -    The name of the SSH certificate issuer   public-key-file-path -    SSH public key   outfile -    Output file path with the certificate. If not provided, the file with the certificate will be created in the same location of the provided public key with the -cert extension   token -    Access token

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var certUsername = "certUsername_example"; // String | The username to sign in the SSH certificate

var certIssuerName = "certIssuerName_example"; // String | The name of the SSH certificate issuer

var publicKeyFilePath = "publicKeyFilePath_example"; // String | SSH public key

var token = "token_example"; // String | Access token

var opts = { 
  'outfile': "outfile_example" // String | Output file path with the certificate. If not provided, the file with the certificate will be created in the same location of the provided public key with the -cert extension
};

var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.getSshCertificate(certUsername, certIssuerName, publicKeyFilePath, token, opts, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **certUsername** | **String**| The username to sign in the SSH certificate | 
 **certIssuerName** | **String**| The name of the SSH certificate issuer | 
 **publicKeyFilePath** | **String**| SSH public key | 
 **token** | **String**| Access token | 
 **outfile** | **String**| Output file path with the certificate. If not provided, the file with the certificate will be created in the same location of the provided public key with the -cert extension | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="help"></a>
# **help**
> ReplyObj help()

help text

help text

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.help(callback);
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="listAuthMethods"></a>
# **listAuthMethods**
> ReplyObj listAuthMethods(token, opts)

Returns a list of all the Auth Methods in the account

Returns a list of all the Auth Methods in the account Options:   pagination-token -    Next page reference   token -    Access token

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var token = "token_example"; // String | Access token

var opts = { 
  'paginationToken': "paginationToken_example" // String | Next page reference
};

var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.listAuthMethods(token, opts, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **token** | **String**| Access token | 
 **paginationToken** | **String**| Next page reference | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="listItems"></a>
# **listItems**
> ReplyObj listItems(token, opts)

Returns a list of all accessible items

Returns a list of all accessible items Options:   type -    The item types list of the requested items. In case it is empty, all types of items will be returned. options- [key, static-secret, dynamic-secret]   ItemsTypes -    ItemsTypes   filter -    Filter by item name or part of it   tag -    Filter by item tag   path -    Path to folder   pagination-token -    Next page reference   token -    Access token

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var token = "token_example"; // String | Access token

var opts = { 
  'type': "type_example", // String | The item types list of the requested items. In case it is empty, all types of items will be returned. options- [key, static-secret, dynamic-secret]
  'itemsTypes': "itemsTypes_example", // String | ItemsTypes
  'filter': "filter_example", // String | Filter by item name or part of it
  'tag': "tag_example", // String | Filter by item tag
  'path': "path_example", // String | Path to folder
  'paginationToken': "paginationToken_example" // String | Next page reference
};

var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.listItems(token, opts, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **token** | **String**| Access token | 
 **type** | **String**| The item types list of the requested items. In case it is empty, all types of items will be returned. options- [key, static-secret, dynamic-secret] | [optional] 
 **itemsTypes** | **String**| ItemsTypes | [optional] 
 **filter** | **String**| Filter by item name or part of it | [optional] 
 **tag** | **String**| Filter by item tag | [optional] 
 **path** | **String**| Path to folder | [optional] 
 **paginationToken** | **String**| Next page reference | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="listRoles"></a>
# **listRoles**
> ReplyObj listRoles(token, opts)

Returns a list of all roles in the account

Returns a list of all roles in the account Options:   pagination-token -    Next page reference   token -    Access token

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var token = "token_example"; // String | Access token

var opts = { 
  'paginationToken': "paginationToken_example" // String | Next page reference
};

var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.listRoles(token, opts, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **token** | **String**| Access token | 
 **paginationToken** | **String**| Next page reference | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="reverseRbac"></a>
# **reverseRbac**
> ReplyObj reverseRbac(path, type, token)

See which authentication methods have access to a particular object

See which authentication methods have access to a particular object Options:   path -    Path to an object   type -    Type of object (item, am, role)   token -    Access token

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var path = "path_example"; // String | Path to an object

var type = "type_example"; // String | Type of object (item, am, role)

var token = "token_example"; // String | Access token


var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.reverseRbac(path, type, token, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **path** | **String**| Path to an object | 
 **type** | **String**| Type of object (item, am, role) | 
 **token** | **String**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="setRoleRule"></a>
# **setRoleRule**
> ReplyObj setRoleRule(roleName, path, capability, token)

Set a rule to a role

Set a rule to a role Options:   role-name -    The role name to be updated   path -    The path the rule refers to   capability -    List of the approved/denied capabilities in the path options- [read, create, update, delete, list, deny]   token -    Access token

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var roleName = "roleName_example"; // String | The role name to be updated

var path = "path_example"; // String | The path the rule refers to

var capability = "capability_example"; // String | List of the approved/denied capabilities in the path options- [read, create, update, delete, list, deny]

var token = "token_example"; // String | Access token


var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.setRoleRule(roleName, path, capability, token, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **roleName** | **String**| The role name to be updated | 
 **path** | **String**| The path the rule refers to | 
 **capability** | **String**| List of the approved/denied capabilities in the path options- [read, create, update, delete, list, deny] | 
 **token** | **String**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="signPkcs1"></a>
# **signPkcs1**
> ReplyObj signPkcs1(keyName, message, token)

Calculates the signature of hashed using RSASSA-PKCS1-V1_5-SIGN from RSA PKCS#1 v1.5

Calculates the signature of hashed using RSASSA-PKCS1-V1_5-SIGN from RSA PKCS#1 v1.5 Options:   key-name -    The name of the RSA key to use in the signing process   message -    The message to be signed   token -    Access token

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var keyName = "keyName_example"; // String | The name of the RSA key to use in the signing process

var message = "message_example"; // String | The message to be signed

var token = "token_example"; // String | Access token


var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.signPkcs1(keyName, message, token, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **keyName** | **String**| The name of the RSA key to use in the signing process | 
 **message** | **String**| The message to be signed | 
 **token** | **String**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="unconfigure"></a>
# **unconfigure**
> ReplyObj unconfigure(token)

Remove Configuration of client profile.

Remove Configuration of client profile. Options:   token -    Access token

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var token = "token_example"; // String | Access token


var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.unconfigure(token, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **token** | **String**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="update"></a>
# **update**
> ReplyObj update(token)

Update a new AKEYLESS CLI version

Update a new AKEYLESS CLI version Options:   token -    Access token

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var token = "token_example"; // String | Access token


var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.update(token, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **token** | **String**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="updateItem"></a>
# **updateItem**
> ReplyObj updateItem(name, token, opts)

Update item name and metadata

Update item name and metadata Options:   name -    Current item name   new-name -    New item name   new-metadata -    New item metadata   add-tag -    List of the new tags that will be attached to this item. To specify multiple tags use argument multiple times- --add-tag Tag1 --add-tag Tag2   rm-tag -    List of the existent tags that will be removed from this item. To specify multiple tags use argument multiple times- --rm-tag Tag1 --rm-tag Tag2   token -    Access token

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var name = "name_example"; // String | Current item name

var token = "token_example"; // String | Access token

var opts = { 
  'newName': "newName_example", // String | New item name
  'newMetadata': "newMetadata_example", // String | New item metadata
  'addTag': "addTag_example", // String | List of the new tags that will be attached to this item. To specify multiple tags use argument multiple times- --add-tag Tag1 --add-tag Tag2
  'rmTag': "rmTag_example" // String | List of the existent tags that will be removed from this item. To specify multiple tags use argument multiple times- --rm-tag Tag1 --rm-tag Tag2
};

var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.updateItem(name, token, opts, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| Current item name | 
 **token** | **String**| Access token | 
 **newName** | **String**| New item name | [optional] 
 **newMetadata** | **String**| New item metadata | [optional] 
 **addTag** | **String**| List of the new tags that will be attached to this item. To specify multiple tags use argument multiple times- --add-tag Tag1 --add-tag Tag2 | [optional] 
 **rmTag** | **String**| List of the existent tags that will be removed from this item. To specify multiple tags use argument multiple times- --rm-tag Tag1 --rm-tag Tag2 | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="updateRole"></a>
# **updateRole**
> ReplyObj updateRole(name, token, opts)

Update role details

Update role details Options:   name -    Role name   new-name -    New Role name   new-comment -    New comment about the role   token -    Access token

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var name = "name_example"; // String | Role name

var token = "token_example"; // String | Access token

var opts = { 
  'newName': "newName_example", // String | New Role name
  'newComment': "newComment_example" // String | New comment about the role
};

var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.updateRole(name, token, opts, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| Role name | 
 **token** | **String**| Access token | 
 **newName** | **String**| New Role name | [optional] 
 **newComment** | **String**| New comment about the role | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="updateSecretVal"></a>
# **updateSecretVal**
> ReplyObj updateSecretVal(name, value, token, opts)

Update static secret value

Update static secret value Options:   name -    Secret name   value -    The new secret value   key -    The name of a key that used to encrypt the secret value (if empty, the account default protectionKey key will be used)   multiline -    The provided value is a multiline value (separated by '\\n')   token -    Access token

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var name = "name_example"; // String | Secret name

var value = "value_example"; // String | The new secret value

var token = "token_example"; // String | Access token

var opts = { 
  'key': "key_example", // String | The name of a key that used to encrypt the secret value (if empty, the account default protectionKey key will be used)
  'multiline': true // Boolean | The provided value is a multiline value (separated by '\\n')
};

var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.updateSecretVal(name, value, token, opts, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| Secret name | 
 **value** | **String**| The new secret value | 
 **token** | **String**| Access token | 
 **key** | **String**| The name of a key that used to encrypt the secret value (if empty, the account default protectionKey key will be used) | [optional] 
 **multiline** | **Boolean**| The provided value is a multiline value (separated by '\\n') | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="uploadPkcs12"></a>
# **uploadPkcs12**
> ReplyObj uploadPkcs12(name, _in, passphrase, token, opts)

Upload a PKCS#12 key and certificates

Upload a PKCS#12 key and certificates Options:   name -    Name of key to be created   in -    PKCS#12 input file (private key and certificate only)   passphrase -    Passphrase to unlock the pkcs#12 bundle   metadata -    A metadata about the key   tag -    List of the tags attached to this key. To specify multiple tags use argument multiple times- -t Tag1 -t Tag2   split-level -    The number of fragments that the item will be split into   customer-frg-id -    The customer fragment ID that will be used to split the key (if empty, the key will be created independently of a customer fragment)   cert -    Path to a file that contain the certificate in a PEM format. If this parameter is not empty, the certificate will be taken from here and not from the PKCS#12 input file   token -    Access token

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var name = "name_example"; // String | Name of key to be created

var _in = "_in_example"; // String | PKCS#12 input file (private key and certificate only)

var passphrase = "passphrase_example"; // String | Passphrase to unlock the pkcs#12 bundle

var token = "token_example"; // String | Access token

var opts = { 
  'metadata': "metadata_example", // String | A metadata about the key
  'tag': "tag_example", // String | List of the tags attached to this key. To specify multiple tags use argument multiple times- -t Tag1 -t Tag2
  'splitLevel': "splitLevel_example", // String | The number of fragments that the item will be split into
  'customerFrgId': "customerFrgId_example", // String | The customer fragment ID that will be used to split the key (if empty, the key will be created independently of a customer fragment)
  'cert': "cert_example" // String | Path to a file that contain the certificate in a PEM format. If this parameter is not empty, the certificate will be taken from here and not from the PKCS#12 input file
};

var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.uploadPkcs12(name, _in, passphrase, token, opts, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| Name of key to be created | 
 **_in** | **String**| PKCS#12 input file (private key and certificate only) | 
 **passphrase** | **String**| Passphrase to unlock the pkcs#12 bundle | 
 **token** | **String**| Access token | 
 **metadata** | **String**| A metadata about the key | [optional] 
 **tag** | **String**| List of the tags attached to this key. To specify multiple tags use argument multiple times- -t Tag1 -t Tag2 | [optional] 
 **splitLevel** | **String**| The number of fragments that the item will be split into | [optional] 
 **customerFrgId** | **String**| The customer fragment ID that will be used to split the key (if empty, the key will be created independently of a customer fragment) | [optional] 
 **cert** | **String**| Path to a file that contain the certificate in a PEM format. If this parameter is not empty, the certificate will be taken from here and not from the PKCS#12 input file | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="uploadRsa"></a>
# **uploadRsa**
> ReplyObj uploadRsa(name, alg, rsaKeyFilePath, token, opts)

Upload RSA key

Upload RSA key Options:   name -    Name of key to be created   alg -    Key type. options- [RSA1024, RSA2048]   rsa-key-file-path -    RSA private key file path   cert -    Path to a file that contain the certificate in a PEM format.   metadata -    A metadata about the key   tag -    List of the tags attached to this key. To specify multiple tags use argument multiple times- -t Tag1 -t Tag2   split-level -    The number of fragments that the item will be split into   customer-frg-id -    The customer fragment ID that will be used to split the key (if empty, the key will be created independently of a customer fragment)   token -    Access token

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var name = "name_example"; // String | Name of key to be created

var alg = "alg_example"; // String | Key type. options- [RSA1024, RSA2048]

var rsaKeyFilePath = "rsaKeyFilePath_example"; // String | RSA private key file path

var token = "token_example"; // String | Access token

var opts = { 
  'cert': "cert_example", // String | Path to a file that contain the certificate in a PEM format.
  'metadata': "metadata_example", // String | A metadata about the key
  'tag': "tag_example", // String | List of the tags attached to this key. To specify multiple tags use argument multiple times- -t Tag1 -t Tag2
  'splitLevel': "splitLevel_example", // String | The number of fragments that the item will be split into
  'customerFrgId': "customerFrgId_example" // String | The customer fragment ID that will be used to split the key (if empty, the key will be created independently of a customer fragment)
};

var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.uploadRsa(name, alg, rsaKeyFilePath, token, opts, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| Name of key to be created | 
 **alg** | **String**| Key type. options- [RSA1024, RSA2048] | 
 **rsaKeyFilePath** | **String**| RSA private key file path | 
 **token** | **String**| Access token | 
 **cert** | **String**| Path to a file that contain the certificate in a PEM format. | [optional] 
 **metadata** | **String**| A metadata about the key | [optional] 
 **tag** | **String**| List of the tags attached to this key. To specify multiple tags use argument multiple times- -t Tag1 -t Tag2 | [optional] 
 **splitLevel** | **String**| The number of fragments that the item will be split into | [optional] 
 **customerFrgId** | **String**| The customer fragment ID that will be used to split the key (if empty, the key will be created independently of a customer fragment) | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="verifyPkcs1"></a>
# **verifyPkcs1**
> ReplyObj verifyPkcs1(keyName, message, signature, token)

Verifies an RSA PKCS#1 v1.5 signature

Verifies an RSA PKCS#1 v1.5 signature Options:   key-name -    The name of the RSA key to use in the verification process   message -    The message to be verified   signature -    The message's signature   token -    Access token

### Example
```javascript
var AkeylessVaultApi = require('akeyless_vault_api');

var apiInstance = new AkeylessVaultApi.DefaultApi();

var keyName = "keyName_example"; // String | The name of the RSA key to use in the verification process

var message = "message_example"; // String | The message to be verified

var signature = "signature_example"; // String | The message's signature

var token = "token_example"; // String | Access token


var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully. Returned data: ' + data);
  }
};
apiInstance.verifyPkcs1(keyName, message, signature, token, callback);
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **keyName** | **String**| The name of the RSA key to use in the verification process | 
 **message** | **String**| The message to be verified | 
 **signature** | **String**| The message's signature | 
 **token** | **String**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

