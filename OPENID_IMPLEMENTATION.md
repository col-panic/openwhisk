# OpenID Authentication Implementation for OpenWhisk

## Summary

This implementation adds OpenID Connect authentication support to Apache OpenWhisk, allowing users to authenticate using JWT tokens from OpenID Connect providers like Keycloak, Google, Auth0, etc. The system dynamically creates users and namespaces on first login.

## Changes Made

### 1. New Files Created

#### Core Implementation
- **`core/controller/src/main/scala/org/apache/openwhisk/core/controller/OpenIdAuthenticationDirective.scala`**
  - Main OpenID authentication provider implementing `AuthenticationDirectiveProvider`
  - Handles JWT token extraction from `Authorization: Bearer` and `X-Auth-Token` headers
  - Validates JWT tokens (signature, issuer, claims)
  - Dynamically creates identities and namespaces for new OpenID users
  - Supports both online and offline JWT validation

#### Entity Classes
- **`common/scala/src/main/scala/org/apache/openwhisk/core/entity/OpenIdAuthKey.scala`**
  - Authentication key class for OpenID users
  - Extends `GenericAuthKey` to integrate with existing authentication system

#### Documentation
- **`docs/openid_auth.md`**
  - Comprehensive documentation for setting up and using OpenID authentication
  - Includes Keycloak setup instructions, configuration examples, and troubleshooting

#### Tests
- **`tests/src/test/scala/org/apache/openwhisk/core/controller/test/OpenIdAuthenticateTests.scala`**
  - Unit tests for OpenID authentication functionality
  - Tests JWT token extraction, decoding, and validation

### 2. Modified Files

#### Configuration
- **`common/scala/src/main/resources/reference.conf`**
  - Added OpenID configuration section with default values
  - Added comment showing how to switch to OpenID authentication

- **`common/scala/src/main/scala/org/apache/openwhisk/core/WhiskConfig.scala`**
  - Added `openid` configuration key to `ConfigKeys` object

#### Entity Classes
- **`common/scala/src/main/scala/org/apache/openwhisk/core/entity/WhiskAuth.scala`**
  - Updated `WhiskNamespace` to use `GenericAuthKey` instead of `BasicAuthenticationAuthKey`
  - Updated serialization/deserialization to handle both Basic and OpenID auth keys
  - Maintains backward compatibility with existing Basic Authentication

- **`common/scala/src/main/scala/org/apache/openwhisk/core/entity/Identity.scala`**
  - Updated `rowToIdentity` method to handle both Basic and OpenID auth keys
  - Maintains backward compatibility with existing database entries

## Architecture

### Authentication Flow

1. **Request Processing**: HTTP request arrives with JWT token in `Authorization: Bearer` or `X-Auth-Token` header
2. **Token Extraction**: `OpenIdAuthenticationDirective` extracts the JWT token from headers
3. **Token Validation**: 
   - Validates JWT signature using configured public key
   - Verifies issuer claim matches configured issuer
   - Extracts claims from JWT payload
4. **Identity Resolution**:
   - Attempts to find existing identity by namespace
   - If not found, creates new identity and namespace dynamically
   - Stores new identity in CouchDB via `WhiskAuthStore`
5. **Request Authorization**: Returns identity to downstream handlers for authorization

### Dynamic User Creation

When a user authenticates for the first time:

1. Extracts `namespaceClaim` (default: `sub`) from JWT
2. Creates namespace name: `{subjectPrefix}{namespaceClaim}` (default: `openid-{sub}`)
3. Creates subject: `{subjectPrefix}{namespaceClaim}`
4. Creates `OpenIdAuthKey` with UUID from namespace claim
5. Creates `WhiskAuth` document with subject and namespace
6. Stores in CouchDB via `AuthStore`
7. Returns new `Identity` object

### SPI Integration

The implementation uses OpenWhisk's existing SPI mechanism:

```scala
// In reference.conf
whisk.spi {
  AuthenticationDirectiveProvider = org.apache.openwhisk.core.controller.OpenIdAuthenticationDirective
}
```

This allows switching between Basic and OpenID authentication by simply changing the configuration.

## Configuration

### Required Settings

```conf
whisk.openid {
  issuer = "http://your-keycloak-host/auth/realms/your-realm"
  publicKey = """-----BEGIN PUBLIC KEY-----
  MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
  -----END PUBLIC KEY-----"""
  namespaceClaim = "sub"        # JWT claim to use as namespace
  subjectPrefix = "openid-"     # Prefix for subject/namespace names
}
```

### Optional Settings

- `namespaceClaim`: Can be changed to use different JWT claims (e.g., `email`, `preferred_username`)
- `subjectPrefix`: Can be changed or removed to customize namespace naming

## Security Features

1. **JWT Signature Validation**: Validates JWT signatures using RSA public key
2. **Issuer Verification**: Ensures tokens are from trusted issuer
3. **Flexible Claim Mapping**: Configurable namespace claim mapping
4. **Namespace Isolation**: Each OpenID user gets their own isolated namespace
5. **Backward Compatibility**: Existing Basic Authentication users are not affected

## Usage Examples

### API Request with JWT Token

```bash
# Using Authorization header
curl -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." \
  https://openwhisk-host/api/v1/namespaces

# Using X-Auth-Token header
curl -H "X-Auth-Token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." \
  https://openwhisk-host/api/v1/namespaces
```

### Keycloak Integration

1. Set up Keycloak realm and client
2. Configure OpenWhisk with Keycloak's issuer URL and public key
3. Users obtain JWT tokens from Keycloak
4. Users include JWT tokens in API requests
5. OpenWhisk validates tokens and creates users dynamically

## Testing

The implementation includes unit tests for:

- JWT token extraction from headers
- JWT payload decoding
- Auth key creation
- Namespace creation

For integration testing:

1. Configure OpenID settings in `application.conf`
2. Start OpenWhisk with OpenID authentication enabled
3. Obtain JWT token from OpenID provider
4. Make API requests with JWT token
5. Verify user and namespace are created automatically

## Limitations and Future Enhancements

### Current Limitations

1. **Simplified JWT Validation**: Current implementation uses basic JWT signature validation. For production, consider integrating a robust JWT library.
2. **No Token Expiration Check**: Currently doesn't validate `exp` claim.
3. **No Audience Validation**: Currently doesn't validate `aud` claim.
4. **No Token Revocation**: No mechanism to revoke tokens.

### Future Enhancements

1. **Enhanced JWT Validation**: Integrate proper JWT library for comprehensive validation
2. **Token Caching**: Cache validated tokens to improve performance
3. **Multiple Providers**: Support multiple OpenID providers simultaneously
4. **Group Mapping**: Map OpenID groups/roles to OpenWhisk privileges
5. **Token Refresh**: Support token refresh mechanisms
6. **Rate Limiting**: Implement rate limiting for authentication endpoints

## Backward Compatibility

The implementation maintains full backward compatibility:

- Existing Basic Authentication continues to work unchanged
- Existing users and namespaces are not affected
- Database schema remains compatible
- Switching between authentication methods is configuration-only

## Migration Path

To migrate from Basic Authentication to OpenID:

1. Configure OpenID settings in configuration
2. Switch `AuthenticationDirectiveProvider` to `OpenIdAuthenticationDirective`
3. Restart OpenWhisk services
4. Users can now authenticate with JWT tokens
5. Existing Basic Auth users can still use their API keys (if both providers are supported)

## Files Modified Summary

### New Files (4)
- `core/controller/src/main/scala/org/apache/openwhisk/core/controller/OpenIdAuthenticationDirective.scala`
- `common/scala/src/main/scala/org/apache/openwhisk/core/entity/OpenIdAuthKey.scala`
- `docs/openid_auth.md`
- `tests/src/test/scala/org/apache/openwhisk/core/controller/test/OpenIdAuthenticateTests.scala`

### Modified Files (4)
- `common/scala/src/main/resources/reference.conf`
- `common/scala/src/main/scala/org/apache/openwhisk/core/WhiskConfig.scala`
- `common/scala/src/main/scala/org/apache/openwhisk/core/entity/WhiskAuth.scala`
- `common/scala/src/main/scala/org/apache/openwhisk/core/entity/Identity.scala`

Total: 8 files changed (4 new, 4 modified)