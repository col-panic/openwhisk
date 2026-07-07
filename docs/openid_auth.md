# OpenID Connect Authentication

OpenWhisk now supports OpenID Connect authentication as an alternative to the traditional API key authentication. This allows users to authenticate using JWT tokens from OpenID Connect providers like Keycloak, Google, Auth0, etc.

## Configuration

To enable OpenID Connect authentication, you need to configure the following settings in your `application.conf` or `local.conf`:

```conf
# Use OpenID authentication instead of Basic authentication
whisk.spi {
  AuthenticationDirectiveProvider = org.apache.openwhisk.core.controller.OpenIdAuthenticationDirective
}

# OpenID Connect configuration
whisk.openid {
  # The issuer URL of your OpenID Connect provider
  issuer = "http://localhost:8080/auth/realms/master"
  
  # The public key of your OpenID Connect provider in PEM format
  # This is used to validate JWT signatures
  publicKey = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA... (your public key here)
-----END PUBLIC KEY-----"""
  
  # The JWT claim to use as the namespace identifier
  # Default: "sub" (subject claim)
  namespaceClaim = "sub"
  
  # Prefix to add to subject names to avoid conflicts with existing namespaces
  # Default: "openid-"
  subjectPrefix = "openid-"
}
```

## Keycloak Setup

### 1. Create a Realm
- Log in to Keycloak admin console
- Create a new realm or use an existing one

### 2. Create a Client
- Go to Clients -> Create
- Client ID: `openwhisk`
- Client Protocol: `openid-connect`
- Root URL: `http://your-openwhisk-host`

### 3. Configure Client Settings
- Access Type: `confidential` or `public` depending on your needs
- Valid Redirect URIs: Add your OpenWhisk callback URLs if needed
- Web Origins: Add your OpenWhisk host

### 4. Get the Public Key
- Go to Realm Settings -> Keys
- Copy the public key in PEM format
- Use this as the `publicKey` in your OpenWhisk configuration

### 5. Get the Issuer URL
- The issuer URL is typically: `http://your-keycloak-host/auth/realms/your-realm-name`
- Use this as the `issuer` in your OpenWhisk configuration

## Authentication Flow

### For API Clients

Users can authenticate by including a JWT token in one of the following ways:

#### 1. Authorization Header (Bearer Token)
```bash
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  https://your-openwhisk-host/api/v1/namespaces
```

#### 2. X-Auth-Token Header
```bash
curl -H "X-Auth-Token: YOUR_JWT_TOKEN" \
  https://your-openwhisk-host/api/v1/namespaces
```

### Dynamic User Creation

When a user authenticates with a valid JWT token for the first time:

1. OpenWhisk validates the JWT signature using the configured public key
2. OpenWhisk verifies the issuer claim matches the configured issuer
3. OpenWhisk extracts the namespace claim (default: `sub`) from the JWT
4. OpenWhisk creates a new namespace using the format: `{subjectPrefix}{namespaceClaim}`
5. OpenWhisk creates a new identity and stores it in the authentication database
6. The user can now access their namespace and perform OpenWhisk operations

## JWT Token Requirements

The JWT token must contain the following claims:
- `iss` - Issuer, must match the configured issuer URL
- `sub` - Subject (or whatever claim is configured as `namespaceClaim`)

## Security Considerations

### Production Deployment
For production deployments, it is recommended to:

1. **Use a proper JWT library** for signature validation. The current implementation includes a simplified signature validation that should be replaced with a robust JWT library like:
   - [java-jwt](https://github.com/auth0/java-jwt)
   - [nimbus-jose-jwt](https://connect2id.com/products/nimbus-jose-jwt)

2. **Enable HTTPS** to ensure tokens are transmitted securely

3. **Rotate public keys** regularly and update the configuration

4. **Validate additional claims** like `aud` (audience), `exp` (expiration), etc.

5. **Use short-lived tokens** and implement token refresh mechanisms

### Testing

For testing purposes, you can:

1. **Skip signature validation** by leaving the `publicKey` empty or invalid
2. **Use mock JWT tokens** that contain the required claims
3. **Configure a test OpenID provider** like Keycloak in development mode

## Example JWT Token

Here's an example of a JWT token payload that would work with the default configuration:

```json
{
  "iss": "http://localhost:8080/auth/realms/master",
  "sub": "1234567890",
  "name": "John Doe",
  "email": "john@example.com",
  "iat": 1516239022,
  "exp": 1516242622
}
```

This would create a namespace: `openid-1234567890` and a subject: `openid-1234567890`

## Fallback to Basic Authentication

To switch back to Basic Authentication, simply change the SPI configuration:

```conf
whisk.spi {
  AuthenticationDirectiveProvider = org.apache.openwhisk.core.controller.BasicAuthenticationDirective
}
```

## Troubleshooting

### Common Issues

1. **Invalid issuer**: Ensure the `iss` claim in your JWT matches the configured `issuer`
2. **Missing namespace claim**: Ensure your JWT contains the claim specified in `namespaceClaim`
3. **Signature validation failure**: Ensure your public key is correctly configured and matches the key used to sign the JWT
4. **Namespace conflicts**: The `subjectPrefix` helps avoid conflicts with existing namespaces

### Debugging

Enable debug logging to see authentication details:

```conf
loglevel = "DEBUG"
```

Check the controller logs for authentication-related messages.

## Implementation Details

The OpenID authentication implementation consists of:

1. **OpenIdAuthenticationDirective** - Main authentication provider implementing `AuthenticationDirectiveProvider`
2. **OpenIdAuthKey** - Authentication key type for OpenID users
3. **OpenIdConfig** - Configuration case class for OpenID settings
4. **Updated WhiskAuth and WhiskNamespace** - Support for GenericAuthKey to handle both Basic and OpenID authentication

The implementation uses the existing SPI mechanism, allowing it to be plugged in as a replacement for BasicAuthenticationDirective without changing the rest of the OpenWhisk codebase.