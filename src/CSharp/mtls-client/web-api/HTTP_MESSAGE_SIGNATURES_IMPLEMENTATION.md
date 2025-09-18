# HTTP Message Signatures Implementation (RFC 9421) - Demo Version

This implementation provides a **demo-focused** HTTP Message Signature validator that extracts public keys directly from DPoP proof tokens.

## Features

### 🎯 **Demo-Focused Design**
- **DPoP-Only Key Resolution**: Keys are extracted exclusively from DPoP proof tokens
- **No External Dependencies**: No need for key management services or configuration
- **Simplified Implementation**: Perfect for demonstrations and proof-of-concepts

### 1. DPoP Integration for Key Resolution
The implementation **automatically extracts public keys from DPoP proof tokens**:

- **Primary Strategy**: Extract JWK from DPoP proof token header
- **Key ID Matching**: Validates that the DPoP key ID matches the signature key ID
- **No Fallback**: Demo version relies entirely on DPoP keys

### 2. Signature Input Reconstruction
Properly reconstructs the signature input string according to RFC 9421:

- Supports standard components: `@method`, `@path`, `@authority`
- Supports HTTP headers: `authorization`, `content-type`, etc.
- Handles special components like `@target-uri`, `@scheme`

### 3. Signature Verification
- Supports RSA-PSS-SHA256 (recommended by RFC 9421)
- Proper cryptographic verification using .NET's RSA implementation

### 4. Security Features
- **Replay Protection**: Timestamp validation with configurable max age
- **Strong Binding**: Same key used for both DPoP and HTTP signatures

## Demo Configuration

### appsettings.json (Minimal)
```json
{
  "HttpSignatures": {
    "Enabled": true,
    "RequireSignature": true,
    "MaxAge": 300
  }
}
```

### Service Registration (Program.cs)
```csharp
// Add HTTP Message Signature validator (demo version)
builder.Services.AddSingleton<IHttpMessageSignatureValidator, CustomHttpMessageSignatureValidator>();
```

## How It Works (Demo Flow)

### 1. Client Request
```http
POST /api/helloworld HTTP/1.1
Authorization: DPoP <access_token>
DPoP: <dpop_proof_with_jwk>
Signature: sig1=:<signature>:
Signature-Input: sig1=("@method" "@path" "@authority" "authorization");keyid="client1",alg="rsa-pss-sha256",created=1234567890
```

### 2. Server Processing
1. **Extract Key ID** from Signature-Input header
2. **Find DPoP Header** and parse the JWT
3. **Extract JWK** from DPoP header if key IDs match
4. **Convert JWK to RSA** public key
5. **Verify HTTP Message Signature** using extracted key

### 3. Success Flow
```
✅ DPoP header found
✅ Key IDs match (client1)
✅ JWK extracted from DPoP
✅ RSA public key created
✅ HTTP Message Signature verified
```

### 4. Failure Scenarios
```
❌ No DPoP header → Validation fails
❌ Invalid JWK → Validation fails
❌ Signature verification fails → Validation fails
```

## Demo Benefits

### ✅ **Simplicity**
- No external key management required
- No pre-configuration needed
- Single source of truth for keys (DPoP proof)

### ✅ **Security**
- Strong binding between DPoP and HTTP signatures
- Uses the same cryptographic key for both
- Prevents key substitution attacks

### ✅ **Standards Compliance**
- Follows RFC 9449 (DPoP) for key extraction
- Follows RFC 9421 (HTTP Message Signatures) for validation

## Demo Limitations

⚠️ **Production Considerations:**
- No fallback key resolution strategies
- No key caching for performance
- No nonce replay protection
- No key rotation management

## Testing the Demo

1. **Run the console-app** to generate DPoP + HTTP Signature requests
2. **Run the web-api** to validate the signatures
3. **Check logs** to see the key extraction and validation process

The demo illustrates the integration between DPoP and HTTP Message Signatures!