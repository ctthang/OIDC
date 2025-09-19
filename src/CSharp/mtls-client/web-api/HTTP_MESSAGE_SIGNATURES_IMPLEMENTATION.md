# HTTP Message Signatures Implementation (RFC 9421) - NSign Library Integration

This implementation provides HTTP Message Signature validation using the **NSign library** with **DPoP integration** for key resolution.

## Features

### 🎯 **NSign Library Integration**
- **Professional Library**: Uses the robust NSign library for RFC 9421 compliance
- **DPoP Key Resolution**: Extracts public keys from DPoP proof tokens for signature verification

### 1. NSign Library with DPoP Integration
The implementation **integrates NSign library with DPoP key resolution**:

- **Primary Strategy**: Extract JWK from DPoP proof token header
- **Key ID Matching**: Validates that the DPoP key ID matches the signature key ID
- **Seamless Integration**: NSign handles RFC 9421 compliance while DPoP provides keys

### 2. Signature Input Reconstruction (via NSign)
NSign properly reconstructs the signature input string according to RFC 9421:

- Supports standard components: `@method`, `@path`, `@authority`
- Supports HTTP headers: `authorization`, `content-type`, etc.
- Handles special components like `@target-uri`, `@scheme`

### 3. Signature Verification (via NSign)
- Supports RSA-PSS-SHA512 (used in this implementation)
- Full cryptographic verification using NSign's robust implementation

### 4. Security Features
- **Replay Protection**: Timestamp validation with configurable max age
- **Strong Binding**: Same key used for both DPoP and HTTP signatures
- **Nonce Verification**: N/A

## NSign Configuration

### appsettings.json
```json
{
  "HttpSignatures": {
    "Enabled": true,
    "MaxAge": 300
  }
}
```

### Service Registration (Program.cs)
```csharp
if (enableHttpSignatures)
{
    builder.Services
        .Configure<RequestSignatureVerificationOptions>(options =>
        {
            options.TagsToVerify.Add("nsign-example-client");
            options.CreatedRequired =
                options.ExpiresRequired =
                options.KeyIdRequired =
                options.AlgorithmRequired =
                options.TagRequired = true;
            options.MissingSignatureResponseStatus = 404;
            options.MaxSignatureAge = TimeSpan.FromMinutes(5);

            options.VerifyNonce = (SignatureParamsComponent signatureParams) =>
            {
                Console.WriteLine($"Got signature with tag={signatureParams.Tag} and nonce={signatureParams.Nonce}.");
                return true;
            };

            options.OnSignatureVerificationFailed = (context, reason) =>
            {
                Console.WriteLine($"Signature verification failed: {reason}");
                return Task.CompletedTask;
            };

            options.OnSignatureInputError = (error, context) =>
            {
                Console.WriteLine("signature input error.");
                return Task.CompletedTask;
            };

            options.OnMissingSignatures = (context) =>
            {
                Console.WriteLine("Missing signatures.");
                return Task.CompletedTask;
            };
        })
        .AddSignatureVerification((serviceProvider) =>
        {
            // DPoP key extraction logic
            var httpContextAccessor = serviceProvider.GetRequiredService<IHttpContextAccessor>();
            var httpContext = httpContextAccessor.HttpContext;
            var rsaFromDPoP = ExtractPublicKeyFromDPoP(httpContext, out string keyId);
            return new RsaPssSha512SignatureProvider(null, rsaFromDPoP, keyId);
        });
}
```

### Middleware Registration
```csharp
if (enableHttpSignatures)
{
    app.UseWhen(ctx => ctx.Request.Path.StartsWithSegments("/HelloWorld"), ValidateSignatureAndDigest);
}
```

## How It Works (NSign + DPoP Flow)

### 1. Client Request
```http
GET /HelloWorld HTTP/1.1
Authorization: DPoP <access_token>
DPoP: <dpop_proof_with_jwk>
Signature: http-msg-sign=:<signature>:
Signature-Input: http-msg-sign=("@method" "@path" "@authority" "authorization");keyid="client1",alg="rsa-pss-sha512",created=1234567890
```

### 2. Server Processing
1. **NSign Middleware** intercepts the request
2. **Extract Key ID** from Signature-Input header
3. **Find DPoP Header** and parse the JWT
4. **Extract JWK** from DPoP header if key IDs match
5. **Convert JWK to RSA** public key for NSign
6. **NSign verifies** HTTP Message Signature using extracted key
7. **Continue to Controller** after successful verification

### 3. Success Flow
```
✅ DPoP header found
✅ Key IDs match (client1)
✅ JWK extracted from DPoP
✅ RSA public key created
✅ NSign HTTP Message Signature verified
✅ Request continues to HelloWorldController
✅ Controller returns "Hello, World!"
```

## NSign Library Benefits

### ✅ **Professional Implementation**
- Industry-standard RFC 9421 compliance
- Robust error handling and edge case coverage
- Well-tested signature verification algorithms

### ✅ **Flexible Configuration**
- Multiple signature algorithms supported
- Configurable signature parameters

### ✅ **Production Ready**
- Performance optimized
- Comprehensive logging and diagnostics
- Full middleware pipeline integration

## DPoP Integration Benefits

### ✅ **Simplified Key Management**
- No external key management required
- No pre-configuration needed
- Single source of truth for keys (DPoP proof)

### ✅ **Security**
- Strong binding between DPoP and HTTP signatures
- Uses the same cryptographic key for both
- Prevents key substitution attacks

### ✅ **Standards Compliance**
- Follows RFC 9449 (DPoP) for key extraction
- Follows RFC 9421 (HTTP Message Signatures) via NSign

## Testing the Implementation

1. **Run the console-app** to generate DPoP + HTTP Signature requests
2. **Run the web-api** to validate the signatures with NSign
3. **Check logs** to see the complete validation flow
4. **Verify controller execution** - should now see "Hello, World!" response

The implementation successfully combines NSign's professional HTTP Message Signatures support with DPoP-based key resolution!