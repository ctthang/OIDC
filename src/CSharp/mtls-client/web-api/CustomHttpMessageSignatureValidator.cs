using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace web_api
{
    public interface IHttpMessageSignatureValidator
    {
        Task<bool> ValidateSignatureAsync(HttpContext context);
    }

    // Custom HTTP Message Signature validator implementing RFC 9421
    public class CustomHttpMessageSignatureValidator : IHttpMessageSignatureValidator
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<CustomHttpMessageSignatureValidator> _logger;

        public CustomHttpMessageSignatureValidator(
            IConfiguration configuration, 
            ILogger<CustomHttpMessageSignatureValidator> logger)
        {
            _configuration = configuration;
            _logger = logger;
        }

        public async Task<bool> ValidateSignatureAsync(HttpContext context)
        {
            try
            {
                var signatureHeader = context.Request.Headers["Signature"].FirstOrDefault();
                var signatureInputHeader = context.Request.Headers["Signature-Input"].FirstOrDefault();

                if (string.IsNullOrEmpty(signatureHeader) || string.IsNullOrEmpty(signatureInputHeader))
                {
                    _logger.LogWarning("[HTTP-SIG] Missing signature headers");
                    return false;
                }

                _logger.LogInformation("[HTTP-SIG] Validating RFC 9421 HTTP Message Signature");
                _logger.LogDebug("   Signature: {Signature}", signatureHeader);
                _logger.LogDebug("   Signature-Input: {SignatureInput}", signatureInputHeader);

                // Extract signature value (RFC 9421 format: sig1=:base64signature:)
                var signatureMatch = Regex.Match(signatureHeader, @"sig1=:([^:]+):");
                if (!signatureMatch.Success)
                {
                    _logger.LogWarning("[HTTP-SIG] Invalid signature format - must be sig1=:base64:");
                    return false;
                }

                var signatureBase64 = signatureMatch.Groups[1].Value;
                var signatureBytes = Convert.FromBase64String(signatureBase64);

                // Extract and validate metadata from signature input
                var validationResult = await ValidateSignatureMetadata(signatureInputHeader);
                if (!validationResult.IsValid)
                {
                    return false;
                }

                // 1. Resolve the public key from DPoP proof
                var publicKey = await ResolvePublicKeyAsync(context);
                if (publicKey == null)
                {
                    _logger.LogWarning("[HTTP-SIG] Could not resolve public key for keyId: {KeyId}", validationResult.KeyId);
                    return false;
                }

                // 2. Reconstruct the signature input string from the request
                var signatureInput = await ReconstructSignatureInputAsync(context, signatureInputHeader);
                if (string.IsNullOrEmpty(signatureInput))
                {
                    _logger.LogWarning("[HTTP-SIG] Failed to reconstruct signature input");
                    return false;
                }

                // 3. Verify the signature using the public key
                var isSignatureValid = await VerifySignatureAsync(publicKey, signatureInput, signatureBytes, validationResult.Algorithm);
                
                if (isSignatureValid)
                {
                    _logger.LogInformation("[HTTP-SIG] RFC 9421 signature validation successful");
                    return true;
                }
                else
                {
                    _logger.LogWarning("[HTTP-SIG] Signature verification failed");
                    return false;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[HTTP-SIG] Signature validation failed with exception");
                return false;
            }
        }

        private async Task<(bool IsValid, string KeyId, string Algorithm, long Created, string Nonce)> ValidateSignatureMetadata(string signatureInputHeader)
        {
            // Extract key ID from signature input (RFC 9421 format)
            var keyIdMatch = Regex.Match(signatureInputHeader, @"keyid=""([^""]+)""");
            if (!keyIdMatch.Success)
            {
                _logger.LogWarning("[HTTP-SIG] Missing keyid in signature input");
                return (false, "", "", 0, "");
            }
            var keyId = keyIdMatch.Groups[1].Value;

            // Extract algorithm
            var algMatch = Regex.Match(signatureInputHeader, @"alg=""([^""]+)""");
            if (!algMatch.Success)
            {
                _logger.LogWarning("[HTTP-SIG] Missing algorithm in signature input");
                return (false, "", "", 0, "");
            }
            var algorithm = algMatch.Groups[1].Value;

            if (algorithm != "rsa-pss-sha256")
            {
                _logger.LogWarning("[HTTP-SIG] Unsupported algorithm: {Algorithm}", algorithm);
                return (false, "", "", 0, "");
            }

            // Extract created timestamp for replay protection
            var createdMatch = Regex.Match(signatureInputHeader, @"created=(\d+)");
            if (!createdMatch.Success)
            {
                _logger.LogWarning("[HTTP-SIG] Missing created timestamp in signature input");
                return (false, "", "", 0, "");
            }

            var createdTimestamp = long.Parse(createdMatch.Groups[1].Value);
            var created = DateTimeOffset.FromUnixTimeSeconds(createdTimestamp);
            var age = DateTimeOffset.UtcNow - created;

            _logger.LogDebug("   Created: {Created:yyyy-MM-dd HH:mm:ss} UTC (age: {Age:F1} minutes)", created, age.TotalMinutes);

            // Check signature age (RFC 9421 recommends limits)
            var maxAge = _configuration.GetValue<int>("HttpSignatures:MaxAge", 300); // 5 minutes default
            if (age.TotalSeconds > maxAge)
            {
                _logger.LogWarning("[HTTP-SIG] Signature too old: {Age}s > {MaxAge}s", age.TotalSeconds, maxAge);
                return (false, "", "", 0, "");
            }

            // Extract nonce for replay protection
            var nonceMatch = Regex.Match(signatureInputHeader, @"nonce=""([^""]+)""");
            var nonce = nonceMatch.Success ? nonceMatch.Groups[1].Value : "";

            // Note: Implement nonce replay protection is ignored for this example demo
            
            return (true, keyId, algorithm, createdTimestamp, nonce);
        }

        // 1. Resolve the public key based on keyId
        private async Task<RSA?> ResolvePublicKeyAsync(HttpContext context)
        {
            // For demo purposes, only extract the public key from the DPoP proof
            var dpopKey = await TryExtractKeyFromDPoPAsync(context);
            if (dpopKey != null)
            {
                _logger.LogInformation("[HTTP-SIG] Using public key extracted from DPoP proof");
                return dpopKey;
            }

            _logger.LogWarning("[HTTP-SIG] Could not extract public key from DPoP proof");
            return null;
        }

        /// <summary>
        /// Extract the public key from the DPoP proof token if the keyId matches
        /// </summary>
        private async Task<RSA?> TryExtractKeyFromDPoPAsync(HttpContext context)
        {
            try
            {
                var dpopHeader = context.Request.Headers["DPoP"].FirstOrDefault();
                if (string.IsNullOrEmpty(dpopHeader))
                {
                    _logger.LogDebug("[HTTP-SIG] No DPoP header found, cannot extract key from DPoP");
                    return null;
                }

                var dpopJwk = ExtractJwkFromDPoPToken(dpopHeader);
                if (dpopJwk == null)
                {
                    _logger.LogDebug("[HTTP-SIG] Could not extract matching JWK from DPoP token");
                    return null;
                }

                var rsaKey = ConvertJwkToRsa(dpopJwk);
                if (rsaKey != null)
                {
                    _logger.LogInformation("[HTTP-SIG] Successfully extracted RSA public key from DPoP proof");
                }

                return rsaKey;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[HTTP-SIG] Failed to extract public key from DPoP proof");
                return null;
            }
        }

        /// <summary>
        /// For the example, where DPoP RSA Key is use to sign the HTTP message,
        /// Extract JWK from DPoP JWT token for signature verification
        /// </summary>
        private JsonWebKey? ExtractJwkFromDPoPToken(string dpopToken)
        {
            try
            {
                var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
                var jwt = handler.ReadJwtToken(dpopToken);

                if (jwt.Header.TryGetValue("jwk", out var jwkObject))
                {
                    var jwkJson = System.Text.Json.JsonSerializer.Serialize(jwkObject);
                    var jwk = new JsonWebKey(jwkJson);
                    
                    _logger.LogDebug("[HTTP-SIG] Extracted JWK from DPoP token: KeyId={KeyId}, Algorithm={Algorithm}, KeyType={KeyType}", 
                        jwk.Kid, jwk.Alg, jwk.Kty);
                    
                    return jwk;
                }
                else
                {
                    _logger.LogWarning("[HTTP-SIG] DPoP token does not contain 'jwk' claim in header");
                    return null;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[HTTP-SIG] Failed to parse DPoP token to extract JWK");
                return null;
            }
        }

        /// <summary>
        /// Convert JsonWebKey to RSA public key
        /// </summary>
        private RSA? ConvertJwkToRsa(JsonWebKey jwk)
        {
            try
            {
                if (jwk.Kty != "RSA")
                {
                    _logger.LogWarning("[HTTP-SIG] JWK is not an RSA key: KeyType={KeyType}", jwk.Kty);
                    return null;
                }

                if (string.IsNullOrEmpty(jwk.N) || string.IsNullOrEmpty(jwk.E))
                {
                    _logger.LogWarning("[HTTP-SIG] JWK is missing required RSA parameters (n or e)");
                    return null;
                }

                // Create RSA instance from JWK
                var rsa = RSA.Create();
                var rsaParameters = new RSAParameters
                {
                    Modulus = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(jwk.N),
                    Exponent = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(jwk.E)
                };

                rsa.ImportParameters(rsaParameters);

                _logger.LogDebug("[HTTP-SIG] Successfully converted JWK to RSA public key");
                return rsa;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[HTTP-SIG] Failed to convert JWK to RSA key");
                return null;
            }
        }

        // 2. Reconstruct the signature input string from the request
        private async Task<string> ReconstructSignatureInputAsync(HttpContext context, string signatureInputHeader)
        {
            try
            {
                // Extract components list from signature input header
                // Format: sig1=("@method" "@path" "@authority" "authorization");keyid="...",alg="...",created=...,nonce="..."
                var componentsMatch = Regex.Match(signatureInputHeader, @"sig1=\(([^)]+)\)");
                if (!componentsMatch.Success)
                {
                    _logger.LogWarning("[HTTP-SIG] Invalid signature input format - missing components");
                    return "";
                }

                var componentsString = componentsMatch.Groups[1].Value;
                var components = Regex.Matches(componentsString, @"""([^""]+)""")
                    .Cast<Match>()
                    .Select(m => m.Groups[1].Value)
                    .ToList();

                var signatureInputLines = new List<string>();

                foreach (var component in components)
                {
                    var componentValue = await GetComponentValueAsync(context, component);
                    if (componentValue == null)
                    {
                        _logger.LogWarning("[HTTP-SIG] Could not resolve component: {Component}", component);
                        return "";
                    }
                    signatureInputLines.Add($"\"{component}\": {componentValue}");
                }

                var signatureInput = string.Join("\n", signatureInputLines);
                _logger.LogDebug("[HTTP-SIG] Reconstructed signature input:\n{SignatureInput}", signatureInput);
                
                return signatureInput;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[HTTP-SIG] Failed to reconstruct signature input");
                return "";
            }
        }

        private async Task<string?> GetComponentValueAsync(HttpContext context, string component)
        {
            return component switch
            {
                "@method" => context.Request.Method.ToUpperInvariant(),
                "@path" => context.Request.Path + context.Request.QueryString,
                "@authority" => context.Request.Host.ToString(),
                "authorization" => context.Request.Headers["Authorization"].FirstOrDefault() ?? "",
                "content-type" => context.Request.Headers["Content-Type"].FirstOrDefault() ?? "",
                "content-length" => context.Request.Headers["Content-Length"].FirstOrDefault() ?? "",
                _ when component.StartsWith("@") => await GetSpecialComponentValueAsync(context, component),
                _ => context.Request.Headers[component].FirstOrDefault()
            };
        }

        private async Task<string?> GetSpecialComponentValueAsync(HttpContext context, string component)
        {
            return component switch
            {
                "@target-uri" => $"{context.Request.Scheme}://{context.Request.Host}{context.Request.Path}{context.Request.QueryString}",
                "@scheme" => context.Request.Scheme,
                "@request-target" => $"{context.Request.Method.ToLowerInvariant()} {context.Request.Path}{context.Request.QueryString}",
                _ => null
            };
        }

        // 3. Verify the signature using the public key
        private async Task<bool> VerifySignatureAsync(RSA publicKey, string signatureInput, byte[] signatureBytes, string algorithm)
        {
            try
            {
                var signatureInputBytes = Encoding.UTF8.GetBytes(signatureInput);

                bool isValid = algorithm switch
                {
                    "rsa-pss-sha256" => publicKey.VerifyData(signatureInputBytes, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pss),
                    "rsa-pkcs1-sha256" => publicKey.VerifyData(signatureInputBytes, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
                    _ => false
                };

                _logger.LogDebug("[HTTP-SIG] Signature verification result: {IsValid}", isValid);
                return isValid;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[HTTP-SIG] Signature verification failed");
                return false;
            }
        }
    }
}
