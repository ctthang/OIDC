using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.JsonWebTokens;
using System.Security.Cryptography;
using Duende.IdentityModel;
using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Configure client certificate authentication
builder.Services.Configure<Microsoft.AspNetCore.Server.Kestrel.Core.KestrelServerOptions>(options =>
{
    options.ConfigureHttpsDefaults(httpsOptions =>
    {
        httpsOptions.ClientCertificateMode = Microsoft.AspNetCore.Server.Kestrel.Https.ClientCertificateMode.AllowCertificate;
    });
});

// JWT authentication with certificate validation and cnf claim check
var authority = builder.Configuration["Jwt:Authority"] ?? "";
var audience = builder.Configuration["Jwt:Audience"] ?? "";
var enforceDpop = builder.Configuration.GetValue<bool>("Jwt:EnforceDpop", false);

Console.WriteLine($"[CONFIG] JWT Configuration:");
Console.WriteLine($"   Authority: {authority}");
Console.WriteLine($"   Audience: {audience}");
Console.WriteLine($"   EnforceDpop: {enforceDpop}");

var httpClient = new HttpClient(new HttpClientHandler()
{
    ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true
});
var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
    metadataAddress: $"{authority}/.well-known/openid-configuration",
    configRetriever: new OpenIdConnectConfigurationRetriever(),
    docRetriever: new HttpDocumentRetriever(httpClient)
);

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = authority,
            ValidAudience = audience,
            ConfigurationManager = configurationManager,
            NameClaimType = "name",
            ClockSkew = TimeSpan.FromMinutes(5) // Allow for some clock skew
        };
        options.Events = new JwtBearerEvents
        {
            OnMessageReceived = context =>
            {
                Console.WriteLine("[AUTH] OnMessageReceived - JWT Bearer authentication started");
                var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();
                var dpopHeader = context.Request.Headers["DPoP"].FirstOrDefault();
                
                if (!string.IsNullOrEmpty(authHeader))
                {
                    Console.WriteLine($"   Authorization Header: {authHeader}");
                    
                    // Handle DPoP authorization scheme by extracting the token
                    if (authHeader.StartsWith("DPoP ", StringComparison.OrdinalIgnoreCase))
                    {
                        var token = authHeader.Substring(5); // Remove "DPoP " prefix
                        context.Token = token;
                        Console.WriteLine("   Converted DPoP authorization to token for JWT validation");
                    }
                    else if (authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                    {
                        // Standard Bearer token - let the default handler process it
                        Console.WriteLine("   Standard Bearer token detected");
                    }
                }
                else
                {
                    Console.WriteLine("   Authorization Header: [Not Present]");
                }
                
                Console.WriteLine($"   DPoP Header Present: {!string.IsNullOrEmpty(dpopHeader)}");
                Console.WriteLine($"   Request Path: {context.Request.Path}");
                Console.WriteLine($"   Request Method: {context.Request.Method}");
                return Task.CompletedTask;
            },
            OnAuthenticationFailed = context =>
            {
                Console.WriteLine($"[ERROR] Authentication failed: {context.Exception?.Message}");
                Console.WriteLine($"   Exception Type: {context.Exception?.GetType().Name}");
                if (context.Exception?.InnerException != null)
                {
                    Console.WriteLine($"   Inner Exception: {context.Exception.InnerException.Message}");
                }
                return Task.CompletedTask;
            },
            OnChallenge = context =>
            {
                Console.WriteLine("[CHALLENGE] OnChallenge - Authentication challenge triggered");
                Console.WriteLine($"   Error: {context.Error}");
                Console.WriteLine($"   Error Description: {context.ErrorDescription}");
                
                // Check if this is a DPoP-related challenge
                var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();
                var dpopHeader = context.Request.Headers["DPoP"].FirstOrDefault();
                bool isDpopRequest = !string.IsNullOrEmpty(dpopHeader) && 
                                   authHeader?.StartsWith("DPoP ", StringComparison.OrdinalIgnoreCase) == true;
                
                // Get custom error information from HttpContext.Items (more reliable than Properties.Items)
                context.HttpContext.Items.TryGetValue("auth_error_code", out var customError);
                context.HttpContext.Items.TryGetValue("auth_error_description", out var customErrorDescription);
                
                var errorCode = customError?.ToString() ?? context.Error ?? "unauthorized";
                var errorDescription = customErrorDescription?.ToString() ?? context.ErrorDescription ?? "Authentication failed";
                
                Console.WriteLine($"   [DEBUG] Custom error from HttpContext: {customError}");
                Console.WriteLine($"   [DEBUG] Properties.Items count: {context.Properties.Items.Count}");
                
                // Customize the WWW-Authenticate header based on request type
                if (isDpopRequest)
                {
                    // For DPoP requests, include DPoP in WWW-Authenticate header
                    var dpopChallenge = $"DPoP realm=\"{context.Request.Host}\"";
                    if (!string.IsNullOrEmpty(errorCode))
                    {
                        dpopChallenge += $", error=\"{errorCode}\"";
                    }
                    if (!string.IsNullOrEmpty(errorDescription))
                    {
                        dpopChallenge += $", error_description=\"{errorDescription}\"";
                    }
                    context.Response.Headers["WWW-Authenticate"] = dpopChallenge;
                }
                else
                {
                    // For Bearer requests, use standard Bearer challenge
                    var challengeHeader = $"Bearer realm=\"{context.Request.Host}\"";
                    if (!string.IsNullOrEmpty(errorCode))
                    {
                        challengeHeader += $", error=\"{errorCode}\"";
                    }
                    if (!string.IsNullOrEmpty(errorDescription))
                    {
                        challengeHeader += $", error_description=\"{errorDescription}\"";
                    }
                    context.Response.Headers["WWW-Authenticate"] = challengeHeader;
                }
                
                // Set custom error response body with detailed information
                context.Response.StatusCode = 401;
                context.Response.ContentType = "application/json";
                
                var errorResponse = new
                {
                    error = errorCode,
                    error_description = errorDescription,
                    request_type = isDpopRequest ? "DPoP" : "Bearer",
                    timestamp = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
                    details = new
                    {
                        path = context.Request.Path.Value,
                        method = context.Request.Method,
                        dpop_header_present = !string.IsNullOrEmpty(dpopHeader),
                        authorization_header_present = !string.IsNullOrEmpty(authHeader)
                    }
                };
                
                var errorJson = JsonSerializer.Serialize(errorResponse, new JsonSerializerOptions { WriteIndented = true });
                context.Response.WriteAsync(errorJson);
                
                // Mark the challenge as handled to prevent default behavior
                context.HandleResponse();
                
                Console.WriteLine($"   [INFO] Custom error response sent to client: {errorCode}");
                return Task.CompletedTask;
            },
            OnTokenValidated = context =>
            {
                Console.WriteLine("[SUCCESS] Token validation started");
                var httpContext = context.HttpContext;
                try
                {
                    var authorizationHeader = httpContext.Request.Headers["Authorization"].FirstOrDefault();
                    var dpopHeader = httpContext.Request.Headers["DPoP"].FirstOrDefault();
                    
                    bool isDpopRequest = !string.IsNullOrEmpty(dpopHeader) && 
                                       authorizationHeader?.StartsWith("DPoP ", StringComparison.OrdinalIgnoreCase) == true;
                    
                    Console.WriteLine($"   Request type: {(isDpopRequest ? "DPoP" : "Bearer")}");
                    Console.WriteLine($"   EnforceDpop setting: {enforceDpop}");
                    
                    // If DPoP is enforced and this is not a DPoP request, fail
                    if (enforceDpop && !isDpopRequest)
                    {
                        Console.WriteLine("   DPoP is enforced but request is not using DPoP");
                        
                        // Store error information in HttpContext for OnChallenge to access
                        httpContext.Items["auth_error_code"] = "dpop_required";
                        httpContext.Items["auth_error_description"] = "This resource requires DPoP authentication. Include a DPoP header with your request.";
                        
                        context.Fail("DPoP authentication is required.");
                        return Task.CompletedTask;
                    }
                    
                    // Handle DPoP-specific validation
                    if (isDpopRequest)
                    {
                        Console.WriteLine("   Validating DPoP request");
                        
                        // Validate DPoP proof token - handle both JsonWebToken and JwtSecurityToken
                        var dpopProofValidation = ValidateDPoPProof(dpopHeader, httpContext, context.SecurityToken);
                        if (!dpopProofValidation.IsValid)
                        {
                            Console.WriteLine($"   DPoP proof validation failed: {dpopProofValidation.ErrorMessage}");
                            
                            // Store error information in HttpContext for OnChallenge to access
                            httpContext.Items["auth_error_code"] = "invalid_dpop_proof";
                            httpContext.Items["auth_error_description"] = dpopProofValidation.ErrorMessage;
                            
                            context.Fail($"DPoP proof validation failed: {dpopProofValidation.ErrorMessage}");
                            return Task.CompletedTask;
                        }
                        
                        Console.WriteLine("   DPoP proof validation successful");
                    }
                    
                    // Check cnf claim and client certificate (for both Bearer and DPoP)
                    var cnf = context.Principal?.FindFirst("cnf")?.Value;
                    if (string.IsNullOrEmpty(cnf))
                    {
                        Console.WriteLine("   Missing cnf claim in token");
                        
                        // Store error information in HttpContext for OnChallenge to access
                        httpContext.Items["auth_error_code"] = "invalid_token";
                        httpContext.Items["auth_error_description"] = "Access token missing required confirmation (cnf) claim for certificate binding.";
                        
                        context.Fail("Missing cnf claim.");
                        return Task.CompletedTask;
                    }

                    // Get client certificate from connection
                    var clientCert = httpContext.Connection.ClientCertificate;
                    if(clientCert == null)
                    {
                        Console.WriteLine("   Client certificate is required but not provided");
                        
                        // Store error information in HttpContext for OnChallenge to access
                        httpContext.Items["auth_error_code"] = "certificate_required";
                        httpContext.Items["auth_error_description"] = "Client certificate is required for mTLS authentication but was not provided.";
                        
                        context.Fail("Client certificate is required.");
                        return Task.CompletedTask;
                    }

                    // Parse cnf as JSON and compare thumbprints
                    var cnfObj = System.Text.Json.JsonDocument.Parse(cnf);
                    if (cnfObj.RootElement.TryGetProperty("x5t#S256", out var thumbprintElement))
                    {
                        // Calculate SHA256 thumbprint of the client certificate
                        using var sha256 = SHA256.Create();
                        var certBytes = clientCert.GetRawCertData();
                        var sha256Hash = sha256.ComputeHash(certBytes);
                        var base64UrlThumbprint = Base64UrlEncoder.Encode(sha256Hash);
                        
                        var expectedThumbprint = thumbprintElement.GetString();
                        Console.WriteLine($"   Client cert thumbprint: {base64UrlThumbprint}");
                        Console.WriteLine($"   Expected thumbprint: {expectedThumbprint}");
                        
                        if (!string.Equals(base64UrlThumbprint, expectedThumbprint, StringComparison.OrdinalIgnoreCase))
                        {
                            Console.WriteLine("   Client certificate thumbprint does not match cnf claim");
                            context.Fail("Client certificate thumbprint does not match cnf claim.");
                            context.Properties.Items["custom_error"] = "certificate_mismatch";
                            context.Properties.Items["custom_error_description"] = "Client certificate thumbprint does not match the confirmation claim in the access token.";
                            return Task.CompletedTask;
                        }
                        
                        Console.WriteLine("   Certificate thumbprint validation successful");
                    }
                    else
                    {
                        Console.WriteLine("   Missing x5t#S256 property in cnf claim");
                        
                        // Store error information in HttpContext for OnChallenge to access
                        httpContext.Items["auth_error_code"] = "invalid_token";
                        httpContext.Items["auth_error_description"] = "Access token cnf claim missing required x5t#S256 certificate thumbprint property.";
                        
                        context.Fail("Missing x5t#S256 property in cnf claim.");
                        return Task.CompletedTask;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"   Error during token validation: {ex.Message}");
                    
                    // Store error information in HttpContext for OnChallenge to access
                    httpContext.Items["auth_error_code"] = "validation_error";
                    httpContext.Items["auth_error_description"] = $"An error occurred during token validation: {ex.Message}";
                    
                    context.Fail($"Error during token validation: {ex.Message}");
                    return Task.CompletedTask;
                }
                
                Console.WriteLine("[SUCCESS] Token validation completed successfully");
                return Task.CompletedTask;
            }
        };
    });

// Add CORS policy to allow all origins (for testing only)
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
        policy.AllowAnyOrigin()
              .AllowAnyHeader()
              .AllowAnyMethod()
    );
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseCors(); // Enable CORS before authentication/authorization

app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();

Console.WriteLine("[STARTUP] Web API starting up...");
app.Run();

// Helper method to validate DPoP proof token according to RFC 9449
static (bool IsValid, string ErrorMessage) ValidateDPoPProof(string dpopHeader, HttpContext httpContext, SecurityToken? accessToken)
{
    try
    {
        if (string.IsNullOrEmpty(dpopHeader))
        {
            return (false, "DPoP header is missing");
        }
        
        Console.WriteLine("[DPOP] Starting comprehensive DPoP validation per RFC 9449");
        
        // STEP 1: Parse the DPoP proof JWT
        var handler = new JwtSecurityTokenHandler();
        if (!handler.CanReadToken(dpopHeader))
        {
            return (false, "Invalid DPoP proof token format");
        }
        
        var dpopToken = handler.ReadJwtToken(dpopHeader);
        Console.WriteLine("   [SUCCESS] DPoP proof JWT parsed successfully");
        
        // STEP 2: Validate DPoP proof JWT structure and headers
        // Validate typ header
        if (!dpopToken.Header.TryGetValue("typ", out var typ) || !typ.Equals("dpop+jwt"))
        {
            return (false, "Invalid typ header in DPoP proof - must be 'dpop+jwt'");
        }
        
        // Validate alg header (must be asymmetric algorithm)
        if (!dpopToken.Header.TryGetValue("alg", out var alg) || string.IsNullOrEmpty(alg?.ToString()))
        {
            return (false, "Missing alg header in DPoP proof");
        }
        
        var algorithm = alg.ToString();
        if (!IsValidDPoPAlgorithm(algorithm))
        {
            return (false, $"Invalid algorithm for DPoP proof: {algorithm}. Must be asymmetric algorithm");
        }
        
        // Extract embedded JWK
        if (!dpopToken.Header.TryGetValue("jwk", out var jwkObj))
        {
            return (false, "Missing jwk header in DPoP proof");
        }
        
        Console.WriteLine($"   [SUCCESS] DPoP proof structure valid (typ: {typ}, alg: {algorithm})");
        
        // STEP 3: Validate DPoP proof signature using embedded JWK
        var signatureValidation = ValidateDPoPProofSignature(dpopHeader, jwkObj);
        if (!signatureValidation.IsValid)
        {
            return (false, $"DPoP proof signature validation failed: {signatureValidation.ErrorMessage}");
        }
        
        Console.WriteLine("   [SUCCESS] DPoP proof signature validated successfully");
        
        // STEP 4: Calculate JWK thumbprint for access token binding validation
        var jwkJson = JsonSerializer.Serialize(jwkObj);
        var jwkThumbprint = CalculateJWKThumbprint(jwkJson);
        if (string.IsNullOrEmpty(jwkThumbprint))
        {
            return (false, "Failed to calculate JWK thumbprint from DPoP proof");
        }
        
        Console.WriteLine($"   [INFO] JWK thumbprint calculated: {jwkThumbprint}");
        
        // STEP 5: Validate access token binding (cnf.jkt claim)
        var tokenBindingValidation = ValidateAccessTokenBinding(httpContext, jwkThumbprint);
        if (!tokenBindingValidation.IsValid)
        {
            return (false, $"Access token binding validation failed: {tokenBindingValidation.ErrorMessage}");
        }
        
        Console.WriteLine("   [SUCCESS] Access token binding validated successfully");
        
        // STEP 6: Validate DPoP proof payload claims
        var payload = dpopToken.Payload;
        
        // Validate htm claim (HTTP method)
        if (!payload.TryGetValue("htm", out var htm) || 
            !string.Equals(htm?.ToString(), httpContext.Request.Method, StringComparison.OrdinalIgnoreCase))
        {
            return (false, $"htm claim mismatch. Expected: {httpContext.Request.Method}, Got: {htm}");
        }
        
        // Validate htu claim (HTTP URI) - must match full request URL
        if (!payload.TryGetValue("htu", out var htu))
        {
            return (false, "Missing htu claim in DPoP proof");
        }
        
        var requestUri = $"{httpContext.Request.Scheme}://{httpContext.Request.Host}{httpContext.Request.Path}";
        if (!string.Equals(htu?.ToString(), requestUri, StringComparison.OrdinalIgnoreCase))
        {
            return (false, $"htu claim mismatch. Expected: {requestUri}, Got: {htu}");
        }
        
        // Validate iat claim (issued at time) - must be recent
        if (!payload.TryGetValue("iat", out var iat))
        {
            return (false, "Missing iat claim in DPoP proof");
        }
        
        var issuedAt = DateTimeOffset.FromUnixTimeSeconds(Convert.ToInt64(iat));
        var now = DateTimeOffset.UtcNow;
        var timeDifference = Math.Abs((now - issuedAt).TotalMinutes);
        
        // Strict timing for DPoP proofs (5 minutes as per RFC 9449)
        if (timeDifference > 5)
        {
            return (false, $"DPoP proof token is too old or from the future. Time difference: {timeDifference} minutes (max 5 minutes allowed)");
        }
        
        // Validate jti claim (JWT ID) - must be unique for replay protection
        if (!payload.TryGetValue("jti", out var jti) || string.IsNullOrEmpty(jti?.ToString()))
        {
            return (false, "Missing or empty jti claim in DPoP proof");
        }
        
        // This is a demo resource server, ignore implementing jti nonce tracking to prevent replay attacks
        
        Console.WriteLine($"   [INFO] jti claim present: {jti} (replay protection - should be tracked in production)");
        
        Console.WriteLine($"   [SUCCESS] DPoP proof claims validated (htm: {htm}, htu: {htu}, iat: {issuedAt:yyyy-MM-dd HH:mm:ss} UTC)");
        
        Console.WriteLine("[SUCCESS] RFC 9449 compliant DPoP validation completed successfully");
        
        return (true, string.Empty);
    }
    catch (Exception ex)
    {
        return (false, $"Exception during DPoP validation: {ex.Message}");
    }
}

// Helper method to validate access token binding via cnf.jkt claim
static (bool IsValid, string ErrorMessage) ValidateAccessTokenBinding(HttpContext httpContext, string expectedJwkThumbprint)
{
    try
    {
        // Get access token from Authorization header
        var authHeader = httpContext.Request.Headers["Authorization"].FirstOrDefault();
        if (string.IsNullOrEmpty(authHeader))
        {
            return (false, "Missing Authorization header for access token binding validation");
        }
        
        // Extract access token string
        string accessTokenString;
        if (authHeader.StartsWith("DPoP ", StringComparison.OrdinalIgnoreCase))
        {
            accessTokenString = authHeader.Substring(5).Trim();
        }
        else if (authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            accessTokenString = authHeader.Substring(7).Trim();
        }
        else
        {
            return (false, "Invalid Authorization header format for access token binding validation");
        }
        
        if (string.IsNullOrEmpty(accessTokenString))
        {
            return (false, "Empty access token string for binding validation");
        }
        
        // Parse access token to extract cnf claim
        var tokenHandler = new JwtSecurityTokenHandler();
        if (!tokenHandler.CanReadToken(accessTokenString))
        {
            return (false, "Cannot parse access token for binding validation");
        }
        
        var accessToken = tokenHandler.ReadJwtToken(accessTokenString);
        
        // Look for cnf (confirmation) claim
        var cnfClaim = accessToken.Claims.FirstOrDefault(c => c.Type == "cnf");
        if (cnfClaim == null)
        {
            return (false, "Access token missing cnf (confirmation) claim - not DPoP-bound");
        }
        
        // Parse cnf claim JSON
        var cnfJson = JsonDocument.Parse(cnfClaim.Value);
        if (!cnfJson.RootElement.TryGetProperty("jkt", out var jktElement))
        {
            return (false, "Access token cnf claim missing jkt (JWK thumbprint) property");
        }
        
        var accessTokenJwkThumbprint = jktElement.GetString();
        if (string.IsNullOrEmpty(accessTokenJwkThumbprint))
        {
            return (false, "Access token cnf.jkt claim is empty");
        }
        
        // Compare JWK thumbprints
        if (!string.Equals(expectedJwkThumbprint, accessTokenJwkThumbprint, StringComparison.OrdinalIgnoreCase))
        {
            Console.WriteLine($"   [ERROR] JWK thumbprint mismatch:");
            Console.WriteLine($"      DPoP proof JWK thumbprint: {expectedJwkThumbprint}");
            Console.WriteLine($"      Access token cnf.jkt:      {accessTokenJwkThumbprint}");
            return (false, "JWK thumbprint mismatch between DPoP proof and access token cnf.jkt claim");
        }
        
        Console.WriteLine($"   [SUCCESS] JWK thumbprint match confirmed: {expectedJwkThumbprint}");
        return (true, string.Empty);
    }
    catch (Exception ex)
    {
        return (false, $"Exception during access token binding validation: {ex.Message}");
    }
}

// Helper method to calculate JWK thumbprint per RFC 7638
static string CalculateJWKThumbprint(string jwkJson)
{
    try
    {
        var jwk = JsonWebKey.Create(jwkJson);
        
        // Create canonical JWK representation for thumbprint calculation
        var canonicalJwk = new Dictionary<string, object>();
        
        // Include only the required parameters for thumbprint calculation per RFC 7638
        if (!string.IsNullOrEmpty(jwk.Kty))
            canonicalJwk["kty"] = jwk.Kty;
            
        if (jwk.Kty == "RSA")
        {
            if (!string.IsNullOrEmpty(jwk.N))
                canonicalJwk["n"] = jwk.N;
            if (!string.IsNullOrEmpty(jwk.E))
                canonicalJwk["e"] = jwk.E;
        }
        else 
        {
            Console.WriteLine($"   [ERROR] Only support the RSA Kty!");
            return string.Empty;
        }
        
        // Sort keys alphabetically and create canonical JSON
        var sortedKeys = canonicalJwk.Keys.OrderBy(k => k).ToArray();
        var canonicalJson = "{" + string.Join(",", sortedKeys.Select(k => $"\"{k}\":\"{canonicalJwk[k]}\"")) + "}";
        
        // Calculate SHA-256 hash of canonical JSON
        var jsonBytes = System.Text.Encoding.UTF8.GetBytes(canonicalJson);
        using var sha256 = SHA256.Create();
        var hash = sha256.ComputeHash(jsonBytes);
        
        // Return base64url-encoded thumbprint
        return Base64UrlEncoder.Encode(hash);
    }
    catch (Exception ex)
    {
        Console.WriteLine($"   [ERROR] Failed to calculate JWK thumbprint: {ex.Message}");
        return string.Empty;
    }
}

static bool IsValidDPoPAlgorithm(string algorithm)
{
    // Valid asymmetric algorithms for DPoP per RFC 9449
    var validAlgorithms = new[] { "RS256", "RS384", "RS512", "PS256", "PS384", "PS512" };
    return validAlgorithms.Contains(algorithm, StringComparer.OrdinalIgnoreCase);
}

// Helper method to validate DPoP proof signature using embedded JWK
static (bool IsValid, string ErrorMessage) ValidateDPoPProofSignature(string dpopProofToken, object jwkObj)
{
    try
    {
        // Convert JWK object to JSON string for processing
        var jwkJson = JsonSerializer.Serialize(jwkObj);
        
        // Create JsonWebKey from the embedded JWK
        var jsonWebKey = new JsonWebKey(jwkJson);
        
        // Validate that the JWK has the required properties for signature validation
        if (string.IsNullOrEmpty(jsonWebKey.Kty))
        {
            return (false, "JWK missing key type (kty)");
        }
        
        // Create token validation parameters for DPoP proof signature validation
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,           // DPoP proofs don't have issuers
            ValidateAudience = false,         // DPoP proofs don't have audiences
            ValidateLifetime = false,         // We validate iat separately with custom logic
            ValidateIssuerSigningKey = true,  // This is what we want to validate
            IssuerSigningKey = jsonWebKey,
            ClockSkew = TimeSpan.Zero         // No clock skew for DPoP proof validation
        };
        
        // Validate the DPoP proof signature
        var tokenHandler = new JwtSecurityTokenHandler();
        
        try
        {
            // Validate the token signature against the embedded JWK
            var principal = tokenHandler.ValidateToken(dpopProofToken, validationParameters, out var validatedToken);
            
            if (validatedToken is JwtSecurityToken validatedJwt)
            {
                Console.WriteLine($"   [SUCCESS] DPoP proof signature validated successfully");
                Console.WriteLine($"      Algorithm: {validatedJwt.Header.Alg}");
                Console.WriteLine($"      Key Type: {jsonWebKey.Kty}");
                return (true, string.Empty);
            }
            else
            {
                return (false, "DPoP proof validation returned unexpected token type");
            }
        }
        catch (SecurityTokenSignatureKeyNotFoundException ex)
        {
            return (false, $"Cannot validate DPoP proof signature - key not found: {ex.Message}");
        }
        catch (SecurityTokenInvalidSignatureException ex)
        {
            return (false, $"DPoP proof has invalid signature: {ex.Message}");
        }
        catch (SecurityTokenValidationException ex)
        {
            return (false, $"DPoP proof signature validation failed: {ex.Message}");
        }
    }
    catch (ArgumentException ex)
    {
        return (false, $"Invalid JWK format in DPoP proof: {ex.Message}");
    }
    catch (Exception ex)
    {
        return (false, $"Exception during DPoP signature validation: {ex.Message}");
    }
}
