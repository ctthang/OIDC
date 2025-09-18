using Duende.IdentityModel.OidcClient.DPoP;
using IdentityModel.Client;
using System.Configuration;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using System.Text.Json;

namespace console_app
{
    internal class Program
    {
        static async Task Main(string[] args)
        {
            // Set console encoding to UTF-8 to support Unicode characters and emojis
            Console.OutputEncoding = Encoding.UTF8;
            Console.InputEncoding = Encoding.UTF8;

            WriteHeader("mTLS Client Application Starting");

            try
            {
                string authority = ConfigurationManager.AppSettings["Authority"] ?? throw new Exception("Authority setting is required");
                string clientId = ConfigurationManager.AppSettings["ClientId"] ?? throw new Exception("ClientId setting is required");
                string certificatePath = ConfigurationManager.AppSettings["CertificatePath"] ?? throw new Exception("CertificatePath setting is required");
                string certificatePassword = ConfigurationManager.AppSettings["CertificatePassword"] ?? throw new Exception("CertificatePassword setting is required");
                string apiEndpoint = ConfigurationManager.AppSettings["ApiEndpoint"] ?? throw new Exception("ApiEndpoint setting is required");
                string tokenEndpoint = $"{authority}/mtls/token.idp";
                var useDpopSetting = ConfigurationManager.AppSettings["UseDpop"] ?? "false";
                bool useDpop = bool.TryParse(useDpopSetting, out var result) && result;
                var useHttpSignaturesSetting = ConfigurationManager.AppSettings["UseHttpSignatures"] ?? "false";
                bool useHttpSignatures = bool.TryParse(useHttpSignaturesSetting, out var httpSigResult) && httpSigResult;
                var dpopToken = string.Empty;

                WriteSuccess("Configuration loaded successfully");
                WriteData("Authority", authority);
                WriteData("Client ID", clientId);
                WriteData("API Endpoint", apiEndpoint);
                WriteData("Use DPoP", useDpop.ToString());
                WriteData("Use HTTP Signatures", useHttpSignatures.ToString());

                // Generate JWK once and reuse for both DPoP and HTTP Message Signatures
                string jwk = string.Empty;
                RSA? rsaKey = null;
                if (useDpop || useHttpSignatures)
                {
                    WriteHeader("Key Generation");
                    var dpopAlg = ConfigurationManager.AppSettings["DpopAlg"] ?? "PS256";
                    WriteInfo($"Generating RSA key pair with algorithm: {dpopAlg}");
                    
                    // Creates a JWK using the configured Alg or default PS256 algorithm:
                    jwk = JsonWebKeys.CreateRsaJson(dpopAlg);
                    WriteData("JWK", jwk);
                    
                    // Extract RSA key from JWK for HTTP Message Signatures
                    if (useHttpSignatures)
                    {
                        var jsonWebKey = new JsonWebKey(jwk);
                        rsaKey = FromJwk(jsonWebKey);
                        WriteSuccess("RSA key extracted for HTTP Message Signatures");
                    }
                    
                    WriteSuccess("Key pair generated successfully");
                }

                if (useDpop)
                {
                    WriteHeader("DPoP Token for Token Request");
                    var dpopMethod = ConfigurationManager.AppSettings["DpopMethod"] ?? "POST";
                    WriteInfo($"Generating DPoP token for token request (method: {dpopMethod})");
                    
                    var dpopRequest = new DPoPProofRequest
                    {
                        Url = tokenEndpoint,
                        Method = dpopMethod
                    };
                    var dpopTokenFactory = new DPoPProofTokenFactory(jwk);
                    dpopToken = dpopTokenFactory.CreateProofToken(dpopRequest).ProofToken;
                    WriteData("Token Request DPoP Token", dpopToken);
                    WriteSuccess("DPoP token for token request generated successfully");
                }

                WriteHeader("Certificate Loading");
                var clientCert = new X509Certificate2(certificatePath, certificatePassword);
                WriteSuccess("Client certificate loaded successfully");
                WriteData("Certificate Subject", clientCert.Subject);
                WriteData("Certificate Thumbprint", clientCert.Thumbprint);

                var handler = new HttpClientHandler();
                // Ignore SSL validation (for development only)
                handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true;
                WriteWarning("SSL certificate validation is disabled (development mode)");
                
                // Include the client certificate for mTLS token requests
                handler.ClientCertificates.Add(clientCert);
                using var httpClient = new HttpClient(handler);

                WriteHeader("Token Request (Client Credentials Flow)");
                WriteInfo("Requesting access token using client credentials flow with mTLS");
                WriteData("Token Endpoint", tokenEndpoint);
                
                // Create the token request
                var request = new ClientCredentialsTokenRequest
                {
                    Address = tokenEndpoint,
                    ClientId = clientId,
                    GrantType = "client_credentials"
                };
                request.Parameters.Add("client_id", clientId);
                if (useDpop)
                {
                    request.Headers.Add("DPoP", dpopToken);
                    WriteInfo("DPoP header added to token request");
                }

                var tokenResponse = await httpClient.RequestClientCredentialsTokenAsync(request);

                if (tokenResponse.IsError)
                {
                    WriteError($"Token request failed: {tokenResponse.Error}");
                    if (!string.IsNullOrEmpty(tokenResponse.ErrorDescription))
                    {
                        WriteError($"Error Description: {tokenResponse.ErrorDescription}");
                    }
                    return;
                }

                WriteSuccess("Token request successful!");
                WriteJson(tokenResponse.Json.ToString());

                // Parse and display Access Token in Json format
                WriteHeader("Access Token Details");
                var handlerJwt = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
                var jwt = handlerJwt.ReadJwtToken(tokenResponse.AccessToken);
                var jwtJsonHeader = System.Text.Json.JsonSerializer.Serialize(jwt.Header, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
                WriteInfo("Access Token (Header):");
                WriteJson(jwtJsonHeader);
                var jwtJson = System.Text.Json.JsonSerializer.Serialize(jwt.Payload, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
                WriteInfo("Access Token (Payload):");
                WriteJson(jwtJson);

                // Now make an API call using the access token
                WriteHeader("API Call");
                var apiHandler = new HttpClientHandler();
                
                HttpClient apiHttpClient;
                if (useHttpSignatures && rsaKey != null)
                {
                    // Create HTTP client with custom HTTP Message Signatures support
                    WriteInfo("Creating HTTP client with custom HTTP Message Signatures support");
                    apiHttpClient = CreateHttpClientWithSignatures(apiHandler, rsaKey, clientId);
                }
                else
                {
                    apiHttpClient = new HttpClient(apiHandler);
                }

                string apiDpopToken = string.Empty;
                if (useDpop)
                {
                    WriteHeader("Generate New DPoP Token for API Call");
                    WriteInfo("Generating fresh DPoP token for API request per RFC 9449");
                    
                    // Generate a new DPoP proof for the API call with correct URL and method
                    var apiDpopRequest = new DPoPProofRequest
                    {
                        Url = apiEndpoint,
                        Method = "GET", // API call method
                        AccessToken = tokenResponse.AccessToken // Include access token for ath claim
                    };
                    
                    // Reuse the same JWK but create a fresh proof
                    var apiDpopTokenFactory = new DPoPProofTokenFactory(jwk);
                    apiDpopToken = apiDpopTokenFactory.CreateProofToken(apiDpopRequest).ProofToken;
                    
                    WriteData("API DPoP Token", apiDpopToken);
                    WriteSuccess("Fresh DPoP token generated for API call");

                    // Add the fresh DPoP header for API request
                    apiHttpClient.DefaultRequestHeaders.Clear(); // Clear any existing headers
                    apiHttpClient.DefaultRequestHeaders.Add("DPoP", apiDpopToken);
                    WriteInfo("Fresh DPoP header added to API request");
                }
                
                apiHttpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(tokenResponse.TokenType, tokenResponse.AccessToken);
                WriteData("Authorization Scheme", tokenResponse.TokenType);
                
                WriteInfo("Sending HTTP request with custom HTTP Message Signatures");
                WriteData("API Endpoint", apiEndpoint);

                // Remove client certificate from the handler before making the API call
                apiHandler.ClientCertificates.Clear();
                var response = await apiHttpClient.GetAsync(apiEndpoint);

                if (response.IsSuccessStatusCode)
                {
                    WriteSuccess($"API call successful! Status: {response.StatusCode}");
                    var content = await response.Content.ReadAsStringAsync();
                    WriteInfo("API Response:");
                    WriteJson(content);
                    
                    // Display HTTP Message Signature headers if present
                    if (useHttpSignatures)
                    {
                        WriteHeader("Custom HTTP Message Signature Headers");
                        foreach (var header in response.Headers.Concat(response.Content.Headers))
                        {
                            if (header.Key.StartsWith("Signature", StringComparison.OrdinalIgnoreCase) ||
                                header.Key.StartsWith("Signature-Input", StringComparison.OrdinalIgnoreCase))
                            {
                                WriteData(header.Key, string.Join(", ", header.Value));
                            }
                        }
                    }
                }
                else
                {
                    WriteError($"API call failed: {response.StatusCode} {response.ReasonPhrase}");
                    var errorContent = await response.Content.ReadAsStringAsync();
                    if (!string.IsNullOrEmpty(errorContent))
                    {
                        WriteError($"Error Content: {errorContent}");
                    }
                }

                WriteHeader("Application Completed");
                WriteInfo("Press any key to exit...");
            }
            catch (Exception ex)
            {
                WriteError($"Application failed with exception: {ex.Message}");
                if (ex.InnerException != null)
                {
                    WriteError($"Inner Exception: {ex.InnerException.Message}");
                }
            }

            Console.Read();
        }

        // Create HTTP client with custom HTTP Message Signatures support (RFC 9421)
        static HttpClient CreateHttpClientWithSignatures(HttpClientHandler handler, RSA rsaKey, string clientId)
        {
            WriteInfo("Configuring HTTP Message Signatures per RFC 9421 (Custom Implementation)");

            try
            {
                // Create a custom delegating handler for HTTP Message Signatures
                var signingHandler = new HttpMessageSigningDelegatingHandler(rsaKey, clientId)
                {
                    InnerHandler = handler
                };

                var httpClient = new HttpClient(signingHandler);

                WriteSuccess("HTTP Message Signatures configured successfully");
                WriteData("Key ID", clientId);
                WriteData("Implementation", "Custom RFC 9421 Implementation");
                WriteData("Algorithm", "rsa-pss-sha256");

                return httpClient;
            }
            catch (Exception ex)
            {
                WriteWarning($"Failed to configure HTTP signatures: {ex.Message}");
                WriteInfo("Falling back to standard HTTP client");

                // Fallback to standard HTTP client if configuration fails
                return new HttpClient(handler);
            }
        }

        // Custom HTTP Message Signing Handler implementing RFC 9421
        public class HttpMessageSigningDelegatingHandler : DelegatingHandler
        {
            private readonly RSA _rsaKey;
            private readonly string _keyId;

            public HttpMessageSigningDelegatingHandler(RSA rsaKey, string keyId)
            {
                _rsaKey = rsaKey ?? throw new ArgumentNullException(nameof(rsaKey));
                _keyId = keyId ?? throw new ArgumentNullException(nameof(keyId));
            }

            protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                // Sign the request before sending
                await SignRequestAsync(request);
                
                // Send the signed request
                return await base.SendAsync(request, cancellationToken);
            }

            private async Task SignRequestAsync(HttpRequestMessage request)
            {
                try
                {
                    // RFC 9421: Signature components to include
                    var components = new List<string>
                    {
                        "@method",
                        "@path", 
                        "@authority",
                        "authorization"
                    };

                    // Build signature input string according to RFC 9421
                    var signatureInputLines = new List<string>();
                    
                    // @method component
                    signatureInputLines.Add($"\"@method\": {request.Method.ToString().ToUpperInvariant()}");
                    
                    // @path component (path + query)
                    var path = request.RequestUri?.PathAndQuery ?? "/";
                    signatureInputLines.Add($"\"@path\": {path}");
                    
                    // @authority component
                    var authority = request.RequestUri?.Authority ?? "";
                    signatureInputLines.Add($"\"@authority\": {authority}");
                    
                    // authorization header component
                    var authHeader = request.Headers.Authorization?.ToString() ?? "";
                    if (!string.IsNullOrEmpty(authHeader))
                    {
                        signatureInputLines.Add($"\"authorization\": {authHeader}");
                    }

                    // Create signature input string (RFC 9421 format)
                    var signatureInput = string.Join("\n", signatureInputLines);
                    
                    // Create signature metadata
                    var created = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                    var nonce = Guid.NewGuid().ToString("N")[..16]; // 16 character nonce
                    
                    // Build signature parameters
                    var signatureParams = new Dictionary<string, string>
                    {
                        ["keyid"] = $"\"{_keyId}\"",
                        ["alg"] = "\"rsa-pss-sha256\"",
                        ["created"] = created.ToString(),
                        ["nonce"] = $"\"{nonce}\""
                    };
                    
                    // Create signature-input header value
                    var componentsList = string.Join(" ", components.Select(c => $"\"{c}\""));
                    var paramsList = string.Join(", ", signatureParams.Select(kvp => $"{kvp.Key}={kvp.Value}"));
                    var signatureInputHeader = $"sig1=({componentsList});{paramsList}";
                    
                    // Sign the signature input string using RSA-PSS with SHA-256
                    var signatureInputBytes = Encoding.UTF8.GetBytes(signatureInput);
                    var signatureBytes = _rsaKey.SignData(signatureInputBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
                    var signatureBase64 = Convert.ToBase64String(signatureBytes);
                    
                    // Create signature header value (RFC 9421 format)
                    var signatureHeader = $"sig1=:{signatureBase64}:";
                    
                    // Add signature headers to request
                    request.Headers.Add("Signature-Input", signatureInputHeader);
                    request.Headers.Add("Signature", signatureHeader);
                    
                    WriteInfo($"HTTP Message Signature applied:");
                    WriteData("  Signature Input", signatureInputHeader);
                    WriteData("  Signature", $"sig1=:{signatureBase64.Substring(0, Math.Min(50, signatureBase64.Length))}...");
                    WriteData("  Components", string.Join(", ", components));
                }
                catch (Exception ex)
                {
                    WriteWarning($"Failed to sign HTTP message: {ex.Message}");
                }
            }
        }

        static RSA FromJwk(JsonWebKey jsonWebKey)
        {
            var nBytes = Base64UrlEncoder.DecodeBytes(jsonWebKey.N);
            var eBytes = Base64UrlEncoder.DecodeBytes(jsonWebKey.E);
            var dBytes = Base64UrlEncoder.DecodeBytes(jsonWebKey.D);
            var pBytes = Base64UrlEncoder.DecodeBytes(jsonWebKey.P);
            var qBytes = Base64UrlEncoder.DecodeBytes(jsonWebKey.Q);
            var dpBytes = Base64UrlEncoder.DecodeBytes(jsonWebKey.DP);
            var dqBytes = Base64UrlEncoder.DecodeBytes(jsonWebKey.DQ);
            var qiBytes = Base64UrlEncoder.DecodeBytes(jsonWebKey.QI);

            var rsaParams = new RSAParameters
            {
                Modulus = nBytes,
                Exponent = eBytes,
                D = dBytes,
                P = pBytes,
                Q = qBytes,
                DP = dpBytes,
                DQ = dqBytes,
                InverseQ = qiBytes
            };

            var rsaKey = RSA.Create();
            rsaKey.ImportParameters(rsaParams);

            return rsaKey;
        }

        // Helper methods for colorful console output
        static void WriteInfo(string message)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"ℹ️  {message}");
            Console.ResetColor();
        }

        static void WriteSuccess(string message)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"✅ {message}");
            Console.ResetColor();
        }

        static void WriteWarning(string message)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"⚠️  {message}");
            Console.ResetColor();
        }

        static void WriteError(string message)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"❌ {message}");
            Console.ResetColor();
        }

        static void WriteHeader(string message)
        {
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine($"\n🚀 {message}");
            Console.WriteLine(new string('=', message.Length + 3));
            Console.ResetColor();
        }

        static void WriteData(string label, string value)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($"{label}: ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine(value);
            Console.ResetColor();
        }

        static void WriteJson(string json)
        {
            Console.ForegroundColor = ConsoleColor.DarkYellow;
            Console.WriteLine(json);
            Console.ResetColor();
        }

    }
}
