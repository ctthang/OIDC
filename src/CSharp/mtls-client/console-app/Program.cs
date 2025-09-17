using Duende.IdentityModel.OidcClient.DPoP;
using IdentityModel.Client;
using System.Configuration;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace console_app
{
    internal class Program
    {
        static void Main(string[] args)
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
                var dpopToken = string.Empty;

                WriteSuccess("Configuration loaded successfully");
                WriteData("Authority", authority);
                WriteData("Client ID", clientId);
                WriteData("API Endpoint", apiEndpoint);

                // Generate JWK once and reuse for both token request and API call DPoP proofs
                string jwk = string.Empty;
                if (useDpop)
                {
                    WriteHeader("DPoP Key Generation");
                    var dpopAlg = ConfigurationManager.AppSettings["DpopAlg"] ?? "PS256";
                    WriteInfo($"Generating DPoP key pair with algorithm: {dpopAlg}");
                    
                    // Creates a JWK using the configured Alg or default PS256 algorithm:
                    jwk = JsonWebKeys.CreateRsaJson(dpopAlg);
                    WriteData("JWK", jwk);
                    WriteSuccess("DPoP key pair generated successfully");
                    
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

                var tokenResponse = httpClient.RequestClientCredentialsTokenAsync(request).Result;

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
                    httpClient.DefaultRequestHeaders.Clear(); // Clear any existing headers
                    httpClient.DefaultRequestHeaders.Add("DPoP", apiDpopToken);
                    WriteInfo("Fresh DPoP header added to API request");
                }
                
                httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(tokenResponse.TokenType, tokenResponse.AccessToken);
                WriteData("Authorization Scheme", tokenResponse.TokenType);
                
                WriteInfo("Sending HTTP request with token and client certificate");
                WriteData("API Endpoint", apiEndpoint);

                // Remove client certificate from the handler before making the API call
                handler.ClientCertificates.Clear();
                var response = httpClient.GetAsync(apiEndpoint).Result;

                if (response.IsSuccessStatusCode)
                {
                    WriteSuccess($"API call successful! Status: {response.StatusCode}");
                    var content = response.Content.ReadAsStringAsync().Result;
                    WriteInfo("API Response:");
                    WriteJson(content);
                }
                else
                {
                    WriteError($"API call failed: {response.StatusCode} {response.ReasonPhrase}");
                    var errorContent = response.Content.ReadAsStringAsync().Result;
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
