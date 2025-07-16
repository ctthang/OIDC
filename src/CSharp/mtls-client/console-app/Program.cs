using IdentityModel.Client;
using System.Configuration;
using System.Security.Cryptography.X509Certificates;

namespace console_app
{
    internal class Program
    {
        static void Main(string[] args)
        {
            string authority = ConfigurationManager.AppSettings["Authority"] ?? throw new Exception("Authority setting is required");
            string clientId = ConfigurationManager.AppSettings["ClientId"] ?? throw new Exception("ClientId setting is required");
            string certificatePath = ConfigurationManager.AppSettings["CertificatePath"] ?? throw new Exception("CertificatePath setting is required");
            string certificatePassword = ConfigurationManager.AppSettings["CertificatePassword"] ?? throw new Exception("CertificatePassword setting is required");
            string apiEndpoint = ConfigurationManager.AppSettings["ApiEndpoint"] ?? throw new Exception("ApiEndpoint setting is required");
            Console.WriteLine($"Using Authority: {authority}, ClientId: {clientId}");
            
            var clientCert = new X509Certificate2(certificatePath, certificatePassword);
            Console.WriteLine($"Using client certificate: {clientCert.Subject}, Thumbprint: {clientCert.Thumbprint}");

            var handler = new HttpClientHandler();
            // Ignore SSL validation (for development only)
            handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true;
            // Include the client certificate for mTLS token requests
            handler.ClientCertificates.Add(clientCert);
            using var httpClient = new HttpClient(handler);

            // client credentials token request

            Console.WriteLine("Requesting token using client credentials flow with mTLS");
            Console.WriteLine($"Token endpoint: {authority}/mtls/token.idp");
            Console.WriteLine($"Client ID: {clientId}");
            Console.WriteLine($"Certificate: {clientCert.Subject}, Thumbprint: {clientCert.Thumbprint}");
            // Create the token request
            
            var request = new ClientCredentialsTokenRequest
            {
                Address = $"{authority}/mtls/token.idp",
                ClientId = clientId,
                GrantType = "client_credentials"
            };
            request.Parameters.Add("client_id", clientId);
            var tokenResponse = httpClient.RequestClientCredentialsTokenAsync(request).Result;

            if (tokenResponse.IsError)
            {
                Console.WriteLine($"Token request failed: {tokenResponse.Error}");
                return;
            }

            Console.WriteLine("Token request successful!");
            Console.WriteLine($"Access Token: {tokenResponse.AccessToken}");

            // Now make an API call using the access token
            httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", tokenResponse.AccessToken);

            Console.WriteLine("Sending HTTP request with Bearer token and client certificate");
            var response = httpClient.GetAsync(apiEndpoint).Result;

            Console.WriteLine($"API response: {response.StatusCode}");

            if (response.IsSuccessStatusCode)
            {
                var content = response.Content.ReadAsStringAsync().Result;
                Console.WriteLine($"API call successful, response: {content}");
            }
            else
            {
                var errorContent = response.Content.ReadAsStringAsync().Result;
                Console.WriteLine($"API call failed: {response.StatusCode} {response.ReasonPhrase} - {errorContent}");
            }

            Console.Read();
        }
    }
}
