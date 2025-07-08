using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.Security.Cryptography.X509Certificates;
using IdentityModel.Client;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();

// Load OIDC/mTLS config
dynamic oidcConfig = builder.Configuration.GetSection("Authentication:OIDC");
string authority = oidcConfig["Authority"] ?? "";
string tokenEndpoint = oidcConfig["TokenEndpoint"] ?? "";
string configEndpoint = oidcConfig["ConfigurationEndpoint"] ?? "";
string clientId = oidcConfig["ClientId"] ?? "";
string callbackPath = oidcConfig["CallbackPath"] ?? "/signin-oidc";
string certPath = oidcConfig.GetSection("Certificate")["Path"] ?? "";
string certPassword = oidcConfig.GetSection("Certificate")["Password"] ?? "";

X509Certificate2? clientCert = null;
if (!string.IsNullOrEmpty(certPath))
{
    clientCert = new X509Certificate2(certPath, certPassword);
}

builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddCookie()
.AddOpenIdConnect(options =>
{
    // Use ConfigurationEndpoint if provided
    if (!string.IsNullOrEmpty(configEndpoint))
    {
        options.MetadataAddress = configEndpoint;
    }
    else
    {
        options.Authority = authority;
    }
    options.ClientId = clientId;
    options.CallbackPath = callbackPath;
    options.UsePkce = true;
    options.ResponseType = OpenIdConnectResponseType.Code;
    options.SaveTokens = true;
    options.GetClaimsFromUserInfoEndpoint = true;
    options.TokenValidationParameters.NameClaimType = "name";
    options.TokenValidationParameters.RoleClaimType = "role";
    // Custom events to use mTLS for token endpoint
    options.Events = new OpenIdConnectEvents
    {
        OnAuthorizationCodeReceived = async ctx =>
        {
            var handler = new HttpClientHandler();

            // Include the client certificate for mTLS token requests
            if (clientCert != null)
                handler.ClientCertificates.Add(clientCert);
            var client = new HttpClient(handler);

            var parameters = new AuthorizationCodeTokenRequest
            {
                Address = tokenEndpoint,
                ClientId = clientId,
                Code = ctx.ProtocolMessage.Code,
                RedirectUri = ctx.Properties.Items[OpenIdConnectDefaults.RedirectUriForCodePropertiesKey],
                // Use the correct PKCE code verifier key
                CodeVerifier = ctx.TokenEndpointRequest.Parameters["code_verifier"]
            };
            parameters.Parameters.Add("client_id", clientId);

            var tokenResponse = await client.RequestAuthorizationCodeTokenAsync(parameters);
            if (tokenResponse.IsError)
            {
                ctx.Fail(tokenResponse.Error);
                return;
            }

            ctx.HandleCodeRedemption(tokenResponse.AccessToken, tokenResponse.IdentityToken);
        }
    };
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
}
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();

app.Run();
