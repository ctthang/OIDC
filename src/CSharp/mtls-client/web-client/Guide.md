# Solution Guide: ASP.NET Core OIDC mTLS Web Client & API

This solution demonstrates a secure integration between a Razor Pages web client and a Web API using OpenID Connect (OIDC) with mTLS (mutual TLS) for the token endpoint and certificate-bound access tokens.

---

## Projects Overview

### 1. web-client (ASP.NET Core Razor Pages Application)
- Provides OIDC login with an external provider (Identify Tenant).
- Uses a client certificate for mTLS at the token endpoint.
- Displays Access Token and Identity Token after login.
- Allows users to call the HelloWorld API with the Access Token and client certificate.

### 2. web-api (ASP.NET Core Web API)
- Secured with JWT Bearer authentication.
- Validates the JWT signature and the `cnf` claim against the client certificate (provided in the `X-Client-Cert` header).
- Exposes a HelloWorld endpoint that requires a valid, certificate-bound access token.

---

## Configuration Steps

Configuration steps to Ctr-F5 run the solution locally:

### Prerequisites
- .NET 8 SDK installed
- A valid Identify Tenant setup with mTLS support, and lets say `https://your-tenant.domain/`. Search and replace `your-tenant.domain` with your actual tenant domain.
- A client certificate in PFX format for mTLS authentication (with private key).
- A public certificate for the web-api to validate the JWT signature and the `cnf` claim.

### 1. Configure the web-client
1. Prepare your OAuth/OIDC connection in Identify Tenant
   - Create a new OIDC client in your Identify Tenant with the following settings:
	 - **Client ID**: Your application client ID
	 - **Client Secret**: Your application client secret
     - **Allow Http Redirects**: Enabled
	 - **Allow Code Flow**: Enabled
	 - **Redirect URI**: `http://localhost:5254/signin-oidc`
	 - **Post Logout Redirect URI**: `http://localhost:5254/signout-callback-oidc`
	 - **Security token audiences**: `https://localhost:7102/` 

2. Place your client certificate (PFX) in a secure location and update the path and password in configuration.
3. Update `appsettings.json` in the web-client project with your Identify Tenant details:

````JSON
"OIDC": {
      "Authority": "https://your-tenant.domain/runtime/oauth2/authorize.idp",
      "TokenEndpoint": "https://your-tenant.domain/runtime/oauth2/mtls/token.idp",
      "ConfigurationEndpoint": "https://your-tenant.domain/runtime/oauth2/.well-known/openid-configuration",
      "ClientId": "[Your client Id]",
      "CallbackPath": "/signin-oidc",
      "Certificate": {
        "Path": "[full file path to your PFX certificate (include a private key)]",
        "Password": "[the certificate password]"
      }
    }
````

Api configuration:
````JSON
"Api": {
    "HelloWorldUrl": "https://localhost:7102/HelloWorld"
  }
````
Just keep it as it is, this is the default API endpoint when running locally.

4. Run the web-client:
   ```sh
   dotnet run --project ./web-client/web-client.csproj
   ```

   As result, the web-client will start on `http://localhost:5254`. (see the configuration in `launchSettings.json`)

### 2. Configure the web-api
1. Update `appsettings.json` in the web-api project with your JWT authority, audience, and the path to the public certificate for signature and the `cnf` claim validation.

```JSON
"Jwt": {
    "Authority": "https://your-tenant.domain/runtime/oauth2",
    "Audience": "https://localhost:7102/",
    "Certificate": {
      "Path": "[Full path to the public certificate to validate the signature and the `cnf` claim]"
    }
  }
```

2. Run the web-api:
   ```sh
   dotnet run --project ./web-api/web-api.csproj
   ```

As a result , the web-api will start on `https://localhost:7102`. (see the configuration in `launchSettings.json`)

---

## How to Use the Solution

### 1. Obtain an Access Token using the web-client
- Start the web-client and log in with your Identify tenant via the browser.
- After successful authentication, the home page will display your Access Token and Identity Token.
- Copy the Access Token for use in API requests.

### 2. Call the HelloWorld API
- Use the web-client UI or a tool like `curl` to call the HelloWorld endpoint.
- You must provide:
  - The `Authorization: Bearer <access_token>` header (from the web-client)
  - The `X-Client-Cert` header containing your client certificate in base64 format
- The web-client provides a button to call the API with the necessary headers. It requires you to input a public certificate in base64 format, the access token will be automatically added to the request.

#### Example using curl
```sh
curl -X GET "https://localhost:7102/HelloWorld" \
  -H "Authorization: Bearer <access_token>" \
  -H "X-Client-Cert: <base64-encoded-client-cert>"
```
- Replace `<access_token>` with the token copied from the web-client app
- Replace `<base64-encoded-client-cert>` with your client certificate in base64 encoding

### 3. Expected Response
```
Hello, World!
```

---

## Notes
- The authorize endpoint does not require mTLS, but the token endpoint does.
- The API will reject requests if the access token is missing, invalid, or the client certificate does not match the `cnf` claim in the token.
- Both projects target .NET 8.
