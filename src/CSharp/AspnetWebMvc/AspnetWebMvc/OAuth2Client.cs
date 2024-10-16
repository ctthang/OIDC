﻿/*
 * Copyright (c) Dominick Baier.  All rights reserved.
 * see Thinktecture.IdentityModel.License.txt
 */

using IdentityModel;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using OAuth2ClientSamples.Controllers;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Web;

namespace AspnetWebMvc
{
    public class OAuth2Client
    {
        private Uri uri;
        private string clientId;

        private HttpClient _client;

        public OAuth2Client(string clientId)
        {
            uri = new Uri(ApplicationSettings.Authority);
            this.clientId = clientId;
            this._client = new HttpClient()
            {
                BaseAddress = uri
            };
        }

        internal static string CreateAuthorizationUrl(string authority
                                                        , string clientId
                                                        , string scope
                                                        , string redirectUri
                                                        , string responseType
                                                        , string responseMode
                                                        , string maxAge
                                                        , string codeVerifier
                                                        , string whr
                                                        , string state = null
                                                        , string prompt=null)
        {
            string nonce = Guid.NewGuid().ToString("N");

            var result = OAuth2Client.CreateUrl(GenerateAuthorizeEndpoint(authority), clientId, scope, redirectUri, responseType
                            , responseMode, maxAge, codeVerifier, whr, state, prompt, nonce);
            if (!string.IsNullOrEmpty(ApplicationSettings.IdTokenHint))
            {
                result = string.Format("{0}&id_token_hint={1}", result, ApplicationSettings.IdTokenHint);
            }
            return result;
        }

        public OAuth2TokenResponse RequestAccessTokenCode(string code, Uri redirectUri, string codeVerifier)
        {
            HttpResponseMessage result = this._client.PostAsync(GenerateTokenEndpoint(this.uri.AbsoluteUri), (HttpContent)this.GetTokenPostContent(code, redirectUri, codeVerifier)).Result;
            var response = JsonConvert.DeserializeObject<OAuth2TokenResponse>(result.Content.ReadAsStringAsync().Result);
            return response;
        }

        public OAuth2TokenResponse RequestAccessTokenRefreshToken(string refreshToken)
        {
            HttpResponseMessage result = this._client.PostAsync(GenerateTokenEndpoint(this.uri.AbsoluteUri), (HttpContent)this.ExchangeTokenFormPostContent(refreshToken)).Result;
            return JsonConvert.DeserializeObject<OAuth2TokenResponse>(result.Content.ReadAsStringAsync().Result);
        }

        private static string GenerateAuthorizeEndpoint(string authority)
        {
            return string.Format("{0}/authorize.idp", authority);
        }

        private static string GenerateTokenEndpoint(string authority)
        {
            var endpoint = string.Format("{0}/token.idp", authority);
            return endpoint;
        }

        private static string CreateUrl(string endpoint
                                , string clientId
                                , string scope
                                , string redirectUri
                                , string responseType
                                , string responseMode
                                , string maxAge
                                , string codeVerifier
                                , string whr
                                , string state = null
                                , string prompt = null
                                , string nonce = null)
        {
            string str = string.Format("{0}?client_id={1}&scope={2}&redirect_uri={3}&response_type={4}"
                , endpoint
                , ApplicationSettings.UrlEncode(clientId)
                , ApplicationSettings.UrlEncode(scope)
                , ApplicationSettings.UrlEncode(redirectUri)
                , ApplicationSettings.UrlEncode(responseType));

            var codeChallengeMethod = ApplicationSettings.CodeChallengeMethod;
            if (responseType.Contains("code") && codeChallengeMethod.ToLower() != "none")
            {
                var codeChallenge = codeVerifier;
                if (codeChallengeMethod == "S256")
                {
                    using (var sha256 = SHA256.Create())
                    {
                        var challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
                        codeChallenge = Base64Url.Encode(challengeBytes);
                    }
                }

                str = string.Format("{0}&code_challenge={1}&code_challenge_method={2}", str,
                    ApplicationSettings.UrlEncode(codeChallenge),
                    ApplicationSettings.UrlEncode(codeChallengeMethod));
            }

            if (ApplicationSettings.UsingRequestObject != "true")
            {
                if (!string.IsNullOrEmpty(maxAge))
                {
                    str = string.Format("{0}&max_age={1}", str, ApplicationSettings.UrlEncode(maxAge));
                }
                if (!string.IsNullOrEmpty(responseMode))
                {
                    str = string.Format("{0}&response_mode={1}", str, ApplicationSettings.UrlEncode(responseMode));
                }
                if (!string.IsNullOrWhiteSpace(state))
                {
                    str = string.Format("{0}&state={1}", str, ApplicationSettings.UrlEncode(state));
                }
                if (!string.IsNullOrWhiteSpace(prompt))
                {
                    str = string.Format("{0}&prompt={1}", str, ApplicationSettings.UrlEncode(prompt));
                }
                if (!string.IsNullOrWhiteSpace(nonce))
                {
                    str = string.Format("{0}&nonce={1}", str, ApplicationSettings.UrlEncode(nonce));
                }
                if (!string.IsNullOrWhiteSpace(whr))
                {
                    str = string.Format("{0}&whr={1}", str, ApplicationSettings.UrlEncode(whr));
                }
            }
            else
            {
                var claimsIdentify = new ClaimsIdentity();
                claimsIdentify.AddClaim(new Claim("client_id", clientId));
                claimsIdentify.AddClaim(new Claim("response_type", responseType));
                claimsIdentify.AddClaim(new Claim("scope", scope));
                claimsIdentify.AddClaim(new Claim("redirect_uri", redirectUri));
                claimsIdentify.AddClaim(new Claim("max_age", maxAge));
                claimsIdentify.AddClaim(new Claim("response_mode", responseMode));
                claimsIdentify.AddClaim(new Claim("state", state));
                claimsIdentify.AddClaim(new Claim("prompt", prompt));
                claimsIdentify.AddClaim(new Claim("nonce", nonce));
                claimsIdentify.AddClaim(new Claim("whr", whr));
                claimsIdentify.AddClaim(new Claim("acr_values", "urn:dk:gov:saml:attribute:AssuranceLevel:2"));
                string token;
                if (ApplicationSettings.SignRequestObject == "true")
                {
                    var securityTokenDescriptor = new SecurityTokenDescriptor
                    {
                        Subject = claimsIdentify,
                        Issuer = clientId,
                        IssuedAt = DateTime.UtcNow,
                        Expires = DateTime.UtcNow.AddYears(10),
                        Audience = endpoint
                    };
                    var signingCertificate = LoadCertificate(StoreName.My, StoreLocation.LocalMachine, ApplicationSettings.ClientCertificate);
                    securityTokenDescriptor.SigningCredentials = new X509SigningCredentials(signingCertificate, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
                    token = new JwtSecurityTokenHandler().CreateEncodedJwt(securityTokenDescriptor);
                }
                else
                {
                    var jwtSecurityToken = new JwtSecurityTokenHandler().CreateJwtSecurityToken(clientId, endpoint, claimsIdentify, DateTime.UtcNow, DateTime.UtcNow.AddYears(10), DateTime.UtcNow);
                    token = "eyJhbGciOiJub25lIn0" + "." + jwtSecurityToken.EncodedPayload + ".";
                }

                str += "&request=" + token;
            }

            return str;
        }

        protected virtual FormUrlEncodedContent ExchangeTokenFormPostContent(string refreshToken)
        {
            Dictionary<string, string> parameters = GenerateTokenEndpointRequestParameters();
            parameters.Add("grant_type", "refresh_token");
            parameters.Add("refresh_token", refreshToken);
            return OAuth2Client.CreateForm(parameters);
        }

        private Dictionary<string, string> GenerateTokenEndpointRequestParameters()
        {
            var result = new Dictionary<string, string>();
            if (ApplicationSettings.AuthenticationType == "client_secret_post")
            {
                result.Add("client_id", this.clientId);
                result.Add("client_secret", ApplicationSettings.ClientSecret);
            }
            else if (ApplicationSettings.AuthenticationType == "private_key_jwt")
            {
                result.Add("client_assertion", GenerateClientAssertion());
                result.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
            }
            else
            {
                var byteArray = new UTF8Encoding().GetBytes(string.Format("{0}:{1}", clientId, ApplicationSettings.ClientSecret));
                _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(byteArray));
            }
            return result;
        }

        private string GenerateClientAssertion()
        {
            var signingCertificate = LoadCertificate(StoreName.My, StoreLocation.LocalMachine, ApplicationSettings.ClientCertificate);
            var claimsIdentify = new ClaimsIdentity();
            claimsIdentify.AddClaim(new Claim("sub", this.clientId));
            claimsIdentify.AddClaim(new Claim("aud", ApplicationSettings.Authority + "/token.idp"));
            claimsIdentify.AddClaim(new Claim("exp", DateTime.UtcNow.AddYears(10).ToLongDateString(), ClaimValueTypes.DateTime));
            claimsIdentify.AddClaim(new Claim("jti", Guid.NewGuid().ToString()));

            var token = new JwtSecurityTokenHandler().CreateEncodedJwt(new SecurityTokenDescriptor
            {
                Subject = claimsIdentify,
                Issuer = this.clientId,
                SigningCredentials = new X509SigningCredentials(signingCertificate, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"),
                IssuedAt = DateTime.UtcNow,
                Expires = DateTime.UtcNow.AddYears(10)
            });
            return token;
        }

        protected virtual FormUrlEncodedContent GetTokenPostContent(string code, Uri redirectUri, string codeVerifier, Dictionary<string, string> additionalProperties = null)
        {
            Dictionary<string, string> parameters = GenerateTokenEndpointRequestParameters();
            parameters.Add("grant_type", "authorization_code");
            parameters.Add("redirect_uri", redirectUri.AbsoluteUri);
            parameters.Add("code", code);
            parameters.Add("code_verifier", codeVerifier);
            return OAuth2Client.CreateForm(parameters);
        }

        /// <summary>
        /// FormUrlEncodes both Sets of Key Value Pairs into one form object
        /// 
        /// </summary>
        /// <param name="explicitProperties"/><param name="additionalProperties"/>
        /// <returns/>
        private static FormUrlEncodedContent CreateForm(Dictionary<string, string> explicitProperties, Dictionary<string, string> additionalProperties = null)
        {
            return new FormUrlEncodedContent((IEnumerable<KeyValuePair<string, string>>)OAuth2Client.MergeAdditionKeyValuePairsIntoExplicitKeyValuePairs(explicitProperties, additionalProperties));
        }
        
        /// <summary>
         /// Merges additional into explicit properties keeping all explicit properties intact
         /// 
         /// </summary>
         /// <param name="explicitProperties"/><param name="additionalProperties"/>
         /// <returns/>
        private static Dictionary<string, string> MergeAdditionKeyValuePairsIntoExplicitKeyValuePairs(Dictionary<string, string> explicitProperties, Dictionary<string, string> additionalProperties = null)
        {
            Dictionary<string, string> dictionary = explicitProperties;
            if (additionalProperties != null)
                dictionary = Enumerable.ToDictionary(Enumerable.Concat(explicitProperties
                    , Enumerable.Where(additionalProperties
                    , (add => !explicitProperties.ContainsKey(add.Key))))
                    , (final => final.Key)
                    , (final => final.Value));
            return dictionary;
        }

        private static X509Certificate2 LoadCertificate(StoreName storename, StoreLocation storelocation, string value)
        {
            var _store = new X509Store(storename, storelocation);
            _store.Open(OpenFlags.ReadOnly);
            var certificate = _store.Certificates.Find(X509FindType.FindByThumbprint, value, false)[0];
            return certificate;
        }
    }
}