using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using HtmlAgilityPack;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Newtonsoft.Json.Linq;

namespace WebAppNetCore.Controllers
{
    public class AccountController : Controller
    {
        private HttpClient _client = new HttpClient();
        private IConfiguration configuration;
        public AccountController(IConfiguration configuration)
        {
            this.configuration = configuration;
        }
        //
        // GET: /Account/SignIn
        [HttpGet]
        public IActionResult SignIn()
        {
            return Challenge(
                new AuthenticationProperties { RedirectUri = "/" }, OpenIdConnectDefaults.AuthenticationScheme);
        }

        //
        // GET: /Account/SignOut
        [HttpGet]
        public IActionResult SignOut()
        {
            var callbackUrl = Url.Action(nameof(SignedOut), "Account", values: null, protocol: Request.Scheme);
            var properties = new AuthenticationProperties { RedirectUri = callbackUrl };
            return SignOut(properties,
                CookieAuthenticationDefaults.AuthenticationScheme, OpenIdConnectDefaults.AuthenticationScheme);
        }

        //
        // GET: /Account/SignedOut
        [HttpGet]
        public IActionResult SignedOut()
        {
            if (HttpContext.User.Identity.IsAuthenticated)
            {
                // Redirect to home page if the user is authenticated.
                return RedirectToAction(nameof(HomeController.Index), "Home");
            }

            return View();
        }

        [HttpPost]
        public IActionResult Reauthenticate()
        {
            string state = RandomDataBase64url(32);

            var idToken = HttpContext.User.Claims.Where(x => x.Type == OpenIdConnectConstants.IdToken).Select(x => x.Value).FirstOrDefault();

            string authorizationRequest = string.Format("{0}?response_type=id_token&scope={4}&redirect_uri={1}&client_id={2}&state={3}&response_mode=form_post&prompt=none&id_token_hint={5}",
                configuration.AuthorizationEndpoint(),
                HttpContext.Request.Scheme + "://" + HttpContext.Request.Host + "/signin-oidc" ,
                HttpUtility.UrlEncode(configuration.ClientId()),
                state,
                HttpUtility.UrlEncode(configuration.Scope()),
                idToken);

            _client.BaseAddress = new Uri(configuration.IssuerDomain());
            HttpResponseMessage result = this._client.GetAsync(authorizationRequest).Result;
            result.EnsureSuccessStatusCode();
            var response = result.Content.ReadAsStringAsync().Result;

            HtmlDocument doc = new HtmlDocument();
            doc.LoadHtml(response);

            var authorizationResult = new AuthorizationResult
            {
                IsLoggedOut = true
            };

            var error = doc.DocumentNode.SelectNodes("//input[@name='error']").FirstOrDefault().Attributes["value"].Value;
            if (!string.IsNullOrEmpty(error))
            {
                return Json(new { success = true, authorizationResult });
            }

            authorizationResult.IsLoggedOut = false;
            var newIdToken = doc.DocumentNode.SelectNodes("//input[@name='id_token']").FirstOrDefault().Attributes["value"].Value;
            authorizationResult.Session = newIdToken;

            return Json(new { success = true, authorizationResult });
        }

        //
        // GET: /Account/AccessDenied
        [HttpGet]
        public IActionResult AccessDenied()
        {
            return View();
        }

        public ActionResult RPIFrame()
        {
            var sessionState = HttpContext.User.Claims.Where(x => x.Type == OpenIdConnectConstants.SessionState).Select(x => x.Value).FirstOrDefault();
            //var idToken = HttpContext.User.Claims.Where(x => x.Type == OpenIdConnectConstants.IdToken).Select(x => x.Value).FirstOrDefault();
            ViewData[OpenIdConnectConstants.ClientId] = configuration.ClientId();
            ViewData[OpenIdConnectConstants.SessionState] = sessionState;
            //ViewData[OpenIdConnectConstants.IdToken] = idToken;
            ViewData["OPDomain"] = configuration.IssuerDomain();

            return View();
        }

        #region Helpers
        private static string RandomDataBase64url(uint length)
        {
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] bytes = new byte[length];
            rng.GetBytes(bytes);
            return Base64UrlEncodeNoPadding(bytes);
        }

        /// <summary>
        /// Base64url no-padding encodes the given input buffer.
        /// </summary>
        /// <param name="buffer"></param>
        /// <returns></returns>
        private static string Base64UrlEncodeNoPadding(byte[] buffer)
        {
            string base64 = Convert.ToBase64String(buffer);

            // Converts base64 to base64url.
            base64 = base64.Replace("+", "-");
            base64 = base64.Replace("/", "_");
            // Strips padding.
            base64 = base64.Replace("=", "");

            return base64;
        }

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }

        private IActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            else
            {
                return RedirectToAction(nameof(HomeController.Index), "Home");
            }
        }

        #endregion
    }
    public class AuthorizationResult
    {
        public bool IsLoggedOut { get; set; }
        public string Session { get; set; }
    }
}
