﻿using System.Configuration;
using System.Web;

namespace OAuth2ClientSamples.Controllers
{
    public class ApplicationSettings
    {
        public static string Authority
        {
            get
            {
                return ConfigurationManager.AppSettings["IdentifyOauth2:Authority"];
            }
        }
        public static string HybridClientId
        {
            get
            {
                return ConfigurationManager.AppSettings["IdentifyOauth2:HybridClientId"];
            }
        }
        public static string CodeFlowClientId
        {
            get
            {
                return ConfigurationManager.AppSettings["IdentifyOauth2:CodeFlowClientId"];
            }
        }
        public static string ImplicitClientId
        {
            get
            {
                return ConfigurationManager.AppSettings["IdentifyOauth2:ImplicitClientId"];
            }
        }
        public static string ClientSecret
        {
            get
            {
                return ConfigurationManager.AppSettings["IdentifyOauth2:ClientSecret"];
            }
        }
        public static string ClientCertificate
        {
            get
            {
                return ConfigurationManager.AppSettings["IdentifyOauth2:ClientCertificate"];
            }
        }

        public static string UsingRequestObject
        {
            get
            {
                return ConfigurationManager.AppSettings["IdentifyOauth2:UsingRequestObject"];
            }
        }

        public static string SignRequestObject
        {
            get
            {
                return ConfigurationManager.AppSettings["IdentifyOauth2:SignRequestObject"];
            }
        }

        public static string AuthenticationType
        {
            get
            {
                return ConfigurationManager.AppSettings["IdentifyOauth2:AuthenticationType"];
            }
        }

        public static string IdTokenHint
        {
            get
            {
                return ConfigurationManager.AppSettings["IdentifyOauth2:IdTokenHint"];
            }
        }

        public static string HybridResponseType
        {
            get
            {
                return ConfigurationManager.AppSettings["IdentifyOauth2:HybridResponseType"];
            }
        }
        public static string ImplicitResponseType
        {
            get
            {
                return ConfigurationManager.AppSettings["IdentifyOauth2:ImplicitResponseType"];
            }
        }
        public static string ResponseMode
        {
            get
            {
                return ConfigurationManager.AppSettings["IdentifyOauth2:ResponseMode"];
            }
        }
        public static string Scope
        {
            get
            {
                return ConfigurationManager.AppSettings["IdentifyOauth2:Scope"];
            }
        }
        public static string State
        {
            get
            {
                return ConfigurationManager.AppSettings["IdentifyOauth2:State"];
            }
        }
        public static string Prompt
        {
            get
            {
                return ConfigurationManager.AppSettings["IdentifyOauth2:Prompt"];
            }
        }
        public static string HybridRedirectUri
        {
            get
            {
                return ConfigurationManager.AppSettings["IdentifyOauth2:HybridRedirectUri"];
            }
        }
        public static string CodeFlowRedirectUri
        {
            get
            {
                return ConfigurationManager.AppSettings["IdentifyOauth2:CodeFlowRedirectUri"];
            }
        }
        public static string ImplicitRedirectUri
        {
            get
            {
                return ConfigurationManager.AppSettings["IdentifyOauth2:ImplicitRedirectUri"];
            }
        }
        public static string PostLogoutRedirectUri
        {
            get
            {
                return ConfigurationManager.AppSettings["IdentifyOauth2:PostLogoutRedirectUri"];
            }
        }
        public static string MaxAge
        {
            get
            {
                return ConfigurationManager.AppSettings["IdentifyOauth2:MaxAge"];
            }
        }

        public static string Whr
        {
            get
            {
                return ConfigurationManager.AppSettings["IdentifyOauth2:Whr"];
            }
        }

        public static string Acr
        {
            get
            {
                return ConfigurationManager.AppSettings["IdentifyOauth2:Acr"];
            }
        }

        public static string CodeChallengeMethod
        {
            get
            {
                return ConfigurationManager.AppSettings["IdentifyOauth2:CodeChallengeMethod"];
            }
        }

        public static string UrlEncode(string value)
        {
            if (!string.IsNullOrEmpty(value))
            {
                return HttpUtility.UrlEncode(value);
            }

            return string.Empty;
        }
    }
}