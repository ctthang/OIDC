namespace web_api
{
    public class HttpMessageSignatureMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IHttpMessageSignatureValidator _validator;
        private readonly IConfiguration _configuration;

        public HttpMessageSignatureMiddleware(RequestDelegate next, IHttpMessageSignatureValidator validator, IConfiguration configuration)
        {
            _next = next;
            _validator = validator;
            _configuration = configuration;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var enableHttpSignatures = _configuration.GetValue<bool>("HttpSignatures:Enabled", false);
            var hasSignature = context.Request.Headers.ContainsKey("Signature");

            if (enableHttpSignatures && !hasSignature)
            {
                Console.WriteLine("[HTTP-SIG] RFC 9421 signature required but not provided");
                context.Response.StatusCode = 401;
                context.Response.Headers["WWW-Authenticate"] = "Signature realm=\"API\", headers=\"@method @path @authority authorization\"";
                await context.Response.WriteAsync("HTTP Message Signature required per RFC 9421");
                return;
            }

            if (hasSignature)
            {
                var isValid = await _validator.ValidateSignatureAsync(context);
                if (!isValid)
                {
                    Console.WriteLine("[HTTP-SIG] RFC 9421 signature validation failed");
                    context.Response.StatusCode = 401;
                    context.Response.Headers["WWW-Authenticate"] = "Signature realm=\"API\", headers=\"@method @path @authority authorization\"";
                    await context.Response.WriteAsync("Invalid HTTP Message Signature per RFC 9421");
                    return;
                }
            }

            await _next(context);
        }
    }
}
