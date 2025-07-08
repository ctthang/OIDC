using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

namespace web_api.Controllers
{
    [ApiController]
    [Route("[controller]")]
    [Authorize]
    public class HelloWorldController : ControllerBase
    {
        [HttpGet]
        public IActionResult Get()
        {
            return Ok("Hello, World!");
        }
    }
}
