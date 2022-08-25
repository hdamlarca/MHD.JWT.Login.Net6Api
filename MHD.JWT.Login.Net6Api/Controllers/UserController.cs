using MHD.JWT.Login.Net6Api.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace MHD.JWT.Login.Net6Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {


        [HttpGet("Admins")]
        [Authorize(Roles = "Administrator, Seller")]
        public IActionResult AdminsEndpoint()
        {
            var currentuser = GetCurrentuser();

            if (currentuser.UserName != null)
            {
                return Ok($"hi {currentuser.UserName}, you are an {currentuser.Role}");
            }

            return Unauthorized();
        }

        [HttpGet("Seller")]
        [Authorize(Roles = "Seller")]
        public IActionResult SellerEndpoint()
        {
            var currentuser = GetCurrentuser();

            if (currentuser.UserName != null)
            {
                return Ok($"hi {currentuser.UserName}, you are an {currentuser.Role}");
            }

            return Unauthorized();
        }

        private Member GetCurrentuser()
        {
            var identity = HttpContext.User.Identity as ClaimsIdentity;

            if (identity != null)
            {
                var userClaims = identity.Claims;

                return new Member
                {
                    UserName = userClaims.FirstOrDefault(o => o.Type == ClaimTypes.NameIdentifier)?.Value,
                    Email = userClaims.FirstOrDefault(o => o.Type == ClaimTypes.Email)?.Value,
                    Role = userClaims.FirstOrDefault(o => o.Type == ClaimTypes.Role)?.Value,
                };
            }

            return null;
        }


    }
}
