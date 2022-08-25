using MHD.JWT.Login.Net6Api.Model;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace MHD.JWT.Login.Net6Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {

        private IConfiguration _config;

        public LoginController(IConfiguration config)
        {
            _config = config;
        }


        [HttpPost]
        public IActionResult Login([FromBody] UserLogin userLogin)
        {
            var member = Authenticate(userLogin);

            if (member != null)
            {
                var token = Generate(member);
                return Ok(token);
            }
            return NotFound("uSer Not found");
        }



        private string Generate(Member user)
        {
            var securitykey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var credentials = new SigningCredentials(securitykey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier,user.UserName),
                new Claim(ClaimTypes.Email,user.Email),
                new Claim(ClaimTypes.Role,user.Role),
            };

            var token = new JwtSecurityToken(_config["Jwt:Issuer"],

                _config["Jwt:Audience"],
                claims,
                expires: DateTime.Now.AddMinutes(15),
                signingCredentials: credentials
                );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }


        private Member Authenticate(UserLogin userLogin)
        {
            var currentuser = Users.FirstOrDefault(o => o.UserName.ToLower() == userLogin.UserName.ToLower()
            && o.Password.ToLower() == userLogin.Password.ToLower());

            if (currentuser != null)
            {
                return currentuser;
            }

            return null;
        }

        public static List<Member> Users = new List<Member>()
        {

            new Member ()
            {
                UserName="Mesut",
                Password="123",
                Role="Administrator",
                Email="mesut@test.com"
            },
             new Member ()
            {
               UserName="Halit",
                Password="456",
                Role="Seller",
                Email="halit@test.com"
            },


        };


    }
}
