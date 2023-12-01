using BelajarAuth.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace BelajarAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static List<User> users = new();

        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserRequest request)
        {
            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);

            var user = new User
            {
                UserName = request.UserName,
                PasswordHash = passwordHash,
                PasswordSalt = passwordSalt,
            };

            users.Add(user);


            return Ok(user);
        }

        private static void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using var hmac = new HMACSHA512();
            passwordSalt = hmac.Key;
            passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
        }


        [HttpPost("get-users")]
        public async Task<ActionResult<List<User>>> GetUser()
        {
            return Ok(users);
        }


        [HttpPost("Login")]
        public async Task<ActionResult<string>> Login(UserRequest request)
        {
            var user = users.Where(x => x.UserName == request.UserName).FirstOrDefault();

            if (user?.UserName != request.UserName)
                return BadRequest("User not found");

            if (!VerifyPassword(request.Password, user.PasswordHash, user.PasswordSalt))
                return BadRequest("Wrong password");

            var token = GenerateToken(user);

            return Ok(token);
        }

        private static bool VerifyPassword(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using var hmac = new HMACSHA512(passwordSalt);
            var hashPassword = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            return hashPassword.SequenceEqual(passwordHash);
        }

        private string GenerateToken(User user)
        {
            List<Claim> claims = new()
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.Role, "Admin")
            };

            var keyBytes = GenerateRandomKey(512);

            var key = new SymmetricSecurityKey(keyBytes);

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var token = new JwtSecurityToken(
                    claims: claims,
                    expires: DateTime.Now.AddDays(1),
                    signingCredentials: creds);

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }

        private byte[] GenerateRandomKey(int keySizeInBits)
        {
            var keyBytes = new byte[keySizeInBits / 8];

            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(keyBytes);
            }

            return keyBytes;
        }

    }
}
