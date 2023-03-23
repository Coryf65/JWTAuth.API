using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;

namespace JWTAuth.API.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    public static User user = new User();

    [HttpPost("register")]
    public async Task<ActionResult<User>> Register(UserDTO request)
    {
        CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);

        user.Username = request.Username;
        user.PasswordSalt = passwordSalt;
        user.PasswordHash = passwordHash;

        return Ok(user);
    }

    private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
    {
        using (var hmac = new HMACSHA512())
        {
            passwordSalt = hmac.Key;
            passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
        }
    }
}