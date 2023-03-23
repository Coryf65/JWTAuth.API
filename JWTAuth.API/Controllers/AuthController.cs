using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace JWTAuth.API.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    public static User user = new User();
    private readonly IConfiguration _configuration;

    public AuthController(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    [HttpPost("register")]
    public async Task<ActionResult<User>> Register(UserDTO request)
    {
        CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);

        user.Username = request.Username;
        user.PasswordSalt = passwordSalt;
        user.PasswordHash = passwordHash;

        return Ok(user);
    }

    [HttpPost("login")]
    public async Task<ActionResult<string>> Login(UserDTO request)
    {
        // check if user exists
        if (user.Username != request.Username)
            return BadRequest("User not found.");
        // verify the password is correct
        if (!VerifyPasswordHash(request.Password, user.PasswordHash, user.PasswordSalt))
            return BadRequest("username / password issue, try again.");

        string token = CreateToken(user);

        return Ok(token);
    }

    /// <summary>
    /// Create the JWT for our user
    /// </summary>
    /// <param name="user"></param>
    /// <returns></returns>
    private string CreateToken(User user)
    {
        // Claims = props of the user to describe them
        List<Claim> claims = new()
        {
            new Claim(ClaimTypes.Name, user.Username)
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.GetSection("AppSettings:Token").Value));

        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

        var token = new JwtSecurityToken(
            claims: claims,
            expires: DateTime.Now.AddDays(1),
            signingCredentials: credentials
        );

        var jwt = new JwtSecurityTokenHandler().WriteToken(token);

        return jwt;
    }

    /// <summary>
    /// Create a hash and salt for the given password
    /// </summary>
    /// <param name="password"></param>
    /// <param name="passwordHash"></param>
    /// <param name="passwordSalt"></param>
    private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
    {
        using (var hmac = new HMACSHA512())
        {
            passwordSalt = hmac.Key;
            passwordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
        }
    }

    /// <summary>
    /// Verify the password given if it matches the hash computed
    /// </summary>
    /// <param name="password"></param>
    /// <param name="passwordHash"></param>
    /// <param name="passwordSalt"></param>
    /// <returns></returns>
    private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
    {
        byte[] computedHash;
        Console.WriteLine("exisiting password hash: {0}", Encoding.UTF8.GetString(passwordHash));

        using (var hmac = new HMACSHA512())
        {
            computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
            Console.WriteLine("entered password hash: {0}", Encoding.UTF8.GetString(computedHash));
            return computedHash.SequenceEqual(passwordHash);
        }
    }
}