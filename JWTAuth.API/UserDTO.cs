namespace JWTAuth.API;

/// <summary>
/// User login and Registration
/// </summary>
public class UserDTO
{
    public string Username { get; set; }  = string.Empty;
    public string Password { get; set; } = string.Empty;
}