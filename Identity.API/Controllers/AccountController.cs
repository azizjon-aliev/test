using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Common;
using Identity.API.DataProvider;
using Identity.API.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace Identity.API.Controllers;

[ApiController]
[Route("api/v1/[controller]/[action]")]
public class AccountController(ApplicationDbContext context) : ControllerBase
{
    private static readonly TimeSpan TokenLifetime = TimeSpan.FromMinutes(30);

    [HttpPost]
    public async Task<ActionResult<TokenInfo>> Register(string username, string password)
    {
        if (await context.Users.AnyAsync(u => u.Username == username))
            return BadRequest("Username already exists");

        var user = new User
        {
            Username = username,
            Password = BCrypt.Net.BCrypt.HashPassword(password)
        };

        context.Users.Add(user);
        await context.SaveChangesAsync();

        var token = GenerateToken(user);

        return Ok(token);
    }

    [HttpPost]
    public async Task<ActionResult<TokenInfo>> Login(string username, string password)
    {
        var user = await context.Users.FirstOrDefaultAsync(u => u.Username == username);
        if (user == null)
            return BadRequest("Invalid username or password");

        if (!BCrypt.Net.BCrypt.Verify(password, user.Password))
            return BadRequest("Invalid username or password");

        var token = GenerateToken(user);

        return Ok(token);
    }

    private TokenInfo GenerateToken(User user)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.UTF8.GetBytes(AuthOptions.Key);
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new Claim[]
            {
                new(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new(ClaimTypes.Name, user.Username)
            }),
            Issuer = AuthOptions.Issuer,
            Audience = AuthOptions.Audience,
            Expires = DateTime.UtcNow.Add(TokenLifetime),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha256Signature)
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);

        return new TokenInfo { AccessToken = tokenHandler.WriteToken(token) };
    }
}