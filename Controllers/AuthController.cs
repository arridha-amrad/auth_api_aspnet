using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using AuthenticationApi.Dto;
using AuthenticationApi.Models;
using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace AuthenticationApi.Controllers
{
  enum TokenType
  {
    Refresh,
    Access
  }

  [Route("api/[controller]")]
  [ApiController]
  public class AuthController : ControllerBase
  {
    private readonly IMapper _mapper;
    private readonly UserManager<User> _user;
    private readonly IConfiguration _config;

    public AuthController(IMapper mapper, UserManager<User> user, IConfiguration config)
    {
      _mapper = mapper;
      _user = user;
      _config = config;
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login(LoginDto dto)
    {
      if (!ModelState.IsValid)
      {
        return BadRequest(ModelState);
      }
      var user = await _user.FindByEmailAsync(dto.Email);
      if (user == null)
      {
        return NotFound("Email is not registered");
      }
      var isMatch = await _user.CheckPasswordAsync(user, dto.Password);
      if (!isMatch)
      {
        return BadRequest("Invalid Password");
      }
      var roles = await _user.GetRolesAsync(user);
      if (roles == null)
      {
        return BadRequest("User with no role");
      }
      string accToken = GenerateToken(user, roles, TokenType.Access);

      var userDevice = Request.Headers.UserAgent;
      var refreshToken = await _user.GenerateUserTokenAsync(user, "MyApp", userDevice.ToString());
      await _user.SetAuthenticationTokenAsync(user, "MyApp", userDevice.ToString(), refreshToken);

      CookieOptions opt = new()
      {
        HttpOnly = true,
        Expires = DateTime.Now.AddYears(1),
        Secure = false
      };
      Response.Cookies.Append("refresh-token", refreshToken, opt);

      var authUser = _mapper.Map<AuthenticatedUser>(user);
      return Ok(new AuthResponse() { Token = accToken, User = authUser }
      );
    }

    private string GenerateToken(User user, IList<string> roles, TokenType tokenType)
    {
      var jwtTokenHandler = new JwtSecurityTokenHandler();

      var key = Encoding.UTF8.GetBytes(_config.GetSection("JwtConfig:Secret").Value!);

      List<Claim> claims = roles.Select(role => new Claim("role", role)).ToList();

      var subject = new ClaimsIdentity();
      subject.AddClaims(claims);
      subject.AddClaims(new[]{
          new Claim("type", tokenType.ToString()),
          new Claim("id", user.Id),
          new Claim(JwtRegisteredClaimNames.Sub, user.Email ?? ""),
          new Claim(JwtRegisteredClaimNames.Email, user.Email ?? ""),
          new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
          new Claim(JwtRegisteredClaimNames.Iat, DateTime.Now.ToUniversalTime().ToString())
    });

      var tokenDescriptor = new SecurityTokenDescriptor()
      {
        Subject = subject,
        Expires = tokenType == TokenType.Refresh ? DateTime.Now.AddYears(1) : DateTime.Now.AddHours(1),
        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256)
      };

      SecurityToken token = jwtTokenHandler.CreateToken(tokenDescriptor);
      string strToken = jwtTokenHandler.WriteToken(token);

      return strToken;
    }
  }


}