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

    private ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
    {
      JwtSecurityToken jwt;
      Console.WriteLine($"token : {token}");
      var key = Encoding.UTF8.GetBytes(_config.GetSection("JwtConfig:Secret").Value!);

      var tokenValidationParameters = new TokenValidationParameters()
      {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ValidateLifetime = false,
        ValidateIssuer = true,
        RequireExpirationTime = false,
        ValidIssuer = "dev.with.ari",
        ValidAudience = "dev.with.ari",
        ClockSkew = TimeSpan.Zero
      };

      var tokenHandler = new JwtSecurityTokenHandler();
      var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
      jwt = (JwtSecurityToken)securityToken;
      return principal;
    }

    [HttpGet("refresh-token")]
    public async Task<IActionResult> RefreshToken()
    {
      var token = Request.Cookies["refresh-token"];
      if (token == null) return Forbid();
      var accToken = Request.Headers.Authorization;
      if (accToken == "")
      {
        return Forbid("You must provide access token");
      }
      var splittedToken = accToken.ToString().Split(" ")[1];
      var principal = GetPrincipalFromExpiredToken(splittedToken);
      var userId = principal.Claims.First(c => c.Type == ClaimTypes.Name).Value;
      try
      {
        var user = await _user.FindByIdAsync(userId);
        if (user == null) return NotFound("User not found");
        var userDevice = Request.Headers.UserAgent;
        var storedRefToken = await _user.GetAuthenticationTokenAsync(user, "MyApp", userDevice.ToString());
        if (storedRefToken == null) return NotFound("Stored ref token not found");
        if (token != storedRefToken) return BadRequest("Token not match");
        var roles = await _user.GetRolesAsync(user);
        if (roles == null) return BadRequest("Roles invalid");
        var newAccToken = GenerateToken(user, roles, TokenType.Refresh);
        var refreshToken = await _user.GenerateUserTokenAsync(user, "MyApp", "refreshingAccessToken");
        await _user.SetAuthenticationTokenAsync(user, "MyApp", userDevice.ToString(), refreshToken);
        CookieOptions opt = new()
        {
          HttpOnly = true,
          Expires = DateTime.Now.AddYears(1),
          Secure = false,
          SameSite = SameSiteMode.Lax
        };
        Response.Cookies.Append("refresh-token", refreshToken, opt);
        AuthenticatedUser authUser = _mapper.Map<AuthenticatedUser>(user);
        return Ok(new AuthResponse() { Token = newAccToken, User = authUser });
      }
      catch (Exception error)
      {
        Console.WriteLine(error);
        return StatusCode(500, error.Message);
      }
    }


    [Authorize]
    [HttpGet("me")]
    public async Task<IActionResult> Me()
    {
      var email = User.Claims.First(claim => claim.Type == ClaimTypes.Email).Value;
      if (email == null) return NotFound("User not found");
      try
      {
        var user = await _user.FindByEmailAsync(email);
        var authUser = _mapper.Map<AuthenticatedUser>(user);
        return Ok(authUser);
      }
      catch (Exception e)
      {
        return StatusCode(500, e.Message);
      }

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
      var refreshToken = await _user.GenerateUserTokenAsync(user, "MyApp", "refreshingAccessToken");
      await _user.SetAuthenticationTokenAsync(user, "MyApp", userDevice.ToString(), refreshToken);
      CookieOptions opt = new()
      {
        HttpOnly = true,
        Expires = DateTime.Now.AddYears(1),
        Secure = false,
        SameSite = SameSiteMode.Lax
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
          new Claim(ClaimTypes.Name, user.Id),
          new Claim(ClaimTypes.Email, user.Email ?? ""),
          new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
          new Claim(JwtRegisteredClaimNames.Iat, DateTime.Now.ToUniversalTime().ToString())
    });

      var tokenDescriptor = new SecurityTokenDescriptor()
      {
        Subject = subject,
        Expires = tokenType == TokenType.Refresh ? DateTime.Now.AddYears(1) : DateTime.Now.AddHours(1),
        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256),
        Audience = "dev.with.ari",
        Issuer = "dev.with.ari"
      };

      SecurityToken token = jwtTokenHandler.CreateToken(tokenDescriptor);
      string strToken = jwtTokenHandler.WriteToken(token);

      return strToken;
    }
  }


}