using System.Security.Claims;
using AuthenticationApi.Dto;
using AuthenticationApi.Repositories.IdentityUser;
using AuthenticationApi.Service;
using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationApi.Controllers
{

  [Route("api/[controller]")]
  [ApiController]
  public class AuthController : ControllerBase
  {
    private readonly IMapper _mapper;
    private readonly TokenService _tokenService;
    private readonly IUserRepository _userRepo;

    public AuthController(
      IMapper mapper,
      TokenService tokenService,
      IUserRepository userRepository
    )
    {
      _mapper = mapper;
      _tokenService = tokenService;
      _userRepo = userRepository;
    }

    [HttpGet("refresh-token")]
    public async Task<IActionResult> RefreshToken()
    {
      var token = Request.Cookies[Global.TokenCookie];
      if (token == null) return Forbid();
      var accToken = Request.Headers.Authorization.ToString();
      if (accToken == "" || accToken == null) return Forbid("You must provide access token");
      string userId = _tokenService.GetUserIdFromAccessToken(accToken);
      try
      {
        var user = await _userRepo.FindById(userId);
        if (user == null) return NotFound("User not found");
        var userDevice = Request.Headers.UserAgent;
        var storedRefToken = await _userRepo.GetToken(user, userDevice.ToString());
        if (storedRefToken == null) return NotFound("Stored ref token not found");
        if (token != storedRefToken) return BadRequest("Token not match");
        var roles = await _userRepo.GetRoles(user);
        if (roles == null) return BadRequest("Roles invalid");
        var newAccToken = _tokenService.GenerateToken(user, roles, TokenType.Refresh);
        var refreshToken = await _userRepo.CreateToken(user, userDevice.ToString());
        Global.SetRefreshTokenCookie(refreshToken, Response);
        AuthenticatedUser authUser = _mapper.Map<AuthenticatedUser>(user);
        return Ok(new AuthResponse() { Token = newAccToken, User = authUser });
      }
      catch (Exception error)
      {
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
        var user = await _userRepo.FindByEmail(email);
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
      if (!ModelState.IsValid) return BadRequest(ModelState);
      var user = await _userRepo.FindByEmail(dto.Email);
      if (user == null) return NotFound("Email is not registered");
      var isMatch = await _userRepo.CheckPassword(user, dto.Password);
      if (!isMatch) return BadRequest("Invalid Password");
      var roles = await _userRepo.GetRoles(user);
      if (roles == null) return BadRequest("User with no role");
      string accToken = _tokenService.GenerateToken(user, roles, TokenType.Access);
      var userDevice = Request.Headers.UserAgent;
      var refreshToken = await _userRepo.CreateToken(user, userDevice.ToString());
      Global.SetRefreshTokenCookie(refreshToken, Response);
      var authUser = _mapper.Map<AuthenticatedUser>(user);
      return Ok(new AuthResponse() { Token = accToken, User = authUser }
      );
    }
  }
}