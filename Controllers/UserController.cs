using AuthenticationApi.Dto;
using AuthenticationApi.Models;
using AutoMapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationApi.Controllers
{

  [Route("api/[controller]")]
  [ApiController]
  public class UserController : ControllerBase
  {

    private readonly UserManager<User> _userManager;
    private readonly IMapper _mapper;

    public UserController(UserManager<User> userManager, IMapper mapper)
    {
      _userManager = userManager;
      _mapper = mapper;
    }

    [HttpPost]
    [Route("register")]
    public async Task<IActionResult> Register(UserRegistrationDto dto)
    {
      if (!ModelState.IsValid)
      {
        return BadRequest(ModelState);
      }
      try
      {
        User user = new()
        {
          Email = dto.Email,
          FirstName = dto.FirstName,
          UserName = dto.Email,
          LastName = dto.LastName
        };
        var result = await _userManager.CreateAsync(user, dto.Password);
        if (!result.Succeeded)
        {
          foreach (var error in result.Errors)
          {
            ModelState.TryAddModelError(error.Code, error.Description);
          }
        }
        Console.WriteLine($"user = {user}");
        return Ok(user);
      }
      catch (Exception e)
      {
        Console.WriteLine(e);
        return StatusCode(500);
      }
    }
  }
}