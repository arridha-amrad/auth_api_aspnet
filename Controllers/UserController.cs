using AuthenticationApi.Dto;
using AuthenticationApi.Models;
using AuthenticationApi.Repositories.IdentityUser;
using AutoMapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationApi.Controllers
{

  [Route("api/[controller]")]
  [ApiController]
  public class UserController : ControllerBase
  {

    private readonly IUserRepository _userRepo;
    private readonly IMapper _mapper;

    public UserController(IUserRepository userRepo, IMapper mapper)
    {
      _userRepo = userRepo;
      _mapper = mapper;
    }

    [HttpPost]
    [Route("register")]
    public async Task<IActionResult> Register(UserRegistrationDto dto)
    {
      if (!ModelState.IsValid) return BadRequest(ModelState);
      try
      {
        User user = _mapper.Map<User>(dto);
        var result = await _userRepo.CreateNew(user, dto.Password);
        if (!result.Succeeded)
        {
          foreach (var error in result.Errors)
          {
            ModelState.TryAddModelError(error.Code, error.Description);
          }
          return BadRequest(ModelState);
        }
        await _userRepo.AssignRole(user, nameof(Role.Visitor));
        return Ok("new user crafted successfully");
      }
      catch (Exception e)
      {
        Console.WriteLine(e);
        return StatusCode(500, e.Message);
      }
    }
  }
}