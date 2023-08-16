using AuthenticationApi.Models;
using Microsoft.AspNetCore.Identity;

namespace AuthenticationApi.Repositories.IdentityUser
{
  public enum Role
  {
    Administrator, Visitor
  }

  public class UserRepository : IUserRepository
  {
    private readonly UserManager<User> _userManager;

    public UserRepository(UserManager<User> userManager)
    {
      _userManager = userManager;
    }

    public async Task<User?> FindByEmail(string email)
    {
      return await _userManager.FindByEmailAsync(email);
    }

    public async Task<User?> FindById(string userId)
    {
      return await _userManager.FindByIdAsync(userId);
    }

    public async Task<string?> GetToken(User user, string tokenName)
    {
      return await _userManager.GetAuthenticationTokenAsync(user, Global.DefaultTokenProvider, tokenName);
    }

    public async Task<IList<string>?> GetRoles(User user)
    {
      return await _userManager.GetRolesAsync(user);
    }

    public async Task<string> CreateToken(User user, string tokenName)
    {
      string token = await _userManager.GenerateUserTokenAsync(user, Global.DefaultTokenProvider, "refreshingAccessToken");
      await _userManager.SetAuthenticationTokenAsync(user, Global.DefaultTokenProvider, tokenName, token);
      return token;
    }

    public async Task<bool> CheckPassword(User user, string password)
    {
      return await _userManager.CheckPasswordAsync(user, password);
    }

    public async Task<IdentityResult> CreateNew(User user, string password)
    {
      return await _userManager.CreateAsync(user, password);
    }

    public async Task AssignRole(User user, string role)
    {
      await _userManager.AddToRoleAsync(user, role);
    }
  }
}