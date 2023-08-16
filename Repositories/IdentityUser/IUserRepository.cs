using AuthenticationApi.Models;
using Microsoft.AspNetCore.Identity;

namespace AuthenticationApi.Repositories.IdentityUser
{
  public interface IUserRepository
  {
    public Task<User?> FindById(string userId);

    public Task<string?> GetToken(User user, string tokenName);

    public Task<IList<string>?> GetRoles(User user);

    public Task<string> CreateToken(User user, string tokenName);

    public Task<User?> FindByEmail(string email);

    public Task<bool> CheckPassword(User user, string password);

    public Task<IdentityResult> CreateNew(User user, string password);

    public Task AssignRole(User user, string role);
  }
}