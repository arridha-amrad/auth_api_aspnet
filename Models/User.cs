using Microsoft.AspNetCore.Identity;

namespace AuthenticationApi.Models
{
  public class User : IdentityUser
  {
    public required string FirstName { get; set; }

    public string? LastName { get; set; }
  }
}