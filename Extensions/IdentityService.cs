using AuthenticationApi.Data;
using AuthenticationApi.Models;
using Microsoft.AspNetCore.Identity;

namespace AuthenticationApi.Extensions
{
  public static class IdentityService
  {
    public static void ConfigureIdentity(this IServiceCollection services)
    {
      services.AddIdentity<User, IdentityRole>(opt =>
      {
        opt.Password.RequiredLength = 3;
        opt.Password.RequireDigit = false;
        opt.Password.RequireUppercase = false;
        opt.Password.RequireNonAlphanumeric = false;
        opt.User.RequireUniqueEmail = true;
      })
      .AddEntityFrameworkStores<AppDbContext>()
      .AddTokenProvider<DataProtectorTokenProvider<User>>("MyApp");
    }
  }
}