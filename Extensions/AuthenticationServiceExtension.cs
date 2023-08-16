using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace AuthenticationApi.Extensions
{
  public static class AuthenticationServiceExtensions
  {
    public static AuthenticationBuilder ConfigureAuthentication(this IServiceCollection services)
    {
      return services.AddAuthentication(options =>
       {
         options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
         options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
         options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
       });
    }
  }
}