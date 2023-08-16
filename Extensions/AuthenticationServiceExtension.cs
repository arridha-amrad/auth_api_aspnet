using AuthenticationApi.Certificate;
using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace AuthenticationApi.Extensions
{
  public static class AuthenticationServiceExtensions
  {
    public static void ConfigureAuthentication(this IServiceCollection services)
    {
      services.AddAuthentication(options =>
       {
         options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
         options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
         options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
       }).AddJwtBearer(jwt =>
       {
         var certificate = new SigningIssuerCertificate();
         var issuerKey = certificate.GetIssuerSigningKey();
         jwt.SaveToken = true;
         jwt.TokenValidationParameters = Global.TokenValidationParameters;
       });
    }
  }
}