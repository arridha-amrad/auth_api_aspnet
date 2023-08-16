using AuthenticationApi.Certificate;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Mvc;


namespace AuthenticationApi
{
  public class Global
  {
    public static TokenValidationParameters TokenValidationParameters
    {
      get
      {
        var certificate = new SigningIssuerCertificate();
        var issuerKey = certificate.GetIssuerSigningKey();
        return new()
        {
          ValidateIssuerSigningKey = true,
          IssuerSigningKey = issuerKey,
          ValidateLifetime = true,
          ValidateIssuer = true,
          RequireExpirationTime = true,
          ValidIssuer = "dev.with.ari",
          ValidAudience = "dev.with.ari",
          ClockSkew = TimeSpan.Zero
        };
      }
    }

    public static CookieOptions CookieOptions
    {
      get
      {
        return new CookieOptions()
        {
          HttpOnly = true,
          Expires = DateTime.Now.AddYears(1),
          Secure = false,
          SameSite = SameSiteMode.Lax
        };
      }
    }

    public static string DefaultTokenProvider { get => "MyApp"; }

    public static string TokenCookie { get => "RefreshToken"; }

    public static void SetRefreshTokenCookie(string token, HttpResponse response)
    {
      response.Cookies.Append(TokenCookie, token, CookieOptions);
    }
  }
}