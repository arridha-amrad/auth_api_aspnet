using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using AuthenticationApi.Certificate;
using AuthenticationApi.Models;
using Microsoft.IdentityModel.Tokens;

namespace AuthenticationApi.Service
{
  public enum TokenType
  {
    Refresh,
    Access
  }
  public class TokenService
  {

    private readonly SigningAudienceCertificate _signingAudienceCertificate;

    public TokenService()
    {
      _signingAudienceCertificate = new SigningAudienceCertificate();
    }

    public string GenerateToken(User user, IList<string> roles, TokenType tokenType)
    {
      var jwtTokenHandler = new JwtSecurityTokenHandler();
      var key = _signingAudienceCertificate.GetAudienceSigningKey();
      ClaimsIdentity subject = SetClaimsIdentity(roles, user);
      var tokenDescriptor = new SecurityTokenDescriptor()
      {
        Subject = subject,
        Expires = tokenType == TokenType.Refresh ? DateTime.Now.AddYears(1) : DateTime.Now.AddHours(1),
        SigningCredentials = key,
        Audience = "dev.with.ari",
        Issuer = "dev.with.ari"
      };
      SecurityToken token = jwtTokenHandler.CreateToken(tokenDescriptor);
      string strToken = jwtTokenHandler.WriteToken(token);
      return strToken;
    }

    public ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
    {
      JwtSecurityToken jwt;
      var tokenValidationParameters = Global.TokenValidationParameters;
      var tokenHandler = new JwtSecurityTokenHandler();
      var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
      jwt = (JwtSecurityToken)securityToken;
      return principal;
    }

    private ClaimsIdentity SetClaimsIdentity(IList<string> roles, User user)
    {
      List<Claim> claims = roles.Select(role => new Claim("role", role)).ToList();
      var subject = new ClaimsIdentity();
      subject.AddClaims(claims);
      subject.AddClaims(new[]{
          new Claim(ClaimTypes.Name, user.Id),
          new Claim(ClaimTypes.Email, user.Email ?? ""),
          new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
          new Claim(JwtRegisteredClaimNames.Iat, DateTime.Now.ToUniversalTime().ToString())
    });
      return subject;
    }

    public string GetUserIdFromAccessToken(string token)
    {
      var splittedToken = token.ToString().Split(" ")[1];
      var principal = GetPrincipalFromExpiredToken(splittedToken);
      var userId = principal.Claims.First(c => c.Type == ClaimTypes.Name).Value;
      return userId;
    }
  }
}