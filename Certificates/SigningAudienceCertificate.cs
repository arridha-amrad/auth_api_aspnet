using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace AuthenticationApi.Certificate
{
  public class SigningAudienceCertificate : IDisposable
  {
    private readonly RSA _rsa;

    public SigningAudienceCertificate()
    {
      _rsa = RSA.Create();
    }

    public SigningCredentials GetAudienceSigningKey()
    {
      string privateXmlKey = File.ReadAllText("private.xml");
      _rsa.FromXmlString(privateXmlKey);
      return new SigningCredentials(
        key: new RsaSecurityKey(_rsa),
        algorithm: SecurityAlgorithms.RsaSha256
      );

    }
    public void Dispose()
    {
      throw new NotImplementedException();
    }
  }
}