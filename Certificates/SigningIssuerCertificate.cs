using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace AuthenticationApi.Certificate
{
  public class SigningIssuerCertificate : IDisposable
  {
    private readonly RSA _rsa;

    public SigningIssuerCertificate()
    {
      _rsa = RSA.Create();
    }

    public RsaSecurityKey GetIssuerSigningKey()
    {
      string publicXml = File.ReadAllText("public.xml");
      _rsa.FromXmlString(publicXml);
      return new RsaSecurityKey(_rsa);
    }

    public void Dispose()
    {
      _rsa.Dispose();
    }
  }
}