namespace AuthenticationApi.Dto
{
  public class AuthResponse
  {
    public required AuthenticatedUser User { get; set; }

    public required string Token { get; set; }
  }
}