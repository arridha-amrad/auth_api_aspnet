namespace AuthenticationApi.Dto
{
  public class AuthenticatedUser
  {
    public required string FullName { get; set; }

    public required string Email { get; set; }

  }
}