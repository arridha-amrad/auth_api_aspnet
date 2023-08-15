using System.ComponentModel.DataAnnotations;

namespace AuthenticationApi.Dto
{
  public class UserRegistrationDto
  {
    public string? FirstName { get; set; }
    public string? LastName { get; set; }

    [Required(ErrorMessage = "Email is required")]
    [EmailAddress]
    public required string Email { get; set; }

    [Required]
    [DataType(DataType.Password)]
    public required string Password { get; set; }

    [Required]
    [DataType(DataType.Password)]
    [Compare("Password", ErrorMessage = "Password not match")]
    public required string ConfirmPassword { get; set; }
  }
}