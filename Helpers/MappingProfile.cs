using AuthenticationApi.Dto;
using AuthenticationApi.Models;
using AutoMapper;

namespace AuthenticationApi.Helpers
{
  public class MappingProfile : Profile
  {
    public MappingProfile()
    {
      // We map email to the username because we are not using the username in the registration form.
      CreateMap<UserRegistrationDto, User>()
        .ForMember(p => p.UserName, opt => opt.MapFrom(user => user.Email));

      CreateMap<User, AuthenticatedUser>()
      .ForMember(u => u.FullName, opt => opt.MapFrom(user => $"{user.FirstName} {user.LastName}"));
    }
  }
}