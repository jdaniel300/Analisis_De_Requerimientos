using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace AccionSocialModels
{
    public class Rol : IdentityRole<int>
    {
        public Rol() : base() { }
        public Rol(string roleName) : base(roleName) { }


    }
}
