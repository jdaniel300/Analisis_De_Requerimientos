using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AccionSocialModels.DTO
{
    public class ActualizarUsuarioDTO
    {
        public string? Nombre { get; set; }
        public string? Apellidos { get; set; }
        public string? PhoneNumber { get; set; }

        [DataType(DataType.Password)]
        public string? CurrentPassword { get; set; }

        [DataType(DataType.Password)]
        public string? NewPassword { get; set; }

        [Compare("NewPassword", ErrorMessage = "Las contraseñas no coinciden")]
        public string? ConfirmNewPassword { get; set; }
    }
}
