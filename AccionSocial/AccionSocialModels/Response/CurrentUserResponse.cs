using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AccionSocialModels.Response
{
    public record CurrentUserResponse(
        int UserId,
        string UserName,
        string Email,
        string NombreCompleto,
        List<string> Roles,
        DateTime FechaCreacion,
        DateTime? UltimoAcceso,
        bool Estado);
}
