using Microsoft.AspNetCore.Identity;

namespace AccionSocialModels
{
    public class Usuario : IdentityUser<int>
    {
        public string Nombre {  get; set; }
        public string Apellidos { get; set; }
        public DateTime FechaCreacion {  get; set; }
        public DateTime? UltimoAcceso { get; set; }

        public bool Estado { get; set; }
        public DateOnly FechaCaducidadContrasena { get; set; }

        
    }
}
