
namespace AccionSocialModels.DTO
{
    public class UsuarioUpdateDto
    {
        public string? UserName { get; set; }
        public string? Email { get; set; }
        public string? Nombre { get; set; }
        public string? Apellidos { get; set; }
        public string? Telefono { get; set; }
        public bool? Estado { get; set; }
        public List<string>? Roles { get; set; }
        public string? CurrentPassword { get; set; }
        public string? NewPassword { get; set; }
    }
}
