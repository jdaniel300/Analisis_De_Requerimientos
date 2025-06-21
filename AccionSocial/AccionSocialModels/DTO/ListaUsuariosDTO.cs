namespace AccionSocialModels.DTO
{
    public class ListaUsuariosDTO
    {
        public int Id { get; set; }
        public string UserName { get; set; }
        public string Email { get; set; }
        public string NombreCompleto { get; set; }
        public DateTime FechaCreacion { get; set; }
        public DateTime? UltimoAcceso { get; set; }
        public DateOnly FechaCaducidadContrasena { get; set; }
        public bool Estado { get; set; }
        public List<string> Roles { get; set; }
    }
}
