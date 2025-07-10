namespace AccionSocialModels
{
    public class Participantes
    {
        public int Id { get; set; }
        public int IdUsuario { get; set; }
        public int IdSesion { get; set; }

        public DateTime FechaInscripcion { get; set; }
        public bool Estado { get; set; } 

        public Usuario Usuario { get; set; }
        public Sesion Sesion { get; set; }

    }
}
