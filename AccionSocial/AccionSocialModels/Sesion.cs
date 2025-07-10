namespace AccionSocialModels
{
    public class Sesion
    {
        public int Id { get; set; }
        public int IdTaller { get; set; } // FK al taller
        public DateOnly Fecha { get; set; }
        public TimeSpan HoraInicio { get; set; } // Cambiado a TimeSpan para mejor manejo de horas
        public TimeSpan HoraFin { get; set; }
        public bool Estado { get; set; } = true;

        // Relaciones
        public Taller Taller { get; set; }
        public ICollection<Participantes> Participantes { get; set; }

    }
}
