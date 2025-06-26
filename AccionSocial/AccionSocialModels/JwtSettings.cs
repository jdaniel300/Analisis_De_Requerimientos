
namespace AccionSocialModels
{
    public class JwtSettings
    {
        public string Key { get; set; }
        public string Issuer { get; set; }
        public string Audience { get; set; }
        public int ExpireMinutes { get; set; } = 15;
        public int RefreshTokenExpireDays { get; set; } = 7; // Para refresh tokens
    }
}
