namespace AccionSocialModels.Response
{
    public class RegisterResponse
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public string Token { get; set; } 
        public IEnumerable<string> Errors { get; set; }
        public bool RequiresEmailVerification { get; set; }
    }
}
