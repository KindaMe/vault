namespace vault.Dtos
{
    public class CredentialUpdatedDetailsDto
    {
        public string Login { get; set; } = null!;

        public string Password { get; set; } = null!;

        public string App { get; set; } = null!;

        public string? Link { get; set; }
    }
}