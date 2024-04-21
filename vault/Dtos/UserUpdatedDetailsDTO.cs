namespace vault.Dtos
{
    public class UserUpdatedDetailsDTO
    {
        public string? NewEmail { get; set; }

        public string? NewPassword { get; set; }

        public string ConfirmPassword { get; set; } = null!;
    }
}