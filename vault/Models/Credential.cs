using System;
using System.Collections.Generic;

namespace vault.Models;

public partial class Credential
{
    public int Id { get; set; }

    public string Login { get; set; } = null!;

    public string Password { get; set; } = null!;

    public string App { get; set; } = null!;

    public string? Link { get; set; }

    public int? UserId { get; set; }

    public virtual User? User { get; set; }
}
