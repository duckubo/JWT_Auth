namespace jwtAuth.Models
{
    public class User
    {
        public int Id { get; set; }
        public string Username { get; set; }
        public string Name { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public string Roles { get; set; }

        public User(int id, string username, string name, string email, string password, string roles)
        {
            Id = id;
            Username = username;
            Name = name;
            Email = email;
            Password = password;
            Roles = roles;
        }
    }
}
