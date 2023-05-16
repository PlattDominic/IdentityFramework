namespace ShoeStoreWebAPI.Models
{
    public class ShoeModel
    {
        public Guid Id { get; set; }
        public string? SellerUsername { get; set; }
        public string? Brand { get; set; }
        public string? Name { get; set; }
        public int Price { get; set; }
        public int Size { get; set; }
    }
}
