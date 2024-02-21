mod sha256;
use sha256::Sha256;
fn main() {
    let message = b"hello world";

    let mut sha256 = Sha256::new();
    sha256.hash(message);

    println!("\nHashes");
    println!("{}", sha256.hash_string);
}
