fn main() {
    use rand::rngs::OsRng;
    let key = aethergate_zcash::keys::ReleaseKey::generate(&mut OsRng).unwrap();
    key.save(std::path::Path::new("rehearsal/release-key.json"))
        .unwrap();
    let addr = aethergate_zcash::address::p2pkh_testnet(&key.public_key_compressed());
    println!("{addr}");
}
