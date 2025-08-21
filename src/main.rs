use x25519_dalek::{EphemeralSecret, PublicKey};
use rand::rngs::OsRng;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, KeyInit, aead::Aead};

fn main() {
    // 鍵ペア生成
    let mut rng = OsRng;
    let sender_secret = EphemeralSecret::random_from_rng(&mut rng);
    let sender_public = PublicKey::from(&sender_secret);

    let receiver_secret = EphemeralSecret::random_from_rng(&mut rng);
    let receiver_public = PublicKey::from(&receiver_secret);

    println!("Sender public key: {:?}", sender_public.as_bytes());
    println!("Receiver public key: {:?}", receiver_public.as_bytes());

    // 共通鍵
    let shared_secret = sender_secret.diffie_hellman(&receiver_public);

    // ChaCha20Poly1305 暗号化
    let key = Key::from_slice(shared_secret.as_bytes());
    let cipher = ChaCha20Poly1305::new(key);

    let nonce_bytes = [0u8; 12];
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = b"Hello, secure chat!";
    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).expect("encryption failure");
    println!("Ciphertext: {:?}", ciphertext);

    let decrypted = cipher.decrypt(nonce, ciphertext.as_ref()).expect("decryption failure");
    println!("Decrypted: {:?}", String::from_utf8(decrypted).unwrap());
}
