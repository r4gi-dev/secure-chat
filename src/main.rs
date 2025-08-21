use x25519_dalek::{EphemeralSecret, PublicKey};
use rand_core::OsRng;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, NewAead};

fn main() {
    // ===== 鍵ペア生成 =====
    // 送信者の鍵ペア
    let sender_secret = EphemeralSecret::new(OsRng);
    let sender_public = PublicKey::from(&sender_secret);

    // 受信者の鍵ペア
    let receiver_secret = EphemeralSecret::new(OsRng);
    let receiver_public = PublicKey::from(&receiver_secret);

    println!("Sender public key: {:?}", sender_public.as_bytes());
    println!("Receiver public key: {:?}", receiver_public.as_bytes());

    // 共通鍵の計算（Diffie-Hellman）
    let shared_secret = sender_secret.diffie_hellman(&receiver_public);
    println!("Shared secret: {:?}", shared_secret.as_bytes());

    // ===== メッセージ暗号化 =====
    let key = Key::from_slice(shared_secret.as_bytes());
    let cipher = ChaCha20Poly1305::new(key);

    // 12バイトの nonce（本番では OsRng でランダム生成）
    let nonce_bytes = [0u8; 12];
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = b"Hello, secure chat!";
    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).expect("encryption failure");

    println!("Ciphertext: {:?}", ciphertext);

    // ===== 復号 =====
    let decrypted = cipher.decrypt(nonce, ciphertext.as_ref()).expect("decryption failure");
    println!("Decrypted: {:?}", String::from_utf8(decrypted).unwrap());
}
