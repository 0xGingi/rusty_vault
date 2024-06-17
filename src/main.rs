extern crate argonautica;
extern crate chacha20poly1305;
extern crate rand;
extern crate serde_json;

use argonautica::Hasher;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, Key, Nonce};
use rand::Rng;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use chacha20poly1305::aead::generic_array::GenericArray;
use std::fs;

#[derive(Serialize, Deserialize)]
struct Entry {
    username: String,
    password: String,
}

#[derive(Serialize, Deserialize)]
struct Vault {
    entries: HashMap<String, Entry>,
    master_password: Option<String>,
}

impl Vault {
    fn new() -> Self {
        Vault {
            entries: HashMap::new(),
            master_password: None,
        }
    }
    
    fn edit_entry(&mut self, website: &str, username: String, password: String) -> bool {
        match self.entries.get_mut(website) {
            Some(entry) => {
                entry.username = username;
                entry.password = password;
                true
            },
            None => false,
        }
    }

    fn set_master_password(&mut self, master_password: String) {
        self.master_password = Some(master_password);
    }
    
    fn check_master_password(&self, master_password: &str) -> bool {
        match &self.master_password {
            Some(stored_password) => stored_password == master_password,
            None => false,
        }
    }


    fn add_entry(&mut self, website: String, username: String, password: String) {
        self.entries.insert(website, Entry { username, password });
    }

    pub fn remove_entry(&mut self, website: &str) -> bool {
        self.entries.remove(website).is_some()
    }

    fn get_entry(&self, website: &str) -> Option<&Entry> {
        self.entries.get(website)
    }

    fn save_to_file(&self, file_path: &str, master_password: &str) {
        let key = derive_key(master_password);
        let serialized_vault = serde_json::to_string(self).unwrap();
        let encrypted_vault = encrypt(&serialized_vault.as_bytes(), &key);
        fs::write(file_path, encrypted_vault).unwrap();
    }

    fn load_from_file(file_path: &str, master_password: &str) -> Self {
        let key = derive_key(master_password);
        let encrypted_vault = fs::read(file_path).unwrap();
        let decrypted_vault = decrypt(&encrypted_vault, &key);
        let serialized_vault = String::from_utf8(decrypted_vault).unwrap();
        serde_json::from_str(&serialized_vault).unwrap()
    }

}

fn derive_key(master_password: &str) -> Key {
    let mut hasher = Hasher::default();
    let mut rng = rand::thread_rng();
    let secret_key: [u8; 32] = rng.gen();
    let salt: [u8; 32] = rng.gen();
    let hash = hasher
        .with_password(master_password)
        .with_secret_key(&secret_key[..])
        .with_salt(&salt[..])
        .hash()
        .unwrap();
    let hash_bytes = hash.as_bytes();
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash_bytes[0..32]);
    *Key::from_slice(&key)
}

fn encrypt_nonce(nonce: &[u8], key: &Key) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).unwrap();
    let mut rng = rand::thread_rng();
    let mut nonce_for_nonce_bytes = [0u8; 24];
    rng.fill(&mut nonce_for_nonce_bytes);
    let nonce_for_nonce = GenericArray::from_slice(&nonce_for_nonce_bytes);
    cipher.encrypt(nonce_for_nonce, nonce).unwrap()
}

fn decrypt_nonce(ciphertext: &[u8], nonce_for_nonce_bytes: &[u8], key: &Key) -> [u8; 24] {
    let cipher = XChaCha20Poly1305::new_from_slice(key).unwrap();
    let nonce_for_nonce = GenericArray::from_slice(nonce_for_nonce_bytes);
    let plaintext = cipher.decrypt(nonce_for_nonce, ciphertext).unwrap();
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&plaintext);
    nonce
}

fn encrypt(data: &[u8], key: &Key) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key);
    let nonce = GenericArray::from_slice(&[0u8; 24]);
    cipher.encrypt(nonce, data).unwrap()
}

fn decrypt(data: &[u8], key: &Key) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key);
    let nonce = GenericArray::from_slice(&[0u8; 24]);
    cipher.decrypt(nonce, data).unwrap()
}

fn main() {
    let file_path = "vault.json";
    let mut master_password;
    let mut vault = Vault::new();

    if fs::metadata(file_path).is_ok() {
        master_password = rpassword::prompt_password("Enter your master password: ").unwrap();
        vault = Vault::load_from_file(file_path, master_password.trim());
        if !vault.check_master_password(master_password.trim()) {
            println!("Incorrect master password. Please try again.");
            return;
        }
    } else {
        master_password = rpassword::prompt_password("No master password set. Please create a new master password: ").unwrap();
        vault.set_master_password(master_password.trim().to_string());
    }

    loop {
        println!("\nWhat would you like to do?");
        println!("1. Add a new login");
        println!("2. Remove an existing login");
        println!("3. Edit an existing login");
        println!("4. View all saved logins");
        println!("5. Quit");

        let mut choice = String::new();
        std::io::stdin().read_line(&mut choice).unwrap();

        match choice.trim() {
            "1" => {
                let mut website = String::new();
                let mut username = String::new();
                let mut password = String::new();

                println!("\nEnter the website:");
                std::io::stdin().read_line(&mut website).unwrap();

                println!("Enter the username:");
                std::io::stdin().read_line(&mut username).unwrap();

                println!("Enter the password:");
                std::io::stdin().read_line(&mut password).unwrap();

                vault.add_entry(website.trim().to_string(), username.trim().to_string(), password.trim().to_string());
                vault.save_to_file(file_path, master_password.trim());
                println!("Login added successfully.");
            },
            "2" => {
                let mut website = String::new();

                println!("\nEnter the website of the login you want to remove:");
                std::io::stdin().read_line(&mut website).unwrap();

                if vault.remove_entry(website.trim()) {
                    vault.save_to_file(file_path, master_password.trim());
                    println!("Login removed successfully.");
                } else {
                    println!("No login found for this website.");
                }
            },
            "3" => {
                let mut website = String::new();
                let mut username = String::new();
                let mut password = String::new();

                println!("\nEnter the website of the login you want to edit:");
                std::io::stdin().read_line(&mut website).unwrap();

                println!("Enter the new username:");
                std::io::stdin().read_line(&mut username).unwrap();

                println!("Enter the new password:");
                std::io::stdin().read_line(&mut password).unwrap();

                if vault.edit_entry(website.trim(), username.trim().to_string(), password.trim().to_string()) {
                    vault.save_to_file(file_path, master_password.trim());
                    println!("Login edited successfully.");
                } else {
                    println!("No login found for this website.");
                }
            },
            "4" => {
                println!("\nSaved logins:");
                let websites: Vec<&String> = vault.entries.keys().collect();
                for (i, website) in websites.iter().enumerate() {
                    println!("{}. {}", i + 1, website);
                }

                let mut index = String::new();
                println!("\nEnter the number of the login you want to view:");
                std::io::stdin().read_line(&mut index).unwrap();
                let index: usize = index.trim().parse().unwrap_or(0);

                if index > 0 && index <= websites.len() {
                    if let Some(entry) = vault.get_entry(websites[index - 1]) {
                        println!("Username: {}", entry.username);
                        println!("Password: {}", entry.password);
                    }
                } else {
                    println!("Invalid number. Please enter a number between 1 and {}.", websites.len());
                }
            },
            "5" => {
                vault.save_to_file(file_path, master_password.trim());
                println!("Vault saved. Goodbye!");
                break;
            },
            _ => {
                println!("Invalid option. Please enter a number between 1 and 4.");
            },
        }
    }
}