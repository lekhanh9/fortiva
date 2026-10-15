// src/ui/menu.rs
use super::theme::*;

pub fn print_logo() {
    println!();
    println!("{}{}  ╭─────────────────────────────────────────────────╮{}", PRIMARY, BOLD, RESET);
    println!("{}{}  │{}                                                 {}{}│{}", PRIMARY, BOLD, RESET, PRIMARY, BOLD, RESET);
    println!("{}{}  │{}   {}███████╗ ██████╗ ██████╗ ████████╗██╗██╗   ██╗{}   {}{}│{}",
        PRIMARY, BOLD, RESET, PRIMARY, RESET, PRIMARY, BOLD, RESET);
    println!("{}{}  │{}   {}██╔════╝██╔═══██╗██╔══██╗╚══██╔══╝██║██║   ██║{}   {}{}│{}",
        PRIMARY, BOLD, RESET, PRIMARY, RESET, PRIMARY, BOLD, RESET);
    println!("{}{}  │{}   {}█████╗  ██║   ██║██████╔╝   ██║   ██║██║   ██║{}   {}{}│{}",
        PRIMARY, BOLD, RESET, PRIMARY, RESET, PRIMARY, BOLD, RESET);
    println!("{}{}  │{}   {}██╔══╝  ██║   ██║██╔══██╗   ██║   ██║╚██╗ ██╔╝{}   {}{}│{}",
        PRIMARY, BOLD, RESET, PRIMARY, RESET, PRIMARY, BOLD, RESET);
    println!("{}{}  │{}   {}██║     ╚██████╔╝██║  ██║   ██║   ██║ ╚████╔╝ {}   {}{}│{}",
        PRIMARY, BOLD, RESET, PRIMARY, RESET, PRIMARY, BOLD, RESET);
    println!("{}{}  │{}   {}╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═══╝  {}   {}{}│{}",
        PRIMARY, BOLD, RESET, PRIMARY, RESET, PRIMARY, BOLD, RESET);
    println!("{}{}  │{}                                                 {}{}│{}", PRIMARY, BOLD, RESET, PRIMARY, BOLD, RESET);
    println!("{}{}  │{}      {}iOS Sideload Tool written in Rust{}          {}{}│{}",
        PRIMARY, BOLD, RESET, MUTED, RESET, PRIMARY, BOLD, RESET);
    println!("{}{}  │{}      {}v0.1.0 — Termux Edition{}                   {}{}│{}",
        PRIMARY, BOLD, RESET, MUTED, RESET, PRIMARY, BOLD, RESET);
    println!("{}{}  ╰─────────────────────────────────────────────────╯{}", PRIMARY, BOLD, RESET);
    println!();
}

pub fn print_menu() {
    println!("{}┌─────────────────────────────────────────────┐{}", MUTED, RESET);
    println!("{}│{}  [{}1{}]  📦  Sideload & Install IPA             {}│{}",
        MUTED, RESET, PRIMARY, RESET, MUTED, RESET);
    println!("{}│{}  [{}2{}]  🔐  Login Apple ID                     {}│{}",
        MUTED, RESET, PRIMARY, RESET, MUTED, RESET);
    println!("{}│{}  [{}3{}]  🌐  Custom Anisette Server             {}│{}",
        MUTED, RESET, PRIMARY, RESET, MUTED, RESET);
    println!("{}│{}  [{}4{}]  🔗  Setup SideStore pairing           {}│{}",
        MUTED, RESET, PRIMARY, RESET, MUTED, RESET);
    println!("{}│{}  [{}5{}]  📱  Manage Devices                     {}│{}",
        MUTED, RESET, PRIMARY, RESET, MUTED, RESET);
    println!("{}│{}  [{}6{}]  🔑  Revoke Certificate                 {}│{}",
        MUTED, RESET, PRIMARY, RESET, MUTED, RESET);
    println!("{}│{}  [{}7{}]  📲  Device Info                        {}│{}",
        MUTED, RESET, PRIMARY, RESET, MUTED, RESET);
    println!("{}│{}  [{}8{}]  🚪  Logout                             {}│{}",
        MUTED, RESET, PRIMARY, RESET, MUTED, RESET);
    println!("{}│{}  [{}9{}]  🧪  Test Session / Developer API       {}│{}",
        MUTED, RESET, PRIMARY, RESET, MUTED, RESET);
    println!("{}│{}  [{}0{}]  ❌  Exit                               {}│{}",
        MUTED, RESET, PRIMARY, RESET, MUTED, RESET);
    println!("{}└─────────────────────────────────────────────┘{}", MUTED, RESET);
    println!();
}


pub fn print_status(iphone_status: &str) {
    println!("  {} 📱 iPhone:  {}", primary("Status"), iphone_status);
    println!();
}

pub fn print_status_with_account(iphone_status: &str, account_status: &str) {
    println!("  {} 📱 iPhone:  {}", primary("Status"), iphone_status);
    println!("  {} 🔑 Account: {}", primary("Status"), account_status);
    println!();
}
