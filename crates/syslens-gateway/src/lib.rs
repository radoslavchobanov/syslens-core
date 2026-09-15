pub mod ai;
pub mod client;
pub mod config;
pub mod daemon;
pub mod state;

pub type Result<T> = std::result::Result<T, String>;
pub const MAX_BODY: usize = 262_144;
pub fn id() -> String {
    uuid::Uuid::new_v4().to_string()
}
