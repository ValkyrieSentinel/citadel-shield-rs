#![no_std]

#[repr(C)]
#[derive(Copy, Clone)]
pub struct PacketInfo {
    pub ipv4_address: u32,
    pub action: u32,
}
