#![no_std]
#![no_main]

use aya_ebpf::bindings::xdp_action;
use aya_ebpf::macros::{map, xdp};
use aya_ebpf::maps::HashMap;
use aya_ebpf::programs::XdpContext;
use citadel_common::PacketInfo;

#[map]
static mut EVENTS: HashMap<u32, PacketInfo> = HashMap::with_max_entries(1024, 0);

#[map]
static mut BLACK_LIST: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[xdp]
pub fn citadel_shield(ctx: XdpContext) -> u32 {
    match try_citadel_shield(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_citadel_shield(ctx: XdpContext) -> Result<u32, ()> {
    let eth = ctx.eth().map_err(|_| ())?;
    let ip = ctx.ip().map_err(|_| ())?;

    let src_addr = u32::from_be(ip.src_addr);

    if let Some(_) = unsafe { BLACK_LIST.get(&src_addr) } {
        log_event(&src_addr, xdp_action::XDP_DROP);
        return Ok(xdp_action::XDP_DROP);
    }

    log_event(&src_addr, xdp_action::XDP_PASS);
    Ok(xdp_action::XDP_PASS)
}

fn log_event(address: &u32, action: u32) {
    let info = PacketInfo { action };
    unsafe {
        let _ = EVENTS.insert(address, &info, 0);
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
