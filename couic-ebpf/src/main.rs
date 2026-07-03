#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{
        LruPerCpuHashMap, PerCpuArray,
        lpm_trie::{Key, LpmTrie},
    },
    programs::XdpContext,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, Ipv6Hdr},
};

const MAX_DROP_ENTRIES: u32 = 1 << 18; // 262144
const MAX_IGNORE_ENTRIES: u32 = 1 << 16; // 65536
const XDP_ACTION_MAX: u32 = 5;
const MAX_TRACKED_TAGS: u32 = 64;

#[derive(Debug, Copy, Clone)]
#[repr(C)]
struct PktStats {
    pub rx_packets: u64,
    pub rx_bytes: u64,
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[map(name = "couic_ipv4_drop")]
static IPV4_DROP: LpmTrie<u32, u64> = LpmTrie::with_max_entries(MAX_DROP_ENTRIES, 0);
#[map(name = "couic_ipv6_drop")]
static IPV6_DROP: LpmTrie<u128, u64> = LpmTrie::with_max_entries(MAX_DROP_ENTRIES, 0);
#[map(name = "couic_ipv4_ignore")]
static IPV4_IGNORE: LpmTrie<u32, u64> = LpmTrie::with_max_entries(MAX_IGNORE_ENTRIES, 0);
#[map(name = "couic_ipv6_ignore")]
static IPV6_IGNORE: LpmTrie<u128, u64> = LpmTrie::with_max_entries(MAX_IGNORE_ENTRIES, 0);
#[map(name = "couic_stats")]
static STATS: PerCpuArray<PktStats> = PerCpuArray::with_max_entries(XDP_ACTION_MAX, 0);
#[map(name = "couic_drop_stats_per_tag")]
static DROP_STATS_PER_TAG: LruPerCpuHashMap<u64, PktStats> =
    LruPerCpuHashMap::with_max_entries(MAX_TRACKED_TAGS, 0);
#[map(name = "couic_ignore_stats_per_tag")]
static IGNORE_STATS_PER_TAG: LruPerCpuHashMap<u64, PktStats> =
    LruPerCpuHashMap::with_max_entries(MAX_TRACKED_TAGS, 0);

#[xdp]
pub fn couic(ctx: XdpContext) -> u32 {
    match try_couic(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    let ptr = (start + offset) as *const T;
    Ok(ptr)
}

#[inline(always)]
fn check_ipv4(address: u32) -> (u32, Option<u64>, bool) {
    let key = Key::new(32, address.to_be());

    if let Some(tag) = IPV4_IGNORE.get(&key) {
        return (xdp_action::XDP_PASS, Some(*tag), true);
    }

    if let Some(tag) = IPV4_DROP.get(&key) {
        return (xdp_action::XDP_DROP, Some(*tag), false);
    }

    (xdp_action::XDP_PASS, None, false)
}

#[inline(always)]
fn check_ipv6(address: u128) -> (u32, Option<u64>, bool) {
    let key = Key::new(128, address.to_be());

    if let Some(tag) = IPV6_IGNORE.get(&key) {
        return (xdp_action::XDP_PASS, Some(*tag), true);
    }

    if let Some(tag) = IPV6_DROP.get(&key) {
        return (xdp_action::XDP_DROP, Some(*tag), false);
    }

    (xdp_action::XDP_PASS, None, false)
}

#[inline(always)]
fn bump_tag_stats(map: &LruPerCpuHashMap<u64, PktStats>, tag_id: u64, pkt_size: u64) {
    if let Some(ptr) = map.get_ptr_mut(tag_id) {
        unsafe {
            (*ptr).rx_packets = (*ptr).rx_packets.saturating_add(1);
            (*ptr).rx_bytes = (*ptr).rx_bytes.saturating_add(pkt_size);
        }
    } else {
        let stats = PktStats {
            rx_packets: 1,
            rx_bytes: pkt_size,
        };
        let _ = map.insert(tag_id, stats, 0);
    }
}

fn try_couic(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };

    let (action, tag, is_ignore) = match unsafe { *ethhdr }.ether_type() {
        Ok(EtherType::Ipv4) => {
            let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
            let source = u32::from_be_bytes(unsafe { (*ipv4hdr).src_addr });
            check_ipv4(source)
        }
        Ok(EtherType::Ipv6) => {
            let ipv6hdr: *const Ipv6Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
            let source = u128::from_be_bytes(unsafe { (*ipv6hdr).src_addr });
            check_ipv6(source)
        }
        _ => (xdp_action::XDP_PASS, None, false),
    };

    Ok(record_stats(&ctx, action, tag, is_ignore))
}

#[inline(always)]
fn record_stats(ctx: &XdpContext, action: u32, tag: Option<u64>, is_ignore: bool) -> u32 {
    let pkt_size = (ctx.data_end() - ctx.data()) as u64;

    // Update action stats
    unsafe {
        if let Some(rec) = STATS.get_ptr_mut(action) {
            (*rec).rx_packets = (*rec).rx_packets.saturating_add(1);
            (*rec).rx_bytes = (*rec).rx_bytes.saturating_add(pkt_size);
        }
    }

    // Update per-tag stats
    if let Some(tag_id) = tag {
        if is_ignore {
            bump_tag_stats(&IGNORE_STATS_PER_TAG, tag_id, pkt_size);
        } else {
            bump_tag_stats(&DROP_STATS_PER_TAG, tag_id, pkt_size);
        }
    }

    action
}
