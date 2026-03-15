use aya::maps::HashMap as BpfHashMap;
use aya::{include_bytes_aligned, Ebpf};
use citadel_common::PacketInfo;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dns_lookup::lookup_addr;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Gauge, List, ListItem, Paragraph},
    Terminal,
};
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    cursor,
};

const INTERFACE: &str = "wlo1";
const ADMIN_IP: &str = "111.222.0.333";

struct HostStats {
    packets: u64,
    last_action: u32,
    hostname: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(debug_assertions)]
    let data = include_bytes_aligned!("../../target/bpfel-unknown-none/debug/citadel-ebpf");
    #[cfg(not(debug_assertions))]
    let data = include_bytes_aligned!("../../target/bpfel-unknown-none/release/citadel-ebpf");

    let mut bpf = Ebpf::load(data)?;
    let program: &mut aya::programs::Xdp = bpf.program_mut("citadel_shield")
        .ok_or("XDP program not found")?
        .try_into()?;
    
    program.load()?;
    program.attach(INTERFACE, aya::programs::XdpFlags::default())?;

    let total_count = Arc::new(AtomicUsize::new(0));
    let hosts_data = Arc::new(Mutex::new(HashMap::<u32, HostStats>::new()));
    
    let h_clone = hosts_data.clone();
    let t_clone = total_count.clone();

    let mut events_map: BpfHashMap<_, u32, PacketInfo> = BpfHashMap::try_from(bpf.map_mut("EVENTS").ok_or("Map not found")?)?;

    tokio::spawn(async move {
        loop {
            for item in events_map.iter() {
                if let Ok((ip_u32, info)) = item {
                    t_clone.fetch_add(1, Ordering::SeqCst);
                    
                    let mut stats = h_clone.lock().unwrap();
                    stats.entry(ip_u32).or_insert_with(|| {
                        let ip_addr = Ipv4Addr::from(ip_u32);
                        let name = if ip_addr.to_string() == ADMIN_IP {
                            "⭐ [ SYSTEM OWNER ]".to_string()
                        } else {
                            lookup_addr(&ip_addr.into()).unwrap_or(ip_addr.to_string())
                        };

                        HostStats {
                            packets: 0,
                            last_action: info.action,
                            hostname: name,
                        }
                    }).packets += 1;
                }
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    });

    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen, cursor::Hide)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout))?;

    let uptime = Instant::now();

    loop {
        terminal.draw(|f| {
            let layout = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([Constraint::Min(10), Constraint::Length(3)])
                .split(f.size());

            let panels = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
                .split(layout[0]);

            let system_info = format!(
                "\n NODE: CITADEL-01\n STATUS: ACTIVE\n\n TOTAL: {}\n UPTIME: {}s\n\n [q] - TERMINATE",
                total_count.load(Ordering::SeqCst),
                uptime.elapsed().as_secs()
            );
            
            f.render_widget(
                Paragraph::new(system_info).block(Block::default().title(" CORE ").borders(Borders::ALL)),
                panels[0]
            );

            let stats = hosts_data.lock().unwrap();
            let entries: Vec<ListItem> = stats.iter()
                .map(|(_, s)| {
                    let (label, color) = if s.last_action == 1 { 
                        ("DROP", Color::Red) 
                    } else { 
                        ("PASS", Color::Green) 
                    };
                    ListItem::new(format!("[{}] | {:<25} | PKTS: {}", label, s.hostname, s.packets))
                        .style(Style::default().fg(color))
                }).collect();

            f.render_widget(
                List::new(entries).block(Block::default().title(" KERNEL EVENTS ").borders(Borders::ALL)),
                panels[1]
            );

            let load = (total_count.load(Ordering::SeqCst) as f64 / 5000.0).min(1.0);
            f.render_widget(
                Gauge::default()
                    .block(Block::default().title(" LOAD ").borders(Borders::ALL))
                    .gauge_style(Style::default().fg(Color::Cyan))
                    .ratio(load),
                layout[1]
            );
        })?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.code == KeyCode::Char('q') { break; }
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, cursor::Show)?;
    Ok(())
}
