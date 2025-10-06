use clap::{Parser, Subcommand};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::UdpSocket;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Parser)]
#[command(name = "ifwatch")]
#[command(about = "Network interface statistics monitoring tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Serve {
        #[arg(short, long, help = "Comma-separated list of network interfaces to monitor (optionally with aliases: eth0=internet,eth1=lan)")]
        interfaces: String,

        #[arg(short, long, default_value = "12120", help = "Port to listen on")]
        port: u16,

        #[arg(short, long, help = "Enable verbose output")]
        verbose: bool,
    },
    Query {
        #[arg(short, long, help = "Server IP address")]
        server: String,

        #[arg(short, long, default_value = "12120", help = "Server port")]
        port: u16,

        #[arg(long, default_value = "0.25", help = "Request timeout in seconds")]
        timeout: f64,

        #[arg(short = 't', long, help = "Interval for continuous polling (in seconds)")]
        interval: Option<f64>,

        #[arg(long, help = "Output in simple text format instead of JSON")]
        text: bool,
    },
}

#[derive(Debug, Clone)]
struct InterfaceStats {
    rx_bytes: u64,
    tx_bytes: u64,
    rx_rate: f64,
    tx_rate: f64,
}

#[derive(Debug, Clone)]
struct InterfaceInfo {
    name: String,
    alias: Option<String>,
}

impl InterfaceInfo {
    fn display_name(&self) -> &str {
        self.alias.as_ref().unwrap_or(&self.name)
    }
}

#[derive(Serialize)]
struct InterfaceJsonOutput {
    interface: String,
    rx_bytes: u64,
    tx_bytes: u64,
    rx_rate: f64,
    tx_rate: f64,
}

#[derive(Serialize)]
struct JsonOutput {
    timestamp: f64,
    interfaces: Vec<InterfaceJsonOutput>,
}

fn parse_interfaces(interfaces_str: &str) -> Vec<InterfaceInfo> {
    interfaces_str
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| {
            if let Some((name, alias)) = s.split_once('=') {
                InterfaceInfo {
                    name: name.trim().to_string(),
                    alias: Some(alias.trim().to_string()),
                }
            } else {
                InterfaceInfo {
                    name: s.to_string(),
                    alias: None,
                }
            }
        })
        .collect()
}

fn read_interface_stats(interface: &str) -> Result<(u64, u64), Box<dyn std::error::Error>> {
    let rx_path = format!("/sys/class/net/{}/statistics/rx_bytes", interface);
    let tx_path = format!("/sys/class/net/{}/statistics/tx_bytes", interface);

    let rx_bytes = fs::read_to_string(rx_path)?.trim().parse::<u64>()?;
    let tx_bytes = fs::read_to_string(tx_path)?.trim().parse::<u64>()?;

    Ok((rx_bytes, tx_bytes))
}

fn encode_stats_packet(interfaces: &[InterfaceInfo], stats: &HashMap<String, InterfaceStats>) -> Vec<u8> {
    let mut packet = Vec::new();

    for interface_info in interfaces {
        if let Some(interface_stats) = stats.get(&interface_info.name) {
            let display_name = interface_info.display_name();
            let name_bytes = display_name.as_bytes();
            packet.push(name_bytes.len() as u8);
            packet.extend_from_slice(name_bytes);
            packet.extend_from_slice(&interface_stats.rx_bytes.to_be_bytes());
            packet.extend_from_slice(&interface_stats.tx_bytes.to_be_bytes());
            packet.extend_from_slice(&interface_stats.rx_rate.to_be_bytes());
            packet.extend_from_slice(&interface_stats.tx_rate.to_be_bytes());
        }
    }

    packet
}

fn decode_stats_packet(
    packet: &[u8],
) -> Result<Vec<(String, u64, u64, f64, f64)>, Box<dyn std::error::Error>> {
    let mut results = Vec::new();
    let mut offset = 0;

    while offset < packet.len() {
        let name_len = packet[offset] as usize;
        offset += 1;

        if offset + name_len + 32 > packet.len() {
            return Err("Invalid packet format".into());
        }

        let name = String::from_utf8(packet[offset..offset + name_len].to_vec())?;
        offset += name_len;

        let rx_bytes = u64::from_be_bytes(packet[offset..offset + 8].try_into()?);
        offset += 8;

        let tx_bytes = u64::from_be_bytes(packet[offset..offset + 8].try_into()?);
        offset += 8;

        let rx_rate = f64::from_be_bytes(packet[offset..offset + 8].try_into()?);
        offset += 8;

        let tx_rate = f64::from_be_bytes(packet[offset..offset + 8].try_into()?);
        offset += 8;

        results.push((name, rx_bytes, tx_bytes, rx_rate, tx_rate));
    }

    Ok(results)
}

fn run_serve(
    interfaces: String,
    port: u16,
    verbose: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let interface_infos = parse_interfaces(&interfaces);
    let socket = UdpSocket::bind(format!("0.0.0.0:{}", port))?;

    if verbose {
        println!("Serving stats for interfaces: {:?} on port {}", interface_infos, port);
    }

    let current_stats: HashMap<String, InterfaceStats> = HashMap::new();
    let current_stats_clone = std::sync::Arc::new(std::sync::Mutex::new(current_stats.clone()));
    let current_stats_ref = current_stats_clone.clone();
    let interface_infos_clone = interface_infos.clone();

    thread::spawn(move || {
        let mut error_interfaces: HashSet<String> = HashSet::new();
        let mut previous_values: HashMap<String, (u64, u64, Instant)> = HashMap::new();

        loop {
            let now = Instant::now();
            let mut new_stats = HashMap::new();

            for interface_info in &interface_infos_clone {
                match read_interface_stats(&interface_info.name) {
                    Ok((rx_bytes, tx_bytes)) => {
                        let (rx_rate, tx_rate) = if let Some((prev_rx, prev_tx, prev_time)) =
                            previous_values.insert(interface_info.name.clone(), (rx_bytes, tx_bytes, now)) {
                            let time_diff = now.duration_since(prev_time).as_secs_f64();
                            if time_diff > 0.0 {
                                let rx_rate = (rx_bytes.saturating_sub(prev_rx)) as f64 / time_diff;
                                let tx_rate = (tx_bytes.saturating_sub(prev_tx)) as f64 / time_diff;
                                (rx_rate, tx_rate)
                            } else {
                                (0.0, 0.0)
                            }
                        } else {
                            (0.0, 0.0)
                        };

                        new_stats.insert(interface_info.name.clone(), InterfaceStats {
                            rx_bytes,
                            tx_bytes,
                            rx_rate,
                            tx_rate,
                        });
                    }
                    Err(e) => {
                        if !error_interfaces.contains(&interface_info.name) {
                            eprintln!("Error reading stats for {}: {}", interface_info.name, e);
                            error_interfaces.insert(interface_info.name.clone());
                        }
                    }
                }
            }

            // Update shared stats
            if let Ok(mut stats) = current_stats_ref.lock() {
                *stats = new_stats;
            }

            thread::sleep(Duration::from_secs(1));
        }
    });

    // Main server loop - respond to queries
    let mut buf = [0; 64];
    loop {
        let (_, src) = socket.recv_from(&mut buf)?;

        // Get current stats
        let stats = if let Ok(stats) = current_stats_clone.lock() {
            stats.clone()
        } else {
            HashMap::new()
        };

        if !stats.is_empty() {
            let packet = encode_stats_packet(&interface_infos, &stats);
            if let Err(e) = socket.send_to(&packet, src) {
                eprintln!("Error sending response: {}", e);
            } else if verbose {
                println!("Sent response to {} ({} bytes)", src, packet.len());
            }
        }
    }
}

fn run_query(
    server: String,
    port: u16,
    timeout: f64,
    interval: Option<f64>,
    text_output: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    let server_addr = format!("{}:{}", server, port);

    // Set timeout
    socket.set_read_timeout(Some(Duration::from_secs_f64(timeout)))?;

    let query_once = || -> Result<(), Box<dyn std::error::Error>> {
        // Send request (empty packet)
        socket.send_to(&[], &server_addr)?;

        // Receive response
        let mut buf = [0; 1024];
        let (size, _) = socket.recv_from(&mut buf)?;

        // Decode response
        let stats = decode_stats_packet(&buf[..size])?;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();

        if text_output {
            for (interface, rx_bytes, tx_bytes, rx_rate, tx_rate) in stats {
                println!("{:.3} {} {} {} {:.1} {:.1}",
                    timestamp, interface, rx_bytes, tx_bytes, rx_rate, tx_rate);
            }
        } else {
            let interfaces: Vec<InterfaceJsonOutput> = stats
                .into_iter()
                .map(|(interface, rx_bytes, tx_bytes, rx_rate, tx_rate)| {
                    InterfaceJsonOutput {
                        interface,
                        rx_bytes,
                        tx_bytes,
                        rx_rate,
                        tx_rate,
                    }
                })
                .collect();

            let json_output = JsonOutput {
                timestamp,
                interfaces,
            };

            println!("{}", serde_json::to_string(&json_output)?);
        }

        Ok(())
    };

    match interval {
        Some(interval_secs) => {
            // Continuous polling
            loop {
                match query_once() {
                    Ok(()) => {},
                    Err(e) => {
                        eprintln!("Error: {}", e);
                    }
                }
                thread::sleep(Duration::from_secs_f64(interval_secs));
            }
        }
        None => {
            // Single query
            query_once()?;
        }
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Serve {
            interfaces,
            port,
            verbose,
        } => run_serve(interfaces, port, verbose),
        Commands::Query {
            server,
            port,
            timeout,
            interval,
            text,
        } => run_query(server, port, timeout, interval, text),
    }
}
