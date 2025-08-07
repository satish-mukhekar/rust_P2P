use anyhow::Result;
use clap::{Arg, Command};
use libp2p::{
    gossipsub, identify, kad, mdns, ping,
    identity, noise, yamux, tcp,
    swarm::{NetworkBehaviour, SwarmEvent},
    Multiaddr, PeerId, Swarm, SwarmBuilder,
};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tracing::{info, warn};
use futures::stream::StreamExt;

#[derive(NetworkBehaviour)]
pub struct BootnodeBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
}

pub struct SecureBootnode {
    swarm: Swarm<BootnodeBehaviour>,
    connected_peers: HashMap<PeerId, PeerInfo>,
    connections_per_ip: HashMap<IpAddr, u32>,
    connection_attempts: HashMap<IpAddr, Vec<Instant>>,
    blacklisted_peers: HashSet<PeerId>,
    max_peers: usize,
    max_peers_per_ip: u32,
}

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub peer_id: PeerId,
    pub connected_at: Instant,
    pub ip_address: String,
    pub violations: u32,
    pub reputation: i32,
}

impl SecureBootnode {
    pub async fn new(max_peers: usize) -> Result<Self> {
        let local_key = identity::Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(local_key.public());
        
        info!("🆔 Bootnode Peer ID: {}", local_peer_id);
        
        // Configure gossipsub
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Duration::from_secs(10))
            .validation_mode(gossipsub::ValidationMode::Strict)
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to build gossipsub config: {}", e))?;

        let mut gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(local_key.clone()),
            gossipsub_config,
        ).map_err(|e| anyhow::anyhow!("Failed to create gossipsub behaviour: {}", e))?;

        // Subscribe to status topic
        gossipsub.subscribe(&gossipsub::IdentTopic::new("ethereum/status"))
            .map_err(|e| anyhow::anyhow!("Failed to subscribe to topic: {}", e))?;

        // Configure other behaviours
        let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)?;
        let kademlia = kad::Behaviour::new(local_peer_id, kad::store::MemoryStore::new(local_peer_id));
        let identify = identify::Behaviour::new(identify::Config::new(
            "/ethereum-bootnode/1.0.0".into(),
            local_key.public(),
        ));
        let ping = ping::Behaviour::new(ping::Config::new());

        let behaviour = BootnodeBehaviour {
            gossipsub,
            mdns,
            kademlia,
            identify,
            ping,
        };

        // Build swarm
        let swarm = SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)?
            .with_behaviour(|_| behaviour)?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(300)))
            .build();

        Ok(SecureBootnode {
            swarm,
            connected_peers: HashMap::new(),
            connections_per_ip: HashMap::new(),
            connection_attempts: HashMap::new(),
            blacklisted_peers: HashSet::new(),
            max_peers,
            max_peers_per_ip: 3,
        })
    }

    pub async fn start(&mut self, port: u16) -> Result<()> {
        // Listen on specified port
        let listen_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", port).parse()?;
        self.swarm.listen_on(listen_addr.clone())?;
        
        info!("🚀 Bootnode starting on port {}", port);
        info!("🔗 Connect using: /ip4/127.0.0.1/tcp/{}", port);
        
        // Main event loop
        let mut maintenance_interval = tokio::time::interval(Duration::from_secs(60));
        
        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => {
                    self.handle_swarm_event(event).await?;
                }
                _ = maintenance_interval.tick() => {
                    self.maintenance().await;
                }
            }
        }
    }

    async fn handle_swarm_event(&mut self, event: SwarmEvent<BootnodeBehaviourEvent>) -> Result<()> {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                info!("🎧 Bootnode listening on: {}", address);
            }
            
            SwarmEvent::ConnectionEstablished { 
                peer_id, 
                endpoint, 
                connection_id, 
                .. 
            } => {
                let remote_addr = endpoint.get_remote_address();
                let ip = self.extract_ip(remote_addr);
                
                info!("🔗 Connection attempt from {} ({}) - ID: {:?}", peer_id, ip, connection_id);
                
                // SECURITY CHECK: Validate new connection
                if self.validate_new_connection(peer_id, ip.clone()) {
                    info!("✅ Accepted connection from: {} ({})", peer_id, ip);
                    self.add_peer(peer_id, ip);
                } else {
                    warn!("❌ Rejected connection from: {} ({})", peer_id, ip);
                    let _ = self.swarm.disconnect_peer_id(peer_id);
                }
            }
            
            SwarmEvent::ConnectionClosed { 
                peer_id, 
                connection_id,
                cause, 
                .. 
            } => {
                info!("👋 Peer disconnected: {} (ID: {:?}, cause: {:?})", peer_id, connection_id, cause);
                self.remove_peer(peer_id);
            }
            
            SwarmEvent::Behaviour(event) => {
                self.handle_behaviour_event(event).await;
            }
            
            _ => {}
        }
        Ok(())
    }

    // SECURITY VALIDATION: Check if connection should be allowed
    fn validate_new_connection(&mut self, peer_id: PeerId, ip: String) -> bool {
        // Check 1: Blacklist
        if self.blacklisted_peers.contains(&peer_id) {
            warn!("🚨 Blacklisted peer attempted connection: {}", peer_id);
            return false;
        }

        // Check 2: Rate limiting
        if !self.check_rate_limit(&ip) {
            warn!("🚨 Rate limit exceeded for IP: {}", ip);
            return false;
        }

        // Check 3: IP connection limit
        if !self.check_ip_limit(&ip) {
            warn!("🚨 Too many connections from IP: {}", ip);
            return false;
        }

        // Check 4: Total capacity
        if self.connected_peers.len() >= self.max_peers {
            warn!("🚨 Bootnode at capacity: {}/{}", self.connected_peers.len(), self.max_peers);
            return false;
        }

        true
    }

    fn check_rate_limit(&mut self, ip: &str) -> bool {
        let ip_addr: IpAddr = match ip.parse() {
            Ok(addr) => addr,
            Err(_) => return false,
        };

        let now = Instant::now();
        let attempts = self.connection_attempts.entry(ip_addr).or_insert_with(Vec::new);
        
        // Remove attempts older than 1 minute
        attempts.retain(|&attempt| now.duration_since(attempt) < Duration::from_secs(60));
        
        // Check if under rate limit (max 10 per minute)
        if attempts.len() >= 10 {
            return false;
        }
        
        attempts.push(now);
        true
    }

    fn check_ip_limit(&self, ip: &str) -> bool {
        let ip_addr: IpAddr = match ip.parse() {
            Ok(addr) => addr,
            Err(_) => return false,
        };

        let current_count = *self.connections_per_ip.get(&ip_addr).unwrap_or(&0);
        current_count < self.max_peers_per_ip
    }

    fn add_peer(&mut self, peer_id: PeerId, ip: String) {
        let ip_addr: IpAddr = ip.parse().unwrap_or("127.0.0.1".parse().unwrap());
        
        let peer_info = PeerInfo {
            peer_id,
            connected_at: Instant::now(),
            ip_address: ip,
            violations: 0,
            reputation: 100, // Start with good reputation
        };
        
        self.connected_peers.insert(peer_id, peer_info);
        *self.connections_per_ip.entry(ip_addr).or_insert(0) += 1;
        
        info!("📊 Bootnode stats: {} peers connected", self.connected_peers.len());
    }

    fn remove_peer(&mut self, peer_id: PeerId) {
        if let Some(peer_info) = self.connected_peers.remove(&peer_id) {
            let ip_addr: IpAddr = peer_info.ip_address.parse()
                .unwrap_or("127.0.0.1".parse().unwrap());
            
            if let Some(count) = self.connections_per_ip.get_mut(&ip_addr) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.connections_per_ip.remove(&ip_addr);
                }
            }
        }
    }

    async fn handle_behaviour_event(&mut self, event: BootnodeBehaviourEvent) {
        match event {
            BootnodeBehaviourEvent::Gossipsub(gossipsub::Event::Message { 
                propagation_source: peer_id, 
                message, 
                .. 
            }) => {
                info!("📨 Received message from {}: {} bytes", peer_id, message.data.len());
                // Validate message content here
                self.validate_peer_message(peer_id, &message.data);
            }
            
            BootnodeBehaviourEvent::Mdns(mdns::Event::Discovered(list)) => {
                for (peer_id, multiaddr) in list {
                    info!("🔍 mDNS discovered: {} at {}", peer_id, multiaddr);
                    self.swarm.behaviour_mut().kademlia.add_address(&peer_id, multiaddr);
                }
            }
            
            BootnodeBehaviourEvent::Identify(identify::Event::Received { 
                peer_id, 
                info,
                connection_id: _,
            }) => {
                info!("🆔 Identified peer {}: {}", peer_id, info.protocol_version);
                
                // Validate protocol version
                if !info.protocol_version.contains("ethereum") {
                    warn!("⚠️  Peer {} has suspicious protocol: {}", peer_id, info.protocol_version);
                    self.flag_suspicious_peer(peer_id);
                }
            }
            
            BootnodeBehaviourEvent::Ping(ping::Event { 
                peer, 
                result,
                connection: _,
            }) => {
                match result {
                    Ok(duration) => {
                        if duration > Duration::from_secs(10) {
                            warn!("⚠️  Slow ping from {}: {:?}", peer, duration);
                        }
                    }
                    Err(failure) => {
                        warn!("❌ Ping failed to {}: {:?}", peer, failure);
                        self.flag_suspicious_peer(peer);
                    }
                }
            }
            
            _ => {}
        }
    }

    fn validate_peer_message(&mut self, peer_id: PeerId, data: &[u8]) {
        // Basic message validation
        if data.len() > 1024 * 1024 { // 1MB limit
            warn!("🚨 Peer {} sent oversized message: {} bytes", peer_id, data.len());
            self.flag_suspicious_peer(peer_id);
            return;
        }

        // Try to parse as JSON (basic validation)
        if serde_json::from_slice::<serde_json::Value>(data).is_err() {
            // Not JSON, could be binary protocol - that's ok
        }

        // Update peer reputation for valid message
        if let Some(peer) = self.connected_peers.get_mut(&peer_id) {
            peer.reputation = (peer.reputation + 1).min(1000);
        }
    }

    fn flag_suspicious_peer(&mut self, peer_id: PeerId) {
        if let Some(peer) = self.connected_peers.get_mut(&peer_id) {
            peer.violations += 1;
            peer.reputation = (peer.reputation - 50).max(-1000);
            
            warn!("🚨 Peer {} flagged: {} violations, reputation {}", 
                  peer_id, peer.violations, peer.reputation);
            
            // Ban peer if too many violations
            if peer.violations >= 5 || peer.reputation <= -500 {
                warn!("🔨 Banning peer {} for repeated violations", peer_id);
                self.blacklisted_peers.insert(peer_id);
                let _ = self.swarm.disconnect_peer_id(peer_id);
            }
        }
    }

    fn extract_ip(&self, multiaddr: &Multiaddr) -> String {
        multiaddr.iter()
            .find_map(|protocol| {
                if let libp2p::multiaddr::Protocol::Ip4(ip) = protocol {
                    Some(ip.to_string())
                } else if let libp2p::multiaddr::Protocol::Ip6(ip) = protocol {
                    Some(ip.to_string())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "unknown".to_string())
    }

    async fn maintenance(&mut self) {
        // Clean up old connection attempts
        let now = Instant::now();
        for attempts in self.connection_attempts.values_mut() {
            attempts.retain(|&attempt| now.duration_since(attempt) < Duration::from_secs(300));
        }

        // Remove empty entries
        self.connection_attempts.retain(|_, attempts| !attempts.is_empty());

        // Log statistics
        info!("📊 Bootnode maintenance:");
        info!("   Connected peers: {}", self.connected_peers.len());
        info!("   Blacklisted peers: {}", self.blacklisted_peers.len());
        info!("   IPs with connections: {}", self.connections_per_ip.len());
        
        // Show top peers by reputation
        let mut sorted_peers: Vec<_> = self.connected_peers.values().collect();
        sorted_peers.sort_by_key(|peer| -peer.reputation);
        
        info!("   Top peers by reputation:");
        for (i, peer) in sorted_peers.iter().take(5).enumerate() {
            info!("     {}. {} (reputation: {})", i+1, peer.peer_id, peer.reputation);
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    // Parse command line arguments
    let matches = Command::new("Ethereum Bootnode")
        .version("1.0.0")
        .about("Secure Ethereum P2P Bootnode")
        .arg(
            Arg::new("port")
                .short('p')
                .long("port")
                .value_name("PORT")
                .help("Port to listen on")
                .default_value("30303"),
        )
        .arg(
            Arg::new("max-peers")
                .long("max-peers")
                .value_name("COUNT")
                .help("Maximum number of peers")
                .default_value("200"),
        )
        .get_matches();

    let port: u16 = matches.get_one::<String>("port").unwrap().parse()?;
    let max_peers: usize = matches.get_one::<String>("max-peers").unwrap().parse()?;

    info!("🚀 Starting Ethereum Bootnode");
    info!("📡 Port: {}", port);
    info!("👥 Max peers: {}", max_peers);

    // Create and start bootnode
    let mut bootnode = SecureBootnode::new(max_peers).await?;
    bootnode.start(port).await?;

    Ok(())
}
