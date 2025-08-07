use futures::StreamExt;
use libp2p::{
    identity, noise, ping, swarm::SwarmEvent, tcp, yamux, Multiaddr, PeerId, SwarmBuilder,
};
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();

    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());
    println!("🆔 Test Client Peer ID: {}", local_peer_id);

    let mut swarm = SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|_| ping::Behaviour::new(ping::Config::new()))?
        .build();

    let bootnode: Multiaddr = "/ip4/127.0.0.1/tcp/30303".parse()?;
    swarm.dial(bootnode)?;

    println!("🔗 Connecting to bootnode...");
    println!("🔄 Will maintain stable connection");
    println!("📝 Press Ctrl+C to disconnect");

    let mut connected = false;
    let mut connection_stable = false;

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                if !connected {
                    println!("✅ Connected to bootnode: {}", peer_id);
                    println!("🎉 Connection established - staying connected!");
                    connected = true;
                    connection_stable = true;
                }
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                if connected {
                    println!("👋 Connection lost to: {}", peer_id);
                    println!("⚠️ Connection dropped - will try to reconnect once...");
                    connected = false;
                    connection_stable = false;

                    // Wait a bit before reconnecting (avoid rate limiting)
                    tokio::time::sleep(Duration::from_secs(5)).await;

                    // Try to reconnect ONCE
                    let bootnode: Multiaddr = "/ip4/127.0.0.1/tcp/30303".parse()?;
                    if let Err(e) = swarm.dial(bootnode) {
                        println!("❌ Reconnection attempt failed: {}", e);
                        println!("🛑 Stopping client - manual restart required");
                        break;
                    }
                }
            }
            SwarmEvent::Behaviour(ping::Event {
                peer,
                result,
                connection: _,
            }) => {
                if connection_stable {
                    match result {
                        Ok(duration) => {
                            println!("🏓 Ping to {}: {:?}", peer, duration);
                        }
                        Err(e) => {
                            println!("❌ Ping failed to {}: {:?}", peer, e);
                        }
                    }
                }
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                println!("❌ Failed to connect to {:?}: {}", peer_id, error);
                println!("🛑 Stopping client - check bootnode is running");
                break;
            }
            _ => {}
        }
    }

    Ok(())
}
