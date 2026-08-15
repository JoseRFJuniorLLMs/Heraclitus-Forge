//! Wire Protocol TCP do Raft (spec §8) — Marco C.2.
//!
//! O MESMO state machine `Msg`/`RaftNode` da simulação por ticks, agora sobre
//! **TCP real**: cada nó tem um listener; as mensagens são enquadradas
//! (`u32` LE de comprimento + JSON de `(versão, from_id, Msg)`); o relógio lógico
//! do Raft é dirigido por um `tokio::time::interval`. Ligação por mensagem
//! (best-effort — se o peer estiver em baixo, o próximo heartbeat/eleição
//! reenvia; pool de ligações fica como otimização futura, como no `net.rs` do
//! HeraclitusDB).
//!
//! As propriedades de segurança (voto durável, Figura-8) vivem no `RaftNode` e
//! são idênticas na simulação e aqui — este módulo só transporta os `Msg`.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::raft::{Msg, RaftNode};

/// Teto de um frame (recusa antes de alocar do fio — um comprimento corrompido
/// não pode pedir GiBs). Um bloco de Fato é minúsculo; 16 MiB sobra.
const MAX_FRAME: usize = 16 * 1024 * 1024;
const WIRE_VERSION: u16 = 1;

async fn write_frame(sock: &mut TcpStream, bytes: &[u8]) -> std::io::Result<()> {
    sock.write_all(&(bytes.len() as u32).to_le_bytes()).await?;
    sock.write_all(bytes).await?;
    sock.flush().await
}

async fn read_frame(sock: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    sock.read_exact(&mut len).await?;
    let n = u32::from_le_bytes(len) as usize;
    if n > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("frame de {n} bytes excede o teto {MAX_FRAME}"),
        ));
    }
    let mut buf = vec![0u8; n];
    sock.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Liga a um peer, envia um frame e fecha. Best-effort: um peer em baixo ou uma
/// ligação recusada não é erro fatal (o Raft reenvia no próximo tick).
async fn send_msg(addr: SocketAddr, from: usize, msg: Msg) {
    let bytes = match serde_json::to_vec(&(WIRE_VERSION, from as u32, msg)) {
        Ok(b) => b,
        Err(_) => return,
    };
    if let Ok(mut sock) = TcpStream::connect(addr).await {
        let _ = write_frame(&mut sock, &bytes).await;
    }
}

/// Despacha as mensagens de saída do state machine para os endereços dos peers.
fn dispatch(outs: Vec<(usize, Msg)>, from: usize, addrs: &Arc<Vec<SocketAddr>>) {
    for (target, msg) in outs {
        if let Some(&addr) = addrs.get(target) {
            tokio::spawn(async move { send_msg(addr, from, msg).await });
        }
    }
}

/// Corre um nó Raft sobre TCP: um listener (entrega cada `Msg` ao state machine
/// e despacha a resposta) + um relógio (tick → possível eleição/heartbeat).
/// `addrs[i]` é o endereço do nó `i`. Devolve o handle da task do relógio; a
/// task do listener corre em background até a runtime terminar.
pub fn serve(
    node: Arc<Mutex<RaftNode>>,
    listener: TcpListener,
    addrs: Vec<SocketAddr>,
    tick_period: Duration,
) -> std::io::Result<tokio::task::JoinHandle<()>> {
    let local = listener.local_addr()?;
    if !local.ip().is_loopback() || addrs.iter().any(|addr| !addr.ip().is_loopback()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "wire Raft do Forge não possui mTLS e é restrito a loopback",
        ));
    }
    let addrs = Arc::new(addrs);
    let id = node.lock().unwrap().id;

    // Listener: uma task por ligação; cada frame (from, Msg) → handle → dispatch.
    {
        let node = node.clone();
        let addrs = addrs.clone();
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => continue, // erro transitório de accept não mata o nó
                };
                let node = node.clone();
                let addrs = addrs.clone();
                tokio::spawn(async move {
                    while let Ok(bytes) = read_frame(&mut sock).await {
                        if let Ok((WIRE_VERSION, from, msg)) =
                            serde_json::from_slice::<(u16, u32, Msg)>(&bytes)
                        {
                            // Secção crítica curta e SÍNCRONA (o `handle` não tem
                            // `.await`); o lock é libertado antes de qualquer envio.
                            let outs = { node.lock().unwrap().handle(from as usize, msg) };
                            dispatch(outs, id, &addrs);
                        }
                    }
                });
            }
        });
    }

    // Relógio lógico: tick periódico → eleição/heartbeat conforme o papel.
    Ok(tokio::spawn(async move {
        let mut tick = tokio::time::interval(tick_period);
        loop {
            tick.tick().await;
            let outs = { node.lock().unwrap().tick() };
            dispatch(outs, id, &addrs);
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::HeraclitusDB;
    use crate::raft::BASE_LSN;
    use serde_json::{json, Value};
    use std::sync::atomic::{AtomicU64, Ordering};

    static CTR: AtomicU64 = AtomicU64::new(0);

    fn fresh_path() -> String {
        let n = CTR.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("forge_wire_{}_{}.hdb", std::process::id(), n));
        let s = p.to_str().unwrap().to_string();
        for ext in [
            "",
            ".anchor",
            ".anchor.sig",
            ".key",
            ".pub",
            ".raftmeta",
            ".raftlog",
        ] {
            let _ = std::fs::remove_file(format!("{s}{ext}"));
        }
        s
    }

    fn fact(action: &str) -> Value {
        json!({
            "fact_id": "019f035c-1823-7fe9-8c54-02b2d1acc30c",
            "fact.identity": {"actor.id":"a","actor.name":"a","target.id":"t","source.ip":null},
            "fact.time": {"system_timestamp": 1_782_467_794_979_937i64, "log_sequence_number": 0u64},
            "fact.behavior": {"class":"c","action":action,"risk_level":"Medium"},
            "fact.evidence": {"raw_observation_hash":"b3:abcd","carimbo_tempo_legal":"icp"},
            "fact.lineage": {"transformation_steps":["parse"],"input_source":"pg","matched_rule":"r"},
            "fact.confidence": 0.9,
            "fact.knowledge_version":"k","fact.reasoning_version":"r","fact.ontology_version":"v9"
        })
    }

    async fn wait_leader(nodes: &[Arc<Mutex<RaftNode>>], tries: usize) -> Option<usize> {
        for _ in 0..tries {
            for (i, n) in nodes.iter().enumerate() {
                if n.lock().unwrap().is_leader() {
                    return Some(i);
                }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        None
    }

    /// Marco C.2: 3 nós REAIS sobre TCP (localhost) elegem um líder, replicam
    /// Fatos e cada um verifica íntegro. Prova que o mesmo state machine que a
    /// simulação por ticks corre sobre a rede.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn tcp_cluster_elects_and_replicates() {
        // Liga 3 listeners em portas efémeras e descobre os endereços.
        let mut listeners = Vec::new();
        let mut addrs = Vec::new();
        for _ in 0..3 {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            addrs.push(l.local_addr().unwrap());
            listeners.push(l);
        }

        let nodes: Vec<Arc<Mutex<RaftNode>>> = (0..3)
            .map(|i| {
                let peers: Vec<usize> = (0..3).filter(|&j| j != i).collect();
                let db = HeraclitusDB::new(&fresh_path()).unwrap();
                Arc::new(Mutex::new(RaftNode::new(i, peers, db)))
            })
            .collect();

        let mut handles = Vec::new();
        for (i, l) in listeners.into_iter().enumerate() {
            handles.push(
                serve(
                    nodes[i].clone(),
                    l,
                    addrs.clone(),
                    Duration::from_millis(25),
                )
                .unwrap(),
            );
        }

        let leader = wait_leader(&nodes, 240)
            .await
            .expect("nenhum líder eleito sobre TCP");

        // O líder ingere 3 Fatos (durável local) e regista-os no log Raft.
        {
            let mut n = nodes[leader].lock().unwrap();
            for k in 0..3 {
                let mut f = fact(&format!("a{k}"));
                let (lsn, root, block) = n.db.commit_local(&mut f).unwrap();
                n.client_commit(lsn, root, block);
            }
        }

        // Deixa os heartbeats replicarem.
        tokio::time::sleep(Duration::from_millis(2000)).await;

        let l_lsn = nodes[leader].lock().unwrap().last_lsn();
        assert_eq!(l_lsn, BASE_LSN + 3, "líder não gravou os 3 Fatos");
        for (i, node) in nodes.iter().enumerate().take(3) {
            let n = node.lock().unwrap();
            assert_eq!(n.last_lsn(), l_lsn, "nó {i} não convergiu sobre TCP");
            assert_eq!(n.db.verify().status, "INTEG_OK", "nó {i} não íntegro");
        }

        for h in handles {
            h.abort();
        }
    }
}
