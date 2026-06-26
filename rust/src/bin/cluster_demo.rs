//! Demo de replicacao Raft — 3 nos do HeraclitusDB sincronizando paginas binarias.
//!
//! Cenario:
//!   1. Eleicao de lider.
//!   2. Lider ingere Fatos (via Runner) e replica para os followers.
//!   3. Particao de rede isola um follower enquanto novos Fatos sao commitados.
//!   4. Cura da particao => o follower faz fast-sync e o cluster converge.
//! Ao final, todos os nos tem o mesmo LSN, a mesma raiz Merkle e `verify() == INTEG_OK`.

use std::collections::VecDeque;
use std::fs;

use heraclitus::db::HeraclitusDB;
use heraclitus::raft::{Msg, RaftNode};
use heraclitus::runner::ReconstitutiveRunner;

const ARTIFACT: &str = "../registry/postgresql.hcx";
const SAMPLES: &[&str] = &[
    "2026-06-26 01:20:05.123 UTC [14802] FATAL:  password authentication failed for user \"admin\"",
    "2026-06-26 01:20:06.230 UTC [14803] FATAL:  password authentication failed for user \"bob\"",
    "2026-06-26 01:20:11.500 UTC [14808] admin@prod LOG:  connection authorized: user=admin database=prod",
    "2026-06-26 01:20:12.000 UTC [14808] admin@prod LOG:  statement: SELECT * FROM salaries;",
    "2026-06-26 01:20:13.000 UTC [14809] guest@prod ERROR:  permission denied for table salaries",
];

struct Cluster {
    nodes: Vec<RaftNode>,
    queue: VecDeque<(usize, usize, Msg)>,
    partitioned: Vec<bool>,
}

impl Cluster {
    fn new(n: usize) -> Self {
        let mut nodes = Vec::new();
        for id in 0..n {
            let path = format!("node{id}.hdb");
            let _ = fs::remove_file(&path);
            let _ = fs::remove_file(format!("{path}.anchor"));
            let peers = (0..n).filter(|&p| p != id).collect();
            nodes.push(RaftNode::new(id, peers, HeraclitusDB::new(&path).unwrap()));
        }
        Self { nodes, queue: VecDeque::new(), partitioned: vec![false; n] }
    }

    fn round(&mut self) {
        for i in 0..self.nodes.len() {
            let outs = self.nodes[i].tick();
            for (to, msg) in outs {
                self.queue.push_back((i, to, msg));
            }
        }
        let mut budget = 50_000;
        while let Some((from, to, msg)) = self.queue.pop_front() {
            budget -= 1;
            if budget == 0 {
                break;
            }
            if self.partitioned[from] || self.partitioned[to] {
                continue; // mensagem perdida na particao
            }
            let outs = self.nodes[to].handle(from, msg);
            for (t, m) in outs {
                self.queue.push_back((to, t, m));
            }
        }
    }

    fn run(&mut self, rounds: usize) {
        for _ in 0..rounds {
            self.round();
        }
    }

    fn leader_id(&self) -> Option<usize> {
        self.nodes.iter().position(|n| n.is_leader())
    }

    fn submit(&mut self, fact: &mut serde_json::Value) {
        let lid = self.leader_id().expect("sem lider");
        let (lsn, root, block) = self.nodes[lid].db.commit_local(fact).unwrap();
        self.nodes[lid].client_commit(lsn, root, block);
    }

    fn report(&self, titulo: &str) {
        println!("\n--- {titulo} ---");
        for n in &self.nodes {
            let v = n.db.verify();
            let root = n.db.trusted_root.clone();
            let root_short = if root.len() >= 12 { &root[..12] } else { &root };
            let part = if self.partitioned[n.id] { " [PARTICIONADO]" } else { "" };
            println!(
                "  node{} {:<9} term={} LSN={} root={}… verify={}{}",
                n.id, n.role_name(), n.term, n.db.current_lsn, root_short, v.status, part
            );
        }
    }
}

fn main() {
    println!("{}", "#".repeat(68));
    println!("#  HERACLITUS (Rust) — REPLICACAO RAFT (LSN + Previous_Merkle_Root)");
    println!("{}", "#".repeat(68));

    let mut runner = ReconstitutiveRunner::load(ARTIFACT).expect("carregar artefato .hcx");
    let mut cluster = Cluster::new(3);

    // 1. Eleicao
    let mut elected = false;
    for _ in 0..60 {
        cluster.round();
        if cluster.leader_id().is_some() {
            elected = true;
            break;
        }
    }
    assert!(elected, "nenhum lider eleito");
    println!("\n[1] Eleicao: node{} eleito LIDER (term {})",
             cluster.leader_id().unwrap(), cluster.nodes[cluster.leader_id().unwrap()].term);

    // 2. Ingestao + replicacao normal
    for line in SAMPLES {
        let mut f = runner.process_observation(line).unwrap();
        cluster.submit(&mut f);
    }
    cluster.run(8);
    cluster.report("[2] Replicacao normal (5 Fatos)");

    // 3. Particao: isola node2 e commita mais Fatos
    println!("\n[3] Particao de rede: node2 isolado; lider commita mais 4 Fatos...");
    cluster.partitioned[2] = true;
    for i in 0..4 {
        let mut f = runner.process_observation(SAMPLES[i % SAMPLES.len()]).unwrap();
        cluster.submit(&mut f);
    }
    cluster.run(6);
    cluster.report("[3] Durante a particao (node2 fica para tras)");

    // 4. Cura da particao => fast-sync
    println!("\n[4] Particao curada: node2 entra em fast-sync (block stream)...");
    cluster.partitioned[2] = false;
    cluster.run(12);
    cluster.report("[4] Apos fast-sync (convergencia)");

    // Verificacao final de convergencia
    let roots: Vec<String> = cluster.nodes.iter().map(|n| n.db.trusted_root.clone()).collect();
    let lsns: Vec<u64> = cluster.nodes.iter().map(|n| n.db.current_lsn).collect();
    let converged = roots.iter().all(|r| r == &roots[0]) && lsns.iter().all(|l| l == &lsns[0]);
    let all_ok = cluster.nodes.iter().all(|n| n.db.verify().status == "INTEG_OK");

    println!("\n{}", "#".repeat(68));
    if converged && all_ok {
        println!("#  CONVERGENCIA OK — todos os nos no LSN {} com raiz {}…",
                 lsns[0], &roots[0][..16]);
        println!("#  Alta disponibilidade garantida: replicas identicas e integras.");
    } else {
        println!("#  FALHA: convergencia={converged} integridade={all_ok}");
    }
    println!("{}", "#".repeat(68));

    for id in 0..cluster.nodes.len() {
        let _ = fs::remove_file(format!("node{id}.hdb"));
        let _ = fs::remove_file(format!("node{id}.hdb.anchor"));
    }
    std::process::exit(if converged && all_ok { 0 } else { 1 });
}
