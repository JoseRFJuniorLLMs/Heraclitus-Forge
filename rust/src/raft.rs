//! Replicacao Raft orientada a LSN (spec secao 11).
//!
//! Raft modificado para logs imutaveis append-only: a ordem global e o **LSN** e cada
//! `AppendEntries` carrega o `Previous_Merkle_Root`. O follower so aceita um bloco se
//! `Last_LSN == Current_LSN - 1` e se a raiz da cadeia Merkle local bater — caso
//! contrario rejeita e o lider faz *fast-sync* (backtracking do log) reenviando os
//! blocos a partir do ultimo ponto de integridade comum.
//!
//! Os nos sao dirigidos por ticks (simulacao determinística, sem rede real). Em
//! producao os mesmos `Msg` viajam pelo Wire Protocol TCP da spec (secao 8).

use std::collections::HashMap;

use crate::db::HeraclitusDB;

pub const BASE_LSN: u64 = 14_812_337;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Role {
    Follower,
    Candidate,
    Leader,
}

#[derive(Clone)]
pub struct LogEntry {
    pub term: u64,
    pub lsn: u64,
    pub merkle_root: String,
    pub block: Vec<u8>,
}

#[derive(Clone)]
pub enum Msg {
    RequestVote { term: u64, candidate: usize, last_lsn: u64, last_term: u64 },
    RequestVoteResp { term: u64, granted: bool },
    AppendEntries {
        term: u64,
        leader: usize,
        prev_lsn: u64,
        prev_root: String,
        entries: Vec<LogEntry>,
        leader_commit: u64,
    },
    AppendEntriesResp { term: u64, success: bool, match_lsn: u64, need_from: u64 },
}

pub struct RaftNode {
    pub id: usize,
    pub role: Role,
    pub term: u64,
    voted_for: Option<usize>,
    pub leader: Option<usize>,
    pub log: Vec<LogEntry>,
    pub commit_lsn: u64,
    pub db: HeraclitusDB,

    peers: Vec<usize>,
    votes: usize,
    election_elapsed: u32,
    election_timeout: u32,
    heartbeat_elapsed: u32,
    heartbeat_timeout: u32,

    next_index: HashMap<usize, u64>,
    match_index: HashMap<usize, u64>,

    // Marco C: estado de consenso DURÁVEL (à la meta.bin do HeraclitusDB).
    meta_path: String, // `<db>.raftmeta` — (currentTerm, votedFor)
    log_path: String,  // `<db>.raftlog`  — entradas do log Raft (term|lsn|root|block)
}

/// Carrega `(currentTerm, votedFor)` do sidecar durável. Sem ficheiro ⇒ estado
/// inicial. É o que impede um nó de votar DUAS VEZES no mesmo termo através de
/// um restart (segurança fundamental do Raft — sem isto há split-brain).
fn load_meta(path: &str) -> (u64, Option<usize>) {
    if let Ok(s) = std::fs::read_to_string(path) {
        let mut it = s.split_whitespace();
        let term = it.next().and_then(|x| x.parse().ok()).unwrap_or(0);
        let vf = it.next().and_then(|x| x.parse::<i64>().ok()).unwrap_or(-1);
        return (term, if vf < 0 { None } else { Some(vf as usize) });
    }
    (0, None)
}

/// Reconstrói o log Raft do sidecar durável. Cauda torn (crash a meio de um
/// append) para o replay — o registo incompleto é descartado.
fn replay_log(path: &str) -> Vec<LogEntry> {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    let mut p = 0usize;
    loop {
        if p + 20 > data.len() {
            break; // header mínimo (term8 + lsn8 + rootlen4) não cabe
        }
        let term = u64::from_le_bytes(data[p..p + 8].try_into().unwrap());
        let lsn = u64::from_le_bytes(data[p + 8..p + 16].try_into().unwrap());
        let rlen = u32::from_le_bytes(data[p + 16..p + 20].try_into().unwrap()) as usize;
        p += 20;
        if p + rlen + 4 > data.len() {
            break;
        }
        let root = String::from_utf8_lossy(&data[p..p + rlen]).into_owned();
        p += rlen;
        let blen = u32::from_le_bytes(data[p..p + 4].try_into().unwrap()) as usize;
        p += 4;
        if p + blen > data.len() {
            break;
        }
        let block = data[p..p + blen].to_vec();
        p += blen;
        out.push(LogEntry { term, lsn, merkle_root: root, block });
    }
    out
}

impl RaftNode {
    pub fn new(id: usize, peers: Vec<usize>, db: HeraclitusDB) -> Self {
        let meta_path = format!("{}.raftmeta", db.db_path);
        let log_path = format!("{}.raftlog", db.db_path);
        let (term, voted_for) = load_meta(&meta_path);
        let log = replay_log(&log_path);
        let commit_lsn = log.last().map(|e| e.lsn).unwrap_or(BASE_LSN);
        Self {
            id,
            role: Role::Follower,
            term,
            voted_for,
            leader: None,
            log,
            commit_lsn,
            db,
            peers,
            votes: 0,
            election_elapsed: 0,
            // timeouts distintos e determinísticos => eleicao reprodutivel (no 0 vence)
            election_timeout: 8 + id as u32 * 5,
            heartbeat_elapsed: 0,
            heartbeat_timeout: 3,
            next_index: HashMap::new(),
            match_index: HashMap::new(),
            meta_path,
            log_path,
        }
    }

    /// Persiste `(currentTerm, votedFor)` ANTES de responder a votos/eleições.
    fn persist_meta(&self) {
        let vf = self.voted_for.map(|v| v as i64).unwrap_or(-1);
        let _ = std::fs::write(&self.meta_path, format!("{} {}\n", self.term, vf));
    }

    /// Acrescenta uma entrada ao log Raft durável (append-only).
    fn append_log_record(&self, e: &LogEntry) {
        use std::io::Write as _;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&self.log_path) {
            let mut buf = Vec::with_capacity(24 + e.merkle_root.len() + e.block.len());
            buf.extend_from_slice(&e.term.to_le_bytes());
            buf.extend_from_slice(&e.lsn.to_le_bytes());
            buf.extend_from_slice(&(e.merkle_root.len() as u32).to_le_bytes());
            buf.extend_from_slice(e.merkle_root.as_bytes());
            buf.extend_from_slice(&(e.block.len() as u32).to_le_bytes());
            buf.extend_from_slice(&e.block);
            let _ = f.write_all(&buf);
            let _ = f.sync_all();
        }
    }

    // -- visao do log ------------------------------------------------------

    pub fn last_lsn(&self) -> u64 {
        self.log.last().map(|e| e.lsn).unwrap_or(BASE_LSN)
    }
    pub fn last_root(&self) -> String {
        self.log.last().map(|e| e.merkle_root.clone()).unwrap_or_default()
    }
    fn last_term(&self) -> u64 {
        self.log.last().map(|e| e.term).unwrap_or(0)
    }
    fn root_at(&self, lsn: u64) -> String {
        if lsn <= BASE_LSN {
            String::new()
        } else {
            self.log
                .get((lsn - BASE_LSN - 1) as usize)
                .map(|e| e.merkle_root.clone())
                .unwrap_or_default()
        }
    }
    pub fn is_leader(&self) -> bool {
        self.role == Role::Leader
    }
    fn majority(&self) -> usize {
        (self.peers.len() + 1) / 2 + 1
    }

    // -- cliente: lider ingere um Fato ja serializado em bloco -------------

    pub fn client_commit(&mut self, lsn: u64, root: String, block: Vec<u8>) {
        // O lider ja persistiu via db.commit_local; aqui registra no log Raft
        // (RAM + sidecar durável).
        let entry = LogEntry { term: self.term, lsn, merkle_root: root, block };
        self.append_log_record(&entry);
        self.log.push(entry);
    }

    // -- tick (relogio logico) --------------------------------------------

    pub fn tick(&mut self) -> Vec<(usize, Msg)> {
        match self.role {
            Role::Leader => {
                self.heartbeat_elapsed += 1;
                if self.heartbeat_elapsed >= self.heartbeat_timeout {
                    self.heartbeat_elapsed = 0;
                    return self.broadcast_append();
                }
                Vec::new()
            }
            _ => {
                self.election_elapsed += 1;
                if self.election_elapsed >= self.election_timeout {
                    self.start_election()
                } else {
                    Vec::new()
                }
            }
        }
    }

    fn start_election(&mut self) -> Vec<(usize, Msg)> {
        self.role = Role::Candidate;
        self.term += 1;
        self.voted_for = Some(self.id);
        self.votes = 1;
        self.election_elapsed = 0;
        self.persist_meta(); // novo termo + auto-voto duráveis antes de pedir votos
        let msg = Msg::RequestVote {
            term: self.term,
            candidate: self.id,
            last_lsn: self.last_lsn(),
            last_term: self.last_term(),
        };
        self.peers.iter().map(|&p| (p, msg.clone())).collect()
    }

    fn become_leader(&mut self) -> Vec<(usize, Msg)> {
        self.role = Role::Leader;
        self.leader = Some(self.id);
        let ni = self.last_lsn() + 1;
        for &p in &self.peers {
            self.next_index.insert(p, ni);
            self.match_index.insert(p, BASE_LSN);
        }
        self.heartbeat_elapsed = 0;
        self.broadcast_append()
    }

    fn become_follower(&mut self, term: u64) {
        self.role = Role::Follower;
        self.term = term;
        self.voted_for = None;
        self.votes = 0;
        self.election_elapsed = 0;
        self.persist_meta(); // novo termo + voto limpo duráveis
    }

    fn broadcast_append(&self) -> Vec<(usize, Msg)> {
        self.peers.iter().map(|&p| (p, self.append_for(p))).collect()
    }

    fn append_for(&self, peer: usize) -> Msg {
        let ni = *self.next_index.get(&peer).unwrap_or(&(self.last_lsn() + 1));
        let prev_lsn = ni - 1;
        let start = (ni - BASE_LSN - 1) as usize;
        let entries = if start < self.log.len() { self.log[start..].to_vec() } else { Vec::new() };
        Msg::AppendEntries {
            term: self.term,
            leader: self.id,
            prev_lsn,
            prev_root: self.root_at(prev_lsn),
            entries,
            leader_commit: self.commit_lsn,
        }
    }

    // -- recebimento de mensagens -----------------------------------------

    pub fn handle(&mut self, from: usize, msg: Msg) -> Vec<(usize, Msg)> {
        match msg {
            Msg::RequestVote { term, candidate, last_lsn, last_term } => {
                if term > self.term {
                    self.become_follower(term);
                }
                let up_to_date = (last_term, last_lsn) >= (self.last_term(), self.last_lsn());
                let granted = term >= self.term
                    && (self.voted_for.is_none() || self.voted_for == Some(candidate))
                    && up_to_date;
                if granted {
                    self.voted_for = Some(candidate);
                    self.election_elapsed = 0;
                    self.persist_meta(); // voto DURÁVEL antes de o conceder (§5.4 Raft)
                }
                vec![(from, Msg::RequestVoteResp { term: self.term, granted })]
            }

            Msg::RequestVoteResp { term, granted } => {
                if term > self.term {
                    self.become_follower(term);
                    return Vec::new();
                }
                if self.role == Role::Candidate && granted {
                    self.votes += 1;
                    if self.votes >= self.majority() {
                        return self.become_leader();
                    }
                }
                Vec::new()
            }

            Msg::AppendEntries { term, leader, prev_lsn, prev_root, entries, leader_commit } => {
                if term < self.term {
                    return vec![(from, Msg::AppendEntriesResp {
                        term: self.term, success: false,
                        match_lsn: self.last_lsn(), need_from: self.last_lsn() + 1,
                    })];
                }
                // Passa a follower reconhecendo o líder. CRÍTICO: só apagar
                // `voted_for` quando o TERMO avança. O `become_follower`
                // incondicional apagava o voto a cada AppendEntries do mesmo
                // termo — um nó que já votara em A no termo T voltava a poder
                // votar em B no mesmo T (dois líderes ⇒ split-brain).
                if term > self.term {
                    self.become_follower(term);
                } else {
                    self.role = Role::Follower;
                    self.votes = 0;
                    self.election_elapsed = 0;
                }
                self.leader = Some(leader);

                // Validacao do follower (spec secao 11, passo 2)
                if prev_lsn == self.last_lsn() && prev_root == self.last_root() {
                    for e in entries {
                        match self.db.append_replicated_block(&e.block) {
                            Ok(_) => {
                                self.append_log_record(&e); // log Raft durável
                                self.log.push(e);
                            }
                            Err(_) => {
                                // Integridade quebrada: rejeita para forcar re-sync
                                return vec![(from, Msg::AppendEntriesResp {
                                    term: self.term, success: false,
                                    match_lsn: self.last_lsn(), need_from: self.last_lsn() + 1,
                                })];
                            }
                        }
                    }
                    self.commit_lsn = leader_commit.min(self.last_lsn());
                    vec![(from, Msg::AppendEntriesResp {
                        term: self.term, success: true,
                        match_lsn: self.last_lsn(), need_from: 0,
                    })]
                } else {
                    // Inconsistencia => pede fast-sync a partir do ultimo ponto comum
                    vec![(from, Msg::AppendEntriesResp {
                        term: self.term, success: false,
                        match_lsn: self.last_lsn(), need_from: self.last_lsn() + 1,
                    })]
                }
            }

            Msg::AppendEntriesResp { term, success, match_lsn, need_from } => {
                if term > self.term {
                    self.become_follower(term);
                    return Vec::new();
                }
                if !self.is_leader() {
                    return Vec::new();
                }
                if success {
                    self.next_index.insert(from, match_lsn + 1);
                    self.match_index.insert(from, match_lsn);
                    self.advance_commit();
                    Vec::new()
                } else {
                    // fast-sync: retrocede e reenvia imediatamente
                    self.next_index.insert(from, need_from.max(BASE_LSN + 1));
                    vec![(from, self.append_for(from))]
                }
            }
        }
    }

    fn advance_commit(&mut self) {
        let mut matches: Vec<u64> = self.match_index.values().copied().collect();
        matches.push(self.last_lsn()); // o proprio lider
        matches.sort_unstable_by(|a, b| b.cmp(a));
        let candidate = matches[self.majority() - 1];
        // REGRA DE FIGURA-8 (Raft §5.4.2): um líder só compromete DIRETAMENTE um
        // índice replicado em maioria se a entrada nesse índice for do termo
        // CORRENTE. Entradas de termos anteriores comprometem-se indiretamente,
        // quando uma entrada do termo corrente acima delas commita — nunca só
        // por contagem de réplicas (senão uma entrada já replicada mas ainda
        // sobreponível seria dada como committed e depois perdida).
        let cand_term = if candidate <= BASE_LSN {
            Some(0)
        } else {
            self.log.get((candidate - BASE_LSN - 1) as usize).map(|e| e.term)
        };
        if candidate > self.commit_lsn && cand_term == Some(self.term) {
            self.commit_lsn = candidate;
        }
    }

    pub fn role_name(&self) -> &'static str {
        match self.role {
            Role::Follower => "Follower",
            Role::Candidate => "Candidate",
            Role::Leader => "Leader",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::HeraclitusDB;
    use serde_json::{json, Value};
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicU64, Ordering};

    static CTR: AtomicU64 = AtomicU64::new(0);

    fn fresh_path() -> String {
        let n = CTR.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("forge_raft_{}_{}.hdb", std::process::id(), n));
        let s = p.to_str().unwrap().to_string();
        for ext in ["", ".anchor", ".anchor.sig", ".key", ".pub", ".raftmeta", ".raftlog"] {
            let _ = std::fs::remove_file(format!("{s}{ext}"));
        }
        s
    }

    fn tmp_db() -> HeraclitusDB {
        HeraclitusDB::new(&fresh_path()).unwrap()
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

    /// Entrega toda a fila de mensagens até quiescência (guard anti-loop).
    fn drain(nodes: &mut [RaftNode], mut q: VecDeque<(usize, usize, Msg)>) {
        let mut guard = 0;
        while let Some((from, to, msg)) = q.pop_front() {
            for (t, m) in nodes[to].handle(from, msg) {
                q.push_back((to, t, m));
            }
            guard += 1;
            assert!(guard < 100_000, "loop de mensagens Raft não convergiu");
        }
    }

    /// Um "tick" global: relógio lógico avança em todos os nós; entrega tudo.
    fn tick_round(nodes: &mut [RaftNode]) {
        let mut q = VecDeque::new();
        for i in 0..nodes.len() {
            for (t, m) in nodes[i].tick() {
                q.push_back((i, t, m));
            }
        }
        drain(nodes, q);
    }

    fn cluster(n: usize) -> Vec<RaftNode> {
        (0..n)
            .map(|i| {
                let peers: Vec<usize> = (0..n).filter(|&j| j != i).collect();
                RaftNode::new(i, peers, tmp_db())
            })
            .collect()
    }

    #[test]
    fn three_nodes_converge_and_each_verifies() {
        let mut nodes = cluster(3);

        // Elege um líder.
        let mut leader = None;
        for _ in 0..120 {
            tick_round(&mut nodes);
            if let Some(l) = (0..3).find(|&i| nodes[i].is_leader()) {
                leader = Some(l);
                break;
            }
        }
        let l = leader.expect("nenhum líder eleito");

        // Líder ingere 5 Fatos e replica.
        for i in 0..5 {
            let mut f = fact(&format!("a{i}"));
            let (lsn, root, block) = nodes[l].db.commit_local(&mut f).unwrap();
            nodes[l].client_commit(lsn, root, block);
            for _ in 0..12 {
                tick_round(&mut nodes);
            }
        }

        // Todos convergem: mesmo LSN, mesma raiz Merkle, e verify() íntegro em cada.
        let lsn0 = nodes[l].last_lsn();
        let root0 = nodes[l].last_root();
        assert_eq!(lsn0, BASE_LSN + 5, "líder não gravou os 5 Fatos");
        for i in 0..3 {
            assert_eq!(nodes[i].last_lsn(), lsn0, "nó {i} não convergiu no LSN");
            assert_eq!(nodes[i].last_root(), root0, "nó {i} não convergiu na raiz");
            assert_eq!(nodes[i].db.verify().status, "INTEG_OK", "nó {i} não íntegro");
        }
    }

    #[test]
    fn no_double_vote_in_same_term() {
        // Regressão do split-brain: depois de votar em 1 no termo T e receber
        // AppendEntries do líder 1 (mesmo T), um RequestVote de 2 no MESMO T
        // TEM de ser recusado. Antes do fix, o become_follower do AppendEntries
        // apagava voted_for e o voto duplo passava.
        let mut n = RaftNode::new(0, vec![1, 2], tmp_db());

        n.handle(1, Msg::RequestVote { term: 5, candidate: 1, last_lsn: BASE_LSN, last_term: 0 });
        n.handle(1, Msg::AppendEntries {
            term: 5, leader: 1, prev_lsn: BASE_LSN, prev_root: String::new(),
            entries: vec![], leader_commit: BASE_LSN,
        });
        let resp = n.handle(2, Msg::RequestVote { term: 5, candidate: 2, last_lsn: BASE_LSN, last_term: 0 });

        match resp.first().map(|(_, m)| m) {
            Some(Msg::RequestVoteResp { granted, .. }) => {
                assert!(!granted, "voto duplo no mesmo termo — split-brain");
            }
            other => panic!("resposta inesperada: {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn higher_term_request_vote_is_granted_after_stepping_down() {
        // Complemento: um termo MAIOR reabre o voto (não é split-brain — é a
        // progressão normal do Raft).
        let mut n = RaftNode::new(0, vec![1, 2], tmp_db());
        n.handle(1, Msg::RequestVote { term: 5, candidate: 1, last_lsn: BASE_LSN, last_term: 0 });
        let resp = n.handle(2, Msg::RequestVote { term: 6, candidate: 2, last_lsn: BASE_LSN, last_term: 0 });
        match resp.first().map(|(_, m)| m) {
            Some(Msg::RequestVoteResp { granted, .. }) => assert!(granted, "termo maior devia reabrir o voto"),
            other => panic!("resposta inesperada: {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn vote_survives_restart() {
        // Marco C: o voto é DURÁVEL. Um nó vota em 1 no termo 5, "reinicia"
        // (novo RaftNode reabrindo o mesmo caminho) e recusa votar em 2 no MESMO
        // termo 5. Sem persistir votedFor, o restart re-votaria ⇒ split-brain.
        let path = fresh_path();
        {
            let db = HeraclitusDB::new(&path).unwrap();
            let mut n = RaftNode::new(0, vec![1, 2], db);
            n.handle(1, Msg::RequestVote { term: 5, candidate: 1, last_lsn: BASE_LSN, last_term: 0 });
        }
        // Restart: reabre o mesmo banco/estado.
        let db = HeraclitusDB::new(&path).unwrap();
        let mut n = RaftNode::new(0, vec![1, 2], db);
        assert_eq!(n.term, 5, "currentTerm não sobreviveu ao restart");
        let resp = n.handle(2, Msg::RequestVote { term: 5, candidate: 2, last_lsn: BASE_LSN, last_term: 0 });
        match resp.first().map(|(_, m)| m) {
            Some(Msg::RequestVoteResp { granted, .. }) => {
                assert!(!granted, "voto duplo no mesmo termo após restart — split-brain");
            }
            other => panic!("resposta inesperada: {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn raft_log_survives_restart() {
        // Marco C: o log Raft (com termos) é durável. Após replicar/registar
        // entradas, um restart recupera last_lsn e last_term.
        let path = fresh_path();
        {
            let db = HeraclitusDB::new(&path).unwrap();
            let mut n = RaftNode::new(0, vec![1, 2], db);
            n.term = 3;
            for i in 0..3 {
                let mut f = fact(&format!("a{i}"));
                let (lsn, root, block) = n.db.commit_local(&mut f).unwrap();
                n.client_commit(lsn, root, block);
            }
            assert_eq!(n.last_lsn(), BASE_LSN + 3);
        }
        let db = HeraclitusDB::new(&path).unwrap();
        let n = RaftNode::new(0, vec![1, 2], db);
        assert_eq!(n.last_lsn(), BASE_LSN + 3, "log Raft não sobreviveu ao restart");
        assert_eq!(n.last_term(), 3, "termo das entradas não sobreviveu");
    }

    #[test]
    fn figure8_does_not_commit_previous_term_by_count_alone() {
        // Marco C: regra de Figura-8. Uma entrada do termo ANTERIOR replicada em
        // maioria NÃO pode ser dada como committed só por contagem — só quando
        // uma entrada do termo CORRENTE acima dela commita.
        let mut n = RaftNode::new(0, vec![1, 2], tmp_db());
        n.role = Role::Leader;
        n.term = 2;
        n.log.push(LogEntry { term: 1, lsn: BASE_LSN + 1, merkle_root: "r1".into(), block: vec![] });
        n.match_index.insert(1, BASE_LSN + 1);
        n.match_index.insert(2, BASE_LSN + 1);
        n.advance_commit();
        assert_eq!(n.commit_lsn, BASE_LSN, "termo anterior não pode commitar só por contagem");

        // Uma entrada do termo CORRENTE replicada em maioria compromete tudo abaixo.
        n.log.push(LogEntry { term: 2, lsn: BASE_LSN + 2, merkle_root: "r2".into(), block: vec![] });
        n.match_index.insert(1, BASE_LSN + 2);
        n.match_index.insert(2, BASE_LSN + 2);
        n.advance_commit();
        assert_eq!(n.commit_lsn, BASE_LSN + 2, "entrada do termo corrente compromete tudo abaixo");
    }
}
