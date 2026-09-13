//! Синхронизация шейров между нодами
//! По спецификации ACCUM v3.2+ Секция 10

use crate::{
    error::Result,
    types::{Hash32, MinerId, Timestamp},
    share::{Share, SharePool},
    p2p::PeerId,
};
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};

// ============================================================
// EPOCH COMMIT - Merkle корень всех шейров эпохи
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochCommit {
    /// Номер эпохи
    pub epoch: u32,
    /// Merkle корень всех шейров
    pub merkle_root: Hash32,
    /// Timestamp коммита
    pub timestamp: Timestamp,
    /// Peer ID создателя
    pub peer_id: PeerId,
}

impl EpochCommit {
    pub fn new(epoch: u32, merkle_root: Hash32, peer_id: PeerId) -> Self {
        Self {
            epoch,
            merkle_root,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            peer_id,
        }
    }
    
    /// Проверить валидность коммита
    pub fn is_valid(&self, current_epoch: u32) -> bool {
        if self.epoch != current_epoch {
            return false;
        }
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Коммит не старше 1 часа
        now - self.timestamp < 3600
    }
}

// ============================================================
// SHARE RESYNC - запрос недостающих шейров
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareResyncRequest {
    /// Эпоха для синхронизации
    pub epoch: u32,
    /// Список майнеров (опционально)
    pub miner_ids: Option<Vec<MinerId>>,
    /// Смещение (для пагинации)
    pub offset: u32,
    /// Максимальное количество
    pub limit: u32,
}

impl ShareResyncRequest {
    pub fn new(epoch: u32, offset: u32, limit: u32) -> Self {
        Self {
            epoch,
            miner_ids: None,
            offset,
            limit,
        }
    }
    
    pub fn with_miners(epoch: u32, miners: Vec<MinerId>, offset: u32, limit: u32) -> Self {
        Self {
            epoch,
            miner_ids: Some(miners),
            offset,
            limit,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareResyncResponse {
    /// Эпоха
    pub epoch: u32,
    /// Пакет шейров
    pub shares: Vec<Share>,
    /// Всего шейров (для пагинации)
    pub total: u32,
    /// Следующее смещение (0 если всё)
    pub next_offset: u32,
}

// ============================================================
// SHARE SYNC MANAGER - управление синхронизацией
// ============================================================

pub struct ShareSyncManager {
    /// Полученные коммиты от пиров (peer_id -> EpochCommit)
    peer_commits: HashMap<PeerId, EpochCommit>,
    /// Голоса за корни (merkle_root -> количество голосов)
    root_votes: HashMap<Hash32, u32>,
    /// Пиры с постоянными расхождениями
    banned_peers: HashMap<PeerId, Timestamp>,
    /// Текущая эпоха
    current_epoch: u32,
    /// Локальный пул шейров
    share_pool: Option<SharePool>,
}

impl ShareSyncManager {
    pub fn new() -> Self {
        Self {
            peer_commits: HashMap::new(),
            root_votes: HashMap::new(),
            banned_peers: HashMap::new(),
            current_epoch: 1,
            share_pool: None,
        }
    }
    
    /// Привязать пул шейров
    pub fn attach_share_pool(&mut self, pool: SharePool) {
        self.share_pool = Some(pool);
    }
    
    /// Получить локальный Merkle корень
    pub fn local_root(&self) -> Option<Hash32> {
        self.share_pool.as_ref().map(|pool| pool.calculate_merkle_root())
    }
    
    /// Обработать коммит от пира
    pub fn process_commit(&mut self, commit: EpochCommit) -> Result<SyncStatus> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Проверяем, не забанен ли пир
        if let Some(ban_until) = self.banned_peers.get(&commit.peer_id) {
            if now < *ban_until {
                return Ok(SyncStatus::PeerBanned);
            }
        }
        
        // Сохраняем коммит
        self.peer_commits.insert(commit.peer_id, commit.clone());
        
        // Голосуем за корень
        *self.root_votes.entry(commit.merkle_root).or_insert(0) += 1;
        
        // Получаем локальный корень
        let local = match self.local_root() {
            Some(root) => root,
            None => return Ok(SyncStatus::NoLocalShares),
        };
        
        // Сравниваем
        if local == commit.merkle_root {
            Ok(SyncStatus::InSync)
        } else {
            // Проверяем, есть ли консенсус
            if let Some(consensus_root) = self.get_consensus_root() {
                if consensus_root != local {
                    // Мы в меньшинстве - нужен resync
                    Ok(SyncStatus::NeedsResync(consensus_root))
                } else {
                    // Пир в меньшинстве - возможно забаним
                    self.check_peer_consensus(&commit.peer_id, consensus_root);
                    Ok(SyncStatus::PeerOutOfSync)
                }
            } else {
                Ok(SyncStatus::NoConsensus)
            }
        }
    }
    
    /// Получить корень с большинством голосов (минимум 5 пиров)
    pub fn get_consensus_root(&self) -> Option<Hash32> {
        self.root_votes.iter()
            .filter(|(_, &count)| count >= 5)
            .max_by_key(|(_, &count)| count)
            .map(|(root, _)| *root)
    }
    
    /// Проверить, не пора ли забанить пира
    fn check_peer_consensus(&mut self, peer_id: &PeerId, consensus_root: Hash32) {
        if let Some(commit) = self.peer_commits.get(peer_id) {
            if commit.merkle_root != consensus_root {
                // Пиров с постоянными расхождениями баним
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                self.banned_peers.insert(*peer_id, now + 3600); // Бан на 1 час
            }
        }
    }
    
    /// Создать запрос на ресинхронизацию
    pub fn create_resync_request(&self, epoch: u32) -> ShareResyncRequest {
        ShareResyncRequest::new(epoch, 0, 500) // по 500 шейров за раз
    }
    
    /// Обработать ответ с шейрами
    pub fn process_resync_response(
        &mut self,
        response: ShareResyncResponse,
    ) -> Result<Vec<Share>> {
        let pool = match &mut self.share_pool {
            Some(p) => p,
            None => return Ok(Vec::new()),
        };
        
        let mut new_shares = Vec::new();
        
        for share in response.shares {
            // Проверяем, есть ли уже такой шейр
            if !pool.has_share(&share) {
                pool.add_share(share.clone(), true)?;
                new_shares.push(share);
            }
        }
        
        Ok(new_shares)
    }
    
    /// Очистить данные для новой эпохи
    pub fn new_epoch(&mut self, epoch: u32) {
        self.current_epoch = epoch;
        self.peer_commits.clear();
        self.root_votes.clear();
        
        // Очищаем старые баны (старше 24 часов)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.banned_peers.retain(|_, &mut until| now - until < 86400);
    }
}

// ============================================================
// СТАТУСЫ СИНХРОНИЗАЦИИ
// ============================================================

#[derive(Debug, Clone, PartialEq)]
pub enum SyncStatus {
    /// Всё синхронизировано
    InSync,
    /// Нет локальных шейров
    NoLocalShares,
    /// Нет консенсуса среди пиров
    NoConsensus,
    /// Пир рассинхронизирован
    PeerOutOfSync,
    /// Нужна ресинхронизация (с указанием правильного корня)
    NeedsResync(Hash32),
    /// Пир забанен
    PeerBanned,
}

// ============================================================
// ТЕСТЫ
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_epoch_commit() {
        let peer_id = [1u8; 32];
        let root = [2u8; 32];
        let commit = EpochCommit::new(1, root, peer_id);
        
        assert!(commit.is_valid(1));
        assert!(!commit.is_valid(2));
    }
    
    #[test]
    fn test_consensus() {
        let mut manager = ShareSyncManager::new();
        
        // Добавляем 5 голосов за один корень
        for i in 0..5 {
            let mut peer_id = [0u8; 32];
            peer_id[0] = i;
            let commit = EpochCommit::new(1, [1u8; 32], peer_id);
            manager.process_commit(commit).unwrap();
        }
        
        // Добавляем 2 голоса за другой корень
        for i in 5..7 {
            let mut peer_id = [0u8; 32];
            peer_id[0] = i;
            let commit = EpochCommit::new(1, [2u8; 32], peer_id);
            manager.process_commit(commit).unwrap();
        }
        
        // Консенсус должен быть за первый корень
        assert_eq!(manager.get_consensus_root(), Some([1u8; 32]));
    }
}