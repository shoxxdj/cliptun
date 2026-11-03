//! cliptun — POC de tunnel TCP à travers un presse-papier partagé.
//!
//!   navigateur ──proxy──► [front] ──(presse-papier)──► [back] ──TCP──► serveur web (localhost de la VM)
//!
//! Le front accepte sur un même port : SOCKS5, SOCKS4/4a, proxy HTTP (+CONNECT), requêtes directes.
//!
//! ── Protocole (half-duplex, maître/esclave, stop-and-wait) ──────────────────────────────
//!   * le presse-papier est un slot unique : le front (maître) écrit une trame F (seq N),
//!     le back répond par une trame B de même N contenant ce qu'il a en attente,
//!   * perte/corruption : le front réécrit sa trame (backoff), le back renvoie sa réponse
//!     en cache s'il revoit le même N ; le CRC32 écarte les trames tronquées,
//!   * chaque direction est donc livrée exactement une fois et dans l'ordre, ce qui permet
//!     une compression À ÉTAT (voir plus bas).
//!
//! ── Sessions (stabilité) ────────────────────────────────────────────────────────────────
//!   * chaque processus tire un identifiant `gen` aléatoire ; chaque trame porte son `gen`
//!     et le `gen` du pair tel que l'émetteur le connaît (`peer`),
//!   * nouveau `gen` côté front → le back ferme tout et repart d'un état neuf,
//!   * le front voit le `gen` du back changer (ou reçoit un RESET) → il ferme ses flux et
//!     repart avec un nouveau `gen` : plus de désynchronisation de la compression,
//!     plus de rejeu d'une vieille trame après un redémarrage,
//!   * pair muet plus de `--peer-timeout-ms` → les flux sont fermés au lieu de pendre.
//!
//! ── Format d'une trame (texte, compatible presse-papier) ────────────────────────────────
//!   CT3|<F|B>|<gen hex>|<peer hex>|<seq>|<base64(wire)>|<crc32 hex de wire>
//!   wire = <flag> <corps>   flag 0 = brut · 1 = flux zstd · 2 = RESET (corps vide)
//!
//! ── Compression ─────────────────────────────────────────────────────────────────────────
//!   Un flux zstd PERSISTANT par direction (flush à chaque trame) : l'historique des trames
//!   précédentes sert de dictionnaire (en-têtes HTTP, HTML/JS répétés…), amorcé par un
//!   dictionnaire intégré. La taille brute des trames s'adapte au ratio observé : `--chunk`
//!   est la taille cible sur le fil, pas la taille avant compression.
//!
//! ── Contrôle de flux ────────────────────────────────────────────────────────────────────
//!   Côté back, chaque flux dispose d'une fenêtre (256 Ko) rendue quand les données partent
//!   dans une trame : un serveur rapide ne remplit plus la mémoire plus vite que le
//!   presse-papier ne l'évacue.
//!
//! ── Chiffrement (`--encrypt`) ───────────────────────────────────────────────────────────
//!   Chaque trame est chiffrée et authentifiée (XChaCha20-Poly1305, clé de 256 bits partagée,
//!   nonce aléatoire de 192 bits par trame). L'en-tête (sens, sessions, seq) est lié au
//!   chiffrement (AAD) : il ne peut être ni modifié ni rejoué ailleurs. Les trames sont
//!   marquées `CT4` ; en mode chiffré, toute trame `CT3` (en clair) est refusée.
//!   Rejeu : une nouvelle session dont le numéro de séquence n'est pas strictement supérieur
//!   à tous ceux déjà vus par ce back est ignorée (les numéros partent de l'horloge du front).
//!   Ordre : compression PUIS chiffrement. La taille des trames reste visible sur le canal ;
//!   si du contenu secret et du contenu contrôlé par un tiers voyagent dans le même flux
//!   HTTP en clair, ajouter --no-compress (effet type CRIME/BREACH). Le trafic HTTPS passant
//!   par CONNECT est déjà chiffré, donc non compressible et non concerné.

use anyhow::{bail, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{BuildHasher, Hasher};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, Semaphore};
use tokio::time::{sleep, timeout};
use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use zstd::stream::raw::{CParameter, Decoder as ZDec, Encoder as ZEnc, InBuffer, Operation, OutBuffer};

static VERBOSE: AtomicBool = AtomicBool::new(false);
macro_rules! vlog {
    ($($a:tt)*) => { if VERBOSE.load(Ordering::Relaxed) { eprintln!($($a)*); } };
}

fn fatal(msg: &str) -> ! {
    eprintln!("erreur fatale: {msg}");
    std::process::exit(2)
}

/// Identifiant de session aléatoire (jamais 0, 0 = "inconnu").
fn rand64() -> u64 {
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(1),
    );
    h.write_u32(std::process::id());
    h.finish().max(1)
}

// ───────────────────────────── CLI ─────────────────────────────

#[derive(Parser)]
#[command(version, about = "Tunnel TCP (SOCKS5/SOCKS4/proxy HTTP) à travers le presse-papier")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
    #[command(flatten)]
    common: Common,
}

#[derive(Args, Clone)]
struct Common {
    /// Transport : presse-papier système, ou simple fichier partagé (pour tester sans VM)
    #[arg(long, value_enum, default_value = "clipboard", global = true)]
    backend: Backend,
    /// Chemin du fichier pour --backend file
    #[arg(long, global = true)]
    file: Option<PathBuf>,
    /// Taille cible d'une trame sur le fil (octets, avant base64). La taille brute avant
    /// compression s'adapte au ratio observé (jusqu'à x4).
    #[arg(long, default_value_t = 49152, global = true)]
    chunk: usize,
    /// Période de lecture du presse-papier (ms)
    #[arg(long, default_value_t = 50, global = true)]
    poll_ms: u64,
    /// Période de polling du front quand il a des flux ouverts mais rien à envoyer (ms)
    #[arg(long, default_value_t = 300, global = true)]
    interval_ms: u64,
    /// Le polling inactif ralentit progressivement jusqu'à cette période (ms)
    #[arg(long, default_value_t = 1500, global = true)]
    idle_max_ms: u64,
    /// Délai avant de réécrire une trame restée sans réponse (ms, doublé à chaque essai jusqu'à x4)
    #[arg(long, default_value_t = 3000, global = true)]
    resend_ms: u64,
    /// Au-delà de ce silence du pair, le front ferme ses flux au lieu d'attendre (ms)
    #[arg(long, default_value_t = 30000, global = true)]
    peer_timeout_ms: u64,
    /// Désactive la compression des trames émises (la réception reste automatique)
    #[arg(long, global = true)]
    no_compress: bool,
    /// Niveau zstd (1-19)
    #[arg(long, default_value_t = 9, global = true)]
    level: i32,
    /// Chiffre et authentifie chaque trame (XChaCha20-Poly1305). La clé se donne par
    /// --key-file ou la variable d'environnement CLIPTUN_KEY ; `cliptun keygen` en génère une
    #[arg(long, global = true)]
    encrypt: bool,
    /// Fichier contenant la clé (64 caractères hexadécimaux)
    #[arg(long, global = true)]
    key_file: Option<PathBuf>,
    /// Test : % d'écritures perdues et ~% corrompues sur le backend fichier
    #[arg(long, default_value_t = 0, global = true, hide = true)]
    chaos: u32,
    /// Logs détaillés
    #[arg(short, long, global = true)]
    verbose: bool,
}

impl Common {
    fn zlevel(&self) -> Option<i32> {
        if self.no_compress { None } else { Some(self.level.clamp(1, 19)) }
    }
}

#[derive(Subcommand)]
enum Cmd {
    /// Côté navigateur : écoute (SOCKS5, SOCKS4/4a, proxy HTTP/CONNECT, détectés
    /// automatiquement sur le même port) et pousse les flux dans le presse-papier
    Front {
        #[arg(long, default_value = "127.0.0.1:1080")]
        listen: String,
    },
    /// Côté VM : lit le presse-papier et ouvre les connexions TCP réelles
    Back {
        // Force toutes les connexions vers cette adresse (ignore la destination demandée),
        // ex. 127.0.0.1:8080
        #[arg(long)]
        connect_to: Option<String>,
        // Hôte supplémentaire autorisé (par défaut seul le loopback l'est). Répétable.
        //#[arg(long)]
        //allow: Vec<String>,
    },
    /// Génère une clé aléatoire de 256 bits (hex) pour --encrypt
    Keygen {
        /// Écrit la clé dans ce fichier (créé en 0600, refuse d'écraser) au lieu de l'afficher
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

#[derive(ValueEnum, Clone, Copy)]
enum Backend {
    Clipboard,
    File,
}

// ───────────────────────────── Messages ─────────────────────────────

#[derive(Debug)]
enum Msg {
    Open { id: u32, host: String, port: u16 },
    Opened { id: u32, ok: bool, err: String },
    Data { id: u32, data: Vec<u8> },
    Close { id: u32 },
}

impl Msg {
    fn id(&self) -> u32 {
        match self {
            Msg::Open { id, .. } | Msg::Opened { id, .. } | Msg::Data { id, .. } | Msg::Close { id } => *id,
        }
    }

    fn size(&self) -> usize {
        match self {
            Msg::Open { host, .. } => 9 + host.len(),
            Msg::Opened { err, .. } => 8 + err.len(),
            Msg::Data { data, .. } => 9 + data.len(),
            Msg::Close { .. } => 5,
        }
    }

    fn encode(&self, o: &mut Vec<u8>) {
        match self {
            Msg::Open { id, host, port } => {
                o.push(1);
                o.extend_from_slice(&id.to_be_bytes());
                o.extend_from_slice(&port.to_be_bytes());
                o.extend_from_slice(&(host.len() as u16).to_be_bytes());
                o.extend_from_slice(host.as_bytes());
            }
            Msg::Opened { id, ok, err } => {
                o.push(2);
                o.extend_from_slice(&id.to_be_bytes());
                o.push(*ok as u8);
                o.extend_from_slice(&(err.len() as u16).to_be_bytes());
                o.extend_from_slice(err.as_bytes());
            }
            Msg::Data { id, data } => {
                o.push(3);
                o.extend_from_slice(&id.to_be_bytes());
                o.extend_from_slice(&(data.len() as u32).to_be_bytes());
                o.extend_from_slice(data);
            }
            Msg::Close { id } => {
                o.push(4);
                o.extend_from_slice(&id.to_be_bytes());
            }
        }
    }
}

struct Rd<'a>(&'a [u8]);
impl<'a> Rd<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.len() < n {
            bail!("message tronqué");
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into()?))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into()?))
    }
}

fn decode_all(b: &[u8]) -> Result<Vec<Msg>> {
    let mut r = Rd(b);
    let mut v = Vec::new();
    while !r.0.is_empty() {
        match r.u8()? {
            1 => {
                let id = r.u32()?;
                let port = r.u16()?;
                let hl = r.u16()? as usize;
                let host = String::from_utf8_lossy(r.take(hl)?).into_owned();
                v.push(Msg::Open { id, host, port });
            }
            2 => {
                let id = r.u32()?;
                let ok = r.u8()? != 0;
                let el = r.u16()? as usize;
                let err = String::from_utf8_lossy(r.take(el)?).into_owned();
                v.push(Msg::Opened { id, ok, err });
            }
            3 => {
                let id = r.u32()?;
                let len = r.u32()? as usize;
                v.push(Msg::Data { id, data: r.take(len)?.to_vec() });
            }
            4 => v.push(Msg::Close { id: r.u32()? }),
            t => bail!("type de message inconnu: {t}"),
        }
    }
    Ok(v)
}

/// Remplit une trame jusqu'à `budget` octets bruts. `on_data(id, n)` est appelé pour chaque
/// message Data embarqué (le back s'en sert pour rendre la fenêtre du flux).
fn build_payload(pending: &mut VecDeque<Msg>, budget: usize, mut on_data: impl FnMut(u32, usize)) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(m) = pending.front() {
        if !out.is_empty() && out.len() + m.size() > budget {
            break;
        }
        let m = pending.pop_front().unwrap();
        if let Msg::Data { id, data } = &m {
            on_data(*id, data.len());
        }
        m.encode(&mut out);
    }
    out
}

// ───────────────────────────── Compression à état ─────────────────────────────

const F_RAW: u8 = 0;
const F_ZSTD: u8 = 1;
const F_RESET: u8 = 2;

/// En dessous, on n'engage pas le flux zstd (trames vides de polling, petits accusés).
const MIN_COMPRESS: usize = 48;
/// Taille max d'un corps décompressé (protège contre une "bombe" de décompression).
const MAX_BODY: u64 = 16 * 1024 * 1024;

/// Dictionnaire d'amorçage, identique des deux côtés (changer = changer de version de protocole) :
/// échantillon de trafic HTTP typique pour que les premières trames compressent déjà bien.
const DICT: &str = "GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate, br\r\nConnection: keep-alive\r\nReferer: http://localhost/\r\nCookie: session=; PHPSESSID=; csrftoken=\r\nUpgrade-Insecure-Requests: 1\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Site: same-origin\r\nSec-Fetch-User: ?1\r\nCache-Control: max-age=0\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: \r\nOrigin: http://localhost\r\nPOST /api/ HTTP/1.1\r\nAuthorization: Bearer \r\nX-Requested-With: XMLHttpRequest\r\n\r\nHTTP/1.1 200 OK\r\nHTTP/1.0 404 File not found\r\nHTTP/1.1 301 Moved Permanently\r\nHTTP/1.1 302 Found\r\nHTTP/1.1 304 Not Modified\r\nHTTP/1.1 403 Forbidden\r\nHTTP/1.1 500 Internal Server Error\r\nServer: nginx\r\nServer: Apache\r\nServer: SimpleHTTP/0.6 Python/3\r\nDate: Mon, 01 Jan 2026 00:00:00 GMT\r\nContent-Type: text/html; charset=utf-8\r\nContent-Type: application/json\r\nContent-Type: text/css\r\nContent-Type: application/javascript\r\nContent-Type: image/png\r\nContent-Length: \r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\nCache-Control: no-cache, no-store, must-revalidate\r\nSet-Cookie: session=; Path=/; HttpOnly; SameSite=Lax\r\nLocation: /\r\nETag: \"\"\r\nLast-Modified: Mon, 01 Jan 2026 00:00:00 GMT\r\nVary: Accept-Encoding\r\nX-Frame-Options: DENY\r\nX-Content-Type-Options: nosniff\r\nAccess-Control-Allow-Origin: *\r\nKeep-Alive: timeout=5\r\nConnection: close\r\n\r\n<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title></title>\n<link rel=\"stylesheet\" href=\"/static/style.css\">\n<script src=\"/static/app.js\"></script>\n</head>\n<body>\n<div class=\"container\">\n<form method=\"post\" action=\"/\">\n<input type=\"text\" name=\"\" value=\"\">\n<input type=\"password\" name=\"\">\n<button type=\"submit\">\n</form>\n<a href=\"/\"></a>\n<ul>\n<li></li>\n</ul>\n<table>\n<tr><td></td></tr>\n</table>\n</div>\n</body>\n</html>\n{\"id\":0,\"name\":\"\",\"status\":\"ok\",\"error\":null,\"data\":[],\"message\":\"\"}\nfunction(){}const var let return document.getElementById(window.location.href=addEventListener(\"click\"fetch(\"/api/\").then(response=>response.json())body{margin:0;padding:0;font-family:sans-serif}.container{display:flex;width:100%}color:#fff;background:#000;";

enum Unpacked {
    Body(Vec<u8>),
    Reset,
}

/// Un compresseur (direction émission) et un décompresseur (direction réception), tous deux
/// à état. Les deux extrémités doivent les créer/réinitialiser en même temps : c'est le rôle
/// des sessions (`gen`).
struct Codec {
    enc: Option<ZEnc<'static>>,
    dec: Option<ZDec<'static>>,
    level: Option<i32>,
    /// Ratio brut/compressé observé (moyenne mobile) → taille brute des prochaines trames
    ratio: f64,
}

impl Codec {
    fn new(level: Option<i32>) -> Self {
        Codec { enc: None, dec: None, level, ratio: 1.0 }
    }

    fn reset(&mut self) {
        self.enc = None;
        self.dec = None;
        self.ratio = 1.0;
    }

    /// Octets bruts à embarquer pour viser `chunk` octets sur le fil.
    fn budget(&self, chunk: usize) -> usize {
        (chunk as f64 * self.ratio.clamp(1.0, 4.0)) as usize
    }

    fn compress(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        if self.enc.is_none() {
            let mut e = ZEnc::with_dictionary(self.level.unwrap_or(3), DICT.as_bytes())?;
            e.set_parameter(CParameter::WindowLog(23))?;
            self.enc = Some(e);
        }
        let enc = self.enc.as_mut().unwrap();
        let mut out = Vec::with_capacity(input.len() / 2 + 64);
        let mut scratch = vec![0u8; 32768];
        let mut inb = InBuffer::around(input);
        while inb.pos() < input.len() {
            let mut ob = OutBuffer::around(&mut scratch[..]);
            enc.run(&mut inb, &mut ob)?;
            let n = ob.pos();
            drop(ob);
            out.extend_from_slice(&scratch[..n]);
        }
        loop {
            // flush : tout ce qui précède devient décodable côté pair, sans fermer le flux
            let mut ob = OutBuffer::around(&mut scratch[..]);
            let remaining = enc.flush(&mut ob)?;
            let n = ob.pos();
            drop(ob);
            out.extend_from_slice(&scratch[..n]);
            if remaining == 0 {
                break;
            }
        }
        Ok(out)
    }

    fn decompress(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        if self.dec.is_none() {
            self.dec = Some(ZDec::with_dictionary(DICT.as_bytes())?);
        }
        let dec = self.dec.as_mut().unwrap();
        let mut out = Vec::new();
        let mut scratch = vec![0u8; 32768];
        let mut inb = InBuffer::around(input);
        loop {
            let before = inb.pos();
            let mut ob = OutBuffer::around(&mut scratch[..]);
            dec.run(&mut inb, &mut ob)?;
            let n = ob.pos();
            drop(ob);
            out.extend_from_slice(&scratch[..n]);
            if out.len() as u64 > MAX_BODY {
                bail!("corps décompressé trop gros");
            }
            if inb.pos() >= input.len() && n < scratch.len() {
                break;
            }
            if n == 0 && inb.pos() == before {
                bail!("décodeur bloqué");
            }
        }
        Ok(out)
    }

    /// Corps → `[flag][données]`.
    fn pack(&mut self, body: &[u8]) -> Vec<u8> {
        if self.level.is_some() && body.len() >= MIN_COMPRESS {
            match self.compress(body) {
                Ok(z) => {
                    self.ratio = 0.7 * self.ratio + 0.3 * (body.len() as f64 / z.len().max(1) as f64);
                    let mut w = Vec::with_capacity(z.len() + 1);
                    w.push(F_ZSTD);
                    w.extend_from_slice(&z);
                    return w;
                }
                // l'état du compresseur serait indéterminé : mieux vaut s'arrêter net
                Err(e) => fatal(&format!("compression zstd: {e}")),
            }
        }
        let mut w = Vec::with_capacity(body.len() + 1);
        w.push(F_RAW);
        w.extend_from_slice(body);
        w
    }

    fn unpack(&mut self, wire: &[u8]) -> Result<Unpacked> {
        match wire.split_first() {
            Some((&F_RAW, rest)) => Ok(Unpacked::Body(rest.to_vec())),
            Some((&F_ZSTD, rest)) => Ok(Unpacked::Body(self.decompress(rest)?)),
            Some((&F_RESET, _)) => Ok(Unpacked::Reset),
            _ => bail!("flag de trame inconnu"),
        }
    }
}

// ───────────────────────────── Chiffrement ─────────────────────────────

struct Cipher {
    aead: XChaCha20Poly1305,
}

impl Cipher {
    fn new(key: &[u8; 32]) -> Self {
        Cipher { aead: XChaCha20Poly1305::new(Key::from_slice(key)) }
    }

    /// Données authentifiées mais non chiffrées : tout l'en-tête de la trame.
    fn aad(dir: char, gen: u64, peer: u64, seq: u64) -> Vec<u8> {
        let mut a = b"cliptun-v3".to_vec();
        a.push(dir as u8);
        a.extend_from_slice(&gen.to_be_bytes());
        a.extend_from_slice(&peer.to_be_bytes());
        a.extend_from_slice(&seq.to_be_bytes());
        a
    }

    /// `nonce(24) || chiffré || tag(16)`. Le nonce est aléatoire : avec 192 bits, aucune
    /// coordination ni compteur persistant n'est nécessaire entre les deux côtés.
    fn seal(&self, aad: &[u8], plain: &[u8]) -> Vec<u8> {
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ct = match self.aead.encrypt(&nonce, Payload { msg: plain, aad }) {
            Ok(c) => c,
            Err(_) => fatal("chiffrement impossible"),
        };
        let mut out = Vec::with_capacity(24 + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        out
    }

    fn open(&self, aad: &[u8], data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < 24 + 16 {
            return None;
        }
        let (n, ct) = data.split_at(24);
        self.aead.decrypt(XNonce::from_slice(n), Payload { msg: ct, aad }).ok()
    }
}

fn parse_key(s: &str) -> Result<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 || !s.is_ascii() {
        bail!("clé invalide : 64 caractères hexadécimaux attendus (voir `cliptun keygen`)");
    }
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
            .map_err(|_| anyhow::anyhow!("clé invalide : caractère non hexadécimal"))?;
    }
    Ok(k)
}

/// La clé ne passe jamais par la ligne de commande (visible dans `ps`) : fichier ou variable d'environnement.
fn load_cipher(c: &Common) -> Result<Option<Arc<Cipher>>> {
    if !c.encrypt {
        if c.key_file.is_some() {
            eprintln!("attention: --key-file ignoré sans --encrypt");
        }
        return Ok(None);
    }
    let raw = match &c.key_file {
        Some(p) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(m) = std::fs::metadata(p) {
                    if m.permissions().mode() & 0o077 != 0 {
                        eprintln!("attention: {} est lisible par d'autres utilisateurs (chmod 600)", p.display());
                    }
                }
            }
            std::fs::read_to_string(p)?
        }
        None => std::env::var("CLIPTUN_KEY").map_err(|_| {
            anyhow::anyhow!("--encrypt demande une clé : --key-file <fichier> ou variable CLIPTUN_KEY (`cliptun keygen` en génère une)")
        })?,
    };
    let key = parse_key(&raw)?;
    eprintln!("chiffrement activé (XChaCha20-Poly1305, trames authentifiées)");
    Ok(Some(Arc::new(Cipher::new(&key))))
}

fn keygen(out: Option<PathBuf>) -> Result<()> {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
    match out {
        Some(p) => {
            use std::io::Write;
            let mut o = std::fs::OpenOptions::new();
            o.write(true).create_new(true); // refuse d'écraser une clé existante
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                o.mode(0o600);
            }
            let mut f = o.open(&p)?;
            writeln!(f, "{hex}")?;
            eprintln!("clé écrite dans {} — à copier (par un canal sûr) des deux côtés", p.display());
        }
        None => println!("{hex}"),
    }
    Ok(())
}

// ───────────────────────────── Trames ─────────────────────────────

const CRC_TABLE: [u32; 256] = {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
};

fn crc32(data: &[u8]) -> u32 {
    let mut c = !0u32;
    for &b in data {
        c = CRC_TABLE[((c ^ b as u32) & 0xFF) as usize] ^ (c >> 8);
    }
    !c
}

struct Frame {
    dir: char,
    gen: u64,
    peer: u64,
    seq: u64,
    wire: Vec<u8>,
}

/// `CT3` = en clair, `CT4` = chiffré. Le CRC32 porte sur les octets tels qu'ils voyagent
/// (simple détection de troncature avant de tenter le déchiffrement).
fn make_frame(dir: char, gen: u64, peer: u64, seq: u64, wire: &[u8], cipher: Option<&Cipher>) -> String {
    let (tag, bytes) = match cipher {
        Some(c) => ("CT4", c.seal(&Cipher::aad(dir, gen, peer, seq), wire)),
        None => ("CT3", wire.to_vec()),
    };
    vlog!("frame {dir}{seq}: {} o sur le fil ({} o transmis)", wire.len(), bytes.len());
    format!("{tag}|{}|{:x}|{:x}|{}|{}|{:08x}", dir, gen, peer, seq, B64.encode(&bytes), crc32(&bytes))
}

/// Ne touche PAS à l'état de compression : le décodage se fait une seule fois par trame
/// traitée, jamais à chaque lecture du presse-papier.
fn parse_frame(s: &str, cipher: Option<&Cipher>) -> Option<Frame> {
    // en mode chiffré, on n'accepte que CT4 ; en clair, que CT3 (pas de rétrogradation possible)
    let tag = if cipher.is_some() { "CT4" } else { "CT3" };
    // certains outils de sync du presse-papier ajoutent/modifient des blancs
    if !s.trim_start().starts_with(tag) {
        return None;
    }
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let mut it = s.split('|');
    if it.next()? != tag {
        return None;
    }
    let dir = it.next()?.chars().next()?;
    let gen = u64::from_str_radix(it.next()?, 16).ok()?;
    let peer = u64::from_str_radix(it.next()?, 16).ok()?;
    let seq: u64 = it.next()?.parse().ok()?;
    let raw = B64.decode(it.next()?).ok()?;
    let crc = u32::from_str_radix(it.next()?, 16).ok()?;
    if it.next().is_some() || crc32(&raw) != crc {
        return None;
    }
    let wire = match cipher {
        Some(c) => match c.open(&Cipher::aad(dir, gen, peer, seq), &raw) {
            Some(w) => w,
            None => {
                vlog!("trame rejetée : authentification échouée (mauvaise clé, ou trame modifiée)");
                return None;
            }
        },
        None => raw,
    };
    Some(Frame { dir, gen, peer, seq, wire })
}

// ───────────────────────────── Transport presse-papier ─────────────────────────────

trait Clip {
    fn get(&mut self) -> Option<String>;
    fn set(&mut self, s: &str) -> Result<()>;
}

/// Presse-papier simulé par un fichier. `chaos` > 0 perd/corrompt des écritures pour tester
/// les retransmissions.
struct FileClip {
    path: PathBuf,
    chaos: u32,
    rng: u64,
}

impl FileClip {
    fn rnd(&mut self) -> u64 {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        self.rng
    }
}

impl Clip for FileClip {
    fn get(&mut self) -> Option<String> {
        std::fs::read_to_string(&self.path).ok()
    }
    fn set(&mut self, s: &str) -> Result<()> {
        let mut data = s;
        if self.chaos > 0 {
            let r = self.rnd() % 100;
            if r < self.chaos as u64 {
                return Ok(()); // écriture perdue
            }
            if r < (self.chaos as u64) * 3 / 2 {
                let cut = (self.rnd() as usize) % s.len().max(1);
                data = &s[..cut]; // trame tronquée (le contenu est de l'ASCII)
            }
        }
        let tmp = self.path.with_extension(format!("tmp{}", std::process::id()));
        std::fs::write(&tmp, data)?;
        std::fs::rename(&tmp, &self.path)?; // écriture atomique
        Ok(())
    }
}

#[cfg(feature = "clip")]
struct SysClip(arboard::Clipboard);
#[cfg(feature = "clip")]
impl Clip for SysClip {
    fn get(&mut self) -> Option<String> {
        self.0.get_text().ok()
    }
    fn set(&mut self, s: &str) -> Result<()> {
        self.0.set_text(s.to_string())?;
        Ok(())
    }
}

enum ClipCmd {
    Get(oneshot::Sender<Option<String>>),
    Set(String, oneshot::Sender<()>),
}

/// Le presse-papier vit dans un thread dédié (certaines plateformes exigent que
/// l'objet reste sur le thread qui l'a créé, et X11 doit garder le propriétaire en vie).
#[derive(Clone)]
struct ClipHandle {
    tx: std::sync::mpsc::Sender<ClipCmd>,
}

impl ClipHandle {
    fn spawn(make: impl FnOnce() -> Result<Box<dyn Clip>> + Send + 'static) -> Result<Self> {
        let (tx, rx) = std::sync::mpsc::channel::<ClipCmd>();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<std::result::Result<(), String>>();
        std::thread::spawn(move || {
            let mut clip = match make() {
                Ok(c) => {
                    let _ = ready_tx.send(Ok(()));
                    c
                }
                Err(e) => {
                    let _ = ready_tx.send(Err(e.to_string()));
                    return;
                }
            };
            while let Ok(cmd) = rx.recv() {
                match cmd {
                    ClipCmd::Get(r) => {
                        let _ = r.send(clip.get());
                    }
                    ClipCmd::Set(s, r) => {
                        if let Err(e) = clip.set(&s) {
                            eprintln!("erreur d'écriture presse-papier: {e}");
                        }
                        let _ = r.send(());
                    }
                }
            }
        });
        match ready_rx.recv() {
            Ok(Ok(())) => Ok(ClipHandle { tx }),
            Ok(Err(e)) => bail!("initialisation du presse-papier impossible: {e}"),
            Err(e) => bail!("thread presse-papier: {e}"),
        }
    }

    async fn get(&self) -> Option<String> {
        let (o, r) = oneshot::channel();
        self.tx.send(ClipCmd::Get(o)).ok()?;
        r.await.ok().flatten()
    }

    async fn set(&self, s: String) {
        let (o, r) = oneshot::channel();
        if self.tx.send(ClipCmd::Set(s, o)).is_ok() {
            let _ = r.await;
        }
    }
}

fn make_clip(c: &Common) -> Result<ClipHandle> {
    match c.backend {
        Backend::File => {
            let path = c.file.clone().unwrap_or_else(|| std::env::temp_dir().join("cliptun.clip"));
            let chaos = c.chaos;
            eprintln!("transport: fichier {}{}", path.display(), if chaos > 0 { format!(" (chaos {chaos}%)") } else { String::new() });
            ClipHandle::spawn(move || Ok(Box::new(FileClip { path, chaos, rng: rand64() }) as Box<dyn Clip>))
        }
        Backend::Clipboard => {
            #[cfg(feature = "clip")]
            {
                ClipHandle::spawn(|| Ok(Box::new(SysClip(arboard::Clipboard::new()?)) as Box<dyn Clip>))
            }
            #[cfg(not(feature = "clip"))]
            {
                bail!("compilé sans la feature `clip` ; utilise --backend file")
            }
        }
    }
}

// ───────────────────────────── FRONT ─────────────────────────────

struct Shared {
    streams: Mutex<HashMap<u32, mpsc::UnboundedSender<Msg>>>,
    next_id: AtomicU32,
    out: mpsc::Sender<Msg>,
    read_buf: usize,
}

#[derive(Debug, Clone, Copy)]
enum Proto {
    Socks5,
    Socks4,
    HttpConnect,
    HttpPlain,
}

/// Destination demandée par le client, quel que soit le protocole utilisé pour la demander.
struct Req {
    proto: Proto,
    host: String,
    port: u16,
    /// Octets à envoyer au serveur dès que le flux est ouvert (requête HTTP réécrite, etc.)
    initial: Vec<u8>,
}

async fn socks_reply(s: &mut TcpStream, code: u8) -> Result<()> {
    s.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    Ok(())
}

async fn http_reply(s: &mut TcpStream, status: &str, body: &str) -> Result<()> {
    let msg = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(msg.as_bytes()).await?;
    Ok(())
}

async fn reply_ok(s: &mut TcpStream, proto: Proto) -> Result<()> {
    match proto {
        Proto::Socks5 => socks_reply(s, 0x00).await,
        Proto::Socks4 => Ok(s.write_all(&[0, 0x5A, 0, 0, 0, 0, 0, 0]).await?),
        Proto::HttpConnect => Ok(s.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?),
        Proto::HttpPlain => Ok(()), // la réponse du serveur arrive directement
    }
}

async fn reply_err(s: &mut TcpStream, proto: Proto, msg: &str, timed_out: bool) -> Result<()> {
    match proto {
        Proto::Socks5 => socks_reply(s, if timed_out { 0x04 } else { 0x05 }).await,
        Proto::Socks4 => Ok(s.write_all(&[0, 0x5B, 0, 0, 0, 0, 0, 0]).await?),
        Proto::HttpConnect | Proto::HttpPlain => {
            if timed_out {
                http_reply(s, "504 Gateway Timeout", msg).await
            } else {
                http_reply(s, "502 Bad Gateway", msg).await
            }
        }
    }
}

fn split_host_port(s: &str, default: u16) -> Result<(String, u16)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (h, after) = rest.split_once(']').ok_or_else(|| anyhow::anyhow!("adresse IPv6 mal formée"))?;
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse()?,
            None => default,
        };
        return Ok((h.to_string(), port));
    }
    match s.rsplit_once(':') {
        Some((h, p)) => Ok((h.to_string(), p.parse()?)),
        None => Ok((s.to_string(), default)),
    }
}

async fn read_cstr(sock: &mut TcpStream, max: usize) -> Result<Vec<u8>> {
    let mut v = Vec::new();
    loop {
        let mut b = [0u8; 1];
        sock.read_exact(&mut b).await?;
        if b[0] == 0 {
            return Ok(v);
        }
        v.push(b[0]);
        if v.len() > max {
            bail!("champ trop long");
        }
    }
}

/// SOCKS4 / SOCKS4a (CONNECT uniquement).
async fn read_socks4(sock: &mut TcpStream) -> Result<Req> {
    let mut h = [0u8; 8]; // VN CD PORT(2) IP(4)
    sock.read_exact(&mut h).await?;
    if h[1] != 1 {
        sock.write_all(&[0, 0x5B, 0, 0, 0, 0, 0, 0]).await?;
        bail!("commande SOCKS4 non supportée: {}", h[1]);
    }
    let port = u16::from_be_bytes([h[2], h[3]]);
    let ip = [h[4], h[5], h[6], h[7]];
    read_cstr(sock, 256).await?; // userid
    let host = if ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0 {
        // SOCKS4a : le nom d'hôte suit
        String::from_utf8_lossy(&read_cstr(sock, 256).await?).into_owned()
    } else {
        std::net::Ipv4Addr::from(ip).to_string()
    };
    Ok(Req { proto: Proto::Socks4, host, port, initial: Vec::new() })
}

/// Proxy HTTP : `CONNECT host:port` (tunnel, HTTPS), `GET http://host/…` (forme absolue),
/// ou requête directe `GET /…` + `Host:` (le front utilisé comme simple relais, à combiner
/// avec `back --connect-to`).
async fn read_http(sock: &mut TcpStream) -> Result<Req> {
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    let end = loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
        if buf.len() > 65536 {
            http_reply(sock, "431 Request Header Fields Too Large", "en-têtes trop volumineux").await?;
            bail!("en-têtes HTTP trop volumineux");
        }
        let n = sock.read(&mut tmp).await?;
        if n == 0 {
            bail!("connexion fermée pendant l'en-tête HTTP");
        }
        buf.extend_from_slice(&tmp[..n]);
    };
    let rest = buf[end..].to_vec();
    let head = String::from_utf8_lossy(&buf[..end - 4]).into_owned();
    let mut lines = head.split("\r\n");
    let reqline = lines.next().unwrap_or("");
    let mut parts = reqline.split_whitespace();
    let (method, target, version) = match (parts.next(), parts.next(), parts.next()) {
        (Some(a), Some(b), Some(c)) => (a, b, c),
        _ => {
            http_reply(sock, "400 Bad Request", "requête illisible").await?;
            bail!("ligne de requête HTTP invalide: {reqline:?}");
        }
    };
    let headers: Vec<&str> = lines.collect();

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = match split_host_port(target, 443) {
            Ok(x) => x,
            Err(e) => {
                http_reply(sock, "400 Bad Request", "cible CONNECT invalide").await?;
                return Err(e);
            }
        };
        return Ok(Req { proto: Proto::HttpConnect, host, port, initial: rest });
    }

    // — requête "normale" : on détermine la destination, puis on réécrit l'en-tête —
    let lower = target.to_ascii_lowercase();
    let (authority, path): (&str, String) = if lower.starts_with("http://") {
        let r = &target[7..];
        match r.find('/') {
            Some(i) => (&r[..i], r[i..].to_string()),
            None => (r, "/".to_string()),
        }
    } else if target.starts_with('/') {
        let host_hdr = headers.iter().find_map(|l| {
            l.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case("host")).map(|(_, v)| v.trim())
        });
        match host_hdr {
            Some(h) => (h, target.to_string()),
            None => {
                http_reply(sock, "400 Bad Request", "en-tête Host manquant").await?;
                bail!("requête directe sans Host");
            }
        }
    } else {
        http_reply(sock, "400 Bad Request", "seul http:// est supporté en forme absolue (HTTPS : CONNECT)").await?;
        bail!("cible HTTP non supportée: {target}");
    };
    let authority = authority.rsplit('@').next().unwrap_or(authority); // retire user:pass@
    let (host, port) = match split_host_port(authority, 80) {
        Ok(x) => x,
        Err(e) => {
            http_reply(sock, "400 Bad Request", "hôte invalide").await?;
            return Err(e);
        }
    };

    // Le navigateur peut enchaîner des requêtes vers des hôtes différents sur la même connexion
    // proxy : on force `Connection: close` pour qu'elles ouvrent chacune un nouveau flux.
    // (Sauf Upgrade, ex. WebSocket, qui a besoin de garder la connexion.)
    let has_upgrade = headers
        .iter()
        .any(|l| l.split_once(':').map(|(k, _)| k.trim().eq_ignore_ascii_case("upgrade")).unwrap_or(false));
    let mut out = format!("{method} {path} {version}\r\n");
    let mut has_host = false;
    for l in &headers {
        let key = l.split_once(':').map(|(k, _)| k.trim().to_ascii_lowercase()).unwrap_or_default();
        match key.as_str() {
            "proxy-connection" | "proxy-authorization" | "keep-alive" => continue,
            "connection" if !has_upgrade => continue,
            "host" => has_host = true,
            _ => {}
        }
        out.push_str(l);
        out.push_str("\r\n");
    }
    if !has_host {
        out.push_str(&format!("Host: {authority}\r\n"));
    }
    if !has_upgrade {
        out.push_str("Connection: close\r\n");
    }
    out.push_str("\r\n");
    let mut initial = out.into_bytes();
    initial.extend_from_slice(&rest);
    Ok(Req { proto: Proto::HttpPlain, host, port, initial })
}

/// SOCKS5, sans authentification, CONNECT uniquement.
async fn read_socks5(mut sock: &mut TcpStream) -> Result<Req> {
    // — handshake SOCKS5 (sans authentification) —
    let mut hdr = [0u8; 2];
    sock.read_exact(&mut hdr).await?;
    if hdr[0] != 5 {
        bail!("pas du SOCKS5");
    }
    let mut methods = vec![0u8; hdr[1] as usize];
    sock.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        sock.write_all(&[5, 0xFF]).await?;
        bail!("méthode d'auth non supportée");
    }
    sock.write_all(&[5, 0]).await?;

    let mut req = [0u8; 4];
    sock.read_exact(&mut req).await?;
    if req[0] != 5 || req[1] != 1 {
        socks_reply(&mut sock, 0x07).await?; // seul CONNECT est supporté
        bail!("commande SOCKS non supportée: {}", req[1]);
    }
    let host = match req[3] {
        1 => {
            let mut a = [0u8; 4];
            sock.read_exact(&mut a).await?;
            std::net::Ipv4Addr::from(a).to_string()
        }
        3 => {
            let mut l = [0u8; 1];
            sock.read_exact(&mut l).await?;
            let mut d = vec![0u8; l[0] as usize];
            sock.read_exact(&mut d).await?;
            String::from_utf8_lossy(&d).into_owned()
        }
        4 => {
            let mut a = [0u8; 16];
            sock.read_exact(&mut a).await?;
            std::net::Ipv6Addr::from(a).to_string()
        }
        _ => {
            socks_reply(&mut sock, 0x08).await?;
            bail!("type d'adresse inconnu");
        }
    };
    let mut p = [0u8; 2];
    sock.read_exact(&mut p).await?;
    let port = u16::from_be_bytes(p);
    Ok(Req { proto: Proto::Socks5, host, port, initial: Vec::new() })
}

/// Point d'entrée de chaque connexion cliente : détecte le protocole sur le premier octet.
///   0x05 → SOCKS5 · 0x04 → SOCKS4/4a · autre (ASCII) → proxy HTTP
async fn handle_client(mut sock: TcpStream, shared: Arc<Shared>) -> Result<()> {
    let _ = sock.set_nodelay(true);
    let mut first_byte = [0u8; 1];
    if sock.peek(&mut first_byte).await? == 0 {
        return Ok(());
    }
    let req = match first_byte[0] {
        5 => read_socks5(&mut sock).await?,
        4 => read_socks4(&mut sock).await?,
        _ => read_http(&mut sock).await?,
    };
    let Req { proto, host, port, initial } = req;

    // — ouverture du flux côté back —
    let id = shared.next_id.fetch_add(1, Ordering::Relaxed);
    let (tx, mut rx) = mpsc::unbounded_channel::<Msg>();
    shared.streams.lock().unwrap().insert(id, tx);
    vlog!("[{id}] {proto:?} → {host}:{port}");
    shared.out.send(Msg::Open { id, host, port }).await?;

    let first = timeout(Duration::from_secs(90), rx.recv()).await;
    match first {
        Ok(Some(Msg::Opened { ok: true, .. })) => reply_ok(&mut sock, proto).await?,
        Ok(Some(Msg::Opened { ok: false, err, .. })) => {
            let _ = reply_err(&mut sock, proto, &format!("refusé par le back: {err}"), false).await;
            shared.streams.lock().unwrap().remove(&id);
            bail!("[{id}] refusé par le back: {err}");
        }
        _ => {
            let _ = reply_err(&mut sock, proto, "pas de réponse du back", true).await;
            shared.streams.lock().unwrap().remove(&id);
            bail!("[{id}] pas de réponse du back");
        }
    }

    // octets déjà lus avec l'en-tête (requête HTTP réécrite, corps, …)
    for chunk in initial.chunks(shared.read_buf) {
        if shared.out.send(Msg::Data { id, data: chunk.to_vec() }).await.is_err() {
            break;
        }
    }

    // — pompage bidirectionnel —
    let (mut r, mut w) = sock.into_split();
    let out = shared.out.clone();
    let bufsize = shared.read_buf;
    let reader = async {
        let mut buf = vec![0u8; bufsize];
        loop {
            match r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if out.send(Msg::Data { id, data: buf[..n].to_vec() }).await.is_err() {
                        break;
                    }
                }
            }
        }
    };
    let writer = async {
        while let Some(m) = rx.recv().await {
            match m {
                Msg::Data { data, .. } => {
                    if w.write_all(&data).await.is_err() {
                        break;
                    }
                }
                Msg::Close { .. } => break,
                _ => {}
            }
        }
        let _ = w.shutdown().await;
    };
    tokio::select! { _ = reader => {}, _ = writer => {} }
    let _ = shared.out.send(Msg::Close { id }).await; // redondant mais inoffensif
    shared.streams.lock().unwrap().remove(&id);
    vlog!("[{id}] fermé");
    Ok(())
}

/// Ferme tous les flux ouverts (les gestionnaires clients reçoivent un Close).
fn fail_all_streams(shared: &Shared) -> HashSet<u32> {
    let drained: Vec<(u32, mpsc::UnboundedSender<Msg>)> = shared.streams.lock().unwrap().drain().collect();
    let mut dead = HashSet::new();
    for (id, tx) in drained {
        let _ = tx.send(Msg::Close { id });
        dead.insert(id);
    }
    dead
}

/// Repart d'une session neuve : flux fermés, état de compression jeté, nouvel identifiant.
fn front_reset(
    shared: &Shared,
    out_rx: &mut mpsc::Receiver<Msg>,
    pending: &mut VecDeque<Msg>,
    codec: &mut Codec,
    gen: &mut u64,
    back_gen: &mut u64,
    why: &str,
) {
    eprintln!("front: session réinitialisée ({why})");
    let dead = fail_all_streams(shared);
    // on ne garde que les messages de flux apparus depuis (ex. un Open tout neuf)
    pending.retain(|m| !dead.contains(&m.id()));
    while let Ok(m) = out_rx.try_recv() {
        if !dead.contains(&m.id()) {
            pending.push_back(m);
        }
    }
    codec.reset();
    *gen = rand64();
    *back_gen = 0;
}

/// Écrit la trame et attend la réponse portant le même numéro de séquence.
/// `None` si le back reste muet plus de `--peer-timeout-ms`.
async fn exchange(
    clip: &ClipHandle,
    frame: &str,
    gen: u64,
    seq: u64,
    c: &Common,
    cipher: Option<&Cipher>,
) -> Option<Frame> {
    clip.set(frame.to_string()).await;
    let start = Instant::now();
    let mut last_write = start;
    let base = Duration::from_millis(c.resend_ms);
    let mut resend = base;
    let mut last_text: Option<String> = None;
    loop {
        sleep(Duration::from_millis(c.poll_ms)).await;
        if let Some(t) = clip.get().await {
            // contenu inchangé depuis la dernière lecture : inutile de le re-décoder
            if last_text.as_deref() != Some(t.as_str()) {
                if let Some(f) = parse_frame(&t, cipher) {
                    if f.dir == 'B' && f.seq == seq && f.peer == gen {
                        return Some(f);
                    }
                }
                last_text = Some(t);
            }
        }
        if start.elapsed() > Duration::from_millis(c.peer_timeout_ms) {
            return None;
        }
        if last_write.elapsed() > resend {
            vlog!("front: pas de réponse pour seq={seq}, réécriture de la trame");
            clip.set(frame.to_string()).await;
            last_write = Instant::now();
            resend = (resend * 2).min(base * 4);
        }
    }
}

async fn front_tunnel(
    clip: ClipHandle,
    shared: Arc<Shared>,
    mut out_rx: mpsc::Receiver<Msg>,
    c: Common,
    cipher: Option<Arc<Cipher>>,
) {
    let mut gen = rand64();
    let mut back_gen: u64 = 0; // 0 = pas encore de contact avec ce back
    let mut codec = Codec::new(c.zlevel());
    let mut pending: VecDeque<Msg> = VecDeque::new();
    // numéro de séquence : démarre à l'epoch (ms), puis +1 par trame
    let mut seq: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(1);
    let mut idle = c.interval_ms;
    loop {
        while let Ok(m) = out_rx.try_recv() {
            pending.push_back(m);
            idle = c.interval_ms;
        }
        let active = !shared.streams.lock().unwrap().is_empty();
        if pending.is_empty() && !active {
            // rien à faire : on ne touche pas au presse-papier
            match out_rx.recv().await {
                Some(m) => {
                    pending.push_back(m);
                    idle = c.interval_ms;
                }
                None => return,
            }
            continue;
        }

        let payload = build_payload(&mut pending, codec.budget(c.chunk), |_, _| {});
        seq += 1;
        let wire = codec.pack(&payload);
        let frame = make_frame('F', gen, back_gen, seq, &wire, cipher.as_deref());
        vlog!("front: → seq={seq} ({} o bruts)", payload.len());

        let Some(reply) = exchange(&clip, &frame, gen, seq, &c, cipher.as_deref()).await else {
            front_reset(&shared, &mut out_rx, &mut pending, &mut codec, &mut gen, &mut back_gen, "le back ne répond plus");
            continue;
        };

        // — analyse de la réponse —
        let mut why: Option<&str> =
            if back_gen != 0 && reply.gen != back_gen { Some("le back a redémarré") } else { None };
        let mut msgs = Vec::new();
        if why.is_none() {
            match codec.unpack(&reply.wire) {
                Ok(Unpacked::Body(b)) => match decode_all(&b) {
                    Ok(m) => msgs = m,
                    Err(_) => why = Some("réponse illisible"),
                },
                Ok(Unpacked::Reset) => why = Some("le back demande une réinitialisation"),
                Err(_) => why = Some("décompression impossible"),
            }
        }
        if let Some(why) = why {
            front_reset(&shared, &mut out_rx, &mut pending, &mut codec, &mut gen, &mut back_gen, why);
            back_gen = reply.gen;
            continue;
        }
        if back_gen == 0 {
            back_gen = reply.gen;
        }

        vlog!("front: ← seq={seq} ({} msg)", msgs.len());
        let got = !msgs.is_empty();
        for m in msgs {
            let id = m.id();
            let end = matches!(m, Msg::Close { .. }) || matches!(m, Msg::Opened { ok: false, .. });
            let tx = shared.streams.lock().unwrap().get(&id).cloned();
            if let Some(tx) = tx {
                let _ = tx.send(m);
            }
            if end {
                shared.streams.lock().unwrap().remove(&id);
            }
        }

        if payload.is_empty() && !got && pending.is_empty() {
            // inactif : polling de plus en plus espacé, réveil immédiat si on a quelque chose à envoyer
            idle = (idle * 3 / 2).min(c.idle_max_ms.max(c.interval_ms));
            tokio::select! {
                _ = sleep(Duration::from_millis(idle)) => {}
                m = out_rx.recv() => {
                    if let Some(m) = m { pending.push_back(m); idle = c.interval_ms; }
                }
            }
        } else {
            idle = c.interval_ms;
        }
    }
}

async fn run_front(clip: ClipHandle, c: Common, listen: String, cipher: Option<Arc<Cipher>>) -> Result<()> {
    let (out_tx, out_rx) = mpsc::channel::<Msg>(256);
    let shared = Arc::new(Shared {
        streams: Mutex::new(HashMap::new()),
        next_id: AtomicU32::new(1),
        out: out_tx,
        read_buf: c.chunk.saturating_sub(64).clamp(256, 32768),
    });
    tokio::spawn(front_tunnel(clip, shared.clone(), out_rx, c, cipher));

    let listener = TcpListener::bind(&listen).await?;
    eprintln!("front: en écoute sur {listen} (SOCKS5 / SOCKS4(a) / proxy HTTP + CONNECT)");
    loop {
        let (sock, peer) = listener.accept().await?;
        vlog!("front: client {peer}");
        let sh = shared.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_client(sock, sh).await {
                vlog!("front: {e}");
            }
        });
    }
}

// ───────────────────────────── BACK ─────────────────────────────

/// Fenêtre par flux (octets) entre le serveur cible et le presse-papier.
const WINDOW: usize = 256 * 1024;

struct StreamCtl {
    tx: mpsc::UnboundedSender<Msg>,
    window: Arc<Semaphore>,
}

type Streams = Arc<Mutex<HashMap<u32, StreamCtl>>>;

fn parse_hostport(s: &str) -> Result<(String, u16)> {
    let (h, p) = s.rsplit_once(':').ok_or_else(|| anyhow::anyhow!("format attendu host:port"))?;
    Ok((h.trim_matches(['[', ']']).to_string(), p.parse()?))
}

// fn allowed(host: &str, allow: &[String]) -> bool {
//     host == "localhost"
//         || host.parse::<std::net::IpAddr>().map(|ip| ip.is_loopback()).unwrap_or(false)
//         || allow.iter().any(|a| a == host)
// }

#[allow(clippy::too_many_arguments)]
async fn target_task(
    id: u32,
    host: String,
    port: u16,
    mut rx: mpsc::UnboundedReceiver<Msg>,
    out: mpsc::UnboundedSender<Msg>,
    streams: Streams,
    window: Arc<Semaphore>,
    epoch: Arc<AtomicU64>,
    my_epoch: u64,
    bufsize: usize,
) {
    // ne retire du registre que SON entrée (l'id peut avoir été réutilisé par une session plus récente)
    let cleanup = || {
        let mut m = streams.lock().unwrap();
        if m.get(&id).map(|s| Arc::ptr_eq(&s.window, &window)).unwrap_or(false) {
            m.remove(&id);
        }
    };
    let current = || epoch.load(Ordering::SeqCst) == my_epoch;
    let fail = |err: String| {
        if current() {
            let _ = out.send(Msg::Opened { id, ok: false, err });
        }
        cleanup();
    };
    let sock = match timeout(Duration::from_secs(10), TcpStream::connect((host.as_str(), port))).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return fail(e.to_string()),
        Err(_) => return fail("timeout".into()),
    };
    let _ = sock.set_nodelay(true);
    vlog!("back: [{id}] connecté à {host}:{port}");
    if !current() {
        return cleanup();
    }
    let _ = out.send(Msg::Opened { id, ok: true, err: String::new() });

    let (mut r, mut w) = sock.into_split();
    let out2 = out.clone();
    let window_r = window.clone();
    let epoch_r = epoch.clone();
    let reader = async move {
        let mut buf = vec![0u8; bufsize];
        loop {
            match r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    // contrôle de flux : on attend que la fenêtre se libère (données parties dans une trame)
                    match window_r.acquire_many(n as u32).await {
                        Ok(p) => p.forget(),
                        Err(_) => break,
                    }
                    if epoch_r.load(Ordering::SeqCst) != my_epoch {
                        return; // session périmée : on ne parle plus
                    }
                    if out2.send(Msg::Data { id, data: buf[..n].to_vec() }).is_err() {
                        break;
                    }
                }
            }
        }
        if epoch_r.load(Ordering::SeqCst) == my_epoch {
            let _ = out2.send(Msg::Close { id });
        }
    };
    let writer = async move {
        while let Some(m) = rx.recv().await {
            match m {
                Msg::Data { data, .. } => {
                    if w.write_all(&data).await.is_err() {
                        break;
                    }
                }
                Msg::Close { .. } => break,
                _ => {}
            }
        }
        let _ = w.shutdown().await;
    };
    tokio::select! { _ = reader => {}, _ = writer => {} }
    cleanup();
    vlog!("back: [{id}] fermé");
}

/// Nouvelle session front (ou resynchronisation) : tout ce qui concernait l'ancienne est jeté.
fn back_reset(
    streams: &Streams,
    epoch: &AtomicU64,
    pending: &mut VecDeque<Msg>,
    out_rx: &mut mpsc::UnboundedReceiver<Msg>,
    codec: &mut Codec,
) {
    epoch.fetch_add(1, Ordering::SeqCst); // les tâches de l'ancienne session se taisent
    let all: Vec<(u32, StreamCtl)> = streams.lock().unwrap().drain().collect();
    for (id, ctl) in all {
        let _ = ctl.tx.send(Msg::Close { id });
    }
    pending.clear();
    while out_rx.try_recv().is_ok() {}
    codec.reset();
}

async fn run_back(
    clip: ClipHandle,
    c: Common,
    connect_to: Option<String>,
    cipher: Option<Arc<Cipher>>,
) -> Result<()> {
    let fixed = connect_to.as_deref().map(parse_hostport).transpose()?;
    let streams: Streams = Arc::new(Mutex::new(HashMap::new()));
    let epoch = Arc::new(AtomicU64::new(0));
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Msg>();
    let bufsize = c.chunk.saturating_sub(64).clamp(256, 32768);

    let my_gen = rand64();
    let mut front_gen: u64 = 0;
    let mut codec = Codec::new(c.zlevel());
    let mut pending: VecDeque<Msg> = VecDeque::new();
    let mut last_seq: u64 = 0;
    // plus grand numéro de séquence accepté, toutes sessions confondues (anti-rejeu en mode chiffré)
    let mut max_seq_seen: u64 = 0;
    let mut cached: Option<String> = None;
    let mut last_rewrite = Instant::now();
    let mut last_text: Option<String> = None;

    match &fixed {
        Some((h, p)) => eprintln!("back: toutes les connexions → {h}:{p}"),
        None => eprintln!("back: relais TCP dynamique (destination demandée par le client)"),
    }
    eprintln!("back: session {my_gen:x}, en attente de trames…");

    loop {
        sleep(Duration::from_millis(c.poll_ms)).await;
        let Some(text) = clip.get().await else { continue };

        // contenu inchangé depuis la dernière lecture traitée : rien à refaire
        if last_text.as_deref() == Some(text.as_str()) {
            continue;
        }

        let Some(f) = parse_frame(&text, cipher.as_deref()) else {
            last_text = Some(text);
            continue;
        };

        if f.dir != 'F' {
            last_text = Some(text);
            continue;
        }

        // 1. le front parle à une ancienne incarnation de ce back
        if f.peer != 0 && f.peer != my_gen {
            eprintln!("back: trame destinée à une ancienne instance du back → resynchronisation demandée");
            last_text = Some(text);
            clip.set(make_frame('B', my_gen, f.gen, f.seq, &[F_RESET], cipher.as_deref())).await;
            continue;
        }

        // 2. nouvelle session côté front : état neuf des deux côtés
        if f.gen != front_gen {
            if cipher.is_some() && f.seq <= max_seq_seen {
                eprintln!("back: nouvelle session avec un numéro de séquence déjà dépassé → ignorée (rejeu, ou horloge du front revenue en arrière ?)");
                last_text = Some(text);
                continue;
            }

            vlog!("back: nouvelle session front {:x}", f.gen);
            back_reset(&streams, &epoch, &mut pending, &mut out_rx, &mut codec);
            front_gen = f.gen;
            last_seq = 0;
            cached = None;
        }

        // 3. doublon : réécriture de la réponse en cache
        if f.seq == last_seq {
            if last_rewrite.elapsed() > Duration::from_millis(500) {
                if let Some(fr) = &cached {
                    vlog!("back: doublon seq={}, réécriture de la réponse", f.seq);
                    clip.set(fr.clone()).await;
                    last_rewrite = Instant::now();
                }
            }
            continue;
        }

        last_text = Some(text);

        if f.seq < last_seq {
            continue;
        }

        max_seq_seen = max_seq_seen.max(f.seq);

        // 4. décodage
        let decoded = match codec.unpack(&f.wire) {
            Ok(Unpacked::Body(b)) => decode_all(&b).ok(),
            _ => None,
        };

        let wire = match decoded {
            None => {
                eprintln!("back: trame illisible (compression désynchronisée ?) → réinitialisation demandée");
                back_reset(&streams, &epoch, &mut pending, &mut out_rx, &mut codec);
                vec![F_RESET]
            }
            Some(msgs) => {
                vlog!("back: ← seq={} ({} msg)", f.seq, msgs.len());

                for m in msgs {
                    match m {
                        Msg::Open { id, host, port } => {
                            // Destination fixe si --connect-to est fourni,
                            // sinon destination demandée par le client SOCKS5.
                            let (h, p) = fixed
                                .clone()
                                .unwrap_or_else(|| (host.clone(), port));

                            let (tx, rx) = mpsc::unbounded_channel();
                            let window = Arc::new(Semaphore::new(WINDOW));

                            streams.lock().unwrap().insert(
                                id,
                                StreamCtl {
                                    tx,
                                    window: window.clone(),
                                },
                            );

                            tokio::spawn(target_task(
                                id,
                                h,
                                p,
                                rx,
                                out_tx.clone(),
                                streams.clone(),
                                window,
                                epoch.clone(),
                                epoch.load(Ordering::SeqCst),
                                bufsize,
                            ));
                        }

                        Msg::Data { id, data } => {
                            let tx = streams.lock().unwrap().get(&id).map(|s| s.tx.clone());
                            if let Some(tx) = tx {
                                let _ = tx.send(Msg::Data { id, data });
                            }
                        }

                        Msg::Close { id } => {
                            let tx = streams.lock().unwrap().get(&id).map(|s| s.tx.clone());
                            if let Some(tx) = tx {
                                let _ = tx.send(Msg::Close { id });
                            }
                        }

                        Msg::Opened { .. } => {}
                    }
                }

                while let Ok(m) = out_rx.try_recv() {
                    pending.push_back(m);
                }

                let budget = codec.budget(c.chunk);
                let resp = build_payload(&mut pending, budget, |id, n| {
                    if let Some(s) = streams.lock().unwrap().get(&id) {
                        s.window.add_permits(n);
                    }
                });

                vlog!("back: → seq={} ({} o bruts)", f.seq, resp.len());
                codec.pack(&resp)
            }
        };

        last_seq = f.seq;

        let frame = make_frame('B', my_gen, front_gen, f.seq, &wire, cipher.as_deref());
        clip.set(frame.clone()).await;
        cached = Some(frame);
        last_rewrite = Instant::now();

        // si l'écriture a été perdue, la trame du front sera encore là : on doit la reparser
        last_text = None;
    }
}

// ───────────────────────────── main ─────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    VERBOSE.store(cli.common.verbose, Ordering::Relaxed);
    if let Cmd::Keygen { out } = &cli.cmd {
        return keygen(out.clone());
    }
    let cipher = load_cipher(&cli.common)?;
    let clip = make_clip(&cli.common)?;
    match cli.cmd {
        Cmd::Front { listen } => run_front(clip, cli.common, listen, cipher).await,
        Cmd::Back { connect_to } => run_back(clip, cli.common, connect_to, cipher).await,
        Cmd::Keygen { .. } => unreachable!(),
    }
}