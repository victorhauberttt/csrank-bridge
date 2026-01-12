/**
 * CSRank Bridge Server
 *
 * Responsabilidades:
 * 1. Receber webhooks do MatchZy com stats das partidas
 * 2. Processar login Steam via OpenID 2.0
 * 3. Sincronizar dados com Firebase
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const axios = require('axios');

const app = express();
app.set('trust proxy', 1);

const PORT = process.env.PORT || 3000;
const STEAM_API_KEY = process.env.STEAM_API_KEY;

// Inicializar Firebase Admin
let firebaseCredential;

if (process.env.FIREBASE_SERVICE_ACCOUNT) {
  const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
  firebaseCredential = admin.credential.cert(serviceAccount);
} else {
  const serviceAccount = require('./firebase-service-account.json');
  firebaseCredential = admin.credential.cert(serviceAccount);
}

admin.initializeApp({
  credential: firebaseCredential
});
const db = admin.firestore();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ============================================
// STEAM AUTHENTICATION (OpenID 2.0 Manual)
// ============================================

function getBaseUrl(req) {
  const protocol = req.protocol;
  const host = req.get('host');
  return `${protocol}://${host}`;
}

// Iniciar login Steam - redireciona para Steam OpenID
app.get('/auth/steam', (req, res) => {
  const baseUrl = getBaseUrl(req);
  const returnUrl = `${baseUrl}/auth/steam/callback`;

  console.log(`[AUTH] Starting Steam auth`);
  console.log(`[AUTH] Base URL: ${baseUrl}`);
  console.log(`[AUTH] Return URL: ${returnUrl}`);

  // Construir URL do Steam OpenID manualmente
  const params = new URLSearchParams({
    'openid.ns': 'http://specs.openid.net/auth/2.0',
    'openid.mode': 'checkid_setup',
    'openid.return_to': returnUrl,
    'openid.realm': baseUrl,
    'openid.identity': 'http://specs.openid.net/auth/2.0/identifier_select',
    'openid.claimed_id': 'http://specs.openid.net/auth/2.0/identifier_select',
  });

  const steamLoginUrl = `https://steamcommunity.com/openid/login?${params.toString()}`;
  console.log(`[AUTH] Redirecting to Steam...`);

  res.redirect(steamLoginUrl);
});

// Callback do Steam - verifica a asserção OpenID
app.get('/auth/steam/callback', async (req, res) => {
  const baseUrl = getBaseUrl(req);

  console.log(`[AUTH] Steam callback received`);
  console.log(`[AUTH] Mode: ${req.query['openid.mode']}`);

  // Verificar se o usuário cancelou
  if (req.query['openid.mode'] === 'cancel') {
    console.log('[AUTH] User cancelled');
    return res.send(`
      <html>
        <body style="background:#1a1a2e;color:white;font-family:Arial;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;">
          <div style="text-align:center;">
            <h1>Login Cancelado</h1>
            <p>Feche esta janela e tente novamente.</p>
          </div>
        </body>
      </html>
    `);
  }

  // Processar a resposta da Steam
  try {
    // Verificar se temos os parâmetros necessários
    const claimedId = req.query['openid.claimed_id'];
    const sig = req.query['openid.sig'];
    const mode = req.query['openid.mode'];

    console.log('[AUTH] Processing callback - mode:', mode, 'sig:', !!sig, 'claimed_id:', claimedId);

    if (mode !== 'id_res' || !claimedId || !sig) {
      console.error('[AUTH] Invalid callback params');
      return res.status(400).send('Invalid callback');
    }

    // Verificar que o claimed_id é do Steam
    if (!claimedId.startsWith('https://steamcommunity.com/openid/id/')) {
      console.error('[AUTH] Invalid claimed_id:', claimedId);
      return res.status(400).send('Invalid Steam ID');
    }

    // Extrair SteamID64 do claimed_id
    const steamId = claimedId.replace('https://steamcommunity.com/openid/id/', '');

    // Validar que é um SteamID64 válido (17 dígitos)
    if (!/^\d{17}$/.test(steamId)) {
      console.error('[AUTH] Invalid steamId format:', steamId);
      return res.status(400).send('Invalid Steam ID format');
    }

    console.log('[AUTH] Steam login successful for:', steamId);

    // Buscar dados do perfil Steam
    const profileData = await getSteamProfile(steamId);

    // Criar/atualizar usuário no Firebase
    await db.collection('users').doc(steamId).set({
      steamId: steamId,
      personaName: profileData.personaname,
      avatarUrl: profileData.avatarfull,
      avatarMedium: profileData.avatarmedium,
      profileUrl: profileData.profileurl,
      lastLogin: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });

    // Verificar se é novo usuário
    const userDoc = await db.collection('users').doc(steamId).get();
    if (!userDoc.data().createdAt) {
      await db.collection('users').doc(steamId).update({
        createdAt: admin.firestore.FieldValue.serverTimestamp()
      });
    }

    // Gerar custom token para o app
    const customToken = await admin.auth().createCustomToken(steamId, {
      steamId: steamId,
      personaName: profileData.personaname
    });

    // Redirecionar para URL scheme do Flutter
    const params = new URLSearchParams({
      token: customToken,
      steamId: steamId,
      personaName: profileData.personaname,
      avatarUrl: profileData.avatarfull
    });

    const redirectUrl = `csrank://auth/success?${params.toString()}`;
    console.log('[AUTH] Redirecting to app...');

    res.redirect(redirectUrl);

  } catch (err) {
    console.error('[AUTH] Error:', err.message);
    res.status(500).send(`
      <html>
        <body style="background:#1a1a2e;color:white;font-family:Arial;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;">
          <div style="text-align:center;">
            <h1 style="color:#ff6b6b;">Erro no Servidor</h1>
            <p>${err.message}</p>
          </div>
        </body>
      </html>
    `);
  }
});

// API para obter token
app.get('/auth/token/:steamId', async (req, res) => {
  try {
    const { steamId } = req.params;

    const userDoc = await db.collection('users').doc(steamId).get();
    if (!userDoc.exists) {
      return res.status(404).json({ error: 'User not found' });
    }

    const customToken = await admin.auth().createCustomToken(steamId);
    res.json({ token: customToken });

  } catch (err) {
    console.error('Error generating token:', err);
    res.status(500).json({ error: 'Failed to generate token' });
  }
});

// ============================================
// MATCHZY WEBHOOK
// ============================================

app.post('/api/matchzy/webhook', async (req, res) => {
  console.log('Received MatchZy webhook:', JSON.stringify(req.body, null, 2));

  try {
    const data = req.body;
    const eventType = data.event;

    switch (eventType) {
      case 'match_end':
      case 'series_end':
        await processMatchEnd(data);
        break;
      case 'round_end':
        console.log('Round ended, waiting for match end...');
        break;
      case 'map_result':
        await processMapResult(data);
        break;
      default:
        console.log('Unknown event type:', eventType);
    }

    res.json({ success: true });

  } catch (err) {
    console.error('Error processing webhook:', err);
    res.status(500).json({ error: 'Failed to process webhook' });
  }
});

async function processMatchEnd(data) {
  console.log('Processing match end...');

  const matchId = data.matchid || `match_${Date.now()}`;
  const mapName = data.map_name || data.map || 'unknown';

  const team1 = data.team1 || data.params?.team1 || {};
  const team2 = data.team2 || data.params?.team2 || {};

  const scoreTeam1 = team1.score || team1.series_score || 0;
  const scoreTeam2 = team2.score || team2.series_score || 0;

  const matchData = {
    matchzyId: matchId,
    map: mapName,
    team1Name: team1.name || 'Team 1',
    team2Name: team2.name || 'Team 2',
    scoreTeam1: scoreTeam1,
    scoreTeam2: scoreTeam2,
    isDraw: scoreTeam1 === scoreTeam2,
    winner: scoreTeam1 > scoreTeam2 ? 1 : (scoreTeam2 > scoreTeam1 ? 2 : 0),
    date: admin.firestore.FieldValue.serverTimestamp(),
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    rawData: data
  };

  await db.collection('matches').doc(matchId).set(matchData);
  console.log('Match saved:', matchId);

  const allPlayers = [
    ...(team1.players || []).map(p => ({ ...p, team: 1 })),
    ...(team2.players || []).map(p => ({ ...p, team: 2 }))
  ];

  for (const player of allPlayers) {
    await processPlayerStats(matchId, player, matchData);
  }

  console.log('Match processing complete!');
}

async function processMapResult(data) {
  await processMatchEnd(data);
}

async function processPlayerStats(matchId, player, matchData) {
  const steamId = player.steamid || player.steam_id;
  if (!steamId) {
    console.log('Player without steamId:', player);
    return;
  }

  const statsId = `${matchId}_${steamId}`;

  const stats = {
    matchId: matchId,
    oderId: steamId,
    odertId: steamId,
    oderne: player.name || 'Unknown',
    team: player.team,
    teamName: player.team === 1 ? matchData.team1Name : matchData.team2Name,
    isWinner: matchData.winner === player.team,

    kills: player.kills || player.stats?.kills || 0,
    deaths: player.deaths || player.stats?.deaths || 0,
    assists: player.assists || player.stats?.assists || 0,

    adr: player.adr || player.stats?.adr || 0,
    kast: player.kast || player.stats?.kast || 0,
    rating: player.rating || player.stats?.rating || 0,

    headshots: player.headshot_kills || player.stats?.headshot_kills || 0,
    headshotPercent: calculateHSPercent(player),

    mvps: player.mvps || player.stats?.mvps || 0,
    utilityDamage: player.utility_damage || player.stats?.utility_damage || 0,
    enemiesFlashed: player.enemies_flashed || player.stats?.enemies_flashed || 0,
    flashAssists: player.flash_assists || player.stats?.flash_assists || 0,

    plants: player.bomb_plants || player.stats?.bomb_plants || 0,
    defuses: player.bomb_defuses || player.stats?.bomb_defuses || 0,

    firstKills: player.first_kills || player.stats?.first_kills || 0,
    firstDeaths: player.first_deaths || player.stats?.first_deaths || 0,

    clutchesWon: player.clutches_won || player.stats?.clutches_won || 0,

    damage: player.damage || player.stats?.damage || 0,

    map: matchData.map,
    date: admin.firestore.FieldValue.serverTimestamp()
  };

  await db.collection('matchStats').doc(statsId).set(stats);
  console.log(`Stats saved for ${player.name} (${steamId})`);

  const userDoc = await db.collection('users').doc(steamId).get();
  if (userDoc.exists) {
    await updatePlayerAggregatedStats(steamId);
  }
}

function calculateHSPercent(player) {
  const kills = player.kills || player.stats?.kills || 0;
  const hsKills = player.headshot_kills || player.stats?.headshot_kills || 0;
  if (kills === 0) return 0;
  return Math.round((hsKills / kills) * 100);
}

async function updatePlayerAggregatedStats(steamId) {
  try {
    const statsSnapshot = await db.collection('matchStats')
      .where('oderId', '==', steamId)
      .get();

    if (statsSnapshot.empty) return;

    let totalKills = 0, totalDeaths = 0, totalAssists = 0;
    let totalAdr = 0, totalRating = 0, totalHsPercent = 0;
    let wins = 0, losses = 0, draws = 0;
    let totalMvps = 0, totalPlants = 0, totalDefuses = 0;
    let totalClutches = 0, totalFirstKills = 0, totalFirstDeaths = 0;
    let totalUtilityDamage = 0, totalEnemiesFlashed = 0, totalFlashAssists = 0;
    let totalKast = 0;
    let matchCount = 0;

    statsSnapshot.forEach(doc => {
      const s = doc.data();
      totalKills += s.kills || 0;
      totalDeaths += s.deaths || 0;
      totalAssists += s.assists || 0;
      totalAdr += s.adr || 0;
      totalRating += s.rating || 0;
      totalHsPercent += s.headshotPercent || 0;
      totalMvps += s.mvps || 0;
      totalPlants += s.plants || 0;
      totalDefuses += s.defuses || 0;
      totalClutches += s.clutchesWon || 0;
      totalFirstKills += s.firstKills || 0;
      totalFirstDeaths += s.firstDeaths || 0;
      totalUtilityDamage += s.utilityDamage || 0;
      totalEnemiesFlashed += s.enemiesFlashed || 0;
      totalFlashAssists += s.flashAssists || 0;
      totalKast += s.kast || 0;

      if (s.isWinner === true) wins++;
      else if (s.isWinner === false) losses++;
      else draws++;

      matchCount++;
    });

    const aggregated = {
      totalMatches: matchCount,
      totalKills,
      totalDeaths,
      totalAssists,
      kdRatio: totalDeaths > 0 ? (totalKills / totalDeaths).toFixed(2) : totalKills,
      avgAdr: matchCount > 0 ? (totalAdr / matchCount).toFixed(1) : 0,
      avgRating: matchCount > 0 ? (totalRating / matchCount).toFixed(2) : 0,
      avgHsPercent: matchCount > 0 ? (totalHsPercent / matchCount).toFixed(1) : 0,
      avgKast: matchCount > 0 ? (totalKast / matchCount).toFixed(1) : 0,
      wins,
      losses,
      draws,
      winRate: matchCount > 0 ? ((wins / matchCount) * 100).toFixed(1) : 0,
      totalMvps,
      totalPlants,
      totalDefuses,
      totalClutches,
      totalFirstKills,
      totalFirstDeaths,
      totalUtilityDamage,
      totalEnemiesFlashed,
      totalFlashAssists,
      lastUpdated: admin.firestore.FieldValue.serverTimestamp()
    };

    await db.collection('users').doc(steamId).update({
      aggregatedStats: aggregated
    });

    console.log(`Aggregated stats updated for ${steamId}`);

  } catch (err) {
    console.error('Error updating aggregated stats:', err);
  }
}

// ============================================
// UTILITY ENDPOINTS
// ============================================

app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    version: '2.2.0'
  });
});

async function getSteamProfile(steamId) {
  const url = `https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/?key=${STEAM_API_KEY}&steamids=${steamId}`;
  const response = await axios.get(url);
  return response.data.response.players[0];
}

app.get('/api/steam/profile/:steamId', async (req, res) => {
  try {
    const profile = await getSteamProfile(req.params.steamId);
    res.json(profile);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// ============================================
// START SERVER
// ============================================

app.listen(PORT, () => {
  console.log('');
  console.log('╔══════════════════════════════════════════════════════════════╗');
  console.log('║              CSRank Bridge Server v2.1                       ║');
  console.log('║              (Manual OpenID 2.0)                             ║');
  console.log('╠══════════════════════════════════════════════════════════════╣');
  console.log(`║  Port: ${PORT}                                                    ║`);
  console.log(`║  Steam API Key: ${STEAM_API_KEY ? 'Configured' : 'MISSING!'}                              ║`);
  console.log('║                                                              ║');
  console.log('║  Endpoints:                                                  ║');
  console.log('║  - GET  /auth/steam          - Iniciar login Steam           ║');
  console.log('║  - GET  /auth/steam/callback - Callback do Steam             ║');
  console.log('║  - POST /api/matchzy/webhook - Webhook do MatchZy            ║');
  console.log('║  - GET  /health              - Health check                  ║');
  console.log('╚══════════════════════════════════════════════════════════════╝');
  console.log('');
});
