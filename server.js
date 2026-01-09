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
const { RelyingParty } = require('openid');

const app = express();
const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const STEAM_API_KEY = process.env.STEAM_API_KEY;

// Inicializar Firebase Admin
let firebaseCredential;

// Verificar se está usando variável de ambiente (deploy na nuvem) ou arquivo local
if (process.env.FIREBASE_SERVICE_ACCOUNT) {
  // Na nuvem: usar variável de ambiente (JSON string)
  const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
  firebaseCredential = admin.credential.cert(serviceAccount);
} else {
  // Local: usar arquivo
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

// Configurar OpenID para Steam
const steamOpenId = new RelyingParty(
  `${BASE_URL}/auth/steam/callback`, // Callback URL
  BASE_URL, // Realm
  true, // Stateless
  false, // Strict mode
  [] // Extensions
);

// ============================================
// STEAM AUTHENTICATION
// ============================================

// Iniciar login Steam
app.get('/auth/steam', (req, res) => {
  const returnUrl = req.query.returnUrl || '';

  steamOpenId.authenticate(
    'https://steamcommunity.com/openid',
    false,
    (error, authUrl) => {
      if (error) {
        console.error('Steam auth error:', error);
        return res.status(500).json({ error: 'Failed to authenticate with Steam' });
      }

      if (!authUrl) {
        return res.status(500).json({ error: 'No auth URL generated' });
      }

      // Salvar returnUrl em state parameter
      const finalUrl = authUrl + (returnUrl ? `&state=${encodeURIComponent(returnUrl)}` : '');
      res.redirect(finalUrl);
    }
  );
});

// Callback do Steam
app.get('/auth/steam/callback', async (req, res) => {
  steamOpenId.verifyAssertion(req, async (error, result) => {
    if (error || !result.authenticated) {
      console.error('Steam verification failed:', error);
      return res.status(401).send(`
        <html>
          <body style="background:#1a1a2e;color:white;font-family:Arial;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;">
            <div style="text-align:center;">
              <h1 style="color:#ff6b6b;">Erro no Login</h1>
              <p>Não foi possível verificar sua conta Steam.</p>
              <p>Feche esta janela e tente novamente.</p>
            </div>
          </body>
        </html>
      `);
    }

    // Extrair SteamID64 da URL retornada
    const steamId = result.claimedIdentifier.replace('https://steamcommunity.com/openid/id/', '');
    console.log('Steam login successful for:', steamId);

    try {
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

      // Retornar página de sucesso com token
      res.send(`
        <html>
          <head>
            <title>CSRank - Login Sucesso</title>
          </head>
          <body style="background:#1a1a2e;color:white;font-family:Arial;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;">
            <div style="text-align:center;">
              <img src="${profileData.avatarfull}" style="border-radius:50%;width:100px;height:100px;border:3px solid #f39c12;">
              <h1 style="color:#2ecc71;">Bem-vindo, ${profileData.personaname}!</h1>
              <p>Login realizado com sucesso.</p>
              <p style="color:#888;">Você pode fechar esta janela.</p>
              <script>
                // Dados de autenticacao
                const authData = JSON.stringify({
                  token: '${customToken}',
                  steamId: '${steamId}',
                  personaName: '${profileData.personaname.replace(/'/g, "\\'")}',
                  avatarUrl: '${profileData.avatarfull}'
                });

                // Enviar via JavaScript channel (WebView Flutter) - metodo principal
                if (window.CSRankAuth) {
                  window.CSRankAuth.postMessage(authData);
                }
              </script>
            </div>
          </body>
        </html>
      `);

    } catch (err) {
      console.error('Error processing Steam login:', err);
      res.status(500).send('Error processing login');
    }
  });
});

// API para obter token (usado pelo app após callback)
app.get('/auth/token/:steamId', async (req, res) => {
  try {
    const { steamId } = req.params;
    const { signature } = req.query;

    // Verificar se usuário existe
    const userDoc = await db.collection('users').doc(steamId).get();
    if (!userDoc.exists) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Gerar novo token
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

  // Extrair informações do time
  const team1 = data.team1 || data.params?.team1 || {};
  const team2 = data.team2 || data.params?.team2 || {};

  const scoreTeam1 = team1.score || team1.series_score || 0;
  const scoreTeam2 = team2.score || team2.series_score || 0;

  // Criar documento da partida
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

  // Processar stats dos jogadores
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
  // Similar ao processMatchEnd mas para resultado de mapa individual
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
    odertId: steamId, // duplicate for compatibility
    oderne: player.name || 'Unknown',
    team: player.team,
    teamName: player.team === 1 ? matchData.team1Name : matchData.team2Name,
    isWinner: matchData.winner === player.team,

    // Stats principais
    kills: player.kills || player.stats?.kills || 0,
    deaths: player.deaths || player.stats?.deaths || 0,
    assists: player.assists || player.stats?.assists || 0,

    // Stats avancadas
    adr: player.adr || player.stats?.adr || 0,
    kast: player.kast || player.stats?.kast || 0,
    rating: player.rating || player.stats?.rating || 0,

    // Headshots
    headshots: player.headshot_kills || player.stats?.headshot_kills || 0,
    headshotPercent: calculateHSPercent(player),

    // MVPs e utilidades
    mvps: player.mvps || player.stats?.mvps || 0,
    utilityDamage: player.utility_damage || player.stats?.utility_damage || 0,
    enemiesFlashed: player.enemies_flashed || player.stats?.enemies_flashed || 0,
    flashAssists: player.flash_assists || player.stats?.flash_assists || 0,

    // Objetivos
    plants: player.bomb_plants || player.stats?.bomb_plants || 0,
    defuses: player.bomb_defuses || player.stats?.bomb_defuses || 0,

    // First kills
    firstKills: player.first_kills || player.stats?.first_kills || 0,
    firstDeaths: player.first_deaths || player.stats?.first_deaths || 0,

    // Clutches
    clutchesWon: player.clutches_won || player.stats?.clutches_won || 0,

    // Damage
    damage: player.damage || player.stats?.damage || 0,

    // Meta
    map: matchData.map,
    date: admin.firestore.FieldValue.serverTimestamp()
  };

  await db.collection('matchStats').doc(statsId).set(stats);
  console.log(`Stats saved for ${player.name} (${steamId})`);

  // Atualizar perfil do jogador se ele estiver cadastrado
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

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

// Obter perfil Steam
async function getSteamProfile(steamId) {
  const url = `https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/?key=${STEAM_API_KEY}&steamids=${steamId}`;
  const response = await axios.get(url);
  return response.data.response.players[0];
}

// API para buscar perfil (usado pelo app)
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
  console.log('║                    CSRank Bridge Server                      ║');
  console.log('╠══════════════════════════════════════════════════════════════╣');
  console.log(`║  Server running on: http://localhost:${PORT}                    ║`);
  console.log('║                                                              ║');
  console.log('║  Endpoints:                                                  ║');
  console.log('║  - GET  /auth/steam          - Iniciar login Steam           ║');
  console.log('║  - GET  /auth/steam/callback - Callback do Steam             ║');
  console.log('║  - POST /api/matchzy/webhook - Webhook do MatchZy            ║');
  console.log('║  - GET  /health              - Health check                  ║');
  console.log('╚══════════════════════════════════════════════════════════════╝');
  console.log('');
});
