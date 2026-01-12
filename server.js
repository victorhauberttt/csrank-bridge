/**
 * CSRank Bridge Server
 *
 * Responsabilidades:
 * 1. Receber webhooks do MatchZy com stats das partidas
 * 2. Processar login Steam via OpenID 2.0 (usando passport-steam)
 * 3. Sincronizar dados com Firebase
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const session = require('express-session');
const passport = require('passport');
const SteamStrategy = require('passport-steam').Strategy;
const admin = require('firebase-admin');
const axios = require('axios');

const app = express();
// IMPORTANTE: Necessário para o Render (que usa proxy reverso HTTPS)
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

// Session para passport (necessário mas não usamos para persistir)
app.use(session({
  secret: process.env.SESSION_SECRET || 'csrank-steam-auth-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // Não precisamos de cookie seguro pois não persistimos sessão
}));

app.use(passport.initialize());

// Passport serialization (mínimo necessário)
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// ============================================
// STEAM AUTHENTICATION (usando passport-steam)
// ============================================

// Configurar estratégia Steam dinamicamente baseado no request
function getBaseUrl(req) {
  const protocol = req.protocol;
  const host = req.get('host');
  return `${protocol}://${host}`;
}

// Iniciar login Steam
app.get('/auth/steam', (req, res, next) => {
  const baseUrl = getBaseUrl(req);
  console.log(`[AUTH] Starting Steam auth with realm: ${baseUrl}`);

  // Criar estratégia dinamicamente com a URL correta
  const strategy = new SteamStrategy({
    returnURL: `${baseUrl}/auth/steam/callback`,
    realm: baseUrl,
    apiKey: STEAM_API_KEY
  }, (identifier, profile, done) => {
    // Extrair steamId do identifier
    const steamId = identifier.replace('https://steamcommunity.com/openid/id/', '');
    profile.steamId = steamId;
    return done(null, profile);
  });

  // Registrar estratégia temporária
  passport.use('steam-dynamic', strategy);

  // Autenticar
  passport.authenticate('steam-dynamic')(req, res, next);
});

// Callback do Steam
app.get('/auth/steam/callback', (req, res, next) => {
  const baseUrl = getBaseUrl(req);
  console.log(`[AUTH] Steam callback received at: ${baseUrl}`);
  console.log(`[AUTH] Query params:`, req.query);
  console.log(`[AUTH] STEAM_API_KEY configured:`, !!STEAM_API_KEY);

  // Recriar estratégia com a mesma URL
  const strategy = new SteamStrategy({
    returnURL: `${baseUrl}/auth/steam/callback`,
    realm: baseUrl,
    apiKey: STEAM_API_KEY
  }, (identifier, profile, done) => {
    const steamId = identifier.replace('https://steamcommunity.com/openid/id/', '');
    profile.steamId = steamId;
    return done(null, profile);
  });

  passport.use('steam-dynamic', strategy);

  passport.authenticate('steam-dynamic', { session: false }, async (err, user, info) => {
    console.log('[AUTH] authenticate callback - err:', err?.message, 'user:', !!user, 'info:', info);

    if (err) {
      console.error('[AUTH] Steam auth error:', err.message, err.stack);
      return res.status(401).send(`
        <html>
          <body style="background:#1a1a2e;color:white;font-family:Arial;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;">
            <div style="text-align:center;">
              <h1 style="color:#ff6b6b;">Erro no Login</h1>
              <p>dados incorretos</p>
              <p style="color:#aaa;font-size:12px;">${err.message || 'Authentication failed'}</p>
            </div>
          </body>
        </html>
      `);
    }

    if (!user) {
      console.error('[AUTH] No user returned from Steam');
      return res.status(401).send(`
        <html>
          <body style="background:#1a1a2e;color:white;font-family:Arial;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;">
            <div style="text-align:center;">
              <h1 style="color:#ff6b6b;">Erro no Login</h1>
              <p>Autenticação cancelada ou falhou</p>
            </div>
          </body>
        </html>
      `);
    }

    const steamId = user.steamId || user.id;
    console.log('[AUTH] Steam login successful for:', steamId);

    try {
      // Buscar dados do perfil Steam (passport-steam já fornece alguns)
      const profileData = user._json || await getSteamProfile(steamId);

      // Criar/atualizar usuário no Firebase
      await db.collection('users').doc(steamId).set({
        steamId: steamId,
        personaName: profileData.personaname || user.displayName,
        avatarUrl: profileData.avatarfull || user.photos?.[2]?.value,
        avatarMedium: profileData.avatarmedium || user.photos?.[1]?.value,
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
        personaName: profileData.personaname || user.displayName
      });

      // Redirecionar para URL scheme do Flutter
      const params = new URLSearchParams({
        token: customToken,
        steamId: steamId,
        personaName: profileData.personaname || user.displayName,
        avatarUrl: profileData.avatarfull || user.photos?.[2]?.value || ''
      });

      const redirectUrl = `csrank://auth/success?${params.toString()}`;
      console.log('[AUTH] Redirecting to app...');

      res.redirect(redirectUrl);

    } catch (err) {
      console.error('[AUTH] Error processing Steam login:', err);
      res.status(500).send(`
        <html>
          <body style="background:#1a1a2e;color:white;font-family:Arial;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;">
            <div style="text-align:center;">
              <h1 style="color:#ff6b6b;">Erro no Servidor</h1>
              <p>Não foi possível processar o login</p>
              <p style="color:#aaa;font-size:12px;">${err.message}</p>
            </div>
          </body>
        </html>
      `);
    }
  })(req, res, next);
});

// API para obter token (usado pelo app após callback)
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
    version: '2.0.0'
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
  console.log('║              CSRank Bridge Server v2.0                       ║');
  console.log('║              (using passport-steam)                          ║');
  console.log('╠══════════════════════════════════════════════════════════════╣');
  console.log(`║  Port: ${PORT}                                                    ║`);
  console.log('║                                                              ║');
  console.log('║  Endpoints:                                                  ║');
  console.log('║  - GET  /auth/steam          - Iniciar login Steam           ║');
  console.log('║  - GET  /auth/steam/callback - Callback do Steam             ║');
  console.log('║  - POST /api/matchzy/webhook - Webhook do MatchZy            ║');
  console.log('║  - GET  /health              - Health check                  ║');
  console.log('╚══════════════════════════════════════════════════════════════╝');
  console.log('');
});
