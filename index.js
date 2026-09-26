const { callGeminiWithRetry } = require('./geminiRetry');
require('dotenv').config();

const {Pool} = require('pg');
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const axios = require('axios');
const {GoogleGenerativeAI} = require('@google/generative-ai');
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY); 

const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const express = require('express');
const app = express();

app.use(cors());
app.use(express.json());

//function for domain analyzingg
async function analyzeDomain(domain) {
  const response = await axios.get(`https://www.virustotal.com/api/v3/domains/${domain}`, 
    {headers: {'x-apikey': process.env.VT_API_KEY}}
  );
  const data = response.data.data.attributes;
  const summary = {
    domain: domain,
        malicious: data.last_analysis_stats.malicious,
        suspicious: data.last_analysis_stats.suspicious,
        harmless: data.last_analysis_stats.harmless,
        undetected: data.last_analysis_stats.undetected,
        reputation: data.reputation,
        creation_date: data.creation_date
  };
  const model = genAI.getGenerativeModel({model: 'gemini-3.6-flash'});
  const prompt =  `You are a security analyst assistant. Given this threat intel data for domain ${domain}:
    ${JSON.stringify(summary)}
    
    Respond ONLY in JSON with this exact structure:
    {"risk_level": "low/medium/high/critical", "explanation": "1-2 sentence plain-English reasoning", "recommended_action": "ignore/monitor/escalate/block"}`;

    const text = await callGeminiWithRetry(model, prompt);
    const verdict = JSON.parse(text.replace(/```json|```/g, '').trim());

    return {summary, verdict};
  
}

//authorization func
function requireAuth(req, res, next){
  const authHeader = req.headers.authorization;

  if(!authHeader){
    return res.status(401).json({error: 'No token provided'});
  }
  const token = authHeader.split(' ')[1];

  try{
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next();
  }
  catch(error){
    return res.status(401).json({error: 'Invalid token or expired token'});
  }
}

//signup
app.post('/signup', async (req, res)=>{
  const {email, password} = req.body;
  try{
    const password_hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email',
      [email, password_hash]
    );
    res.json({user: result.rows[0]});
  }
  catch(error){
    console.log(error.message);
    res.status(500).json({error: 'Signup failed (email might already be taken)'});
  }
}
);

//login 
app.post('/login', async (req, res)=>{
  const {email, password} = req.body;
  try{
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    if(!user){
      return res.status(401).json({error: 'invalid email or password'});
    }
    const passwordMatch = await bcrypt.compare(password, user.password_hash);

    if(!passwordMatch){
      return res.status(401).json({error: 'invalid email or password'});
    }
    const token = jwt.sign({userId: user.id}, process.env.JWT_SECRET , {expiresIn: '1h'});
    res.json({token});
  }
  catch(error){
    console.log(error.message);
    res.status(500).json({error: 'Failed to login:('})
  }
}

);

//function for url analyzing
async function analyzeUrl(targetUrl) {
  const submitResponse = await axios.post(
    'https://www.virustotal.com/api/v3/urls',
    `url=${encodeURIComponent(targetUrl)}`,
    {
      headers: {
        'x-apikey': process.env.VT_API_KEY,
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    }
  );
  const analysisId = submitResponse.data.data.id;

  const resultResponse = await axios.get(
    `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
    { headers: { 'x-apikey': process.env.VT_API_KEY } }
  );
  const stats = resultResponse.data.data.attributes.stats;
  const summary = {
    url: targetUrl,
    malicious: stats.malicious,
    suspicious: stats.suspicious,
    harmless: stats.harmless,
    undetected: stats.undetected
  };
  const model = genAI.getGenerativeModel({model: 'gemini-3.6-flash'});
  const prompt =  `You are a security analyst assistant. Given this threat intel data for url ${targetUrl}:
    ${JSON.stringify(summary)}
    
    Respond ONLY in JSON with this exact structure:
    {"risk_level": "low/medium/high/critical", "explanation": "1-2 sentence plain-English reasoning", "recommended_action": "ignore/monitor/escalate/block"}`;

    const text = await callGeminiWithRetry(model, prompt);
    const verdict = JSON.parse(text.replace(/```json|```/g, '').trim());

    return {summary, verdict};
}
//function for hash analyzingg
async function analyzeHash(hash) {
  const response = await axios.get(`https://www.virustotal.com/api/v3/files/${hash}`, {
    headers: {'x-apikey': process.env.VT_API_KEY}
  });
  const data = response.data.data.attributes;
  const summary = {
    hash: hash,
    malicious: data.last_analysis_stats.malicious,
    suspicious: data.last_analysis_stats.suspicious,
    harmless: data.last_analysis_stats.harmless,
    undetected: data.last_analysis_stats.undetected,
    reputation: data.reputation,
    first_submission_date: data.first_submission_date
  };
  const model = genAI.getGenerativeModel({model: 'gemini-3.6-flash'});
  const prompt =  `You are a security analyst assistant. Given this threat intel data for hash ${hash}:
    ${JSON.stringify(summary)}
    
    Respond ONLY in JSON with this exact structure:
    {"risk_level": "low/medium/high/critical", "explanation": "1-2 sentence plain-English reasoning", "recommended_action": "ignore/monitor/escalate/block"}`;

    const text = await callGeminiWithRetry(model, prompt);
    const verdict = JSON.parse(text.replace(/```json|```/g, '').trim());
  
    return{summary, verdict};
}
app.get('/check-ip/:ip', requireAuth, async (req, res) => {
  const ip = req.params.ip;
  try {
    const response = await axios.get(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
      headers: { 'x-apikey': process.env.VT_API_KEY }
    });
    const data = response.data.data.attributes;
    const summary = {
        ip: ip,
        malicious: data.last_analysis_stats.malicious,
        suspicious: data.last_analysis_stats.suspicious,
        harmless: data.last_analysis_stats.harmless,
        undetected: data.last_analysis_stats.undetected,
        reputation: data.reputation,
        country: data.country
    };
    const model = genAI.getGenerativeModel({ model: 'gemini-3.6-flash' });

    const prompt = `You are a security analyst assistant. Given this threat intel data for IP ${ip}:
    ${JSON.stringify(summary)}
    
    Respond ONLY in JSON with this exact structure:
    {"risk_level": "low/medium/high/critical", "explanation": "1-2 sentence plain-English reasoning", "recommended_action": "ignore/monitor/escalate/block"}`;

    const text = await callGeminiWithRetry(model, prompt);
    const verdict = JSON.parse(text.replace(/```json|```/g, '').trim());

    await pool.query(
      'INSERT INTO checks(indicator_type, indicator_value, summary, verdict, user_id) VALUES ($1, $2, $3, $4, $5)',
      ['ip', ip, summary, verdict, req.userId]
    );

    res.json({ summary, verdict });

  } catch (error) {
    console.log(error.response?.data || error.message);
    if(error.response?.status === 429){
      return res.status(429).json({error: "Rate limit reached. Please wait a moment and try again later."});
    }
     if (error.isGeminiUnavailable) {
    return res.status(503).json({ error: error.message });
    }
    if (error.response?.status === 404) {
  return res.status(404).json({ error: 'No VirusTotal record found for this indicator.', notFound: true });
}
    res.status(500).json({ error: 'Failed to check IP' });
  }
});

app.get('/check-url', requireAuth, async(req, res)=> {
  try{
    const result = await analyzeUrl(req.query.url);
    await pool.query(
      'INSERT INTO checks(indicator_type, indicator_value, summary, verdict, user_id) VALUES ($1, $2, $3, $4, $5)',
      ['url', req.query.url, result.summary, result.verdict, req.userId]
    );
    res.json(result);
  }
  catch(error){
    console.log(error.response?.data || error.message);
    if(error.response?.status === 429){
      return res.status(429).json({error: "Rate limit reached. Please wait a moment and try again later."});
    }
    if (error.isGeminiUnavailable) {
    return res.status(503).json({ error: error.message });
  }
    if (error.response?.status === 404) {
  return res.status(404).json({ error: 'No VirusTotal record found for this indicator.', notFound: true });
}
    res.status(500).json({error: 'failed to check URL'});
  }
});

app.get('/check-domain/:domain', requireAuth, async (req, res) => {
  try{
    const result = await analyzeDomain(req.params.domain);
    await pool.query(
      'INSERT INTO checks(indicator_type, indicator_value, summary, verdict, user_id) VALUES ($1, $2, $3, $4, $5)',
      ['domain', req.params.domain, result.summary, result.verdict, req.userId]
    );
    res.json(result);
  }
  catch (error) {
    console.log(error.response?.data || error.message);
    if(error.response?.status === 429){
      return res.status(429).json({error: "Rate limit reached. Please wait a moment and try again later."});
    }
    if (error.isGeminiUnavailable) {
    return res.status(503).json({ error: error.message });
  }
    if (error.response?.status === 404) {
  return res.status(404).json({ error: 'No VirusTotal record found for this indicator.', notFound: true });
}
    res.status(500).json({ error: 'Failed to check the domain' });
  }
});

app.get('/check-hash/:hash', requireAuth, async (req, res) => {
  try {
    const result = await analyzeHash(req.params.hash);
    await pool.query(
      'INSERT INTO checks(indicator_type, indicator_value, summary, verdict, user_id) VALUES ($1, $2, $3, $4, $5)',
      ['hash', req.params.hash, result.summary, result.verdict, req.userId]
    );
    res.json(result);

  } catch (error) {
    console.log(error.response?.data || error.message);
    if(error.response?.status === 429){
      return res.status(429).json({error: "Rate limit reached. Please wait a moment and try again later."});
    }
    if (error.response?.status === 404) {
  return res.status(404).json({ error: 'No VirusTotal record found for this indicator.', notFound: true });
}
  if (error.isGeminiUnavailable) {
    return res.status(503).json({ error: error.message });
  }
    res.status(500).json({ error: 'Failed to check hash.' });
  }
});

app.post('/check-email', requireAuth, async (req, res) => {
  const emailContent = req.body.email;

  try {
    const fromMatch = emailContent.match(/From:.*@([\w.-]+)/i);
    const senderDomain = fromMatch ? fromMatch[1] : null;

    const urlMatches = emailContent.match(/https?:\/\/[^\s]+/g) || [];

    const domainResult = senderDomain ? await analyzeDomain(senderDomain) : null;

    if (domainResult) {
      await pool.query(
        'INSERT INTO checks (indicator_type, indicator_value, summary, verdict, user_id) VALUES ($1, $2, $3, $4, $5)',
        ['domain', senderDomain, domainResult.summary, domainResult.verdict, req.userId]
      );
    }

    const urlResults = [];
    for (const link of urlMatches) {
      const result = await analyzeUrl(link);
      urlResults.push(result);

      await pool.query(
        'INSERT INTO checks (indicator_type, indicator_value, summary, verdict, user_id) VALUES ($1, $2, $3, $4, $5)',
        ['url', link, result.summary, result.verdict, req.userId]
      );
    }

    res.json({ senderDomain, domainResult, urlResults });

  } catch (error) {
    console.log(error.response?.data || error.message);
    if(error.response?.status === 429){
      return res.status(429).json({error: "Rate limit reached. Please wait a moment and try again later."});
    }
    if (error.isGeminiUnavailable) {
    return res.status(503).json({ error: error.message });
  }
    res.status(500).json({ error: 'Failed to check email' });
  }
});

app.get('/history', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM checks WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50',
      [req.userId]
    );
    res.json(result.rows);
  } catch (error) {
    console.log(error.message);
    res.status(500).json({ error: 'Failed to fetch history' });
  }
});
app.listen(3000, () => {
  console.log("Listening on port 3000");
});
// At the end of index.js
module.exports = app;