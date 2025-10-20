import { load } from 'cheerio';
import axios from 'axios';

const SHOP_DOMAIN = process.env.SHOP_DOMAIN; 
const SHOPIFY_TOKEN = process.env.SHOPIFY_ADMIN_TOKEN; 
const BLOG_ID = process.env.SHOPIFY_BLOG_ID; 
const RECAPTCHA_SECRET = process.env.RECAPTCHA_SECRET; 
const NOTIFY_WEBHOOK = process.env.NOTIFY_WEBHOOK;

const ipMap = new Map();
const RATE_LIMIT_WINDOW_MS = 60_000;
const MAX_PER_WINDOW = 10;

function isValidUrl(s) {
  try {
    const u = new URL(s);
    return (u.protocol === 'http:' || u.protocol === 'https:') && !!u.hostname;
  } catch (e) { return false; }
}

async function verifyRecaptcha(token, remoteip) {
  if (!RECAPTCHA_SECRET) return true;
  try {
    const resp = await axios.post('https://www.google.com/recaptcha/api/siteverify', null, {
      params: { secret: RECAPTCHA_SECRET, response: token, remoteip }
    });
    return resp.data && resp.data.success && (resp.data.score ? resp.data.score >= 0.5 : true);
  } catch (e) {
    console.log('recaptcha error', e?.message);
    return false;
  }
}

async function notifyEditors(text) {
  if (!NOTIFY_WEBHOOK) return;
  try {
    await axios.post(NOTIFY_WEBHOOK, { text });
  } catch (e) {
    console.log('notify error', e?.message);
  }
}

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;
  const now = Date.now();
  const entry = ipMap.get(ip) || { count: 0, ts: now };
  if (now - entry.ts > RATE_LIMIT_WINDOW_MS) { entry.count = 0; entry.ts = now; }
  entry.count++;
  ipMap.set(ip, entry);
  if (entry.count > MAX_PER_WINDOW) return res.status(429).json({ error: 'Too many requests' });

  let body;
  try { body = req.body && typeof req.body === 'object' ? req.body : JSON.parse(req.body); } 
  catch (e) { return res.status(400).json({ error: 'Invalid JSON' }); }

  const { url, name, recaptchaToken } = body || {};
  if (!url || !isValidUrl(url)) return res.status(400).json({ error: 'Invalid or missing URL' });

  const recaptchaOk = await verifyRecaptcha(recaptchaToken, ip);
  if (!recaptchaOk) return res.status(403).json({ error: 'recaptcha failed' });

  let html;
  try {
    const pageResp = await axios.get(url, { timeout: 10000, headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SubmitBot/1.0)' } });
    html = pageResp.data;
  } catch (err) {
    console.log('fetch page error', err?.message);
    return res.status(400).json({ error: 'Could not fetch target URL' });
  }

  const $ = load(html);
  const title = $('meta[property="og:title"]').attr('content') || $('title').text() || 'Submitted article';
  const description = $('meta[name="description"]').attr('content') || $('meta[property="og:description"]').attr('content') || $('p').first().text() || '';
  const ogImage = $('meta[property="og:image"]').attr('content') || $('meta[name="twitter:image"]').attr('content') || null;

  const excerpt = description ? `<p>${escapeHtml(description)}</p>` : '';
  const body_html = `${excerpt}`;

  // Siempre creamos el artículo sin image
  const articlePayload = {
    article: {
      title,
      body_html,
      tags: ['submitted-via-form'],
      published: false
    }
  };

  if (!SHOP_DOMAIN || !SHOPIFY_TOKEN || !BLOG_ID) {
    return res.status(500).json({ error: 'Server misconfiguration' });
  }

  try {
    // Crear artículo primero
    const shopResp = await axios.post(
      `https://${SHOP_DOMAIN}/admin/api/2024-10/blogs/${BLOG_ID}/articles.json`,
      articlePayload,
      { headers: { 'Content-Type': 'application/json', 'X-Shopify-Access-Token': SHOPIFY_TOKEN } }
    );

    const created = shopResp.data?.article;

    if (created?.id) {
      // Intentar agregar imagen solo si existe
      if (ogImage && isValidUrl(ogImage)) {
        try {
          await axios.head(ogImage, { timeout: 5000 }); // verificar URL
          await axios.put(
            `https://${SHOP_DOMAIN}/admin/api/2024-10/articles/${created.id}.json`,
            { article: { image: { src: ogImage, alt: `${title} - image` } } },
            { headers: { 'Content-Type': 'application/json', 'X-Shopify-Access-Token': SHOPIFY_TOKEN } }
          );
        } catch (imgErr) {
          console.log('Image upload failed, skipping image', ogImage);
        }
      }

      // Agregar metafields siempre
      const metaFields = [
        { namespace: 'community_submission', key: 'source_url', type: 'url', value: url }
      ];
      if (name) {
        metaFields.push({ namespace: 'community_submission', key: 'submitted_by', type: 'single_line_text_field', value: name });
      }

      for (const mf of metaFields) {
        try {
          await axios.post(
            `https://${SHOP_DOMAIN}/admin/api/2024-10/articles/${created.id}/metafields.json`,
            { metafield: mf },
            { headers: { 'Content-Type': 'application/json', 'X-Shopify-Access-Token': SHOPIFY_TOKEN } }
          );
        } catch (mfErr) {
          console.log('Metafield error', mfErr?.response?.data || mfErr?.message);
        }
      }
    }

    await notifyEditors(`New submission (draft): ${url} — article id: ${created?.id || 'unknown'}`);
    return res.status(201).json({ ok: true, article: created });

  } catch (shopErr) {
    console.log('shopify create error', shopErr?.response?.data || shopErr?.message);
    return res.status(500).json({ error: 'Shopify API error', details: shopErr?.response?.data || shopErr?.message });
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/[&<>"']/g, m => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":"&#39;" }[m]));
}
