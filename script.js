/* ═══════════════════════════════════════════════════
   PHISHGUARD — THREAT ANALYSIS ENGINE
   Pure JavaScript · No dependencies
   Built by Nomcebo Mtshali
═══════════════════════════════════════════════════ */

/* ─── THREAT DATABASE ─────────────────────────────── */
const THREATS = {

  urgencyKeywords: [
    { word: /urgent/i, weight: 8, label: 'Urgency trigger' },
    { word: /immediately/i, weight: 7, label: 'Urgency trigger' },
    { word: /act now/i, weight: 9, label: 'Urgency trigger' },
    { word: /limited time/i, weight: 7, label: 'Urgency trigger' },
    { word: /expires (today|soon|in \d)/i, weight: 8, label: 'Expiry pressure' },
    { word: /last (chance|warning)/i, weight: 9, label: 'Fear tactic' },
    { word: /within 24 hours/i, weight: 9, label: 'Time pressure' },
    { word: /account (will be |has been )?(suspended|locked|disabled|terminated)/i, weight: 10, label: 'Account threat' },
    { word: /verify (your|immediately)/i, weight: 7, label: 'Fake verification' },
    { word: /confirm (your|now)/i, weight: 6, label: 'Fake confirmation' },
    { word: /unusual (activity|sign.?in|login)/i, weight: 8, label: 'False security alert' },
    { word: /suspicious activity/i, weight: 8, label: 'False security alert' },
    { word: /your account (is|has been)/i, weight: 6, label: 'Account targeting' },
  ],

  rewardKeywords: [
    { word: /you('ve| have) won/i, weight: 10, label: 'Prize scam' },
    { word: /congratulations/i, weight: 7, label: 'Fake reward' },
    { word: /free (gift|prize|reward|offer|iphone|money)/i, weight: 9, label: 'Free item bait' },
    { word: /claim (your|now)/i, weight: 8, label: 'Fake claim prompt' },
    { word: /selected (you|winner)/i, weight: 9, label: 'Fake selection' },
    { word: /\$[\d,]+ (reward|prize|cash)/i, weight: 9, label: 'Monetary bait' },
    { word: /r[\d ,]+ (reward|prize|cash|voucher)/i, weight: 9, label: 'Monetary bait (ZAR)' },
    { word: /unclaimed (funds|money|prize)/i, weight: 10, label: 'Funds scam' },
    { word: /lottery/i, weight: 9, label: 'Lottery scam' },
    { word: /inheritance/i, weight: 9, label: 'Inheritance scam' },
  ],

  credentialKeywords: [
    { word: /click (here|below|this link)/i, weight: 6, label: 'Link bait' },
    { word: /(enter|provide|submit|update) (your )?(password|pin|otp|banking|card)/i, weight: 10, label: 'Credential harvesting' },
    { word: /login (here|now|below)/i, weight: 8, label: 'Fake login prompt' },
    { word: /sign.?in (here|now)/i, weight: 7, label: 'Fake sign-in' },
    { word: /reset (your )?password/i, weight: 6, label: 'Password reset lure' },
    { word: /(id|ssn|national id|id number|passport)/i, weight: 8, label: 'ID harvesting' },
    { word: /otp|one.?time.?pin/i, weight: 9, label: 'OTP harvesting' },
    { word: /cvv|card (number|details)/i, weight: 10, label: 'Card harvesting' },
    { word: /banking (details|credentials|login)/i, weight: 10, label: 'Banking credential theft' },
  ],

  senderChecks: [
    { pattern: /noreply.*@(?!.*\.(gov\.za|absa\.co\.za|fnb\.co\.za|standardbank\.co\.za|nedbank\.co\.za|microsoft\.com|google\.com|apple\.com|amazon\.com|paypal\.com))/i, weight: 5, label: 'Unverified noreply sender' },
    { pattern: /@[a-z0-9-]+\.(xyz|top|club|online|site|info|biz|click|work|loan|win|bid|gq|ml|cf|ga|tk)$/i, weight: 9, label: 'Suspicious TLD domain' },
    { pattern: /[a-z]+-[a-z]+-[a-z]+\./i, weight: 5, label: 'Hyphenated domain (common in phishing)' },
    { pattern: /(paypal|amazon|microsoft|google|apple|absa|fnb|nedbank|standardbank|sars|home\s?affairs)[^@]*@(?!.*\.(paypal\.com|amazon\.com|microsoft\.com|google\.com|apple\.com|absa\.co\.za|fnb\.co\.za|nedbank\.co\.za|standardbank\.co\.za|sars\.gov\.za|dha\.gov\.za))/i, weight: 10, label: 'Brand impersonation in sender' },
    { pattern: /\d{4,}@/i, weight: 6, label: 'Numeric username (suspicious)' },
    { pattern: /@gmail\.com|@yahoo\.com|@hotmail\.com/i, weight: 4, label: 'Free email provider (verify sender)' },
  ],

  linkPatterns: [
    { pattern: /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i, weight: 10, label: 'Raw IP address link' },
    { pattern: /bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|buff\.ly|rb\.gy|cutt\.ly/i, weight: 7, label: 'Shortened/obscured URL' },
    { pattern: /http:\/\//i, weight: 5, label: 'Insecure HTTP link (not HTTPS)' },
    { pattern: /\.(exe|zip|rar|bat|cmd|msi|vbs|js)\b/i, weight: 10, label: 'Executable file attachment' },
    { pattern: /(paypal|amazon|microsoft|apple|google|absa|fnb|sars).*\.(xyz|top|click|info|online|biz)/i, weight: 10, label: 'Brand + suspicious domain combo' },
  ],

  impersonationKeywords: [
    { word: /dear (customer|user|member|account holder|valued)/i, weight: 7, label: 'Generic impersonal greeting' },
    { word: /dear (sir|madam)/i, weight: 4, label: 'Generic greeting' },
    { word: /sars|south african revenue service/i, weight: 3, label: 'SARS mention (verify carefully)' },
    { word: /home affairs|dha/i, weight: 3, label: 'Home Affairs mention' },
    { word: /you owe|tax (refund|return|penalty)/i, weight: 7, label: 'Tax scam tactic' },
    { word: /federal (bureau|agent|officer)/i, weight: 9, label: 'Authority impersonation' },
    { word: /police|interpol|cyber (crime|police)/i, weight: 7, label: 'Law enforcement impersonation' },
  ],

  grammarIssues: [
    { pattern: /kindly (do the needful|revert|provide)/i, weight: 4, label: 'Non-native phrasing' },
    { pattern: /please to (click|verify|confirm)/i, weight: 5, label: 'Grammatical error' },
    { pattern: /your (account|information) will (deleted|removed|cancelled)/i, weight: 5, label: 'Grammar error' },
    { pattern: /we (inform|notify) you that/i, weight: 3, label: 'Formal but awkward phrasing' },
  ]
};

/* ─── SAMPLE DATA ─────────────────────────────────── */
const SAMPLES = {
  phish: {
    sender: 'security-alert@paypal-accounts-update.online',
    subject: 'URGENT: Your PayPal account has been SUSPENDED - Act within 24 hours',
    body: `Dear valued customer,

We have detected UNUSUAL ACTIVITY on your PayPal account. Your account has been TEMPORARILY SUSPENDED due to suspicious login attempts from an unknown device.

You must IMMEDIATELY verify your identity to restore access. Failure to verify within 24 hours will result in PERMANENT account termination and all funds held for 180 days.

Click here to verify now: http://bit.ly/paypal-verify-account

You will need to provide:
- Full name and ID number  
- Banking details and card number
- CVV and PIN
- OTP sent to your phone

ACT NOW before your account is permanently deleted!

PayPal Security Team`
  },
  legit: {
    sender: 'newsletter@github.com',
    subject: 'GitHub: Your monthly developer digest — February 2025',
    body: `Hi Nomcebo,

Here's what happened in the world of open source this month:

Trending repositories this week include projects in AI, web development, and developer tools. The GitHub community has been particularly active around new frameworks and CLI tooling.

Upcoming events:
- GitHub Universe virtual sessions start next week
- Open source contribution guide updated

You're receiving this because you signed up for GitHub developer news. To manage your preferences, visit your notification settings at github.com/settings/notifications.

Thanks,
The GitHub Team`
  }
};

/* ─── BOOT SEQUENCE ───────────────────────────────── */
const bootMessages = [
  { text: 'BIOS initialisation complete', type: 'ok', delay: 200 },
  { text: 'Loading PhishGuard threat engine v2.4.1', type: 'ok', delay: 500 },
  { text: 'Mounting pattern database [47 signatures]', type: 'ok', delay: 750 },
  { text: 'Loading impersonation fingerprints', type: 'ok', delay: 950 },
  { text: 'Domain reputation module loaded', type: 'ok', delay: 1150 },
  { text: 'Social engineering vector analysis: READY', type: 'ok', delay: 1350 },
  { text: 'NLP urgency detection module: READY', type: 'ok', delay: 1550 },
  { text: 'Credential harvesting detector: READY', type: 'ok', delay: 1750 },
  { text: 'WARNING: Educational tool only. Not for production use.', type: 'warn', delay: 2000 },
  { text: 'All systems operational. Launching interface...', type: 'ok', delay: 2200 },
];

window.addEventListener('DOMContentLoaded', () => {
  const bootLines = document.getElementById('bootLines');
  const bootScreen = document.getElementById('bootScreen');
  const app = document.getElementById('app');

  bootMessages.forEach(({ text, type, delay }) => {
    setTimeout(() => {
      const line = document.createElement('div');
      line.className = `boot-line ${type}`;
      line.textContent = `> ${text}`;
      bootLines.appendChild(line);
    }, delay);
  });

  // Transition to app
  setTimeout(() => {
    bootScreen.style.transition = 'opacity 0.6s ease';
    bootScreen.style.opacity = '0';
    setTimeout(() => {
      bootScreen.style.display = 'none';
      app.style.display = 'block';
      app.style.opacity = '0';
      app.style.transition = 'opacity 0.6s ease';
      requestAnimationFrame(() => { app.style.opacity = '1'; });
    }, 600);
  }, 2800);
});

/* ─── LOAD SAMPLES ────────────────────────────────── */
function loadSample(type) {
  const s = SAMPLES[type];
  document.getElementById('senderInput').value = s.sender;
  document.getElementById('subjectInput').value = s.subject;
  document.getElementById('bodyInput').value = s.body;
}

/* ─── CLEAR ───────────────────────────────────────── */
function clearAll() {
  document.getElementById('senderInput').value = '';
  document.getElementById('subjectInput').value = '';
  document.getElementById('bodyInput').value = '';
  document.getElementById('idleState').style.display = 'flex';
  document.getElementById('scanningState').style.display = 'none';
  document.getElementById('resultsState').style.display = 'none';
  document.getElementById('scanLog').innerHTML = '';
}

/* ─── CORE ANALYSIS ENGINE ────────────────────────── */
function runAnalysis(sender, subject, body) {
  const fullText = `${subject} ${body}`;
  const flags = [];
  const scores = { urgency: 0, reward: 0, credentials: 0, sender: 0, links: 0, impersonation: 0 };
  const maxScores = { urgency: 30, reward: 30, credentials: 40, sender: 30, links: 40, impersonation: 20 };

  // URGENCY
  THREATS.urgencyKeywords.forEach(({ word, weight, label }) => {
    if (word.test(fullText)) {
      scores.urgency = Math.min(scores.urgency + weight, maxScores.urgency);
      flags.push({ severity: weight >= 8 ? 'high' : 'medium', category: 'Urgency & Fear', label, detail: `Pattern matched in email content` });
    }
  });

  // REWARD
  THREATS.rewardKeywords.forEach(({ word, weight, label }) => {
    if (word.test(fullText)) {
      scores.reward = Math.min(scores.reward + weight, maxScores.reward);
      flags.push({ severity: weight >= 8 ? 'high' : 'medium', category: 'Reward Bait', label, detail: 'Potential prize/reward scam detected' });
    }
  });

  // CREDENTIALS
  THREATS.credentialKeywords.forEach(({ word, weight, label }) => {
    if (word.test(fullText)) {
      scores.credentials = Math.min(scores.credentials + weight, maxScores.credentials);
      flags.push({ severity: weight >= 9 ? 'high' : 'medium', category: 'Credential Theft', label, detail: 'Possible attempt to harvest sensitive information' });
    }
  });

  // SENDER
  THREATS.senderChecks.forEach(({ pattern, weight, label }) => {
    if (pattern.test(sender)) {
      scores.sender = Math.min(scores.sender + weight, maxScores.sender);
      flags.push({ severity: weight >= 8 ? 'high' : weight >= 5 ? 'medium' : 'low', category: 'Sender Analysis', label, detail: `Sender address: ${sender}` });
    }
  });

  // LINKS
  THREATS.linkPatterns.forEach(({ pattern, weight, label }) => {
    if (pattern.test(body)) {
      scores.links = Math.min(scores.links + weight, maxScores.links);
      flags.push({ severity: weight >= 9 ? 'high' : 'medium', category: 'Suspicious Links', label, detail: 'Found in email body' });
    }
  });

  // IMPERSONATION
  THREATS.impersonationKeywords.forEach(({ word, weight, label }) => {
    if (word.test(fullText)) {
      scores.impersonation = Math.min(scores.impersonation + weight, maxScores.impersonation);
      flags.push({ severity: weight >= 7 ? 'medium' : 'low', category: 'Impersonation', label, detail: 'Possible brand/authority impersonation' });
    }
  });

  // GRAMMAR
  THREATS.grammarIssues.forEach(({ pattern, weight, label }) => {
    if (pattern.test(fullText)) {
      flags.push({ severity: 'low', category: 'Writing Quality', label, detail: 'Common in non-native/automated phishing emails' });
    }
  });

  // CALCULATE TOTAL THREAT SCORE (0-100)
  const totalPossible = Object.values(maxScores).reduce((a, b) => a + b, 0);
  const totalScore = Object.values(scores).reduce((a, b) => a + b, 0);
  const threatPercent = Math.min(Math.round((totalScore / totalPossible) * 100 * 2.2), 100);

  // DEDUPLICATE FLAGS (keep unique labels)
  const seen = new Set();
  const uniqueFlags = flags.filter(f => {
    if (seen.has(f.label)) return false;
    seen.add(f.label);
    return true;
  });

  // VERDICT
  let verdict, verdictSub, recommendation;
  if (threatPercent >= 60) {
    verdict = 'DANGEROUS';
    verdictSub = `${uniqueFlags.length} threat indicators detected`;
    recommendation = {
      level: 'dangerous',
      title: '⚠ DO NOT INTERACT WITH THIS EMAIL',
      body: 'This email shows strong signs of a phishing attack. Do NOT click any links, download attachments, or provide any personal information. Report this email to your IT department or email provider and delete it immediately.'
    };
  } else if (threatPercent >= 25) {
    verdict = 'SUSPICIOUS';
    verdictSub = `${uniqueFlags.length} potential indicators found`;
    recommendation = {
      level: 'suspicious',
      title: '⚡ PROCEED WITH CAUTION',
      body: 'This email contains some suspicious patterns. Verify the sender\'s identity through a separate channel (e.g., call the organisation directly). Do not click links — instead, go directly to the official website.'
    };
  } else {
    verdict = 'LIKELY SAFE';
    verdictSub = uniqueFlags.length === 0 ? 'No threat indicators detected' : `${uniqueFlags.length} minor indicators (low risk)`;
    recommendation = {
      level: 'safe',
      title: '✓ EMAIL APPEARS LEGITIMATE',
      body: 'No significant phishing patterns were detected. However, always stay vigilant — verify the sender if you weren\'t expecting this email, and never share sensitive information unless you initiated the request.'
    };
  }

  // NORMALISE CATEGORY SCORES TO %
  const categoryPercents = {};
  Object.entries(scores).forEach(([key, val]) => {
    categoryPercents[key] = Math.min(Math.round((val / maxScores[key]) * 100), 100);
  });

  return { threatPercent, verdict, verdictSub, flags: uniqueFlags, scores: categoryPercents, recommendation };
}

/* ─── SCAN SEQUENCE ───────────────────────────────── */
function analyseEmail() {
  const sender = document.getElementById('senderInput').value.trim();
  const subject = document.getElementById('subjectInput').value.trim();
  const body = document.getElementById('bodyInput').value.trim();

  if (!sender && !subject && !body) {
    alert('Please enter at least a sender address or email body to analyse.');
    return;
  }

  // Show scanning state
  document.getElementById('idleState').style.display = 'none';
  document.getElementById('resultsState').style.display = 'none';
  document.getElementById('scanningState').style.display = 'flex';
  document.getElementById('scanLog').innerHTML = '';

  const scanSteps = [
    { text: '> Parsing email headers...', type: 'ok', delay: 200 },
    { text: '> Analysing sender domain reputation...', type: 'ok', delay: 500 },
    { text: '> Running urgency pattern matching...', type: 'ok', delay: 750 },
    { text: '> Checking credential harvesting indicators...', type: 'ok', delay: 1000 },
    { text: '> Scanning for malicious links...', type: 'ok', delay: 1200 },
    { text: '> Checking impersonation fingerprints...', type: 'ok', delay: 1400 },
    { text: '> Calculating threat score...', type: 'ok', delay: 1650 },
    { text: '> Compiling report...', type: 'ok', delay: 1850 },
  ];

  const scanLog = document.getElementById('scanLog');
  scanSteps.forEach(({ text, type, delay }) => {
    setTimeout(() => {
      const line = document.createElement('div');
      line.className = `scan-log-line ${type}`;
      line.textContent = text;
      scanLog.appendChild(line);
    }, delay);
  });

  // Run actual analysis and show results
  setTimeout(() => {
    const result = runAnalysis(sender, subject, body);
    showResults(result);
  }, 2100);
}

/* ─── RENDER RESULTS ──────────────────────────────── */
function showResults(result) {
  document.getElementById('scanningState').style.display = 'none';
  document.getElementById('resultsState').style.display = 'flex';

  // VERDICT
  const verdictEl = document.getElementById('verdict');
  verdictEl.textContent = result.verdict;
  verdictEl.className = 'verdict ' + result.verdict.toLowerCase().replace('likely ', '');
  document.getElementById('verdictSub').textContent = result.verdictSub;

  // VERDICT BOX COLOUR
  const vWrap = document.getElementById('verdictWrap');
  vWrap.style.borderColor = result.verdict === 'DANGEROUS' ? 'rgba(255,49,49,0.4)' :
                             result.verdict === 'SUSPICIOUS' ? 'rgba(255,204,0,0.4)' :
                             'rgba(0,255,65,0.4)';

  // METER
  const meter = document.getElementById('meterFill');
  const meterVal = document.getElementById('meterValue');
  setTimeout(() => {
    meter.style.width = result.threatPercent + '%';
    meterVal.textContent = result.threatPercent + '%';
    meterVal.style.color = result.threatPercent >= 60 ? 'var(--red)' :
                            result.threatPercent >= 25 ? 'var(--yellow)' : 'var(--green)';
  }, 100);

  // FLAGS
  const flagsList = document.getElementById('flagsList');
  flagsList.innerHTML = '';
  if (result.flags.length === 0) {
    flagsList.innerHTML = '<div class="no-flags">✓ No threat indicators detected</div>';
  } else {
    result.flags.forEach((flag, i) => {
      const el = document.createElement('div');
      el.className = `flag-item ${flag.severity}`;
      el.style.animationDelay = `${i * 0.08}s`;
      el.innerHTML = `
        <div class="flag-icon">${flag.severity === 'high' ? '🔴' : flag.severity === 'medium' ? '🟡' : '🟢'}</div>
        <div class="flag-text">
          <strong>${flag.label}</strong>
          <span>${flag.category} · ${flag.detail}</span>
        </div>
      `;
      flagsList.appendChild(el);
    });
  }

  // BREAKDOWN
  const breakdownGrid = document.getElementById('breakdownGrid');
  breakdownGrid.innerHTML = '';
  const categoryNames = {
    urgency: 'Urgency & Fear',
    reward: 'Reward Bait',
    credentials: 'Credential Theft',
    sender: 'Sender Trust',
    links: 'Link Safety',
    impersonation: 'Impersonation'
  };

  Object.entries(result.scores).forEach(([key, val], i) => {
    const color = val >= 60 ? 'var(--red)' : val >= 25 ? 'var(--yellow)' : 'var(--green-2)';
    const el = document.createElement('div');
    el.className = 'breakdown-item';
    el.style.animationDelay = `${0.3 + i * 0.07}s`;
    el.innerHTML = `
      <div class="breakdown-item-label">${categoryNames[key]}</div>
      <div class="breakdown-item-bar">
        <div class="breakdown-item-fill" style="width:0%; background:${color}" data-target="${val}%"></div>
      </div>
      <div class="breakdown-item-score" style="color:${color}">${val}%</div>
    `;
    breakdownGrid.appendChild(el);
  });

  // Animate breakdown bars
  setTimeout(() => {
    document.querySelectorAll('.breakdown-item-fill').forEach(bar => {
      bar.style.width = bar.dataset.target;
    });
  }, 600);

  // RECOMMENDATION
  const rec = document.getElementById('recommendation');
  rec.className = `recommendation ${result.recommendation.level}`;
  rec.innerHTML = `<strong>${result.recommendation.title}</strong>${result.recommendation.body}`;
}
