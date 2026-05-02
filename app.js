const demoData = {
    "1": {
        input: "URGENT ALERT: Your Chase Bank account has been temporarily locked due to a suspicious login attempt from Russia. Click here immediately to verify your identity within 12 hours or your account will be permanently closed: http://chase-security-verify-auth.com/login",
        classification: "[RED FLAG] - ALERT: FAKE / SCAM",
        isRedFlag: true,
        riskLevel: "Critical Phishing Risk",
        category: "Financial Phishing",
        explainability: [
            { type: "red", text: "The URL chase-security-verify-auth.com is a typosquatting/malicious domain. Official communications use chase.com." },
            { type: "red", text: "Artificial urgency and threats of permanent closure are psychological manipulation tactics." }
        ],
        justification: "Cross-referencing official JPMorgan Chase security protocols confirms they do not use third-party domains for account verification and never threaten account deletion via SMS/Email links. SSL certificate registered < 24 hrs ago.",
        advice: "Do not click links or provide PII to this domain; navigate directly to chase.com in your browser."
    },
    "2": {
        input: "OpenAI has officially launched GPT-4o, a new flagship model capable of real-time audio, vision, and text processing, which will be rolled out to all free users over the coming weeks.",
        classification: "[BLUE FLAG] - VERIFIED LEGITIMATE",
        isRedFlag: false,
        riskLevel: "Low",
        category: "Global Breaking News (Technology)",
        explainability: [
            { type: "blue", text: "Absence of urgency bias or requests for personal data." },
            { type: "blue", text: "Factual, objective phrasing without emotional manipulation." }
        ],
        justification: "Live Global Cross-Referencing against Reuters, AP News, and OpenAI's official press releases confirms the announcement of GPT-4o, its multimodal capabilities, and its rollout plan.",
        advice: "Content is factually verified and safe to consume or share."
    },
    "3": {
        input: "Amazon is hiring remote Data Entry Specialists immediately! Earn $55/hr working from home, set your own hours. No experience needed. Equipment provided. Send your updated resume, banking details for direct deposit, and a photo of your ID to amazon-careers-hr-dept@gmail.com to get started today.",
        classification: "[RED FLAG] - ALERT: FAKE / SCAM",
        isRedFlag: true,
        riskLevel: "High",
        category: "Employment Offer / Identity Theft Scam",
        explainability: [
            { type: "red", text: "The email domain @gmail.com is unverified. Corporate HR uses @amazon.com." },
            { type: "red", text: "Requesting sensitive PII (banking details, ID) via email before formal interview is a security violation." },
            { type: "red", text: "$55/hr for unskilled remote data entry breaks standard market compensation logic." }
        ],
        justification: "Scanning amazon.jobs reveals no such listing. Standard corporate HR never requests banking details via generic email addresses during initial contact.",
        advice: "Do not send resume, ID, or banking info; this is an identity theft trap."
    }
};

const inputArea = document.getElementById('target-input');
const scanBtn = document.getElementById('scan-btn');
const scanningOverlay = document.getElementById('scanning-overlay');
const resultsPanel = document.getElementById('results-panel');
const demoBtns = document.querySelectorAll('.demo-btn');

// UI Elements
const uiClass = document.getElementById('primary-classification');
const uiRisk = document.getElementById('risk-level');
const uiCat = document.getElementById('category');
const uiList = document.getElementById('explainability-list');
const uiJust = document.getElementById('factual-justification');
const uiAdv = document.getElementById('security-advice');

const MAX_INPUT_CHARS = 5000;
const REQUEST_TIMEOUT_MS = 4500;

const SOURCE_REPUTATION = {
    trustedNews: [
        "reuters.com", "apnews.com", "bbc.com", "thehindu.com", "indianexpress.com",
        "hindustantimes.com", "ndtv.com", "timesofindia.indiatimes.com", "business-standard.com",
        "livemint.com", "theprint.in", "npr.org", "nytimes.com", "washingtonpost.com",
        "theguardian.com", "aljazeera.com", "espn.com", "espncricinfo.com", "olympics.com",
        "google.com", "news.google.com", "yahoo.com", "msn.com", "cnn.com", "foxnews.com",
        "cnbc.com", "bloomberg.com", "forbes.com", "techcrunch.com", "theverge.com", "wired.com",
        "cbsnews.com", "nbcnews.com", "abcnews.go.com", "usatoday.com", "wsj.com"
    ],
    officialGovernment: [
        "gov.in", "nic.in", "india.gov.in", "pib.gov.in", "upsc.gov.in", "ssc.gov.in",
        "nta.ac.in", "joinindianarmy.nic.in", "indianrailways.gov.in", "rrbcdg.gov.in",
        "employmentnews.gov.in", "ncs.gov.in", "mygov.in", "uidai.gov.in", "rbi.org.in",
        "gov.uk", "gov", "mil"
    ],
    officialJobs: [
        "amazon.jobs", "careers.google.com", "jobs.apple.com", "careers.microsoft.com",
        "metacareers.com", "linkedin.com", "indeed.com", "naukri.com", "greenhouse.io",
        "lever.co", "workdayjobs.com", "glassdoor.com", "monster.com", "simplyhired.com",
        "ziprecruiter.com", "foundit.in", "shine.com"
    ],
    riskyShorteners: [
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rb.gy", "shorturl.at"
    ],
    disposableMail: [
        "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "proton.me", "protonmail.com", "rediffmail.com"
    ]
};

const CLAIM_PATTERNS = {
    breakingNews: /\b(breaking|latest|just in|viral|exclusive|shocking|alert|earthquake|blast|attack|resigned|death|arrested|ban|war|election|result)\b/i,
    newspaper: /\b(news|newspaper|article|headline|report|press release|journalist|editorial|published)\b/i,
    jobs: /\b(job|hiring|vacancy|recruitment|career|work from home|remote work|data entry|salary|stipend|interview|offer letter)\b/i,
    governmentJobs: /\b(government job|govt job|sarkari|upsc|ssc|railway|rrb|bank po|police constable|teacher vacancy|admit card|result|notification)\b/i,
    sports: /\b(cricket|football|soccer|ipl|fifa|world cup|olympic|match|score|won|lost|runs|wickets|goals|tournament|league)\b/i,
    asksForSensitiveData: /\b(bank|banking|upi|aadhaar|aadhar|pan card|passport|otp|password|pin|ssn|credit card|debit card|photo of your id|identity proof)\b/i,
    urgency: /\b(urgent|immediately|within \d+\s*(hour|hours|day|days)|limited time|act now|last date today|final warning|permanently closed|avoid penalty)\b/i,
    unrealisticMoney: /(\$|rs\.?|inr|\u20b9)\s?\d{2,}(?:,\d{3})*(?:\s?\/?\s?(hr|hour|day|week|month))?|\b\d+\s?(lakh|crore)\b/i
};

const WEIGHTS = {
    critical: 35,
    strong: 22,
    medium: 14,
    small: 7,
    trust: -16,
    official: -28
};

function cleanInput(text) {
    return text
        .normalize('NFKC')
        .replace(/[\u200B-\u200D\uFEFF]/g, '')
        .replace(/\s+/g, ' ')
        .trim()
        .slice(0, MAX_INPUT_CHARS);
}

function extractUrls(text) {
    const matches = text.match(/(?:https?:\/\/|www\.)[^\s<>"']+|(?:[a-z0-9-]+\.)+[a-z]{2,}(?:\/[^\s<>"']*)?/gi) || [];
    return [...new Set(matches.map(url => url.replace(/[),.;!?]+$/g, '')))].slice(0, 12);
}

function toUrl(value) {
    try {
        const prefixed = /^https?:\/\//i.test(value) ? value : `https://${value}`;
        return new URL(prefixed);
    } catch (error) {
        return null;
    }
}

function getHost(value) {
    const url = toUrl(value);
    return url ? url.hostname.replace(/^www\./, '').toLowerCase() : "";
}

function domainMatches(host, domains) {
    return domains.some(domain => host === domain || host.endsWith(`.${domain}`));
}

function findEmails(text) {
    return text.match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi) || [];
}

function addSignal(signals, type, text, weight) {
    signals.push({ type, text, weight });
}

function classifyCategory(text) {
    const categories = [];
    if (CLAIM_PATTERNS.governmentJobs.test(text)) categories.push("Government Job / Sarkari Alert");
    else if (CLAIM_PATTERNS.jobs.test(text)) categories.push("Job Alert / Employment Claim");
    if (CLAIM_PATTERNS.sports.test(text)) categories.push("Sports Information");
    if (CLAIM_PATTERNS.breakingNews.test(text) || CLAIM_PATTERNS.newspaper.test(text)) categories.push("Breaking News / Newspaper Claim");
    return categories.length ? categories.join(" + ") : "General Content";
}

const STOP_WORDS = new Set(["the","and","for","that","this","with","from","your","have","will","they","what","about","when","make","can","like","time","just","know","take","people","into","year","good","some","could","them","see","other","than","then","now","look","only","come","its","over","think","also","back","after","use","two","how","our","work","first","well","way","even","new","want","because","any","these","give","day","most","us"]);

function buildSearchPhrase(text) {
    return text
        .replace(/https?:\/\/\S+/gi, '')
        .replace(/[^\w\s.-]/g, ' ')
        .split(/\s+/)
        .map(w => w.toLowerCase())
        .filter(word => word.length > 3 && !STOP_WORDS.has(word))
        .slice(0, 6)
        .join(' ');
}

function buildGdeltUrl(query) {
    const gdeltQuery = encodeURIComponent(query);
    return `https://api.gdeltproject.org/api/v2/doc/doc?query=${gdeltQuery}&mode=ArtList&format=json&maxrecords=8&sort=hybridrel&timespan=7d`;
}

async function fetchWithTimeout(url, timeoutMs) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
        const response = await fetch(url, {
            signal: controller.signal,
            referrerPolicy: 'no-referrer',
            cache: 'no-store'
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return await response.json();
    } finally {
        clearTimeout(timer);
    }
}

async function collectLiveNewsEvidence(text) {
    const phrase = buildSearchPhrase(text);
    const shouldCheckRecentSources =
        CLAIM_PATTERNS.breakingNews.test(text) ||
        CLAIM_PATTERNS.newspaper.test(text) ||
        CLAIM_PATTERNS.sports.test(text) ||
        CLAIM_PATTERNS.governmentJobs.test(text);

    if (phrase.split(' ').length < 3 || !shouldCheckRecentSources) {
        return { checked: false, trustedCount: 0, domains: [] };
    }

    try {
        const data = await fetchWithTimeout(buildGdeltUrl(phrase), REQUEST_TIMEOUT_MS);
        const articles = Array.isArray(data.articles) ? data.articles : [];
        const trustedDomains = articles
            .map(article => getHost(article.url || article.sourceurl || ''))
            .filter(host => domainMatches(host, SOURCE_REPUTATION.trustedNews));
        return {
            checked: true,
            trustedCount: new Set(trustedDomains).size,
            domains: [...new Set(trustedDomains)].slice(0, 4)
        };
    } catch (error) {
        return { checked: true, trustedCount: 0, domains: [], error: true };
    }
}

function analyzeUrls(urls, signals) {
    urls.forEach(rawUrl => {
        const url = toUrl(rawUrl);
        const host = getHost(rawUrl);

        if (!url || !host) {
            addSignal(signals, "red", `Malformed or unreadable link detected: ${rawUrl}`, WEIGHTS.medium);
            return;
        }

        if (!/^https:$/i.test(url.protocol)) {
            addSignal(signals, "red", `Link does not use HTTPS: ${host}`, WEIGHTS.medium);
        }

        if (domainMatches(host, SOURCE_REPUTATION.riskyShorteners)) {
            addSignal(signals, "red", `Shortened link hides the final destination: ${host}`, WEIGHTS.strong);
        }

        if (domainMatches(host, SOURCE_REPUTATION.trustedNews)) {
            addSignal(signals, "blue", `Recognized newspaper/news source detected: ${host}`, WEIGHTS.trust);
        }

        if (domainMatches(host, SOURCE_REPUTATION.officialGovernment)) {
            addSignal(signals, "blue", `Official government domain detected: ${host}`, WEIGHTS.official);
        }

        if (domainMatches(host, SOURCE_REPUTATION.officialJobs)) {
            addSignal(signals, "blue", `Recognized official/recruitment job domain detected: ${host}`, WEIGHTS.trust);
        }

        if (/(login|verify|kyc|account|reward|bonus|claim|free|urgent|password)/i.test(url.pathname + url.search)) {
            addSignal(signals, "red", `Link path contains high-risk action words on ${host}`, WEIGHTS.medium);
        }

        if (host.split('.').some(part => part.length > 24 || /\d{4,}/.test(part))) {
            addSignal(signals, "red", `Domain structure looks machine-generated or deceptive: ${host}`, WEIGHTS.medium);
        }
    });
}

function analyzeJobsAndGovClaims(text, emails, urls, signals) {
    const lowerText = text.toLowerCase();
    const hosts = urls.map(getHost).filter(Boolean);
    const hasOfficialGov = hosts.some(host => domainMatches(host, SOURCE_REPUTATION.officialGovernment));
    const hasOfficialJobSite = hosts.some(host => domainMatches(host, SOURCE_REPUTATION.officialJobs));

    if (CLAIM_PATTERNS.jobs.test(text)) {
        addSignal(signals, hasOfficialJobSite ? "blue" : "red", hasOfficialJobSite
            ? "Job alert includes a recognized official career/recruitment link."
            : "Job alert has no recognized official career or recruiter link.", hasOfficialJobSite ? WEIGHTS.trust : WEIGHTS.strong);

        if (/data entry|typing job|no experience|daily payout|registration fee|security deposit|training fee/i.test(text)) {
            addSignal(signals, "red", "Job wording matches common fake job/identity-theft patterns.", WEIGHTS.strong);
        }

        if (CLAIM_PATTERNS.asksForSensitiveData.test(text)) {
            addSignal(signals, "red", "Job message asks for sensitive identity or banking information.", WEIGHTS.critical);
        }

        emails.forEach(email => {
            const domain = email.split('@')[1].toLowerCase();
            if (SOURCE_REPUTATION.disposableMail.includes(domain)) {
                addSignal(signals, "red", `Recruiter uses a public email domain instead of an official company domain: ${email}`, WEIGHTS.strong);
            }
        });
    }

    if (CLAIM_PATTERNS.governmentJobs.test(text)) {
        addSignal(signals, hasOfficialGov ? "blue" : "red", hasOfficialGov
            ? "Government job claim includes an official .gov.in/.nic.in or known government source."
            : "Government job claim is missing an official government source link.", hasOfficialGov ? WEIGHTS.official : WEIGHTS.critical);

        if (/pay.*(fee|deposit)|whatsapp|telegram|guaranteed selection|direct joining|without exam|no exam/i.test(lowerText)) {
            addSignal(signals, "red", "Government recruitment claim contains payment, messaging-app, or guaranteed-selection language.", WEIGHTS.critical);
        }
    }
}

function analyzeNewsAndSports(text, urls, signals) {
    const hosts = urls.map(getHost).filter(Boolean);
    const trustedNewsCount = new Set(hosts.filter(host => domainMatches(host, SOURCE_REPUTATION.trustedNews))).size;

    if (CLAIM_PATTERNS.breakingNews.test(text) || CLAIM_PATTERNS.newspaper.test(text)) {
        if (trustedNewsCount > 0) {
            addSignal(signals, "blue", "Breaking/news claim includes at least one recognized news or newspaper source.", WEIGHTS.trust);
        } else {
            addSignal(signals, "red", "Breaking/news claim has no recognizable newspaper, wire, or official source link.", WEIGHTS.medium);
        }

        if (/forwarded as received|share to everyone|media is hiding|do not trust news channels|100% true/i.test(text)) {
            addSignal(signals, "red", "Message uses viral forwarding language instead of verifiable reporting.", WEIGHTS.strong);
        }
    }

    if (CLAIM_PATTERNS.sports.test(text)) {
        const hasSportsSource = hosts.some(host => domainMatches(host, ["espn.com", "espncricinfo.com", "fifa.com", "olympics.com", "icc-cricket.com", "iplt20.com"]));
        addSignal(signals, hasSportsSource ? "blue" : "red", hasSportsSource
            ? "Sports information includes a recognized sports/official tournament source."
            : "Sports information should be checked against an official scoreboard or established sports source.", hasSportsSource ? WEIGHTS.trust : WEIGHTS.small);
    }
}

function analyzeSecurityLanguage(text, signals) {
    if (CLAIM_PATTERNS.urgency.test(text)) {
        addSignal(signals, "red", "Urgency or threat language is present.", WEIGHTS.medium);
    }

    if (/\b(click here|verify now|claim now|login now|send otp|scan qr|download apk|install app)\b/i.test(text)) {
        addSignal(signals, "red", "Message pushes the user toward risky immediate action.", WEIGHTS.strong);
    }

    if (CLAIM_PATTERNS.unrealisticMoney.test(text) && /easy|no experience|guaranteed|free|reward|bonus|work from home/i.test(text)) {
        addSignal(signals, "red", "Money claim appears unusually high or guaranteed for low-verification work.", WEIGHTS.strong);
    }

    if (/\b(apk|\.exe|macro|enable editing|allow permission|remote access|anydesk|teamviewer)\b/i.test(text)) {
        addSignal(signals, "red", "Potential malware or remote-access instruction detected.", WEIGHTS.critical);
    }
}

function calculateRisk(signals) {
    const rawScore = signals.reduce((total, signal) => total + signal.weight, 0);
    return Math.max(0, Math.min(100, rawScore + 20));
}

function riskLabel(score) {
    if (score >= 80) return "Critical";
    if (score >= 60) return "High";
    if (score >= 40) return "Medium";
    if (score >= 20) return "Low-Medium";
    return "Low";
}

function buildVerdict(score, signals, liveEvidence) {
    const hasCriticalRed = signals.some(signal => signal.type === "red" && signal.weight >= WEIGHTS.critical);
    const hasTrustedLiveSources = liveEvidence.trustedCount >= 1;
    const hasTrustedBlue = signals.some(signal => signal.type === "blue" && signal.weight <= WEIGHTS.trust);

    if (hasCriticalRed || score >= 55) {
        return {
            classification: "[RED FLAG] - LIKELY FAKE / SCAM",
            isRedFlag: true
        };
    }

    if (hasTrustedLiveSources || hasTrustedBlue || score <= 30) {
        return {
            classification: "[BLUE FLAG] - VERIFIED / LIKELY TRUE",
            isRedFlag: false
        };
    }

    return {
        classification: "[RED FLAG] - UNVERIFIED / NEEDS SOURCE CHECK",
        isRedFlag: true
    };
}

function compactSignals(signals, isRedFlag) {
    const preferredType = isRedFlag ? "red" : "blue";
    const sorted = [...signals].sort((a, b) => {
        if (a.type !== b.type) return a.type === preferredType ? -1 : 1;
        return Math.abs(b.weight) - Math.abs(a.weight);
    });

    return sorted.slice(0, 6).map(signal => ({
        type: signal.type,
        text: signal.text
    }));
}

function buildJustification(text, urls, emails, signals, liveEvidence) {
    const parts = [];
    parts.push(`Checked ${urls.length} link(s), ${emails.length} email address(es), source reputation, claim category, urgency, sensitive-data requests, and known scam language.`);

    if (liveEvidence.checked && liveEvidence.trustedCount > 0) {
        parts.push(`Recent-news cross-reference found supporting coverage from: ${liveEvidence.domains.join(', ')}.`);
    } else if (liveEvidence.checked && liveEvidence.error) {
        parts.push("Recent-news cross-reference was attempted but the public news index could not be reached from this browser session.");
    } else if (liveEvidence.checked) {
        parts.push("Recent-news cross-reference found no strong support from recognized sources in the latest public news index.");
    }

    const redCount = signals.filter(signal => signal.type === "red").length;
    const blueCount = signals.filter(signal => signal.type === "blue").length;
    parts.push(`Evidence balance: ${redCount} risk signal(s), ${blueCount} trust signal(s).`);
    return parts.join(' ');
}

function buildAdvice(isRedFlag, category) {
    if (isRedFlag) {
        if (/Government Job/i.test(category)) {
            return "Treat as false until confirmed on the official recruitment site, Employment News, PIB, or the relevant .gov.in/.nic.in portal. Do not pay fees through private links.";
        }
        if (/Job Alert/i.test(category)) {
            return "Do not send ID, banking details, OTPs, deposits, or resumes to public-email recruiters. Verify only through the company's official careers page.";
        }
        return "Do not click unknown links or share personal data. Verify the claim through at least two trusted news sources or an official website before forwarding.";
    }

    return "Information appears true or low risk based on available signals, but important breaking news should still be confirmed with an official source and a second reputable outlet.";
}

async function simulateAnalysis(text) {
    const cleanedText = cleanInput(text);
    const urls = extractUrls(cleanedText);
    const emails = findEmails(cleanedText);
    const signals = [];

    analyzeUrls(urls, signals);
    analyzeJobsAndGovClaims(cleanedText, emails, urls, signals);
    analyzeNewsAndSports(cleanedText, urls, signals);
    analyzeSecurityLanguage(cleanedText, signals);

    if (!urls.length && (CLAIM_PATTERNS.breakingNews.test(cleanedText) || CLAIM_PATTERNS.jobs.test(cleanedText) || CLAIM_PATTERNS.sports.test(cleanedText))) {
        addSignal(signals, "red", "Claim is presented without a source link, official notice, or traceable citation.", WEIGHTS.medium);
    }

    const hasTrustedUrl = urls.some(url => {
        const h = getHost(url);
        return h && (domainMatches(h, SOURCE_REPUTATION.trustedNews) || domainMatches(h, SOURCE_REPUTATION.officialGovernment) || domainMatches(h, SOURCE_REPUTATION.officialJobs));
    });

    if (!signals.length) {
        addSignal(signals, "blue", "No phishing, scam, malware, or fake-news language was detected.", WEIGHTS.trust);
    }

    const liveEvidence = await collectLiveNewsEvidence(cleanedText);
    if (liveEvidence.trustedCount >= 1) {
        addSignal(signals, "blue", "Recent public news cross-reference found recognized sources covering the claim.", WEIGHTS.official);
    } else if (liveEvidence.checked && !liveEvidence.error && liveEvidence.trustedCount === 0 && !hasTrustedUrl && (CLAIM_PATTERNS.breakingNews.test(cleanedText) || CLAIM_PATTERNS.sports.test(cleanedText))) {
        addSignal(signals, "red", "Recent public news cross-reference did not find reliable supporting coverage.", WEIGHTS.medium);
    }

    const score = calculateRisk(signals);
    const verdict = buildVerdict(score, signals, liveEvidence);
    const category = classifyCategory(cleanedText);

    return {
        classification: verdict.classification,
        isRedFlag: verdict.isRedFlag,
        riskLevel: `${riskLabel(score)} (${score}/100)`,
        category,
        explainability: compactSignals(signals, verdict.isRedFlag),
        justification: buildJustification(cleanedText, urls, emails, signals, liveEvidence),
        advice: buildAdvice(verdict.isRedFlag, category)
    };
}

function displayResults(data) {
    // Hide scanner, show results
    scanningOverlay.classList.add('hidden');
    
    // reset display
    resultsPanel.style.display = 'block';
    
    // small timeout to allow display:block to apply before animating opacity
    setTimeout(() => {
        resultsPanel.classList.remove('hidden');
        resultsPanel.classList.add('visible');
    }, 50);

    // Populate data
    uiClass.textContent = data.classification;
    uiClass.className = 'classification ' + (data.isRedFlag ? 'red-flag' : 'blue-flag');
    
    uiRisk.textContent = data.riskLevel;
    uiCat.textContent = data.category;
    
    uiJust.textContent = data.justification;
    uiAdv.textContent = data.advice;

    uiList.innerHTML = '';
    data.explainability.forEach(item => {
        const li = document.createElement('li');
        li.textContent = item.text;
        li.className = item.type === 'red' ? 'li-red-flag' : 'li-trust-signal';
        uiList.appendChild(li);
    });
}

scanBtn.addEventListener('click', () => {
    const text = inputArea.value.trim();
    if (!text) return;

    if (text.length > MAX_INPUT_CHARS) {
        inputArea.value = text.slice(0, MAX_INPUT_CHARS);
    }

    // Reset UI
    resultsPanel.classList.remove('visible');
    scanBtn.disabled = true;
    
    setTimeout(() => {
        resultsPanel.style.display = 'none';
        scanningOverlay.classList.remove('hidden');
    }, 300);

    // Simulate Network/Processing Delay
    setTimeout(async () => {
        try {
            // Check if it exactly matches a demo input
            let result = null;
            for (let key in demoData) {
                if (demoData[key].input === text) {
                    result = demoData[key];
                    break;
                }
            }

            if (!result) {
                result = await simulateAnalysis(text);
            }

            displayResults(result);
        } catch (error) {
            displayResults({
                classification: "[RED FLAG] - SCAN ERROR / VERIFY MANUALLY",
                isRedFlag: true,
                riskLevel: "Unknown",
                category: "Analysis Runtime Protection",
                explainability: [
                    { type: "red", text: "The analysis engine hit a browser or network error before completing verification." },
                    { type: "red", text: "Treat the claim as unverified until it is checked on official sources." }
                ],
                justification: "The app failed closed instead of marking unknown information as true.",
                advice: "Retry the scan, then verify through official websites and reputable news sources before trusting or sharing the claim."
            });
        } finally {
            scanBtn.disabled = false;
        }
    }, 2000);
});

demoBtns.forEach(btn => {
    btn.addEventListener('click', (e) => {
        const demoId = e.target.getAttribute('data-demo');
        inputArea.value = demoData[demoId].input;
        resultsPanel.classList.remove('visible');
        setTimeout(() => {
            resultsPanel.style.display = 'none';
        }, 300);
    });
});
