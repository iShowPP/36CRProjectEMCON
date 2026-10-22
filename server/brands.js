// Real brands phishers impersonate most, with their official domains. Used by the
// extension for (1) look-alike domain detection and (2) "asks for a password while
// mentioning <brand> on a non-official domain". Tokens are matched against whole
// hostname parts (split on "." and "-"), after undoing look-alike characters.

export const REAL_BRANDS = [
  { name: 'PayPal', domains: ['paypal.com', 'paypal.me', 'paypalobjects.com'], tokens: ['paypal'] },
  { name: 'Google', domains: ['google.com', 'google.co.in', 'gmail.com', 'youtube.com', 'googleusercontent.com', 'gstatic.com', 'googleapis.com', 'withgoogle.com'], tokens: ['google', 'gmail'] },
  { name: 'Microsoft', domains: ['microsoft.com', 'microsoftonline.com', 'live.com', 'outlook.com', 'office.com', 'office365.com', 'sharepoint.com', 'onedrive.com', 'bing.com', 'azure.com', 'xbox.com', 'skype.com'], tokens: ['microsoft', 'outlook', 'office365', 'onedrive', 'hotmail'] },
  { name: 'Apple', domains: ['apple.com', 'icloud.com', 'me.com'], tokens: ['apple', 'icloud', 'appleid'] },
  { name: 'Amazon', domains: ['amazon.com', 'amazon.in', 'amazon.co.uk', 'amazon.de', 'amazonaws.com', 'primevideo.com', 'a2z.com'], tokens: ['amazon'] },
  { name: 'Netflix', domains: ['netflix.com', 'nflxext.com'], tokens: ['netflix'] },
  { name: 'Meta', domains: ['facebook.com', 'fb.com', 'instagram.com', 'whatsapp.com', 'whatsapp.net', 'messenger.com', 'meta.com'], tokens: ['facebook', 'instagram', 'whatsapp'] },
  { name: 'LinkedIn', domains: ['linkedin.com', 'licdn.com'], tokens: ['linkedin'] },
  { name: 'Binance', domains: ['binance.com'], tokens: ['binance'] },
  { name: 'Coinbase', domains: ['coinbase.com'], tokens: ['coinbase'] },
  { name: 'MetaMask', domains: ['metamask.io'], tokens: ['metamask'] },
  { name: 'DHL', domains: ['dhl.com', 'dhl.de'], tokens: ['dhl'] },
  // Indian banks are moving to RBI's restricted ".bank.in" zone, where only verified banks
  // can register names, so anything under bank.in counts as official for them.
  { name: 'State Bank of India', domains: ['sbi', 'sbi.co.in', 'onlinesbi.com', 'sbicard.com', 'bank.in'], tokens: ['onlinesbi', 'sbi', 'yonosbi'] },
  { name: 'HDFC Bank', domains: ['hdfcbank.com', 'hdfc.com', 'hdfcbank.net', 'bank.in'], tokens: ['hdfc', 'hdfcbank'] },
  { name: 'ICICI Bank', domains: ['icicibank.com', 'icici.com', 'icicidirect.com', 'bank.in'], tokens: ['icici', 'icicibank'] },
  { name: 'Axis Bank', domains: ['axisbank.com', 'bank.in'], tokens: ['axisbank'] },
  { name: 'Paytm', domains: ['paytm.com', 'paytm.in'], tokens: ['paytm'] },
  { name: 'PhonePe', domains: ['phonepe.com'], tokens: ['phonepe'] },
];

// Multi-tenant hosts where the *path*, not the hostname, belongs to the attacker.
// A phishing URL on these must never get the whole host marked as a scam.
export const SHARED_HOSTS = new Set([
  'sites.google.com', 'docs.google.com', 'drive.google.com', 'forms.gle', 'script.google.com', 'storage.googleapis.com',
  'firebasestorage.googleapis.com', 'github.com', 'raw.githubusercontent.com', 'gist.github.com', 'gitlab.com', 'bitbucket.org',
  'dropbox.com', 'dl.dropboxusercontent.com', 'onedrive.live.com', '1drv.ms', 'forms.office.com', 'docs.zoho.com',
  'ipfs.io', 'dweb.link', 'cloudflare-ipfs.com', 'bit.ly', 't.co', 'tinyurl.com', 'linktr.ee', 'telegra.ph', 'wa.me',
  'web.archive.org', 'translate.goog', 'canva.com', 'notion.so', 'docs.qq.com',
]);
