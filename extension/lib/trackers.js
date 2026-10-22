// Third-party tracking / advertising domains (a small, readable subset of public lists such
// as Disconnect and EasyPrivacy). Matched by domain suffix.

export const TRACKERS = {
  'google-analytics.com': 'Google Analytics',
  'googletagmanager.com': 'Google Tag Manager',
  'doubleclick.net': 'Google Ads (DoubleClick)',
  'googlesyndication.com': 'Google AdSense',
  'googleadservices.com': 'Google Ads',
  'adservice.google.com': 'Google Ads',
  'facebook.net': 'Meta Pixel',
  'clarity.ms': 'Microsoft Clarity',
  'bat.bing.com': 'Microsoft Ads',
  'hotjar.com': 'Hotjar',
  'hotjar.io': 'Hotjar',
  'scorecardresearch.com': 'Comscore',
  'quantserve.com': 'Quantcast',
  'criteo.com': 'Criteo',
  'criteo.net': 'Criteo',
  'taboola.com': 'Taboola',
  'outbrain.com': 'Outbrain',
  'adnxs.com': 'Xandr',
  'amazon-adsystem.com': 'Amazon Ads',
  'ads-twitter.com': 'X Ads',
  'analytics.tiktok.com': 'TikTok Pixel',
  'snap.licdn.com': 'LinkedIn Insight',
  'px.ads.linkedin.com': 'LinkedIn Ads',
  'mixpanel.com': 'Mixpanel',
  'segment.io': 'Segment',
  'segment.com': 'Segment',
  'amplitude.com': 'Amplitude',
  'chartbeat.com': 'Chartbeat',
  'branch.io': 'Branch',
  'appsflyer.com': 'AppsFlyer',
  'moengage.com': 'MoEngage',
  'clevertap-prod.com': 'CleverTap',
  'webengage.com': 'WebEngage',
  'rubiconproject.com': 'Magnite',
  'pubmatic.com': 'PubMatic',
  'openx.net': 'OpenX',
  'casalemedia.com': 'Index Exchange',
  'mc.yandex.ru': 'Yandex Metrica',
  'adnetwork-demo.example': 'Demo ad network (EMCON stand-in, never resolves)',
};

export function trackerFor(host) {
  for (const [d, name] of Object.entries(TRACKERS)) if (host === d || host.endsWith('.' + d)) return name;
  return null;
}
