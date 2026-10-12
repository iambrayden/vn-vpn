"""Turn a hostname (from DNS) or network owner (from ip2asn) into an app and a category, UniFi-style.

Categories are a fixed, ordered list (7 + Other) so dashboard colours always mean the same thing.
"""

CATEGORIES = ["Streaming", "Social", "Messaging & Calls", "Gaming", "Web & Search", "Cloud & Software",
              "Ads & Tracking", "Other"]

# (domain suffix, app, category). Longest suffix wins.
_RULES = [
    # Streaming
    ("youtube.com", "YouTube", "Streaming"), ("googlevideo.com", "YouTube", "Streaming"),
    ("ytimg.com", "YouTube", "Streaming"), ("youtu.be", "YouTube", "Streaming"),
    ("netflix.com", "Netflix", "Streaming"), ("nflxvideo.net", "Netflix", "Streaming"),
    ("nflximg.net", "Netflix", "Streaming"), ("nflxso.net", "Netflix", "Streaming"), ("nflxext.com", "Netflix", "Streaming"),
    ("twitch.tv", "Twitch", "Streaming"), ("ttvnw.net", "Twitch", "Streaming"), ("jtvnw.net", "Twitch", "Streaming"),
    ("hulu.com", "Hulu", "Streaming"), ("hulustream.com", "Hulu", "Streaming"),
    ("disneyplus.com", "Disney+", "Streaming"), ("dssott.com", "Disney+", "Streaming"), ("bamgrid.com", "Disney+", "Streaming"),
    ("primevideo.com", "Prime Video", "Streaming"), ("aiv-cdn.net", "Prime Video", "Streaming"),
    ("aiv-delivery.net", "Prime Video", "Streaming"), ("amazonvideo.com", "Prime Video", "Streaming"),
    ("max.com", "Max", "Streaming"), ("hbomax.com", "Max", "Streaming"),
    ("spotify.com", "Spotify", "Streaming"), ("scdn.co", "Spotify", "Streaming"), ("spotifycdn.com", "Spotify", "Streaming"),
    ("soundcloud.com", "SoundCloud", "Streaming"), ("vimeo.com", "Vimeo", "Streaming"), ("vimeocdn.com", "Vimeo", "Streaming"),
    ("plex.tv", "Plex", "Streaming"), ("plex.direct", "Plex", "Streaming"), ("pandora.com", "Pandora", "Streaming"),
    ("peacocktv.com", "Peacock", "Streaming"), ("paramountplus.com", "Paramount+", "Streaming"),
    ("crunchyroll.com", "Crunchyroll", "Streaming"), ("tv.apple.com", "Apple TV+", "Streaming"),
    ("music.apple.com", "Apple Music", "Streaming"), ("kick.com", "Kick", "Streaming"),
    # Social
    ("facebook.com", "Facebook", "Social"), ("fbcdn.net", "Facebook", "Social"), ("facebook.net", "Facebook", "Social"),
    ("fb.com", "Facebook", "Social"), ("fbsbx.com", "Facebook", "Social"),
    ("instagram.com", "Instagram", "Social"), ("cdninstagram.com", "Instagram", "Social"),
    ("tiktok.com", "TikTok", "Social"), ("tiktokcdn.com", "TikTok", "Social"), ("tiktokv.com", "TikTok", "Social"),
    ("tiktokcdn-us.com", "TikTok", "Social"), ("byteoversea.com", "TikTok", "Social"), ("ibytedtos.com", "TikTok", "Social"),
    ("musical.ly", "TikTok", "Social"),
    ("twitter.com", "X", "Social"), ("x.com", "X", "Social"), ("twimg.com", "X", "Social"), ("t.co", "X", "Social"),
    ("snapchat.com", "Snapchat", "Social"), ("sc-cdn.net", "Snapchat", "Social"), ("snap-dev.net", "Snapchat", "Social"),
    ("reddit.com", "Reddit", "Social"), ("redd.it", "Reddit", "Social"), ("redditmedia.com", "Reddit", "Social"),
    ("redditstatic.com", "Reddit", "Social"), ("linkedin.com", "LinkedIn", "Social"), ("licdn.com", "LinkedIn", "Social"),
    ("pinterest.com", "Pinterest", "Social"), ("pinimg.com", "Pinterest", "Social"), ("threads.net", "Threads", "Social"),
    ("tumblr.com", "Tumblr", "Social"),
    # Messaging & calls
    ("whatsapp.net", "WhatsApp", "Messaging & Calls"), ("whatsapp.com", "WhatsApp", "Messaging & Calls"),
    ("messenger.com", "Messenger", "Messaging & Calls"), ("telegram.org", "Telegram", "Messaging & Calls"),
    ("t.me", "Telegram", "Messaging & Calls"), ("signal.org", "Signal", "Messaging & Calls"),
    ("discord.com", "Discord", "Messaging & Calls"), ("discord.gg", "Discord", "Messaging & Calls"),
    ("discordapp.com", "Discord", "Messaging & Calls"), ("discordapp.net", "Discord", "Messaging & Calls"),
    ("discord.media", "Discord", "Messaging & Calls"), ("zoom.us", "Zoom", "Messaging & Calls"),
    ("zoom.com", "Zoom", "Messaging & Calls"), ("teams.microsoft.com", "Microsoft Teams", "Messaging & Calls"),
    ("teams.live.com", "Microsoft Teams", "Messaging & Calls"), ("skype.com", "Skype", "Messaging & Calls"),
    ("slack.com", "Slack", "Messaging & Calls"), ("slack-edge.com", "Slack", "Messaging & Calls"),
    ("facetime.apple.com", "FaceTime", "Messaging & Calls"), ("webex.com", "Webex", "Messaging & Calls"),
    # Gaming
    ("steampowered.com", "Steam", "Gaming"), ("steamcommunity.com", "Steam", "Gaming"), ("steamcontent.com", "Steam", "Gaming"),
    ("steamserver.net", "Steam", "Gaming"), ("steamstatic.com", "Steam", "Gaming"), ("valvesoftware.com", "Steam", "Gaming"),
    ("epicgames.com", "Epic Games", "Gaming"), ("epicgames.dev", "Epic Games", "Gaming"), ("fortnite.com", "Epic Games", "Gaming"),
    ("xboxlive.com", "Xbox", "Gaming"), ("xbox.com", "Xbox", "Gaming"), ("playstation.com", "PlayStation", "Gaming"),
    ("playstation.net", "PlayStation", "Gaming"), ("sonyentertainmentnetwork.com", "PlayStation", "Gaming"),
    ("nintendo.net", "Nintendo", "Gaming"), ("nintendo.com", "Nintendo", "Gaming"), ("riotgames.com", "Riot Games", "Gaming"),
    ("leagueoflegends.com", "Riot Games", "Gaming"), ("roblox.com", "Roblox", "Gaming"), ("rbxcdn.com", "Roblox", "Gaming"),
    ("battle.net", "Battle.net", "Gaming"), ("blizzard.com", "Battle.net", "Gaming"), ("ea.com", "EA", "Gaming"),
    ("minecraft.net", "Minecraft", "Gaming"), ("mojang.com", "Minecraft", "Gaming"), ("activision.com", "Activision", "Gaming"),
    ("callofduty.com", "Activision", "Gaming"), ("ubisoft.com", "Ubisoft", "Gaming"),
    # Web & search
    ("google.com", "Google", "Web & Search"), ("gstatic.com", "Google", "Web & Search"),
    ("googleusercontent.com", "Google", "Web & Search"), ("googleapis.com", "Google", "Web & Search"),
    ("bing.com", "Bing", "Web & Search"), ("duckduckgo.com", "DuckDuckGo", "Web & Search"),
    ("wikipedia.org", "Wikipedia", "Web & Search"), ("wikimedia.org", "Wikipedia", "Web & Search"),
    ("yahoo.com", "Yahoo", "Web & Search"), ("amazon.com", "Amazon", "Web & Search"), ("media-amazon.com", "Amazon", "Web & Search"),
    ("ebay.com", "eBay", "Web & Search"), ("chatgpt.com", "ChatGPT", "Web & Search"), ("openai.com", "ChatGPT", "Web & Search"),
    ("oaistatic.com", "ChatGPT", "Web & Search"), ("claude.ai", "Claude", "Web & Search"),
    ("anthropic.com", "Claude", "Web & Search"), ("nytimes.com", "New York Times", "Web & Search"),
    ("cnn.com", "CNN", "Web & Search"), ("espn.com", "ESPN", "Web & Search"), ("paypal.com", "PayPal", "Web & Search"),
    # Cloud & software
    ("apple.com", "Apple", "Cloud & Software"), ("icloud.com", "iCloud", "Cloud & Software"),
    ("icloud-content.com", "iCloud", "Cloud & Software"), ("mzstatic.com", "Apple", "Cloud & Software"),
    ("apple-cloudkit.com", "iCloud", "Cloud & Software"), ("aaplimg.com", "Apple", "Cloud & Software"),
    ("cdn-apple.com", "Apple", "Cloud & Software"), ("push.apple.com", "Apple Push", "Cloud & Software"),
    ("microsoft.com", "Microsoft", "Cloud & Software"), ("windowsupdate.com", "Windows Update", "Cloud & Software"),
    ("live.com", "Microsoft", "Cloud & Software"), ("office.com", "Microsoft 365", "Cloud & Software"),
    ("office.net", "Microsoft 365", "Cloud & Software"), ("office365.com", "Microsoft 365", "Cloud & Software"),
    ("microsoftonline.com", "Microsoft 365", "Cloud & Software"), ("outlook.com", "Outlook", "Cloud & Software"),
    ("sharepoint.com", "Microsoft 365", "Cloud & Software"), ("onedrive.com", "OneDrive", "Cloud & Software"),
    ("msedge.net", "Microsoft", "Cloud & Software"), ("azureedge.net", "Azure", "Cloud & Software"),
    ("azure.com", "Azure", "Cloud & Software"), ("amazonaws.com", "AWS", "Cloud & Software"),
    ("cloudfront.net", "CloudFront", "Cloud & Software"), ("akamaized.net", "Akamai", "Cloud & Software"),
    ("akamai.net", "Akamai", "Cloud & Software"), ("akamaiedge.net", "Akamai", "Cloud & Software"),
    ("edgekey.net", "Akamai", "Cloud & Software"), ("edgesuite.net", "Akamai", "Cloud & Software"),
    ("cloudflare.com", "Cloudflare", "Cloud & Software"), ("cloudflare-dns.com", "Cloudflare", "Cloud & Software"),
    ("fastly.net", "Fastly", "Cloud & Software"), ("dropbox.com", "Dropbox", "Cloud & Software"),
    ("dropboxapi.com", "Dropbox", "Cloud & Software"), ("github.com", "GitHub", "Cloud & Software"),
    ("githubusercontent.com", "GitHub", "Cloud & Software"), ("docker.io", "Docker", "Cloud & Software"),
    ("ubuntu.com", "Ubuntu", "Cloud & Software"), ("drive.google.com", "Google Drive", "Cloud & Software"),
    ("gmail.com", "Gmail", "Cloud & Software"), ("mail.google.com", "Gmail", "Cloud & Software"),
    # Ads & tracking
    ("doubleclick.net", "Google Ads", "Ads & Tracking"), ("googlesyndication.com", "Google Ads", "Ads & Tracking"),
    ("googleadservices.com", "Google Ads", "Ads & Tracking"), ("google-analytics.com", "Google Analytics", "Ads & Tracking"),
    ("googletagmanager.com", "Google Analytics", "Ads & Tracking"), ("app-measurement.com", "Firebase Analytics", "Ads & Tracking"),
    ("adnxs.com", "AppNexus", "Ads & Tracking"), ("criteo.com", "Criteo", "Ads & Tracking"),
    ("scorecardresearch.com", "Comscore", "Ads & Tracking"), ("taboola.com", "Taboola", "Ads & Tracking"),
    ("outbrain.com", "Outbrain", "Ads & Tracking"), ("adsrvr.org", "The Trade Desk", "Ads & Tracking"),
    ("amazon-adsystem.com", "Amazon Ads", "Ads & Tracking"), ("appsflyer.com", "AppsFlyer", "Ads & Tracking"),
    ("adjust.com", "Adjust", "Ads & Tracking"), ("branch.io", "Branch", "Ads & Tracking"),
    ("hotjar.com", "Hotjar", "Ads & Tracking"), ("mixpanel.com", "Mixpanel", "Ads & Tracking"),
    ("segment.io", "Segment", "Ads & Tracking"), ("sentry.io", "Sentry", "Ads & Tracking"),
]
_BY_SUFFIX = {s: (a, c) for s, a, c in _RULES}

# Fallback when there's no hostname: the destination network's owner (ip2asn description), upper-cased.
_ORG_RULES = [
    ("NETFLIX", "Netflix", "Streaming"), ("TWITCH", "Twitch", "Streaming"), ("SPOTIFY", "Spotify", "Streaming"),
    ("FACEBOOK", "Facebook", "Social"), ("BYTEDANCE", "TikTok", "Social"),
    ("TIKTOK", "TikTok", "Social"), ("TWITTER", "X", "Social"), ("SNAPCHAT", "Snapchat", "Social"),
    ("WHATSAPP", "WhatsApp", "Messaging & Calls"), ("DISCORD", "Discord", "Messaging & Calls"),
    ("ZOOM", "Zoom", "Messaging & Calls"), ("TELEGRAM", "Telegram", "Messaging & Calls"),
    ("VALVE", "Steam", "Gaming"), ("RIOT", "Riot Games", "Gaming"), ("SONY", "PlayStation", "Gaming"),
    ("NINTENDO", "Nintendo", "Gaming"), ("BLIZZARD", "Battle.net", "Gaming"), ("ROBLOX", "Roblox", "Gaming"),
    ("GOOGLE", "Google", "Web & Search"), ("APPLE", "Apple", "Cloud & Software"),
    ("MICROSOFT", "Microsoft", "Cloud & Software"), ("AMAZON", "AWS", "Cloud & Software"),
    ("CLOUDFLARE", "Cloudflare", "Cloud & Software"), ("AKAMAI", "Akamai", "Cloud & Software"),
    ("FASTLY", "Fastly", "Cloud & Software"), ("DIGITALOCEAN", "DigitalOcean", "Cloud & Software"),
    ("OVH", "OVH", "Cloud & Software"), ("HETZNER", "Hetzner", "Cloud & Software"), ("LINODE", "Linode", "Cloud & Software"),
]
_PORT_APPS = {53: ("DNS", "Other"), 853: ("DNS over TLS", "Other"), 123: ("NTP", "Other"), 22: ("SSH", "Other"),
              3389: ("Remote Desktop", "Other"), 25: ("Email (SMTP)", "Other"), 587: ("Email (SMTP)", "Other"),
              993: ("Email (IMAP)", "Other"), 5223: ("Apple Push", "Cloud & Software"),
              5228: ("Google Play", "Cloud & Software"), 3478: ("STUN / calls", "Messaging & Calls")}


def classify(host: str, org: str = "", port: int = 0) -> tuple[str, str]:
    """(app, category) for a flow. Hostname first, then network owner, then well-known port."""
    host = (host or "").lower().rstrip(".")
    if host:
        parts = host.split(".")
        for i in range(len(parts) - 1):
            hit = _BY_SUFFIX.get(".".join(parts[i:]))
            if hit:
                return hit
    up = (org or "").upper()
    for needle, app, cat in _ORG_RULES:
        if needle in up:
            return app, cat
    if port in _PORT_APPS:
        return _PORT_APPS[port]
    if host:
        return ".".join(host.split(".")[-2:]), "Other"   # unknown site: its registrable-ish domain
    return "", "Other"
