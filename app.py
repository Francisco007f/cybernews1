import streamlit as st
import datetime
import feedparser
import time
import re

# Page configuration
st.set_page_config(
    page_title="CyberNews1 - Cybersecurity News",
    page_icon="🔒",
    layout="wide"
)

# Custom CSS styles
st.markdown("""
    <style>
    .main {
        background-color: #f0f2f6;
    }
    .title {
        color: #2c3e50;
        font-size: 2.5em;
        text-align: center;
        margin-bottom: 0.5em;
    }
    .news-card {
        background-color: #2c3e50;
        padding: 1.5em;
        border-radius: 10px;
        margin-bottom: 1em;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    .news-title {
        color: #2c3e50;
        font-size: 1.5em;
        margin-bottom: 0.5em;
    }
    .news-date {
        color: #7f8c8d;
        font-size: 0.9em;
        margin-bottom: 0.5em;
    }
    .sidebar .sidebar-content {
        background-color: #2c3e50;
        color: white;
        padding: 1em;
        border-radius: 10px;
    }
    .glossary-term {
        font-weight: bold;
        color: white;
    }
    .glossary-card {
        background-color: #2c3e50;
        padding: 1.5em;
        border-radius: 10px;
        margin-bottom: 1em;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    .tool-card {
        background-color: #2c3e50;
        padding: 1.5em;
        border-radius: 10px;
        margin-bottom: 1em;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    </style>
""", unsafe_allow_html=True)

# Main title
st.markdown("<h1 class='title'>CyberNews1 - Latest Cybersecurity News</h1>", unsafe_allow_html=True)

# Sidebar
with st.sidebar:
    st.markdown("## Filters")
    category = st.selectbox(
        "Category",
        ["All", "Ransomware", "Phishing", "Malware", "Data Breach", "DDoS Attacks"]
    )
    st.markdown("## Search")
    search_query = st.text_input("Search news by keyword", placeholder="Enter keywords...")

# Function to categorize news based on content
def categorize_news(content):
    content = content.lower()
    if any(keyword in content for keyword in ["ransomware", "lockbit", "blackcat", "ranion"]):
        return "Ransomware"
    elif any(keyword in content for keyword in ["phishing", "smishing", "vishing", "spear phishing", "fake email"]):
        return "Phishing"
    elif any(keyword in content for keyword in ["malware", "virus", "trojan", "spyware", "worm", "botnet"]):
        return "Malware"
    elif any(keyword in content for keyword in ["data breach", "leak", "unauthorized access", "exposed data"]):
        return "Data Breach"
    elif any(keyword in content for keyword in ["ddos", "denial of service", "distributed denial"]):
        return "DDoS Attacks"
    return "All"

# RSS feeds for cybersecurity news
RSS_FEEDS = [
    "https://www.bleepingcomputer.com/feed/",          # BleepingComputer
    "https://thehackernews.com/feed",                 # The Hacker News
    "https://www.darkreading.com/rss.xml",            # Dark Reading
    "https://cybernews.com/feed/",                    # Cybernews
    "https://threatpost.com/feed/",                   # Threatpost
    "https://krebsonsecurity.com/feed/",              # Krebs on Security
    "https://www.scmagazine.com/feed",                # SC Media
    "https://nakedsecurity.sophos.com/feed/"          # Naked Security by Sophos
]

# Fetch news from RSS feeds
@st.cache_data(ttl=600, show_spinner=False)  # Cache for 10 minutes
def fetch_cybersecurity_news(_cache_buster):
    news_items = []
    try:
        for feed_url in RSS_FEEDS:
            feed = feedparser.parse(feed_url)
            for entry in feed.entries[:10]:  # Limit to 10 articles per feed
                title = entry.get("title", "No title")
                url = entry.get("link", "#")
                # Get description or summary, clean HTML tags
                content = entry.get("summary", entry.get("description", "No description available"))
                content = re.sub(r'<[^>]+>', '', content)  # Remove HTML tags
                published = entry.get("published", "2025-01-01T00:00:00Z")
                try:
                    date = datetime.datetime.strptime(published, "%a, %d %b %Y %H:%M:%S %z").date()
                except (ValueError, TypeError):
                    date = datetime.date(2025, 1, 1)  # Fallback date
                category = categorize_news(content + " " + title)
                news_items.append({
                    "title": title,
                    "date": date,
                    "category": category,
                    "content": content[:200] + "..." if len(content) > 200 else content,  # Truncate long content
                    "url": url
                })
    except Exception as e:
        st.error(f"Error fetching news: {str(e)}")
        # Fallback data
        news_items = [
            {
                "title": "Pro-Russian Hackers Target Italian Government Websites",
                "date": datetime.date(2025, 1, 15),
                "category": "DDoS Attacks",
                "content": "A pro-Russian hacking group launched a DDoS attack on Italian government websites.",
                "url": "https://www.reuters.com/world/europe/italy-government-websites-hit-by-pro-russian-hackers-2025-01-15/"
            },
            {
                "title": "Ransomware Surge Hits UK Businesses",
                "date": datetime.date(2025, 2, 10),
                "category": "Ransomware",
                "content": "UK businesses faced a doubled ransomware attack rate in 2025.",
                "url": "https://www.bbc.com/news/technology-2025-ransomware-surge"
            }
        ]
    return sorted(news_items, key=lambda x: x["date"], reverse=True)[:10]  # Sort by date, limit to 10

# Glossary data
glossary = [
    {
        "term": "Ransomware",
        "definition": "A type of malware that encrypts a victim's files, demanding payment to restore access."
    },
    {
        "term": "Phishing",
        "definition": "A cyberattack that uses fraudulent emails to trick users into providing sensitive information."
    },
    {
        "term": "Malware",
        "definition": "Malicious software designed to harm or compromise a computer system."
    },
    {
        "term": "Data Breach",
        "definition": "An incident where unauthorized individuals gain access to confidential information."
    },
    {
        "term": "DDoS Attack",
        "definition": "Distributed Denial-of-Service attack, flooding a target with traffic to disrupt availability."
    },
    {
        "term": "Spyware",
        "definition": "Malicious software that secretly collects user information without their knowledge."
    },
    {
        "term": "Botnet",
        "definition": "A network of compromised devices controlled remotely to perform coordinated attacks."
    },
    {
        "term": "Zero-Day",
        "definition": "A vulnerability exploited before the software developer releases a patch."
    },
    {
        "term": "Social Engineering",
        "definition": "Techniques that manipulate individuals into divulging sensitive information."
    },
    {
        "term": "Cryptojacking",
        "definition": "Unauthorized use of a device's resources to mine cryptocurrencies."
    }
]

# Free security tools data
security_tools = [
    {
        "name": "Wireshark",
        "description": "A widely-used network protocol analyzer for capturing and inspecting network traffic.",
        "url": "https://www.wireshark.org/"
    },
    {
        "name": "Nmap",
        "description": "A powerful network scanning tool for discovering hosts and services on a network.",
        "url": "https://nmap.org/"
    },
    {
        "name": "ClamAV",
        "description": "An open-source antivirus engine for detecting malware, viruses, and other threats.",
        "url": "https://www.clamav.net/"
    },
    {
        "name": "Metasploit Framework",
        "description": "A penetration testing framework for identifying and exploiting vulnerabilities.",
        "url": "https://www.metasploit.com/"
    },
    {
        "name": "OSSEC",
        "description": "An open-source host-based intrusion detection system for monitoring and alerting.",
        "url": "https://www.ossec.net/"
    },
    {
        "name": "VeraCrypt",
        "description": "A free disk encryption software for securing sensitive data on your devices.",
        "url": "https://www.veracrypt.fr/"
    },
    {
        "name": "Snort",
        "description": "An open-source network intrusion detection and prevention system for real-time traffic analysis.",
        "url": "https://www.snort.org/"
    },
    {
        "name": "Kali Linux",
        "description": "A Linux distribution specifically designed for security researchers and penetration testers.",
        "url": "https://www.kali.org/"
    }
]

# Create tabs
tab1, tab2, tab3 = st.tabs(["News", "Glossary", "Tools"])

# News tab
with tab1:
    st.markdown("<h2>Recent Cybersecurity News (2025)</h2>", unsafe_allow_html=True)
    # Generate a cache buster that changes every 10 minutes
    cache_buster = int(time.time() // 600)
    news = fetch_cybersecurity_news(cache_buster)

    # Add a button to manually refresh news
    if st.button("Refresh News Now"):
        st.cache_data.clear()  # Clear cache
        st.rerun()  # Rerun the app to fetch fresh data

    # Filter news by category
    if category != "All":
        filtered_news = [item for item in news if item["category"] == category]
    else:
        filtered_news = news

    # Filter news by search query
    if search_query:
        search_query = search_query.lower()
        filtered_news = [
            item for item in filtered_news
            if search_query in item["title"].lower() or search_query in item["content"].lower()
        ]

    # Display news
    if filtered_news:
        for item in filtered_news:
            with st.container():
                st.markdown(f"""
                    <div class='news-card'>
                        <h2 class='news-title'><a href="{item['url']}" target="_blank">{item['title']}</a></h2>
                        <p class='news-date'>{item['date']}</p>
                        <p>{item['content']}</p>
                    </div>
                """, unsafe_allow_html=True)
                if st.button("Read more", key=item["title"]):
                    st.write(f"Visit the full article: {item['url']}")
    else:
        st.warning("No news articles found for the selected category or search query.")

# Glossary tab
with tab2:
    st.markdown("<h2>Cybersecurity Glossary</h2>", unsafe_allow_html=True)
    for item in glossary:
        with st.container():
            st.markdown(f"""
                <div class='glossary-card'>
                    <p><span class='glossary-term'>{item['term']}:</span> {item['definition']}</p>
                </div>
            """, unsafe_allow_html=True)

# Tools tab
with tab3:
    st.markdown("<h2>Free Cybersecurity Tools</h2>", unsafe_allow_html=True)
    for tool in security_tools:
        with st.container():
            st.markdown(f"""
                <div class='tool-card'>
                    <p><span class='glossary-term'>{tool['name']}:</span> {tool['description']}</p>
                    <p><a href="{tool['url']}" target="_blank">Visit {tool['name']}</a></p>
                </div>
            """, unsafe_allow_html=True)

# Footer
st.markdown("""
    <hr>
    <p style='text-align: center; color: #7f8c8d;'>
        CyberNews1 © 2025 | All rights reserved
    </p>
""", unsafe_allow_html=True)
