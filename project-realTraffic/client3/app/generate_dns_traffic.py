import dns.resolver
import random
import time
import socket

# Lista di domini benigni e potenzialmente sospetti per test di sicurezza
domains = [
    "google.com", "facebook.com", "youtube.com", "twitter.com", "wikipedia.org",
    "example.com", "openai.com", "github.com", "cloudflare.com", "amazon.com"
]

def generate_dns_traffic(interval=1, max_queries=100):
    resolver = dns.resolver.Resolver()
    dns_server_ip = socket.gethostbyname("serverDNS")
    resolver.nameservers = [dns_server_ip]
    resolver.port = 53
    
    for _ in range(max_queries):
        domain = random.choice(domains)  # Sceglie un dominio casuale
        record_type = random.choice(["A", "AAAA", "MX", "TXT", "CNAME"])
        
        try:
            answer = resolver.resolve(domain, record_type)
            print(f"Query: {domain} ({record_type}) -> {[rdata.to_text() for rdata in answer]}")
        except Exception as e:
            print(f"Errore nella risoluzione di {domain} ({record_type}): {e}")
        
        time.sleep(interval)  # Ritardo tra le richieste per evitare flooding

if __name__ == "__main__":
    time.sleep(10)  # Attesa per l'avvio del server DNS
    generate_dns_traffic(interval=2, max_queries=50)
