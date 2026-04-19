"""Test complet du pipeline Mobile API Misuse Detector."""
 
import os
 
print("=" * 60)
print("  TEST PIPELINE — Mobile API Misuse Detector")
print("=" * 60)
 
# 1. Génération des logs
print("\n[1] Génération des logs simulés...")
from generator.log_generator import generate_logs
logs = generate_logs(n_normal=200)
print(f"    {len(logs)} logs générés.")
 
# 2. Parsing
print("\n[2] Parsing des logs...")
from parser.mobile_parser import parse_log_file
df = parse_log_file("samples/mobile_api_logs.txt")
print(f"    {len(df)} entrées parsées.")
print(f"    Requêtes mobiles : {df['is_mobile'].sum()}")
 
# 3. Détection
print("\n[3] Détection des menaces...")
from detection.rules import run_all_detections
alerts = run_all_detections(df)
print(f"    {len(alerts)} alertes levées.")
for a in alerts:
    print(f"    [{a.severity}] {a.type} — {a.ip} — {a.details}")
 
# 4. Clustering IA
print("\n[4] Clustering IA...")
from ai.clustering import extract_ip_features, run_clustering
features  = extract_ip_features(df)
clustered = run_clustering(features, n_clusters=4)
print(f"    {len(clustered)} IPs clusterisées.")
print(clustered[["ip", "cluster_name", "total_requests"]].head(10).to_string())
 
# 5. Recommandations
print("\n[5] Recommandations...")
from recommendations.advisor import generate_recommendations
recos = generate_recommendations(alerts)
for r in recos:
    print(f"    [{r['priority']}] {r['title']}")
 
print("\n" + "=" * 60)
print("  ✅ Pipeline complet — Tous les modules fonctionnent !")
print("=" * 60)
