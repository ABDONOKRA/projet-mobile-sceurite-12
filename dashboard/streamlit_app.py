"""
Dashboard Streamlit pour Mobile API Misuse Detector.
Visualisation interactive des alertes et clusters IA.
"""


import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
 
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
 
from generator.log_generator import generate_logs
from parser.mobile_parser import parse_log_file
from detection.rules import run_all_detections
from ai.clustering import extract_ip_features, run_clustering
from recommendations.advisor import generate_recommendations
 
 
# Configuration de la page
st.set_page_config(
    page_title="Mobile API Misuse Detector",
    page_icon="🔐",
    layout="wide",
)
 
st.title("🔐 Mobile API Misuse Detector")
st.markdown("Détection d'abus d'API mobiles par analyse de logs et clustering IA")
 
# --- Sidebar ---
st.sidebar.header("⚙️ Configuration")
log_file = st.sidebar.text_input("Fichier de logs", value="samples/mobile_api_logs.txt")
 
if st.sidebar.button("🔄 Régénérer les logs simulés"):
    with st.spinner("Génération des logs..."):
        generate_logs()
    st.sidebar.success("Logs régénérés !")
 
n_clusters = st.sidebar.slider("Nombre de clusters IA", 2, 6, 4)
 
# --- Chargement des données ---
@st.cache_data
def load_data(filepath, _cache_key=0):
    df = parse_log_file(filepath)
    return df
 
try:
    df = load_data(log_file)
except FileNotFoundError:
    st.warning("Fichier de logs introuvable. Génération automatique...")
    generate_logs()
    df = load_data(log_file, _cache_key=1)
 
if df.empty:
    st.error("Aucune donnée disponible.")
    st.stop()
 
# --- Métriques globales ---
alerts  = run_all_detections(df)
features = extract_ip_features(df)
clustered = run_clustering(features, n_clusters=n_clusters)
 
col1, col2, col3, col4 = st.columns(4)
col1.metric("📊 Total requêtes",   f"{len(df):,}")
col2.metric("📱 Requêtes mobiles", f"{df['is_mobile'].sum():,}")
col3.metric("🚨 Alertes détectées", len(alerts))
col4.metric("🌐 IPs uniques",      df["ip"].nunique())
 
st.divider()
 
# --- Alertes ---
st.subheader("🚨 Alertes de sécurité")
if alerts:
    alert_data = [
        {
            "Type":     a.type,
            "IP":       a.ip,
            "Sévérité": a.severity,
            "Count":    a.count,
            "Détails":  a.details,
        }
        for a in alerts
    ]
    alert_df = pd.DataFrame(alert_data)
 
    # Colorer par sévérité
    def color_severity(val):
        colors = {
            "CRITICAL": "background-color: #e74c3c; color: white",
            "HIGH":     "background-color: #e67e22; color: white",
            "MEDIUM":   "background-color: #f39c12; color: black",
            "LOW":      "background-color: #27ae60; color: white",
        }
        return colors.get(val, "")
 
    st.dataframe(
        alert_df.style.map(color_severity, subset=["Sévérité"]),
        use_container_width=True,
    )
else:
    st.success("Aucune alerte détectée.")
 
st.divider()
 
# --- Clustering IA ---
st.subheader("🤖 Clustering IA des comportements")
 
col_a, col_b = st.columns(2)
 
with col_a:
    # Scatter plot cluster
    fig = px.scatter(
        clustered,
        x="total_requests",
        y="auth_fail_ratio",
        color="cluster_name",
        size="unique_endpoints",
        hover_data=["ip", "nb_404", "rate_limit_hits"],
        title="Clusters de comportement par IP",
        labels={
            "total_requests":   "Total requêtes",
            "auth_fail_ratio":  "Taux d'échecs auth",
            "cluster_name":     "Cluster",
        },
    )
    st.plotly_chart(fig, use_container_width=True)
 
with col_b:
    # Distribution des clusters (camembert)
    cluster_counts = clustered["cluster_name"].value_counts().reset_index()
    cluster_counts.columns = ["Cluster", "Nombre d'IPs"]
    fig2 = px.pie(
        cluster_counts,
        names="Cluster",
        values="Nombre d'IPs",
        title="Distribution des clusters",
    )
    st.plotly_chart(fig2, use_container_width=True)
 
st.divider()
 
# --- Trafic dans le temps ---
st.subheader("📈 Trafic par heure")
traffic_by_hour = df.groupby("hour").size().reset_index(name="requêtes")
fig3 = px.bar(
    traffic_by_hour,
    x="hour",
    y="requêtes",
    title="Volume de requêtes par heure",
    color="requêtes",
    color_continuous_scale="reds",
)
st.plotly_chart(fig3, use_container_width=True)
 
st.divider()
 
# --- Recommandations ---
st.subheader("💡 Recommandations anti-abus")
reco = generate_recommendations(alerts)
for r in reco:
    icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(r["priority"], "⚪")
    with st.expander(f"{icon} {r['title']}"):
        st.write(r["description"])
        if r.get("code"):
            st.code(r["code"], language="python")
