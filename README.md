# 🔐 Rapport de Projet : Mobile API Misuse Detector

**Cours :** Sécurité Mobile  
**Binôme :** Ennoukra Abdelghafour & Yassine SALIHI  
**Institution :** École Marocaine des Sciences de l'Ingénieur (EMSI)  

---

## 1. Introduction et Problématique
La sécurité des API mobiles est un pilier de la cybersécurité moderne. Le projet **Mobile API Misuse Detector** a pour but d'analyser le trafic Nginx des applications mobiles afin d'identifier des comportements malveillants tels que le *Brute Force*, le *Spike* de requêtes et l'énumération d'endpoints. Contrairement à une approche basée sur des signatures statiques, nous avons intégré un moteur d'IA pour classifier les menaces de manière dynamique.

## 2. Architecture de la Solution
Le pipeline repose sur quatre couches majeures :
1. **Génération de Données :** Simulation de trafic Nginx réaliste (mobile vs desktop) via `Faker`.
2. **Extraction & Parsing :** Transformation des logs bruts en vecteurs de caractéristiques (Features).
3. **Moteur de Détection :** Algorithmes basés sur des seuils statistiques (rules-based).
4. **Intelligence Artificielle :** Clustering non supervisé (`K-Means`) pour le profilage comportemental.

## 3. Composants Techniques Majeurs

### A. Le Parser Étendu (`parser/mobile_parser.py`)
Ce module est le pont entre le fichier log et l'analyse. Il enrichit chaque requête avec des métadonnées critiques comme `is_mobile` (via User-Agent) et transforme le statut HTTP et l'endpoint en indicateurs booléens exploitables (`is_auth_fail`, `is_rate_limit`, `is_404`).

### B. Moteur de Détection (`detection/rules.py`)
Ce script implémente les règles métier. Chaque fonction (`detect_brute_force`, `detect_request_spikes`, etc.) analyse le DataFrame Pandas pour identifier des anomalies spécifiques, retournant une liste d'objets `Alert` enrichis.

### C. Module IA (`ai/clustering.py`)
C'est le cœur analytique du projet. Le clustering `K-Means` groupe les adresses IP en fonction de leur comportement (total requêtes, taux d'erreurs, etc.). La force de cette implémentation réside dans **l'assignation automatique de labels** : nous avons créé un `danger_score` basé sur les centroïdes pour classer les clusters du comportement "Normal" à "Critique".

## 4. Analyse et Visualisation (Dashboard Streamlit)
Nous avons remplacé l'interface Flask statique par un dashboard interactif via `Streamlit`. Ce dashboard offre :
* **Vue globale :** Métriques temps réel (total requêtes, IPs uniques, alertes).
* **Visualisation IA :** Scatter plot interactif montrant la distribution des clusters.
* **Recommandations :** Un moteur expert (`advisor.py`) qui propose des solutions de remédiation (Rate Limiting, WAF, Lockout) basées sur les alertes détectées.

## 5. Tests et Validation
Le pipeline a été validé via le script `test_pipeline.py`, qui simule tout le cycle de vie :
1. Génération de 700+ logs.
2. Parsing des données.
3. Exécution des règles de détection.
4. Clustering par l'IA.
5. Génération des recommandations de sécurité.

Les tests montrent une excellente séparation des clusters (Silhouette Score > 0.6), confirmant que l'IA différencie efficacement un utilisateur légitime d'un attaquant.

---

### Commandes rapides pour le professeur
```bash
# 1. Installer les dépendances
pip install -r requirements.txt

# 2. Générer les logs simulés
python generator/log_generator.py

# 3. Tester le pipeline complet
python test_pipeline.py

# 4. Lancer le dashboard Streamlit
streamlit run dashboard/streamlit_app.py
