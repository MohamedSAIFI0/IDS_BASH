#!/bin/bash
# Configuration du système de détection d'intrusion

# Chemins des fichiers de logs à surveiller
LOG_AUTH="/var/log/auth.log"
LOG_SYSLOG="/var/log/syslog"
LOG_MESSAGES="/var/log/messages"
LOG_NGINX="/var/log/nginx/access.log"

# Chemins des fichiers de l'IDS
LOG_DIR="$(dirname "$(readlink -f "$0")")/logs"
INTRUSION_LOG="$LOG_DIR/intrusion.log"
REPORT_DIR="$(dirname "$(readlink -f "$0")")/reports"
WEEKLY_REPORT="$REPORT_DIR/weekly_report.txt"

# Créer les répertoires si non existants
mkdir -p "$LOG_DIR"
mkdir -p "$REPORT_DIR"

# Configuration des seuils d'alerte
SSH_FAIL_THRESHOLD=5          # Nombre d'échecs de connexion SSH avant alerte
SCAN_THRESHOLD=10             # Nombre de scans de ports avant alerte
BRUTE_FORCE_THRESHOLD=15      # Nombre de tentatives de brute force avant alerte
TIME_WINDOW=300               # Fenêtre de temps en secondes pour considérer des événements comme liés (5 minutes)

# Configuration des alertes
ENABLE_EMAIL=false            # Activer/désactiver les alertes par email
EMAIL_RECIPIENT="saifimsc@gmail.com"  # Adresse email pour les alertes
ENABLE_WALL=true              # Activer/désactiver les messages wall

# Configuration du blocage automatique
ENABLE_AUTO_BLOCK=false       # Activer/désactiver le blocage automatique
BLOCK_DURATION=3600           # Durée du blocage en secondes (1 heure)
USE_UFW=false                 # Utiliser UFW au lieu d'iptables

# Configuration de l'interface utilisateur
UI_TOOL="whiptail"            # "whiptail" ou "dialog"
TERMINAL_WIDTH=80             # Largeur du terminal pour l'affichage
TERMINAL_HEIGHT=24            # Hauteur du terminal pour l'affichage

# Configuration du daemon
CHECK_INTERVAL=5              # Intervalle de vérification en secondes en mode daemon

# Regex pour la détection d'événements suspects
SSH_FAIL_PATTERN="Failed password for .* from .* port"
ROOT_ACCESS_PATTERN="Failed password for root from .* port"
PORT_SCAN_PATTERN="SRC=.* DST=.* PROTO=(TCP|UDP) .* DPT="
BRUTE_FORCE_PATTERN="Failed password for .* from .* port .* ssh"

# Activer le mode debug (plus de détails dans les logs)
DEBUG=false

# Fichier principal de log pour le système de monitoring
LOG_FILE="$LOG_DIR/bash-ids.log"

# Fichier pour stocker le PID du processus de surveillance
PID_FILE="/var/run/ids/bash-ids.pid"

# Dossier pour Enregistrer le pid de L'ids
RUNTIME_DIR="/var/run/ids"
# Patterns à utiliser pour la surveillance en temps réel dans monitor.sh
PATTERNS=(
    "$SSH_FAIL_PATTERN"
    "$ROOT_ACCESS_PATTERN"
    "$BRUTE_FORCE_PATTERN"
)

# Commande de blocage (utilisée si ENABLE_AUTO_BLOCK est true)
BLOCK_COMMAND="iptables -A INPUT -s"

# Liste des IP bannies - harmonisée avec monitor.sh
BLOCKED_IPS_FILE="$LOG_DIR/blocked_ips.txt"

# Gardons l'ancienne variable pour compatibilité
BANNED_IP_LIST="$BLOCKED_IPS_FILE"


# Configuration des Processus 
MODE_FORK=false
MODE_THREAD=false
MODE_SUBSHELL=false

declare -a CHILD_PIDS
MONITOR_PID_FILE="$RUNTIME_DIR/monitor.pid"
CHILDREN_PID_FILE="$RUNTIME_DIR/children.pid"
