#!/bin/bash
# Fonctions pour la gestion des alertes

# Source le fichier de configuration
SCRIPT_DIR="$(dirname  "$(readlink -f "$0")")"
source "$SCRIPT_DIR/config.sh"

# Fonction pour déclencher une alerte
trigger_alert() {
    local ip="$1"
    local event_type="$2"
    local log_line="$3"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    local alert_message=""
    
    # Formater le message d'alerte selon le type d'événement
    case "$event_type" in
        "SSH_FAIL")
            alert_message="[ALERTE] Échecs multiples d'authentification SSH depuis $ip"
            ;;
        "ROOT_ACCESS_ATTEMPT")
            alert_message="[ALERTE CRITIQUE] Tentative d'accès root depuis $ip"
            ;;
        "PORT_SCAN")
            alert_message="[ALERTE] Scan de ports détecté depuis $ip"
            ;;
        "BRUTE_FORCE")
            alert_message="[ALERTE] Attaque par force brute détectée depuis $ip"
            ;;
        *)
            alert_message="[ALERTE] Activité suspecte détectée depuis $ip"
            ;;
    esac
    
    # Enregistrer l'alerte dans le fichier de log
    log_alert "$timestamp" "$ip" "$event_type" "$alert_message" "$log_line"
    
    # Envoyer l'alerte par email si configuré
    if [[ "$ENABLE_EMAIL" == "true" ]]; then
        send_email_alert "$ip" "$event_type" "$alert_message" "$log_line"
    fi
    
    # Envoyer l'alerte via wall si configuré
    if [[ "$ENABLE_WALL" == "true" ]]; then
        send_wall_alert "$ip" "$event_type" "$alert_message"
    fi
    
    # Bloquer l'IP si le blocage automatique est activé
    if [[ "$ENABLE_AUTO_BLOCK" == "true" ]]; then
        block_ip "$ip" "$event_type"
    fi
}

# Fonction pour enregistrer une alerte dans le fichier de log
log_alert() {
    local timestamp="$1"
    local ip="$2"
    local event_type="$3"
    local alert_message="$4"
    local log_line="$5"
    
    echo "[$timestamp] $alert_message" >> "$INTRUSION_LOG"
    echo "  Type: $event_type" >> "$INTRUSION_LOG"
    echo "  IP: $ip" >> "$INTRUSION_LOG"
    echo "  Log: $log_line" >> "$INTRUSION_LOG"
    echo "---" >> "$INTRUSION_LOG"
}

# Fonction pour envoyer une alerte par email
send_email_alert() {
    local ip="$1"
    local event_type="$2"
    local alert_message="$3"
    local log_line="$4"
    
    # Vérifier si l'utilitaire mail est disponible
    if ! command -v mail &> /dev/null; then
        echo "[ERREUR] Commande 'mail' non trouvée, impossible d'envoyer l'alerte par email" >> "$INTRUSION_LOG"
        return 1
    fi
    
    # Construire le sujet et le corps de l'email
    local subject="[IDS BASH] $alert_message"
    local body="Alerte de sécurité détectée par IDS Bash:
    
$alert_message
    
Détails:
- Type d'événement: $event_type
- Adresse IP: $ip
- Horodatage: $(date)
- Ligne de log: $log_line
    
Cette alerte a été générée automatiquement par le système IDS Bash.
"
    
    # Envoyer l'email
    echo "$body" | mail -s "$subject" "$EMAIL_RECIPIENT"
    
    if [[ $? -eq 0 ]]; then
        echo "[INFO] Alerte envoyée par email à $EMAIL_RECIPIENT" >> "$INTRUSION_LOG"
    else
        echo "[ERREUR] Échec de l'envoi de l'alerte par email" >> "$INTRUSION_LOG"
    fi
}

# Fonction pour envoyer une alerte via wall
send_wall_alert() {
    local ip="$1"
    local event_type="$2"
    local alert_message="$3"
    
    # Vérifier si l'utilitaire wall est disponible
    if ! command -v wall &> /dev/null; then
        echo "[ERREUR] Commande 'wall' non trouvée, impossible d'envoyer l'alerte via wall" >> "$INTRUSION_LOG"
        return 1
    fi
    
    # Construire le message wall
    local wall_message="
===== ALERTE SÉCURITÉ IDS BASH =====
$alert_message
IP: $ip
Type: $event_type
Date: $(date)
===================================="
    
    # Envoyer le message à tous les utilisateurs connectés
    echo "$wall_message" | wall
    
    echo "[INFO] Alerte envoyée via wall" >> "$INTRUSION_LOG"
}

# Fonction pour générer un résumé des alertes
generate_alert_summary() {
    local timeframe="$1"  # "day", "week", "month"
    local start_date=""
    local output_file="$REPORT_DIR/summary_$(date +%Y%m%d).txt"
    
    # Définir la date de début selon le timeframe
    case "$timeframe" in
        "day")
            start_date=$(date -d "1 day ago" "+%Y-%m-%d")
            ;;
        "week")
            start_date=$(date -d "7 days ago" "+%Y-%m-%d")
            ;;
        "month")
            start_date=$(date -d "30 days ago" "+%Y-%m-%d")
            ;;
        *)
            start_date=$(date -d "1 day ago" "+%Y-%m-%d")
            ;;
    esac
    
    echo "=== RÉSUMÉ DES ALERTES (depuis $start_date) ===" > "$output_file"
    echo "Généré le: $(date)" >> "$output_file"
    echo "" >> "$output_file"
    # Compter les alertes par type
    echo "ALERTES PAR TYPE:" >> "$output_file"
    grep -e "\[ALERTE\]" "$INTRUSION_LOG" | awk -F']' '{print $2}' | sort | uniq -c | sort -nr >> "$output_file"
    echo "" >> "$output_file"
    
    # Compter les alertes par IP
    echo "ALERTES PAR IP:" >> "$output_file"
    grep -e "IP:" "$INTRUSION_LOG" | awk '{print $2}' | sort | uniq -c | sort -nr | head -10 >> "$output_file"
    echo "" >> "$output_file"
    
    # Liste des IPs bloquées
    echo "IPs ACTUELLEMENT BLOQUÉES:" >> "$output_file"
    for ip in "${!BLOCKED_IPS[@]}"; do
        echo "$ip (bloquée le: ${BLOCKED_IPS[$ip]})" >> "$output_file"
    done
    
    echo "" >> "$output_file"
    echo "=== FIN DU RÉSUMÉ ===" >> "$output_file"
    
    echo "[INFO] Résumé des alertes généré dans $output_file" >> "$INTRUSION_LOG"
    
    return 0
}

# Fonction pour nettoyer les anciennes alertes
clean_old_alerts() {
    local days="$1"  # Nombre de jours à conserver
    
    if [[ -z "$days" ]]; then
        days=30  # Par défaut, conserver 30 jours
    fi
    
    # Créer un fichier temporaire
    local temp_file="$LOG_DIR/intrusion_temp.log"
    local current_date=$(date +%s)
    local cutoff_date=$(date -d "$days days ago" +%s)
    
    echo "[INFO] Nettoyage des alertes de plus de $days jours" >> "$INTRUSION_LOG"
    
    # Conserver uniquement les entrées récentes
    echo "=== IDS BASH LOG (nettoyé le $(date)) ===" > "$temp_file"
    
    while IFS= read -r line; do
        # Extraire la date de la ligne si elle existe
        if [[ $line =~ \[([0-9]{4}-[0-9]{2}-[0-9]{2}\ [0-9]{2}:[0-9]{2}:[0-9]{2})\] ]]; then
            log_date="${BASH_REMATCH[1]}"
            log_timestamp=$(date -d "$log_date" +%s 2>/dev/null)
            
            # Si la conversion a réussi et la date est récente, conserver l'entrée
            if [[ $? -eq 0 ]] && (( log_timestamp >= cutoff_date )); then
                echo "$line" >> "$temp_file"
            fi
        else
            # Si la ligne ne contient pas de date, la conserver
            echo "$line" >> "$temp_file"
        fi
    done < "$INTRUSION_LOG"
    
    # Remplacer le fichier original par le fichier temporaire
    mv "$temp_file" "$INTRUSION_LOG"
    
    echo "[INFO] Nettoyage terminé. Les alertes de plus de $days jours ont été supprimées." >> "$INTRUSION_LOG"
    return 0
}
