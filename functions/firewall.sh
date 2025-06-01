#!/bin/bash
# Fonctions pour la gestion du pare-feu
# Source le fichier de configuration
SCRIPT_DIR="$(dirname  "$(readlink -f "$0")")"
source "$SCRIPT_DIR/config.sh"
# Fonction pour vérifier si les outils de pare-feu sont disponibles
check_firewall_tools() {
    local tools_available=true
    
    if [[ "$USE_UFW" == "true" ]]; then
        if ! command -v ufw &> /dev/null; then
            echo "[ERREUR] UFW n'est pas installé sur le système" >> "$INTRUSION_LOG"
            tools_available=false
        fi
    else
        if ! command -v iptables &> /dev/null; then
            echo "[ERREUR] iptables n'est pas installé sur le système" >> "$INTRUSION_LOG"
            tools_available=false
        fi
    fi
    
    $tools_available
}

# Fonction pour bloquer une adresse IP
block_ip() {
    local ip="$1"
    local event_type="$2"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    
    # Vérifier si l'IP est déjà bloquée
    if [[ -n "${BLOCKED_IPS[$ip]}" ]]; then
        echo "[INFO] L'IP $ip est déjà bloquée depuis ${BLOCKED_IPS[$ip]}" >> "$INTRUSION_LOG"
        return 0
    fi
    
    # Vérifier si les outils de pare-feu sont disponibles
    if ! check_firewall_tools; then
        echo "[ERREUR] Impossible de bloquer l'IP $ip : outils de pare-feu manquants" >> "$INTRUSION_LOG"
        return 1
    fi
    
    # Bloquer l'IP avec UFW ou iptables
    local block_result=0
    if [[ "$USE_UFW" == "true" ]]; then
        sudo ufw deny from "$ip" to any comment "IDS Bash block $timestamp"
        block_result=$?
    else
        sudo iptables -A INPUT -s "$ip" -j DROP
        block_result=$?
    fi
    
    # Vérifier si le blocage a réussi
    if [[ $block_result -eq 0 ]]; then
        echo "[INFO] IP $ip bloquée avec succès ($event_type)" >> "$INTRUSION_LOG"
        BLOCKED_IPS["$ip"]="$timestamp"
        
        # Programmer le déblocage si la durée est définie
        if [[ $BLOCK_DURATION -gt 0 ]]; then
            schedule_unblock "$ip" "$BLOCK_DURATION"
        fi
        
        return 0
    else
        echo "[ERREUR] Échec du blocage de l'IP $ip" >> "$INTRUSION_LOG"
        return 1
    fi
}

# Fonction pour débloquer une adresse IP
unblock_ip() {
    local ip="$1"
    
    # Vérifier si l'IP est effectivement bloquée
    if [[ -z "${BLOCKED_IPS[$ip]}" ]]; then
        echo "[INFO] L'IP $ip n'est pas dans la liste des IPs bloquées" >> "$INTRUSION_LOG"
        return 0
    fi
    
    # Vérifier si les outils de pare-feu sont disponibles
    if ! check_firewall_tools; then
        echo "[ERREUR] Impossible de débloquer l'IP $ip : outils de pare-feu manquants" >> "$INTRUSION_LOG"
        return 1
    fi
    
    # Débloquer l'IP avec UFW ou iptables
    local unblock_result=0
    if [[ "$USE_UFW" == "true" ]]; then
        sudo ufw delete deny from "$ip" to any
        unblock_result=$?
    else
        sudo iptables -D INPUT -s "$ip" -j DROP
        unblock_result=$?
    fi
    
    # Vérifier si le déblocage a réussi
    if [[ $unblock_result -eq 0 ]]; then
        echo "[INFO] IP $ip débloquée avec succès" >> "$INTRUSION_LOG"
        unset BLOCKED_IPS["$ip"]
        return 0
    else
        echo "[ERREUR] Échec du déblocage de l'IP $ip" >> "$INTRUSION_LOG"
        return 1
    fi
}

# Fonction pour programmer le déblocage d'une IP après un certain temps
schedule_unblock() {
    local ip="$1"
    local duration="$2"
    
    # Créer une tâche en arrière-plan pour débloquer l'IP après la durée spécifiée
    (
        sleep "$duration"
        unblock_ip "$ip"
    ) &
    
    echo "[INFO] Déblocage de l'IP $ip programmé dans $duration secondes" >> "$INTRUSION_LOG"
}

# Fonction pour afficher la liste des IPs bloquées
list_blocked_ips() {
    echo "=== IPs BLOQUÉES ===" > "$LOG_DIR/blocked_ips.txt"
    echo "Date de génération: $(date)" >> "$LOG_DIR/blocked_ips.txt"
    echo "" >> "$LOG_DIR/blocked_ips.txt"
    
    if [[ ${#BLOCKED_IPS[@]} -eq 0 ]]; then
        echo "Aucune IP bloquée actuellement." >> "$LOG_DIR/blocked_ips.txt"
    else
        echo "Nombre total d'IPs bloquées: ${#BLOCKED_IPS[@]}" >> "$LOG_DIR/blocked_ips.txt"
        echo "" >> "$LOG_DIR/blocked_ips.txt"
        echo "ADRESSE IP | DATE DE BLOCAGE" >> "$LOG_DIR/blocked_ips.txt"
        echo "----------|----------------" >> "$LOG_DIR/blocked_ips.txt"
        
        for ip in "${!BLOCKED_IPS[@]}"; do
            echo "$ip | ${BLOCKED_IPS[$ip]}" >> "$LOG_DIR/blocked_ips.txt"
        done
    fi
    
    echo "" >> "$LOG_DIR/blocked_ips.txt"
    echo "=====================" >> "$LOG_DIR/blocked_ips.txt"
    
    echo "[INFO] Liste des IPs bloquées générée dans $LOG_DIR/blocked_ips.txt" >> "$INTRUSION_LOG"
    
    return 0
}

# Fonction pour vérifier l'état du pare-feu
check_firewall_status() {
    local status_file="$LOG_DIR/firewall_status.txt"
    
    echo "=== ÉTAT DU PARE-FEU ===" > "$status_file"
    echo "Date de vérification: $(date)" >> "$status_file"
    echo "" >> "$status_file"
    
    # Vérifier quel pare-feu est utilisé
    if [[ "$USE_UFW" == "true" ]]; then
        echo "Pare-feu utilisé: UFW" >> "$status_file"
        
        if command -v ufw &> /dev/null; then
            echo "" >> "$status_file"
            echo "État UFW:" >> "$status_file"
            sudo ufw status verbose >> "$status_file"
        else
            echo "UFW n'est pas installé sur le système" >> "$status_file"
        fi
    else
        echo "Pare-feu utilisé: iptables" >> "$status_file"
        
        if command -v iptables &> /dev/null; then
            echo "" >> "$status_file"
            echo "Règles iptables (chaîne INPUT):" >> "$status_file"
            sudo iptables -L INPUT -n -v >> "$status_file"
        else
            echo "iptables n'est pas installé sur le système" >> "$status_file"
        fi
    fi
    
    echo "" >> "$status_file"
    echo "=====================" >> "$status_file"
    
    echo "[INFO] État du pare-feu vérifié et enregistré dans $status_file" >> "$INTRUSION_LOG"
    
    return 0
}
