#!/bin/bash
# functions/monitor.sh
# Fonctions de surveillance des logs pour détection d'intrusions

# Inclure la configuration générale
# Utilisation du chemin absolu pour éviter les problèmes si le script est appelé depuis un autre répertoire
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
source "$SCRIPT_DIR/config.sh"

# Inclure les fonctions liées aux alertes
source "$SCRIPT_DIR/functions/alert.sh"
# Inclure les fonctions du pare-feu
source "$SCRIPT_DIR/functions/firewall.sh"

# Variables globales pour le suivi des tentatives
declare -A ssh_fail_count
declare -A scan_count
declare -A brute_force_count
declare -A last_seen_time

# Utiliser un fichier PID spécifique à la surveillance pour éviter les conflits avec ids.sh
MONITOR_PID_LOG_FILE="$LOG_DIR/monitor.pid"

# Fonction pour réinitialiser les compteurs après la fenêtre de temps
reset_counters() {
    local current_time=$(date +%s)
    
    # Pour chaque IP dans les dictionnaires
    for ip in "${!last_seen_time[@]}"; do
        if (( current_time - ${last_seen_time[$ip]} > TIME_WINDOW )); then
            # Réinitialiser les compteurs pour cette IP
            unset ssh_fail_count[$ip]
            unset scan_count[$ip]
            unset brute_force_count[$ip]
            unset last_seen_time[$ip]
            
            [[ "$DEBUG" == "true" ]] && echo "[DEBUG] Compteurs réinitialisés pour l'IP $ip après $TIME_WINDOW secondes d'inactivité" >> "$INTRUSION_LOG"
        fi
    done
}

# Fonction pour détecter les tentatives d'intrusion SSH
detect_ssh_failures() {
    local line="$1"
    local ip="$2"
    
    if [[ "$line" =~ $SSH_FAIL_PATTERN ]]; then
        # Incrémenter le compteur pour cette IP
        ssh_fail_count[$ip]=$((${ssh_fail_count[$ip]:-0} + 1))
        last_seen_time[$ip]=$(date +%s)
        
        [[ "$DEBUG" == "true" ]] && echo "[DEBUG] Tentative SSH échouée #${ssh_fail_count[$ip]} pour l'IP $ip" >> "$INTRUSION_LOG"
        
        # Vérifier si le seuil d'alerte est atteint
        if (( ${ssh_fail_count[$ip]} >= SSH_FAIL_THRESHOLD )); then
            local message="Alerte de sécurité: ${ssh_fail_count[$ip]} tentatives de connexion SSH échouées depuis l'IP $ip"
            trigger_alert "$ip" "SSH_FAIL" "$line" # Utilisation de la fonction d'alert.sh
            
            # Réinitialiser le compteur pour cette alerte spécifique
            ssh_fail_count[$ip]=0
        fi
        
        return 0  # Événement traité
    fi
    
    return 1  # Aucun événement de ce type détecté
}

# Fonction pour détecter les tentatives d'accès root
detect_root_access() {
    local line="$1"
    local ip="$2"
    
    if [[ "$line" =~ $ROOT_ACCESS_PATTERN ]]; then
        local message="Alerte de sécurité: Tentative d'accès root depuis l'IP $ip"
        trigger_alert "$ip" "ROOT_ACCESS_ATTEMPT" "$line" # Correction du type d'événement
        
        return 0  # Événement traité
    fi
    
    return 1  # Aucun événement de ce type détecté
}

# Fonction pour détecter les scans de ports
detect_port_scan() {
    local line="$1"
    local ip="$2"
    
    if [[ "$line" =~ $PORT_SCAN_PATTERN ]]; then
        # Extraire l'IP source du scan si le pattern est différent
        if [[ -z "$ip" ]]; then
            ip=$(echo "$line" | grep -oP 'SRC=\K[\d\.]+')
            # Si toujours pas d'IP, on ne peut pas continuer
            if [[ -z "$ip" ]]; then
                return 1
            fi
        fi
        
        # Incrémenter le compteur pour cette IP
        scan_count[$ip]=$((${scan_count[$ip]:-0} + 1))
        last_seen_time[$ip]=$(date +%s)
        
        [[ "$DEBUG" == "true" ]] && echo "[DEBUG] Tentative de scan #${scan_count[$ip]} depuis l'IP $ip" >> "$INTRUSION_LOG"
        
        # Vérifier si le seuil d'alerte est atteint
        if (( ${scan_count[$ip]} >= SCAN_THRESHOLD )); then
            local message="Alerte de sécurité: Possible scan de ports détecté depuis l'IP $ip (${scan_count[$ip]} connexions)"
            trigger_alert "$ip" "PORT_SCAN" "$line" # Utilisation de la fonction d'alert.sh
            
            # Réinitialiser le compteur pour cette alerte spécifique
            scan_count[$ip]=0
        fi
        
        return 0  # Événement traité
    fi
    
    return 1  # Aucun événement de ce type détecté
}

# Fonction pour détecter les attaques par force brute
detect_brute_force() {
    local line="$1"
    local ip="$2"
    
    if [[ "$line" =~ $BRUTE_FORCE_PATTERN ]]; then
        # Incrémenter le compteur pour cette IP
        brute_force_count[$ip]=$((${brute_force_count[$ip]:-0} + 1))
        last_seen_time[$ip]=$(date +%s)
        
        [[ "$DEBUG" == "true" ]] && echo "[DEBUG] Possible tentative de brute force #${brute_force_count[$ip]} depuis l'IP $ip" >> "$INTRUSION_LOG"
        
        # Vérifier si le seuil d'alerte est atteint
        if (( ${brute_force_count[$ip]} >= BRUTE_FORCE_THRESHOLD )); then
            local message="Alerte de sécurité: Possible attaque par force brute détectée depuis l'IP $ip (${brute_force_count[$ip]} tentatives)"
            trigger_alert "$ip" "BRUTE_FORCE" "$line" # Utilisation de la fonction d'alert.sh
            
            # Réinitialiser le compteur pour cette alerte spécifique
            brute_force_count[$ip]=0
        fi
        
        return 0  # Événement traité
    fi
    
    return 1  # Aucun événement de ce type détecté
}

# Fonction pour analyser un fichier log complet pour détecter des patterns historiques
analyze_log_file() {
    local log_file="$1"
    local days_back="${2:-1}"  # Par défaut, analyser les logs d'une journée
    
    echo "[INFO] Analyse du fichier $log_file pour les $days_back derniers jours..." >> "$INTRUSION_LOG"
    
    # Vérifier si le fichier existe
    if [[ ! -f "$log_file" ]]; then
        echo "[ERREUR] Le fichier $log_file n'existe pas." >> "$INTRUSION_LOG"
        return 1
    fi
    
    # Calculer la date de début pour l'analyse
    local start_date=$(date -d "$days_back days ago" +"%Y-%m-%d")
    
    # Utilisés pour stocker les résultats d'analyse
    local ssh_failures=0
    local root_attempts=0
    local scan_attempts=0
    local brute_force_attempts=0
    declare -A suspicious_ips
    
    # Extraire les lignes des x derniers jours et les analyser
    while IFS= read -r line || [[ -n "$line" ]]; do
        # Tenter d'extraire une IP
        local ip=$(echo "$line" | grep -oP 'from \K[\d\.]+')
        
        # Si pas d'IP via le pattern standard, essayer un autre pattern
        if [[ -z "$ip" ]]; then
            ip=$(echo "$line" | grep -oP 'SRC=\K[\d\.]+')
        fi
        
        # Si on a une IP, la traiter
        if [[ -n "$ip" ]]; then
            # Incrémenter le compteur pour chaque type d'alerte
            if [[ "$line" =~ $SSH_FAIL_PATTERN ]]; then
                ((ssh_failures++))
                suspicious_ips[$ip]=$((${suspicious_ips[$ip]:-0} + 1))
            fi
            
            if [[ "$line" =~ $ROOT_ACCESS_PATTERN ]]; then
                ((root_attempts++))
                suspicious_ips[$ip]=$((${suspicious_ips[$ip]:-0} + 3))  # Tentative root = 3 points d'importance
            fi
            
            if [[ "$line" =~ $PORT_SCAN_PATTERN ]]; then
                ((scan_attempts++))
                suspicious_ips[$ip]=$((${suspicious_ips[$ip]:-0} + 2))  # Scan = 2 points d'importance
            fi
            
            if [[ "$line" =~ $BRUTE_FORCE_PATTERN ]]; then
                ((brute_force_attempts++))
                suspicious_ips[$ip]=$((${suspicious_ips[$ip]:-0} + 2))  # Brute force = 2 points d'importance
            fi
        fi
    done < <(grep -a "$start_date" "$log_file" 2>/dev/null)
    
    # Générer un rapport d'analyse
    local report_file="$REPORT_DIR/log_analysis_$(date +"%Y%m%d").txt"
    
    {
        echo "=== Rapport d'analyse des logs de sécurité ==="
        echo "Fichier analysé: $log_file"
        echo "Période: du $start_date à aujourd'hui"
        echo "Date d'analyse: $(date)"
        echo ""
        echo "=== Résumé des activités suspectes ==="
        echo "- Tentatives de connexion SSH échouées: $ssh_failures"
        echo "- Tentatives d'accès root: $root_attempts"
        echo "- Tentatives de scan de ports: $scan_attempts"
        echo "- Tentatives d'attaque par force brute: $brute_force_attempts"
        echo ""
        echo "=== IPs les plus suspectes ==="
        
        # Vérifier s'il y a des IPs suspectes avant de tenter le tri
        if [[ ${#suspicious_ips[@]} -gt 0 ]]; then
            # Trier les IPs par niveau de suspicion et afficher les 10 premières
            for ip in $(
                for i in "${!suspicious_ips[@]}"; do 
                    echo "$i ${suspicious_ips[$i]}"; 
                done | sort -k2rn | head -10 | cut -d' ' -f1
            ); do
                echo "- $ip (Score: ${suspicious_ips[$ip]})"
            done
        else
            echo "Aucune IP suspecte détectée dans la période analysée."
        fi
    } > "$report_file"
    
    echo "[INFO] Analyse terminée. Rapport généré dans $report_file" >> "$INTRUSION_LOG"
    return 0
}

# Fonction pour surveiller plusieurs fichiers logs simultanément
monitor_multiple_logs() {
    echo "[INFO] Démarrage de la surveillance multi-fichiers..." >> "$INTRUSION_LOG"
    
    # Verifier Existance de Logs
    local log_files=()
    for log_file in "$LOG_AUTH" "$LOG_SYSLOG" "$LOG_MESSAGES" "$LOG_NGINX"; do
        if [[ -f "$log_file" ]]; then
            log_files+=("$log_file")
        fi
    done
    
    if [[ ${#log_files[@]} -eq 0 ]]; then
        echo "[ERREUR] Aucun fichier log valide trouvé" >> "$INTRUSION_LOG"
        return 1
    fi
    
    # loop de moniteration
    tail -F "${log_files[@]}" 2>/dev/null | while read -r line; do
        # Extracter Address IP
        local ip=$(echo "$line" | grep -oP 'from \K[\d\.]+' || \
                   echo "$line" | grep -oP 'SRC=\K[\d\.]+')
        
        [[ -n "$ip" ]] || continue
        
        # Skipper les Ip blocker
        is_ip_blocked "$ip" && continue
        
        # Detecter Des Paternes d'intrusion
        detect_ssh_failures "$line" "$ip" ||
        detect_root_access "$line" "$ip" ||
        detect_port_scan "$line" "$ip" ||
        detect_brute_force "$line" "$ip"
        
        reset_counters
    done
}
# Fonction principale qui démarre la surveillance
start_monitoring() {
    echo "[INFO] Démarrage de la surveillance des logs..." >> "$INTRUSION_LOG"
    
    # Checker si deja est en cours
    if [[ -f "$MONITOR_PID_FILE" ]]; then
        local pid=$(cat "$MONITOR_PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            echo "[ERREUR] La surveillance est déjà active avec le PID $pid" >> "$INTRUSION_LOG"
            return 1
        else
            rm -f "$MONITOR_PID_FILE"
        fi
    fi
    
    # Creation des Repertoire Important
    mkdir -p "$LOG_DIR" "$REPORT_DIR"
    
    # Fully daemonize the monitoring process
    (
        # Creation dune session est la detacher du terminal
        setsid >/dev/null 2>&1
        
        # Close standard file descriptors
        exec >/dev/null 2>&1 </dev/null
        
        # Fonction Principale de Monitoring 
        monitor_multiple_logs
        
        # Netyo
        rm -f "$MONITOR_PID_FILE"
    ) &
    
    # Save the PID after ensuring process started
    local monitor_pid=$!
    sleep 0.5  # Brief pause for process startup
    
    if kill -0 "$monitor_pid" 2>/dev/null; then
        echo "$monitor_pid" > "$MONITOR_PID_FILE"
        disown $monitor_pid  # Remove from shell job list
        echo "[INFO] Surveillance démarrée avec PID $monitor_pid" >> "$INTRUSION_LOG"
        return 0
    else
        echo "[ERREUR] Échec du démarrage de la surveillance" >> "$INTRUSION_LOG"
        return 1
    fi
}
start_monitoring() {
    echo "[INFO] Démarrage de la surveillance des logs..." >> "$INTRUSION_LOG"
    
    # Check if already running
    if [[ -f "$MONITOR_PID_FILE" ]]; then
        local pid=$(cat "$MONITOR_PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            echo "[ERREUR] La surveillance est déjà active avec le PID $pid" >> "$INTRUSION_LOG"
            return 1
        else
            rm -f "$MONITOR_PID_FILE"
        fi
    fi
    
    # Create necessary directories
    mkdir -p "$LOG_DIR" "$REPORT_DIR"
    
    # Fully daemonize the monitoring process
    (
        # Create new session and detach from terminal
        setsid >/dev/null 2>&1
        
        # Close standard file descriptors
        exec >/dev/null 2>&1 </dev/null
        
        # Main monitoring function
        monitor_multiple_logs
        
        # Nettoyage à la sortie
        rm -f "$MONITOR_PID_FILE"
    ) &
    
    # Sauvegarder le PID apres avoir commencer le Processus
    local monitor_pid=$!
    sleep 0.5  
    
    if kill -0 "$monitor_pid" 2>/dev/null; then
        echo "$monitor_pid" > "$MONITOR_PID_FILE"
        disown $monitor_pid  # Remove from shell job list
        echo "[INFO] Surveillance démarrée avec PID $monitor_pid" >> "$INTRUSION_LOG"
        return 0
    else
        echo "[ERREUR] Échec du démarrage de la surveillance" >> "$INTRUSION_LOG"
        return 1
    fi
}

# Fonction pour arrêter la surveillance
stop_monitoring() {
    echo "[INFO] Arrêt de la surveillance des logs..." >> "$INTRUSION_LOG"
    
    if [[ -f "$MONITOR_PID_FILE" ]]; then
        local monitor_pid=$(cat "$MONITOR_PID_FILE")
        
             if kill -0 "$monitor_pid" 2>/dev/null; then
            echo "[INFO] Envoi de SIGTERM au processus de surveillance (PID: $monitor_pid)" >> "$INTRUSION_LOG"
            kill -TERM "$monitor_pid" 2>/dev/null
            
            # Attendre le Process avent de sortir
            local timeout=5
            while kill -0 "$monitor_pid" 2>/dev/null && (( timeout-- > 0 )); do
                sleep 1
            done
            
            # Force kill si le procesus est encore active
            if kill -0 "$monitor_pid" 2>/dev/null; then
                echo "[INFO] Processus encore actif, envoi de SIGKILL (PID: $monitor_pid)" >> "$INTRUSION_LOG"
                kill -KILL "$monitor_pid" 2>/dev/null
            fi
        fi
        
        #  Nettoyer le PID   
        rm -f "$MONITOR_PID_FILE"

        echo "[INFO] Processus de surveillance arrêté" >> "$INTRUSION_LOG"
    else
        echo "[AVERTISSEMENT] Aucun fichier PID de surveillance trouvé" >> "$INTRUSION_LOG"
    fi
    
    return 0
}

# Fonction pour tester la détection sur une ligne de log fictive (pour le débogage)
test_detection() {
    echo "[INFO] Test de détection d'intrusion..." >> "$INTRUSION_LOG"
    
    # Exemples de logs à tester
    local test_logs=(
        "May 18 15:30:42 server sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 58204 ssh2"
        "May 18 15:31:12 server sshd[1235]: Failed password for root from 192.168.1.100 port 58205 ssh2"
        "May 17 10:25:14 server kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=45678 DPT=22"
    )
    
    for test_log in "${test_logs[@]}"; do
        echo "[TEST] Log à tester: $test_log" >> "$INTRUSION_LOG"
        
        # Extraire l'IP
        local ip=$(echo "$test_log" | grep -oP 'from \K[\d\.]+')
        if [[ -z "$ip" ]]; then
            ip=$(echo "$test_log" | grep -oP 'SRC=\K[\d\.]+')
        fi
        
        echo "[TEST] IP extraite: $ip" >> "$INTRUSION_LOG"
        
        # Tester chaque type de détection
        detect_ssh_failures "$test_log" "$ip" && echo "[TEST] SSH failure détecté" >> "$INTRUSION_LOG"
        detect_root_access "$test_log" "$ip" && echo "[TEST] Root access détecté" >> "$INTRUSION_LOG"
        detect_port_scan "$test_log" "$ip" && echo "[TEST] Port scan détecté" >> "$INTRUSION_LOG"
        detect_brute_force "$test_log" "$ip" && echo "[TEST] Brute force détecté" >> "$INTRUSION_LOG"
    done
    
    echo "[INFO] Test de détection terminé" >> "$INTRUSION_LOG"
    return 0
}
