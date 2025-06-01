#!/bin/bash
# Script principal du système de detection d'intrusion (IDS) Bash

# Recuperer le chemin du script
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"

# Sourcer les fichiers de configuration et de fonctions
source "$SCRIPT_DIR/config.sh"
source "$SCRIPT_DIR/functions/monitor.sh"
source "$SCRIPT_DIR/functions/alert.sh"
source "$SCRIPT_DIR/functions/firewall.sh"
source "$SCRIPT_DIR/functions/process.sh"

#Les Variables globales
MONITORING_ACTIVE=false
PID_LOG_FILE="$LOG_DIR/ids.pid"



#Verifier si L'IDS est en cours d'execution
is_ids_running(){
    if [[ -f "$MONITOR_PID_FILE" ]]; then
        local pid=$(cat "$MONITOR_PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            return 0
        else
            rm -f "$MONITOR_PID_FILE"
        fi
    fi
    if [[ "$MODE_FORK" = true && -f "$CHILDREN_PID_FILE" ]]; then
        for pid in $(cat "$CHILDREN_PID_FILE"); do
            if kill -0 "$pid" 2>/dev/null; then
                # Si un Enfant est en vie on consider que l'ids est en cours d'execution
                return 0
            fi
        done
        rm -f "$CHILDREN_PID_FILE"
    fi

    return 1
 }


# Fonction pour enregistrer le PID
save_pid() {

    if [[ "$MODE_FORK" = true ]]; then
        echo "${CHILD_PIDS[@]}" > "$CHILDREN_PID_FILE"
        echo "${CHILD_PIDS[0]}" > "$MONITOR_PID_FILE"  
    fi
}

# Fonction pour la creation du fichier pour le PID du Processus
setup_runtime_dir() {
    sudo mkdir -p "$RUNTIME_DIR"
    sudo chown "$(whoami)":root "$RUNTIME_DIR"
    sudo chmod 775 "$RUNTIME_DIR"
}

# Fonction pour demarrer l'IDS
start_ids() {
    if is_ids_running; then
        echo "[ERREUR] L'IDS est déjà en cours d'exécution" >> "$INTRUSION_LOG"
        echo "[ERREUR] L'IDS est déjà en cours d'exécution"
        return 1
    fi

    setup_runtime_dir
    # Créer les répertoires de logs et de rapports 
    mkdir -p "$LOG_DIR" "$REPORT_DIR"
    
    # Demarrer la surveillance
   
    if $MODE_FORK; then
       execute_fork
       save_pid
    elif $MODE_THREAD; then
       execute_thread
    elif $MODE_SUBSHELL; then
       execute_subshell || {
            echo "[ERREUR] Échec du mode subshell" >> "$INTRUSION_LOG"
            return 1
        }
    else 
       start_monitoring  || return 1
    fi

    sleep 0.5
    # Enregistrer le PID
    if ! is_ids_running; then
        echo "[ERREUR] Le démarrage du monitoring a échoué" >> "$INTRUSION_LOG"
        echo "[ERREUR] Le démarrage du monitoring a échoué"
        return 1
    fi
    MONITORING_ACTIVE=true
    echo "[INFO] IDS démarré avec succès (PID: $$)" >> "$INTRUSION_LOG"
    echo "[INFO] IDS démarré avec succès (PID: $$)"
    
}

# Fonction pour arrêter l'IDS
stop_ids() {
    if ! is_ids_running; then
        echo "[ERREUR] L'IDS n'est pas en cours d'exécution" >> "$INTRUSION_LOG"
        return 1
    fi
    
    stop_monitoring
    # Appeler cette fonction de process.sh pour tuer les Processes fils ....
    cleanup_processes 
    # Supprimer le fichier PID
    [[ -f "$PID_FILE" ]] && rm -f "$PID_FILE" 
    [[ -f "$CHILDREN_PID_FILE" ]] && rm -f "$CHILDREN_PID_FILE"
    MONITORING_ACTIVE=false
    if is_ids_running; then
        echo "[ERREUR] Échec de l'arrêt complet de l'IDS" >> "$INTRUSION_LOG"
        return 1
    fi
    echo "[INFO] IDS arrêté avec succès" >> "$INTRUSION_LOG"
    return 0
}

# Fonction pour afficher l'etat de l'IDS
status_ids() {
    local status_file="$LOG_DIR/ids_status.txt"
    
    echo "=== ÉTAT DE L'IDS BASH ===" > "$status_file"
    echo "Date de vérification: $(date)" >> "$status_file"
    echo "" >> "$status_file"
    
    if is_ids_running; then
        local pid=$(cat "$MONITOR_PID_FILE")
        echo "STATUT: ACTIF (PID: $pid)" >> "$status_file"
        echo "En fonctionnement depuis: $(ps -p $pid -o lstart=)" >> "$status_file"
    else
        echo "STATUT: INACTIF" >> "$status_file"
    fi
    
    echo "" >> "$status_file"
    
    # Nombre d'alertes récentes
    local recent_alerts=$(grep -c "\[ALERTE\]" "$INTRUSION_LOG" 2>/dev/null || echo "0")
    echo "Alertes récentes: $recent_alerts" >> "$status_file"
    
    # Nombre d'IPs bloquées
    echo "IPs actuellement bloquées: ${#BLOCKED_IPS[@]}" >> "$status_file"
    
    echo "" >> "$status_file"
    echo "Fichiers logs surveillés:" >> "$status_file"
    
    # Vérifier quels fichiers logs sont surveillés
    for log_file in "$LOG_AUTH" "$LOG_SYSLOG" "$LOG_MESSAGES" "$LOG_NGINX"; do
        if [[ -f "$log_file" ]]; then
            echo "  - $log_file (OK)" >> "$status_file"
        else
            echo "  - $log_file (INTROUVABLE)" >> "$status_file"
        fi
    done
    
    echo "" >> "$status_file"
    echo "Configuration:" >> "$status_file"
    echo "  - Alertes par email: $ENABLE_EMAIL" >> "$status_file"
    echo "  - Alertes wall: $ENABLE_WALL" >> "$status_file"
    echo "  - Blocage automatique: $ENABLE_AUTO_BLOCK" >> "$status_file"
    if [[ "$ENABLE_AUTO_BLOCK" == "true" ]]; then
        echo "  - Durée de blocage: $BLOCK_DURATION secondes" >> "$status_file"
        echo "  - Pare-feu utilisé: $([[ "$USE_UFW" == "true" ]] && echo "UFW" || echo "iptables")" >> "$status_file"
    fi
    
    echo "" >> "$status_file"
    echo "================" >> "$status_file"
    
    cat "$status_file"
    echo "[INFO] État de l'IDS généré dans $status_file" >> "$INTRUSION_LOG"
    
    return 0
}

# Fonction pour afficher l'aide
show_help() {
    cat << EOF
IDS Bash - Système de Détection d'Intrusion en Bash

Usage: $0 [OPTION]

Options:
  -h          Affiche cette aide
  -f          Mode fork (multi-processus)
  -t          Mode thread (simulé)
  -s          Mode subshell
  -l <dir>    Spécifie le répertoire des logs
  -r          Réinitialise la configuration (admin seulement)
  -v          Mode verbeux
  -d          Mode debug

Commands:
  start       Démarrer l'IDS
  stop        Arrêter l'IDS
  restart     Redémarrer l'IDS
  status      Afficher l'état de l'IDS
  summary [n] Générer un résumé des alertes (n jours, défaut:7)
  clean [n]   Nettoyer les alertes (>n jours, défaut:30)
  block <ip>  Bloquer une adresse IP
  unblock <ip> Débloquer une adresse IP
  list-blocked Lister les IPs bloquées
  menu        Interface interactive
  test        Mode test
  help        Affiche cette aide

Exemples:
  $0 -f start          # Démarrer en mode fork
  $0 -l /var/log/myids start  # Démarrer avec répertoire log personnalisé
  $0 -r                # Réinitialiser la config (admin)
  $0 status            # Vérifier le statut
  $0 block 192.168.1.100 # Bloquer une IP

Sans argument, l'IDS lance l'interface utilisateur interactive si disponible,
ou affiche cette aide.

EOF
}

# Fonction pour afficher les dernieres alertes
show_recent_alerts() {
    local lines="$1"
    
    if [[ -z "$lines" ]]; then
        lines=20  # Par defaut, afficher les 20 dernieres alertes
    fi
    
    if [[ ! -f "$INTRUSION_LOG" ]]; then
        echo "Aucun fichier de log d'intrusion trouvé."
        return 1
    fi
    
    echo "=== $lines DERNIÈRES ALERTES ==="
    grep "\[ALERTE\]" "$INTRUSION_LOG" | tail -n "$lines"
    echo "=============================="
}


# Fonction pour créer un menu interactif avec whiptail ou dialog
show_interactive_menu() {
    # Déterminer quel outil utiliser pour l'interface
    local ui_cmd="$UI_TOOL"
    if ! command -v "$ui_cmd" &> /dev/null; then
        if command -v "whiptail" &> /dev/null; then
            ui_cmd="whiptail"
        elif command -v "dialog" &> /dev/null; then
            ui_cmd="dialog"
        else
            echo "[ERREUR] Ni whiptail ni dialog ne sont installés. Impossible d'afficher le menu interactif." >> "$INTRUSION_LOG"
            show_help
            return 1
        fi
    fi
    
    # Variables pour l'interface
    local title="IDS Bash - Système de Détection d'Intrusion"
    local menu_height=15
    local menu_width=60
    local menu_list_height=10
    
    # Boucle principale du menu
    while true; do
        # Déterminer l'état actuel de l'IDS
        local ids_status="INACTIF"
        local start_stop_option="Démarrer l'IDS"
        
        if is_ids_running; then
            ids_status="ACTIF"
            start_stop_option="Arrêter l'IDS"
        fi
        
        # Créer le menu principal
        local choice=$($ui_cmd --title "$title" --menu "État actuel: $ids_status" $menu_height $menu_width $menu_list_height \
            "1" "$start_stop_option" \
            "2" "Afficher l'état de l'IDS" \
            "3" "Voir les dernières alertes" \
            "4" "Générer un résumé des alertes" \
            "5" "Gérer les IPs bloquées" \
            "6" "Maintenance du système" \
            "7" "Quitter" 3>&1 1>&2 2>&3)
        
        # Traiter le choix de l'utilisateur
        case "$choice" in
            1)
                # Demarrer ou arreter l'IDS
                if is_ids_running; then
                    if $ui_cmd --title "Confirmation" --yesno "Voulez-vous vraiment arrêter l'IDS ?" 8 50; then
                        stop_ids
                        $ui_cmd --title "Opération réussie" --msgbox "L'IDS a été arrêté avec succès." 8 50
                    fi
                else
                    if $ui_cmd --title "Confirmation" --yesno "Voulez-vous démarrer l'IDS ?" 8 50; then
                        start_ids
                        $ui_cmd --title "Opération réussie" --msgbox "L'IDS a été démarré avec succès." 8 50
                    fi
                fi
                ;;
            2)
                # Afficher l'etat de l'IDS
                status_ids > /tmp/ids_status.txt
                $ui_cmd --title "État de l'IDS" --textbox /tmp/ids_status.txt $menu_height $menu_width
                ;;
            3)
                # Voir les dernieres alertes
                local alert_count=$($ui_cmd --title "Alertes" --inputbox "Nombre d'alertes à afficher:" 8 50 "20" 3>&1 1>&2 2>&3)
                if [[ -n "$alert_count" ]]; then
                    show_recent_alerts "$alert_count" > /tmp/recent_alerts.txt
                    $ui_cmd --title "Dernières alertes" --textbox /tmp/recent_alerts.txt $menu_height $menu_width
                fi
                ;;
            4)
                # Generer un resume des alertes
                local timeframe=$($ui_cmd --title "Résumé des alertes" --menu "Période à analyser:" $menu_height $menu_width $menu_list_height \
                    "day" "Dernières 24 heures" \
                    "week" "Dernière semaine" \
                    "month" "Dernier mois" 3>&1 1>&2 2>&3)
                
                if [[ -n "$timeframe" ]]; then
                    generate_alert_summary "$timeframe"
                    $ui_cmd --title "Résumé généré" --msgbox "Le résumé des alertes a été généré avec succès dans $REPORT_DIR" 8 50
                fi
                ;;
            5)
                # Gerer les IPs bloquees
                local block_choice=$($ui_cmd --title "Gestion des IPs bloquées" --menu "Choisissez une option:" $menu_height $menu_width $menu_list_height \
                    "1" "Voir les IPs bloquées" \
                    "2" "Bloquer une IP manuellement" \
                    "3" "Débloquer une IP" 3>&1 1>&2 2>&3)
                
                case "$block_choice" in
                    1)
                        list_blocked_ips
                        $ui_cmd --title "IPs bloquées" --textbox "$LOG_DIR/blocked_ips.txt" $menu_height $menu_width
                        ;;
                    2)
                        local new_ip=$($ui_cmd --title "Blocage manuel" --inputbox "Entrez l'adresse IP à bloquer:" 8 50 3>&1 1>&2 2>&3)
                        if [[ -n "$new_ip" ]]; then
                            block_ip "$new_ip" "MANUAL_BLOCK"
                            $ui_cmd --title "Opération réussie" --msgbox "L'IP $new_ip a été bloquée." 8 50
                        fi
                        ;;
                    3)
                        list_blocked_ips
                        local ip_to_unblock=$($ui_cmd --title "Déblocage d'IP" --inputbox "Entrez l'adresse IP à débloquer:" 8 50 3>&1 1>&2 2>&3)
                        if [[ -n "$ip_to_unblock" ]]; then
                            unblock_ip "$ip_to_unblock"
                            $ui_cmd --title "Opération réussie" --msgbox "L'IP $ip_to_unblock a été débloquée." 8 50
                        fi
                        ;;
                esac
                ;;
            6)
                # Maintenance du systeme
                local maint_choice=$($ui_cmd --title "Maintenance du système" --menu "Choisissez une option:" $menu_height $menu_width $menu_list_height \
                    "1" "Nettoyer les anciennes alertes" \
                    "2" "Vérifier l'état du pare-feu" \
                    "3" "Tester l'envoi d'alertes" 3>&1 1>&2 2>&3)
                
                case "$maint_choice" in
                    1)
                        local days=$($ui_cmd --title "Nettoyage des alertes" --inputbox "Conserver les alertes des n derniers jours:" 8 50 "30" 3>&1 1>&2 2>&3)
                        if [[ -n "$days" ]]; then
                            clean_old_alerts "$days"
                            $ui_cmd --title "Opération réussie" --msgbox "Les alertes de plus de $days jours ont été supprimées." 8 50
                        fi
                        ;;
                    2)
                        check_firewall_status
                        $ui_cmd --title "État du pare-feu" --textbox "$LOG_DIR/firewall_status.txt" $menu_height $menu_width
                        ;;
                    3)
                        local test_alert_msg="Ceci est un test d'alerte depuis l'IDS Bash."
                        if $ui_cmd --title "Test d'alerte" --yesno "Voulez-vous tester l'envoi d'alertes avec le message:\n\n$test_alert_msg" 10 60; then
                            if [[ "$ENABLE_EMAIL" == "true" ]]; then
                                send_email_alert "127.0.0.1" "TEST" "$test_alert_msg" "Test manuel depuis l'interface IDS"
                            fi
                            if [[ "$ENABLE_WALL" == "true" ]]; then
                                send_wall_alert "127.0.0.1" "TEST" "$test_alert_msg"
                            fi
                            $ui_cmd --title "Test d'alerte" --msgbox "Les alertes de test ont été envoyées." 8 50
                        fi
                        ;;
                esac
                ;;
            7|"")
                # Quitter le menu
                break
                ;;
        esac
    done
    
    return 0
}




# Fonction pour exécuter le mode daemon
run_daemon_mode() {
    echo "[INFO] Démarrage de l'IDS en mode daemon" >> "$INTRUSION_LOG"
    
    # Démarrer l'IDS
    start_ids
    
    # Boucle principale du daemon
    while true; do
        sleep "$CHECK_INTERVAL"
        
        # Vérifier si le signal d'arrêt a été reçu
        if [[ ! -f "$PID_FILE" ]]; then
            echo "[INFO] Signal d'arrêt reçu, arrêt du daemon" >> "$INTRUSION_LOG"
            break
        fi
    done
    
    # Arrêter proprement l'IDS
    stop_ids
    
    echo "[INFO] Daemon IDS arrêté" >> "$INTRUSION_LOG"
    return 0
}

# Fonction principale
main() {
      

    while getopts ":hfts" opt; do
       case $opt in
          h) show_help; exit 0 ;;
          f) MODE_FORK=true ;;
          t) MODE_THREAD=true ;; 
          s) MODE_SUBSHELL=true ;;
          \?)
             echo "Options invalide: -$OPTARG" >&2
             show_help
             exit 1 ;;
          esac
    done
    shift $((OPTIND-1))
    # Créer les répertoires nécessaires
    mkdir -p "$LOG_DIR" "$REPORT_DIR"
    
    # Traiter les arguments de la ligne de commande
    case "$1" in
        start)
            start_ids
            echo "IDS démarré."
            ;;
        stop)
            stop_ids
            echo "IDS arrêté."
            ;;
        restart)
            stop_ids
            sleep 1
            start_ids
            echo "IDS redémarré."
            ;;
        status)
            status_ids
            ;;
        summary)
            generate_alert_summary "${2:-week}"
            echo "Résumé des alertes généré dans $REPORT_DIR"
            ;;
        clean)
            clean_old_alerts "${2:-30}"
            echo "Anciennes alertes nettoyées."
            ;;
        block)
            if [[ -z "$2" ]]; then
                echo "Erreur: Adresse IP manquante."
                show_help
                exit 1
            fi
            block_ip "$2" "MANUAL_BLOCK"
            echo "IP $2 bloquée."
            ;;
        unblock)
            if [[ -z "$2" ]]; then
                echo "Erreur: Adresse IP manquante."
                show_help
                exit 1
            fi
            unblock_ip "$2"
            echo "IP $2 débloquée."
            ;;
        list-blocked)
            list_blocked_ips
            cat "$LOG_DIR/blocked_ips.txt"
            ;;
        daemon)
            run_daemon_mode
            ;;
        menu)
            show_interactive_menu
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            # Sans argument, lancer le menu interactif
            if command -v "$UI_TOOL" &> /dev/null || command -v "whiptail" &> /dev/null || command -v "dialog" &> /dev/null; then
                show_interactive_menu
            else
                show_help
            fi
            ;;
    esac
    
    return 0
}

# Executer la fonction principale
main "$@"
