#!/bin/bash
# functions/process.sh - Process management functions for IDS

# fonction d'execution de fork 
execute_fork() {
    echo "[INFO] Starting in fork mode" >> "$INTRUSION_LOG"
    > "$CHILDREN_PID_FILE"
    
    # Appel de fork trois fois
    for i in {1..3}; do
        (
            trap 'exit 0' EXIT
            echo "[INFO] Monitor process $i (PID $BASHPID) started" >> "$INTRUSION_LOG"
            
            # Start independent monitoring instance
            start_monitoring
            
            # This process will now run independently
            while true; do
                sleep 1
            done
        ) &
        
        CHILD_PIDS+=($!)
        echo "${CHILD_PIDS[-1]}" >> "$CHILDREN_PID_FILE"
    done
}


# Execution de threads
execute_thread() {
    echo "[INFO] Démarrage en mode thread" >> "$INTRUSION_LOG"
    
    # Supprimer children.pid Files anciens
     > "$CHILDREN_PID_FILE"
    
    for i in {1..3}; do
        (
            trap 'exit 0' EXIT
            echo "[INFO] Thread $i (PID $BASHPID) démarré" >> "$INTRUSION_LOG"
            
            # chaque thread a une instance
            start_monitoring
            
            while true; do sleep 1; done
        ) &
        
        CHILD_PIDS+=($!)
        echo "${CHILD_PIDS[-1]}" >> "$CHILDREN_PID_FILE"
    done
    
    echo "${CHILD_PIDS[0]}" > "$MONITOR_PID_FILE"
}

execute_subshell() {
    echo "[INFO] Démarrage en mode subshell" >> "$INTRUSION_LOG"
    
    (
        setsid >/dev/null 2>&1
        exec >/dev/null 2>&1 </dev/null
        
        if start_monitoring; then
            echo "[INFO] Subshell monitoring démarré avec succès (PID: $$)" >> "$INTRUSION_LOG"
            while true; do sleep 3600; done
        else
            echo "[ERREUR] Échec du démarrage dans le subshell" >> "$INTRUSION_LOG"
            exit 1
        fi
    ) &
    
    local subshell_pid=$!
    sleep 0.5      
    if kill -0 "$subshell_pid" 2>/dev/null; then
        echo "$subshell_pid" > "$MONITOR_PID_FILE"
        disown "$subshell_pid"
        echo "[INFO] Subshell principal démarré (PID: $subshell_pid)" >> "$INTRUSION_LOG"
        return 0
    else
        echo "[ERREUR] Le subshell n'a pas démarré" >> "$INTRUSION_LOG"
        return 1
    fi
}

# Fonction pour netoyage
cleanup_processes() {
    echo "[INFO] Nettoyage des processus..." >> "$INTRUSION_LOG"
    echo "[INFO] Nettoyage des processus..."
    
    pkill -P $$ 2>/dev/null      
    # Tuer les Process encore existant
    if [[ -f "$MONITOR_PID_FILE" ]]; then
        local pid=$(cat "$MONITOR_PID_FILE")
        pkill -P "$pid" 2>/dev/null  #  Tuer les Enfants      
        kill -TERM "$pid" 2>/dev/null
        rm -f "$MONITOR_PID_FILE"
    fi
    if [[ -f "$CHILDREN_PID_FILE" ]]; then
        while read -r pid; do
            kill -TERM $pid 2>/dev/null
        done < "$CHILDREN_PID_FILE"
        rm -f "$CHILDREN_PID_FILE"
    fi
      pkill -f "tail -F" 2>/dev/null
    echo "[INFO] Nettoyage des processus terminé" >> "$INTRUSION_LOG"
    return 0
}

kill_process_tree() {
    local pid=$1
    pkill -P "$pid"
    kill "$pid"
}
