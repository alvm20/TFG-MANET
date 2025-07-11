#!/usr/bin/env python3

import os
import re
import glob
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

## Ejecutar script desde PyCharm o Cursor

try:
    from scapy.all import rdpcap, UDP, Ether
except ImportError:
    print("Scapy no está instalado. Instálalo con 'pip3 install scapy'")
    exit(1)


#######################
# Funciones para parsear logs de ping
#######################

def parse_ping_log(file_path):
    """
    Parsea un archivo de log de ping y extrae las métricas:
    - RTT (Round-Trip Time) promedio (ms)
    - Jitter (mdev, ms)
    - Porcentaje de pérdida
    - Tiempo de RE-convergencia (segundos): Detecta automáticamente el salto en la secuencia
      de icmp_seq y calcula el tiempo desde el último ping antes del salto hasta el primer
      ping después del salto.
      REQUIERE que el log de ping haya sido generado con la opción -D (timestamps).
    """
    with open(file_path, "r", errors='ignore') as f:
        content = f.read()

    # --- Parseo de resumen ---
    summary_match = re.search(r'(\d+) packets transmitted, (\d+) received,.*?([\d\.]+)% packet loss', content)
    tx = int(summary_match.group(1)) if summary_match else None
    rx = int(summary_match.group(2)) if summary_match else None
    loss_pct = float(summary_match.group(3)) if summary_match else None

    rtt_match = re.search(r'rtt min/avg/max/[a-zA-Z]+ = [\d\.]+/([\d\.]+)/[\d\.]+/([\d\.]+) ms', content)
    avg_latency = float(rtt_match.group(1)) if rtt_match else None
    jitter = float(rtt_match.group(2)) if rtt_match else None

    # --- Cálculo automático de Tiempo de Re-convergencia ---
    reconvergence_time = None
    if tx and tx > 0:
        # Regex para extraer timestamp e icmp_seq de pings exitosos
        ping_regex = re.compile(r'^\[(\d+\.\d+)\].*icmp_seq=(\d+).*(?:bytes from|ttl=)', re.MULTILINE)
        
        # Encontrar todos los pings exitosos con su timestamp y seq
        successful_pings = [(float(m.group(1)), int(m.group(2))) for m in ping_regex.finditer(content)]
        
        if len(successful_pings) >= 2:
            # Detectar el salto automáticamente
            gap_detected = False
            last_ping_before_gap = None
            first_ping_after_gap = None
            
            for i in range(1, len(successful_pings)):
                prev_ts, prev_seq = successful_pings[i-1]
                curr_ts, curr_seq = successful_pings[i]
                
                # Detectar un salto significativo en la secuencia (> 3 números)
                seq_gap = curr_seq - prev_seq
                if seq_gap > 3:  # Umbral para considerar que hay un salto significativo
                    last_ping_before_gap = (prev_ts, prev_seq)
                    first_ping_after_gap = (curr_ts, curr_seq)
                    gap_detected = True
                    break
            
            # Calcular el tiempo de re-convergencia si se detectó un salto
            if gap_detected and last_ping_before_gap and first_ping_after_gap:
                reconvergence_time = first_ping_after_gap[0] - last_ping_before_gap[0]
                # Debug info
                print(f"  Salto detectado: seq {last_ping_before_gap[1]} -> {first_ping_after_gap[1]}, "
                      f"tiempo re-convergencia: {reconvergence_time:.2f}s")
            else:
                print(f"  No se detectó salto significativo en icmp_seq para este protocolo")

    return {
        "tx": tx,
        "rx": rx,
        "loss_pct": loss_pct,
        "avg_latency": avg_latency,
        "jitter": jitter,
        "reconvergence_time": reconvergence_time
    }


#######################
# Funciones para parsear logs de iperf3
#######################

def parse_iperf_log(file_path):
    """
    Parsea un archivo de log de iperf3 y extrae:
    - Una lista de throughput por intervalo (en Mbps)
    - El throughput promedio total (en Mbps) (del resumen)

    Se asume que la salida tiene líneas con formato similar a:
    "[  5]   0.00-1.00 sec  1.05 MBytes  8.81 Mbits/sec"
    y al final una línea similar a:
    "[  5]   0.00-10.00 sec  10.79 MBytes  9.05 Mbits/sec  receiver"
    """
    interval_throughputs = []
    avg_throughput = None

    with open(file_path, "r") as f:
        lines = f.readlines()

    # Regex para líneas intervalales: extraer la tasa (en Mbits/sec)
    interval_regex = re.compile(r'\[\s*\d+\]\s+\d+\.\d+-\d+\.\d+\s+sec\s+.*?\s+([\d\.]+)\s+Mbits/sec')
    # Regex para el resumen final (sender o receiver)
    summary_regex = re.compile(
        r'\[\s*\d+\]\s+\d+\.\d+-\d+\.\d+\s+sec\s+.*?\s+([\d\.]+)\s+Mbits/sec\s+(sender|receiver)')

    for line in lines:
        m = interval_regex.search(line)
        if m:
            try:
                val = float(m.group(1))
                interval_throughputs.append(val)
            except ValueError:
                continue
        m_sum = summary_regex.search(line)
        if m_sum:
            try:
                avg_throughput = float(m_sum.group(1))
            except ValueError:
                continue
    # Si no encontramos resumen, calcular media de los intervalos:
    if avg_throughput is None and interval_throughputs:
        avg_throughput = np.mean(interval_throughputs)
    return {
        "intervals": interval_throughputs,
        "avg_throughput": avg_throughput
    }


#######################
# Funciones para parsear archivos pcap de control de routing
#######################

def parse_pcap_control(file_path, protocol):
    """
    Usa Scapy para leer el archivo pcap y contar los mensajes de control según protocolo.

    - Para BATMAN (batmand): filtra paquetes UDP cuyo puerto (src o dst) es 4305.
    - Para BATMAN-Adv: filtra tramas Ethernet con Ethertype 0x4305 o 0x0842.
    - Para Babel: filtra paquetes UDP con puerto 6696.

    Retorna un diccionario con:\n
      - 'count': número total de mensajes encontrados\n
      - 'duration': tiempo transcurrido en la captura (segundos)\n
      - 'freq': mensajes por segundo (count/duration)
    """
    packets = rdpcap(file_path)
    count = 0
    # Aseguramos que existen paquetes
    if len(packets) == 0:
        return {"count": 0, "duration": 0, "freq": 0}

    # Determinamos el tiempo de inicio y fin de la captura:
    start_time = packets[0].time
    end_time = packets[-1].time
    duration = end_time - start_time if end_time > start_time else 1.0

    if protocol.lower() in ["batman", "batmand"]:
        # Filtrar paquetes UDP en puerto 4305 (src o dst)
        filtered = [p for p in packets if p.haslayer(UDP) and
                    (p[UDP].sport == 4305 or p[UDP].dport == 4305)]
    elif protocol.lower() in ["batman_adv"]:
        # Filtrar tramas Ethernet con tipo 0x4305 o 0x0842
        filtered = [p for p in packets if p.haslayer(Ether) and
                    p[Ether].type in [0x4305, 0x0842]]
    elif protocol.lower() in ["babel"]:
        # Filtrar paquetes UDP con puerto 6696
        filtered = [p for p in packets if p.haslayer(UDP) and
                    (p[UDP].sport == 6696 or p[UDP].dport == 6696)]
    else:
        filtered = []

    count = len(filtered)
    freq = count / duration
    return {"count": count, "duration": duration, "freq": freq}


#######################
# Funciones para graficar resultados
#######################

def ensure_directory(path):
    if not os.path.exists(path):
        os.makedirs(path)


def graficar_throughput_tiempo(data_dict, output_file, test_duration=None):
    """
    Genera un gráfico de líneas de Throughput vs Tiempo para cada protocolo.
    El eje X se muestra en segundos.
    """
    plt.figure(figsize=(12, 6)) # Figura más ancha para mejor visualización
    interval_duration = 10  # Duración de cada intervalo de iperf3 en segundos

    for proto, d in data_dict.items():
        if len(d["intervals"]) > 0:
            # Crear el eje de tiempo en segundos (10, 20, 30, ...)
            num_intervals = len(d["intervals"])
            t = np.arange(1, num_intervals + 1) * interval_duration
            plt.plot(t, d["intervals"], marker='.', linestyle='-', label=proto)
            
    # Añadir línea vertical para marcar el evento de movilidad si se proporciona la duración
    if test_duration:
        mobility_time = test_duration / 2
        # Usamos try-except por si la gráfica no llega a ese punto, para evitar errores
        try:
            plt.axvline(x=mobility_time, color='r', linestyle='--', linewidth=2, label=f'Movilidad (t={int(mobility_time)}s)')
        except:
            pass # No dibujar la línea si está fuera de rango

    plt.xlabel("Tiempo (s)") # Etiqueta del eje X corregida
    plt.ylabel("Throughput (Mbps)")
    plt.title("Throughput vs. Tiempo")
    # Forzar que la leyenda de la línea de movilidad no se duplique
    handles, labels = plt.gca().get_legend_handles_labels()
    by_label = dict(zip(labels, handles))
    plt.legend(by_label.values(), by_label.keys())
    plt.grid(True)
    plt.savefig(output_file)
    plt.close()


def graficar_barra(metric_dict, ylabel, title, output_file):
    """
    Genera un gráfico de barras a partir de un diccionario
    metric_dict: { 'protocol1': value1, 'protocol2': value2, ... }
    """
    protocols = list(metric_dict.keys())
    # Convertir todos los valores a float para asegurar la compatibilidad con las operaciones de matplotlib
    values = [float(metric_dict[p]) for p in protocols]
    
    plt.figure(figsize=(6, 4))
    bars = plt.bar(protocols, values, color=['#1f77b4', '#ff7f0e', '#2ca02c'])
    
    plt.ylabel(ylabel)
    
    # Añadir padding al título y ajustar el límite del eje Y para evitar solapamientos
    plt.title(title, pad=15)
    if values:
        plt.ylim(top=max(values) * 1.15)
        
    for bar in bars:
        yval = bar.get_height()
        # El offset del texto usa max(values) que ahora es un float seguro
        plt.text(bar.get_x() + bar.get_width() / 2, yval + (max(values) * 0.01), f'{yval:.2f}', ha='center', va='bottom')
        
    plt.savefig(output_file)
    plt.close()


#######################
# Función principal: procesar todos los resultados
#######################

def main():
    # Definir directorios base para cada protocolo
    base_dir = "resultados"
    protocolos = ["batmand", "batman_adv", "babel"]

    # Inicializar diccionarios para guardar métricas agregadas por protocolo
    summary_ping = {}  # latencia, jitter, perdida y convergencia
    summary_iperf = {}  # throughput promedio y serie de intervalos
    summary_pcap = {}  # overhead de control (mensajes/seg)

    # Iterar sobre cada protocolo
    for proto in protocolos:
        proto_dir = os.path.join(base_dir, proto)
        # Lista de archivos de ping e iperf
        ping_files = glob.glob(os.path.join(proto_dir, "*ping*.txt"))
        iperf_files = glob.glob(os.path.join(proto_dir, "*iperf*.txt"))
        pcap_files = glob.glob(os.path.join(proto_dir, "*.pcap"))

        # Listas para acumular métricas por prueba
        lat_list = []
        jitter_list = []
        loss_list = []
        reconv_list = []

        # Definir la variable aquí, antes del bucle, para asegurar que siempre exista.
        estimated_test_duration = None 

        for i, ping_file in enumerate(ping_files):
            metrics = parse_ping_log(ping_file)
            
            # Extraer la duración de la prueba del primer archivo de ping
            if i == 0 and metrics.get("tx") is not None:
                estimated_test_duration = metrics["tx"]
                
            if metrics["avg_latency"] is not None: lat_list.append(metrics["avg_latency"])
            if metrics["jitter"] is not None: jitter_list.append(metrics["jitter"])
            if metrics["loss_pct"] is not None: loss_list.append(metrics["loss_pct"])
            if metrics["reconvergence_time"] is not None: reconv_list.append(metrics["reconvergence_time"])

        # Promedios de ping
        avg_lat = np.mean(lat_list) if lat_list else 0.0
        avg_jitter = np.mean(jitter_list) if jitter_list else 0.0
        avg_loss = np.mean(loss_list) if loss_list else 0.0
        avg_reconv = np.mean(reconv_list) if reconv_list else 0.0
        
        summary_ping[proto] = {
            "avg_latency": avg_lat,
            "jitter": avg_jitter,
            "loss_pct": avg_loss,
            "reconvergence_time": avg_reconv,
            "duration": estimated_test_duration # Ahora la variable está definida
        }

        # Iperf: para cada archivo, acumular la lista de throughput de intervalos y el promedio
        throughput_series = []
        avg_thr_list = []
        for iperf_file in iperf_files:
            ip_metrics = parse_iperf_log(iperf_file)
            if ip_metrics["intervals"]:
                throughput_series.append(ip_metrics["intervals"])
            if ip_metrics["avg_throughput"] is not None:
                avg_thr_list.append(ip_metrics["avg_throughput"])
        avg_thr = np.mean(avg_thr_list) if avg_thr_list else 0.0
        # Para graficar throughput vs tiempo, promediamos la serie si hay varias pruebas
        if throughput_series:
            # Asumir que todas las series tienen la misma longitud, tomar el promedio por intervalo
            series_array = np.array(throughput_series)
            mean_series = np.mean(series_array, axis=0)
            summary_iperf[proto] = {"intervals": mean_series.tolist(), "avg": avg_thr}
        else:
            summary_iperf[proto] = {"intervals": [], "avg": 0.0}

        # PCAP: para overhead de control, sumar todos los mensajes de control
        msg_counts = []
        for pcap_file in pcap_files:
            pcap_metrics = parse_pcap_control(pcap_file, proto)
            msg_counts.append(pcap_metrics["freq"])
        avg_overhead = np.mean(msg_counts) if msg_counts else 0.0
        summary_pcap[proto] = avg_overhead

    # Mostrar resumen en consola
    print("=== Resumen de métricas extraídas ===")
    for proto in protocolos:
        print(f"\nProtocolo: {proto}")
        print(f"  Ping: RTT promedio = {summary_ping[proto]['avg_latency']:.3f} ms, "
              f"Jitter = {summary_ping[proto]['jitter']:.3f} ms, "
              f"Pérdida = {summary_ping[proto]['loss_pct']:.2f}%, "
              f"Tiempo de Re-convergencia = {summary_ping[proto]['reconvergence_time']:.2f} s")
        print(f"  Iperf: Throughput promedio = {summary_iperf[proto]['avg']} Mbps")
        print(f"  PCAP (overhead): {summary_pcap[proto]:.2f} mensajes/seg")

    # Crear la carpeta de gráficas
    ensure_directory("graficas")

    # Graficar Throughput vs Tiempo
    throughput_data = {}
    for proto in protocolos:
        throughput_data[proto] = summary_iperf[proto]
    
    # Obtener la duración de la prueba para pasarla a la función de la gráfica
    test_duration_for_graph = None
    if protocolos and summary_ping.get(protocolos[0]):
        test_duration_for_graph = summary_ping[protocolos[0]].get("duration")

    graficar_throughput_tiempo(throughput_data, "graficas/throughput_tiempo.png", test_duration=test_duration_for_graph)

    # Graficar Throughput promedio
    avg_thr_dict = {proto: summary_iperf[proto]["avg"] for proto in protocolos}
    graficar_barra(avg_thr_dict, "Throughput (Mbps)", "Throughput Promedio", "graficas/throughput_promedio.png")

    # Graficar RTT promedio
    avg_lat_dict = {proto: summary_ping[proto]["avg_latency"] for proto in protocolos}
    graficar_barra(avg_lat_dict, "RTT (ms)", "RTT Promedio", "graficas/latencia_promedio.png")

    # Graficar Pérdida de paquetes
    loss_dict = {proto: summary_ping[proto]["loss_pct"] for proto in protocolos}
    graficar_barra(loss_dict, "Pérdida (%)", "Pérdida de Paquetes", "graficas/packet_loss.png")

    # Graficar Jitter
    jitter_dict = {proto: summary_ping[proto]["jitter"] for proto in protocolos}
    graficar_barra(jitter_dict, "Jitter (ms)", "Jitter Promedio", "graficas/jitter_promedio.png")

    # Graficar Tiempo de Re-Convergencia
    conv_dict = {proto: summary_ping[proto]["reconvergence_time"] for proto in protocolos}
    graficar_barra(conv_dict, "Tiempo (s)", "Tiempo de Re-convergencia tras Movilidad", "graficas/convergencia.png")

    # Graficar Overhead de control (mensajes/seg)
    graficar_barra(summary_pcap, "Mensajes/seg", "Overhead de Control", "graficas/overhead.png")

    print("\nTodas las gráficas han sido guardadas en la carpeta 'graficas/'.")
    print("Gráficas generadas:")
    print("  - throughput_tiempo.png: Throughput vs. tiempo con evento de movilidad")
    print("  - throughput_promedio.png: Throughput promedio por protocolo")
    print("  - latencia_promedio.png: RTT promedio por protocolo")
    print("  - jitter_promedio.png: Jitter promedio por protocolo")
    print("  - packet_loss.png: Pérdida de paquetes por protocolo")
    print("  - convergencia.png: Tiempo de re-convergencia por protocolo")
    print("  - overhead.png: Overhead de control por protocolo")


if __name__ == '__main__':
    main()