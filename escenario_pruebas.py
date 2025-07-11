#!/usr/bin/env python3
"""
escenario_pruebas.py

Comparativa de protocolos: batmand, batman_adv y babel
 · Topología inicial: malla 3×3 + puente sta10
 · Evento de movilidad en t = test_duration / 2:
     sta2  (150,0)    → (300,100)
     sta3  (300,0)    → (150,0)
     sta6  (300,100)  → (150,200)
     sta8  (150,200)  → ( 50,150)
   (sta1,4,5,7,9,10 no cambian)
 · Mide ping, iperf3 y captura PCAP

Resultados     resultados/<proto>/{ping_log.txt,iperf_log.txt,capture.pcap}
"""

import os, sys, time, signal
from mininet.log          import setLogLevel, info
from mn_wifi.net          import Mininet_wifi
from mn_wifi.link         import wmediumd, adhoc
from mn_wifi.wmediumdConnector import interference
from mn_wifi.cli          import CLI

# ==========Utilidades =======================================================
def ensure_dir(path):
    if not os.path.isdir(path):
        os.makedirs(path, exist_ok=True)

def kill_bg(node, procname):
    node.cmd(f"pkill -INT -f {procname} >/dev/null 2>&1")

# ==========Posiciones =======================================================
# Coordenadas iniciales (x,y,z)
POS_INIT = {
    'sta1':  "50,50,0",   'sta2':  "100,50,0",  'sta3':  "150,50,0",
    'sta4':  "50,100,0", 'sta5':  "100,100,0",'sta6':  "150,100,0",
    'sta7':  "50,150,0", 'sta8':  "100,150,0",'sta9':  "150,150,0",
    'sta10': "200,125,0"
}
# Coordenadas tras la movilidad (t = T/2)
POS_FINAL = {
    'sta1':  "50,50,0",
    'sta2':  "150,100,0",
    'sta3':  "100,50,0",
    'sta4':  "50,100,0",
    'sta5':  "100,100,0",
    'sta6':  "100,150,0",
    'sta7':  "50,150,0",
    'sta8':  "75,125,0",
    'sta9':  "150,150,0",
    'sta10': "200,125,0"
}

# ==========Configuración de red =============================================
def setup_network(proto:str):
    info("*** Creando red WiFi\n")
    net = Mininet_wifi(link=wmediumd, wmediumd_mode=interference)

    info("*** Añadiendo 10 estaciones\n")
    stations = []
    for name,pos in POS_INIT.items():
        sta = net.addStation(name, ip=f"10.0.0.{len(stations)+1}/24",
                             ipv6=f"fe80::{len(stations)+1}",
                             position=pos)   # rango 160m
        stations.append(sta)

    net.setPropagationModel(model="logDistance", exp=4)
    net.configureWifiNodes()

    info("*** Creando enlaces ad‑hoc (proto=%s)\n" % proto)
    for sta in stations:
        net.addLink(sta, cls=adhoc, intf=f"{sta.name}-wlan0",
                    ssid="adhocNet", mode='g', channel=5, proto=proto)

    net.plotGraph(max_x=300, max_y=300)
    # net.build()
    return net, stations

# ==========Evento de movilidad =============================================
def schedule_mobility(net, half_time:int):
    info("*** Programando movimiento\n")
    net.startMobility(time=0, mob_rep=1, reverse=False)
    delay = 5
    for name,pos in POS_FINAL.items():
        sta = net.get(name)
        net.mobility(sta, 'start', time=half_time, position=POS_INIT[name])
        net.mobility(sta, 'stop',  time=half_time + delay, position=POS_FINAL[name])
    net.stopMobility(time=half_time + delay + 1)

# ==========Pruebas de tráfico ===============================================
def launch_tests(net, stations, proto, duration:int):
    result_dir = os.path.join("resultados", proto)
    ensure_dir(result_dir)

    sta1, sta10 = stations[0], stations[-1]
    sta10_index = len(stations)

    # dst_ip = "192.168.123.10" if proto=="batman_adv" else '10.0.0.10'
    dst_ip = f"192.168.123.{sta10_index}" if proto=="batman_adv" else f"10.0.0.{sta10_index}"
    # --- 1. Ping continuo ----------------------------------------------------
    ping_log = os.path.join(result_dir, "ping_log.txt")
    sta1.cmd(f"ping -D -i 1 -c {duration} {dst_ip} > {ping_log} 2>&1 &")

    # --- 2. Captura (tcpdump o tshark) --------------------------------------
    pcap_file = os.path.join(result_dir, "capture.pcap")
    sta1.cmd(f"tcpdump -i {sta1.name}-wlan0 -w {pcap_file} &")
    
    # --- 3. Iperf3 -----------------------------------------------------------
    iperf_log = os.path.join(result_dir, "iperf_log.txt")
    sta10.cmd("iperf3 -s -p 5201 &")
    # time.sleep(30)                 # servidor listo
    #
    # sta1.cmd(f"iperf3 -c {dst_ip} -p 5201 -t {duration} -i 10 "
    #            f"> {iperf_log} 2>&1 &")
    
    monitor_script = f"""
    ( 
        # Esperar a que el archivo de ping exista
        while [ ! -f {ping_log} ]; do sleep 0.5; done
        
        # Contar pings exitosos hasta llegar a 10
        count=0
        while [ $count -lt 10 ]; do
            new_count=$(grep -c "bytes from" {ping_log})
            if [ $new_count -ge 10 ]; then
                echo "*** 10 pings exitosos detectados, iniciando iperf3 cliente..."
                iperf3 -c {dst_ip} -p 5201 -t {duration} -i 10 > {iperf_log} 2>&1 &
                break
            fi
            sleep 1
        done
    ) &
    """
    
    sta1.cmd(monitor_script)



    info("*** Tráfico y captura activos. iperf3 iniciará tras 10 pings exitosos (%d s max)\n" % duration)

# ==========Main =============================================================
def main():
    setLogLevel('info')

    proto         = sys.argv[1] if len(sys.argv)>=2 else "babel"
    test_duration = int(sys.argv[2]) if len(sys.argv)>=3 else 600
    half_time     = test_duration // 2

    net, stations = setup_network(proto)

    # # Espera corta para demonios de routing
    info("*** Esperando 30s para convergencia inicial\n")
    time.sleep(30)

    launch_tests(net, stations, proto, test_duration)
    schedule_mobility(net, half_time)

    net.build()

    # Esperar hasta fin de prueba
    time.sleep(test_duration+10)


    stations[0].cmd("killall iperf3")
    stations[0].cmd("killall ping")
    stations[0].cmd("killall tcpdump")
    stations[-1].cmd("killall iperf3")

    info("\n*** Pruebas completadas; resultados en resultados/%s/\n" % proto)

    # Detener procesos background
    # for sta in stations:
    #     kill_bg(sta, "iperf3")
    #     kill_bg(sta, "ping")
    #     kill_bg(sta, "tcpdump")


    info("*** Running CLI\n")
    CLI(net)

    net.stop()

if __name__ == '__main__':
    main()