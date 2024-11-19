from scapy.all import ARP, Ether, srp
from mac_vendor_lookup import MacLookup
from openpyxl import Workbook, load_workbook
from openpyxl.styles import PatternFill
from collections import defaultdict
import os

def escanear_red(red, intentos=3):
    """
    Escanea la red usando ARP varias veces y combina resultados únicos.
    """
    dispositivos = defaultdict(dict)

    for intento in range(intentos):
        paquete = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=red)
        resultado = srp(paquete, timeout=2, verbose=False)[0]

        for enviado, recibido in resultado:
            mac = recibido.hwsrc
            ip = recibido.psrc
            proveedor = "Proveedor desconocido"
            try:
                proveedor = MacLookup().lookup(mac)
            except Exception:
                pass

            # Actualizar dispositivo en el diccionario
            dispositivos[mac] = {
                "IP": ip,
                "Proveedor": proveedor
            }

    # Convertir a lista de diccionarios
    return [{"IP": datos["IP"], "MAC": mac, "Proveedor": datos["Proveedor"]}
            for mac, datos in dispositivos.items()]

def guardar_en_excel(dispositivos, archivo_excel, red_objetivo):
    """
    Guarda la información de los dispositivos en un archivo Excel.
    Si ya existe, compara los datos y resalta cambios en amarillo.
    Si algún dispositivo ya no está presente, se marca en rojo.
    """
    # Sustituir caracteres no válidos en el nombre de la hoja
    nombre_hoja = red_objetivo.replace("/", "-")
    
    # Definir colores
    amarillo = PatternFill(start_color="FFFF00", end_color="FFFF00", fill_type="solid")
    rojo = PatternFill(start_color="FF0000", end_color="FF0000", fill_type="solid")
    # blanco

    archivo_existe = True
    
    if os.path.exists(archivo_excel):
        # Cargar el archivo existente
        wb = load_workbook(archivo_excel)
        if nombre_hoja in wb.sheetnames:
            ws = wb[nombre_hoja]
        else:
            ws = wb.create_sheet(title=nombre_hoja)
            archivo_existe = False
    else:
        # Crear un nuevo archivo
        wb = Workbook()
        ws = wb.active
        ws.title = nombre_hoja
        archivo_existe = False

    # Leer datos existentes
    datos_existentes = set()
    for fila in ws.iter_rows(min_row=2, max_row=ws.max_row, min_col=2, max_col=3, values_only=True):
        ip, mac = fila
        if ip and mac:
            datos_existentes.add((ip, mac))

    # Crear un conjunto de dispositivos nuevos (IPs y MACs), ahora como diccionarios
    nuevos_dispositivos = []
    for dispositivo in dispositivos:
        nuevos_dispositivos.append({
            'IP': dispositivo['IP'],
            'MAC': dispositivo['MAC'],
            'Proveedor': dispositivo['Proveedor']
        })

    # Comparar los dispositivos nuevos con los existentes
    dispositivos_a_agregar = [d for d in nuevos_dispositivos if (d['IP'], d['MAC']) not in datos_existentes]  # Solo los dispositivos nuevos
    dispositivos_a_eliminar = [(ip, mac) for (ip, mac) in datos_existentes if not any(d['IP'] == ip and d['MAC'] == mac for d in nuevos_dispositivos)]  # Dispositivos que ya no están

    # Escribir encabezados si están vacíos
    if ws.max_row == 1:
        ws['B1'] = "IP"
        ws['C1'] = "MAC"
        ws['E1'] = "Proveedor"

    # Resaltar dispositivos que ya no están presentes en rojo
    if archivo_existe:
        for fila_num, fila in enumerate(ws.iter_rows(min_row=2, max_row=ws.max_row, min_col=2, max_col=3), start=2):
            ip, mac = fila[0].value, fila[1].value
            if (ip, mac) in dispositivos_a_eliminar:
                ws[f'B{fila_num}'].fill = rojo
                ws[f'C{fila_num}'].fill = rojo

    # Escribir nuevos datos y resaltar cambios en amarillo
    fila = ws.max_row + 1
    for dispositivo in dispositivos_a_agregar:
        ip = dispositivo['IP']
        mac = dispositivo['MAC']
        proveedor = dispositivo['Proveedor']
        ws[f'B{fila}'] = ip
        ws[f'C{fila}'] = mac
        ws[f'E{fila}'] = proveedor

        # Detectar si es un dispositivo nuevo
        if ip not in datos_existentes and archivo_existe and ip != None:
            ws[f'B{fila}'].fill = amarillo
        if mac not in datos_existentes and archivo_existe and mac != None:
            ws[f'C{fila}'].fill = amarillo
        fila += 1

    # Guardar el archivo
    wb.save(archivo_excel)
    print(f"Datos guardados en {archivo_excel}")

def main():
    """
    Función principal que ejecuta el flujo del programa.
    """
    red_objetivo = input("Introduce el rango de red (por ejemplo, 192.168.1.0/24): ").strip()
    archivo_excel = input("Introduce el nombre del archivo Excel de salida (por ejemplo, dispositivos_red.xlsx): ").strip()

    print(f"Escaneando la red: {red_objetivo}...")
    dispositivos = escanear_red(red_objetivo)

    if dispositivos:
        print(f"Se encontraron {len(dispositivos)} dispositivos únicos.")
        guardar_en_excel(dispositivos, archivo_excel, red_objetivo)
    else:
        print("No se encontraron dispositivos en la red.")

if __name__ == "__main__":
    main()
