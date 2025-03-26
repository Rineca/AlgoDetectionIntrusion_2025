import pandas as pd

# Définir le chemin du fichier en entrée directement dans le code
file_path = 'capture20110812.pcap.netflow.labeled'  # Remplace par le chemin de ton fichier

# Définir les noms des colonnes
column_names = [
    'Date flow', 'start', 'Durat', 'Prot', 'Src IP Addr:Port', 'Unknown',
    'Dst IP Addr:Port', 'Flags', 'Tos', 'Packets', 'Bytes', 'Flows', 'Label Labels', 'last'
]

try:
    # Charger les données
    df = pd.read_csv(file_path, sep='\s+', names=column_names, skiprows=1, engine='python', header=None)

    # Extraire les adresses IP sources et ports
    df[['Src IP Addr', 'Src Port']] = df['Src IP Addr:Port'].str.extract(r'([0-9.]+):([0-9]+)')

    # Filtrer les IP sources marquées comme "Botnet"
    botnet_ips = df[df['Label Labels'] == 'Botnet']['Src IP Addr']

    # Compter les occurrences des IP sources botnet
    botnet_ip_counts = botnet_ips.value_counts()

    # Sauvegarder dans un fichier CSV
    output_file = 'botnet_src_ips_counts_9.csv'
    botnet_ip_counts.to_csv(output_file, index_label='IP Address', header=['Occurrences'], sep=',')

    print(f'Les adresses IP sources de Botnet et leur fréquence ont été sauvegardées dans {output_file}.')

except FileNotFoundError:
    print(f'Le fichier spécifié {file_path} est introuvable. Veuillez vérifier le chemin.')
except Exception as e:
    print(f'Une erreur s\'est produite : {e}')
