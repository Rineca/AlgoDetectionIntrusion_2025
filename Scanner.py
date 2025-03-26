from scapy.all import rdpcap
import pandas as pd
from datetime import timedelta
import csv



timer = 10
# Set thresholds for hypothesis testing
k = 3  # Access ratio threshold
eta1 = 10  # Upper threshold (declare scanner)
eta0 = 0.01  # Lower threshold (remove from tracking)

theta0=0.8
theta1=0.2

column_names = [
    "Date flow", "start", "Durat", "Prot", "Src IP Addr:Port", "Unknown",
    "Dst IP Addr:Port", "Flags", "Tos", "Packets", "Bytes", "Flows", "Label Labels", "last"
]

# Charger le fichier en précisant les noms de colonnes
df = pd.read_csv("capture20110817.pcap.netflow.labeled", sep="\s+", names=column_names, skiprows=1, engine="python", header=None)


filtered_df = df

filtered_df[['Src IP Addr', 'Src Port']] = filtered_df['Src IP Addr:Port'].str.extract(r'([0-9.]+):([0-9]+)')
filtered_df[['Dst IP Addr', 'Dst Port']] = filtered_df['Dst IP Addr:Port'].str.extract(r'([0-9.]+):([0-9]+)')
filtered_df["Timestamp"] = df["Date flow"] + " " + filtered_df["start"]
filtered_df["Timestamp"] = pd.to_datetime(filtered_df["Timestamp"])
filtered_df = filtered_df.drop(columns=["Date flow", "start", "Src IP Addr:Port", "Unknown",
    "Dst IP Addr:Port", "Flags", "Tos", "Packets", "Bytes", "Flows", "last"])

filtered_df = filtered_df.dropna(subset=["Dst Port"])
result = filtered_df


Liste_S = {}
Liste_ip_legim=[]
Liste_SCANNER = {}
id=1
result['time_bin'] = '' #Création d'une nouvelle colonne pour les intervalles
start_time = result["Timestamp"].min()
#Regrouper les flux en intervalles de 10 secondes
for index, row in result.iterrows():
    flow_start = row["Timestamp"]
    duration = row["Durat"]
    end_time = flow_start + timedelta(seconds=duration)
    if flow_start  < start_time + timedelta(seconds=timer):
        result.at[index, 'time_bin'] = id
    else:
        start_time = flow_start
        id +=1
    
agg_data = result.groupby(['time_bin', 'Src IP Addr']).agg(
    unique_dst_ip=('Dst IP Addr', pd.Series.nunique),   # Count unique destination IPs per source IP in the bin
    unique_dst_port=('Dst Port', pd.Series.nunique)  # Count unique destination ports per source IP in the bin
).reset_index()

agg_data['ip_to_port_ratio'] = agg_data['unique_dst_ip'] / (agg_data['unique_dst_port']+1)
agg_data['port_to_ip_ratio'] = agg_data['unique_dst_port'] / (agg_data['unique_dst_ip']+1)



def update_likelihood(src_ip, ip_to_port, port_to_ip):
    global Liste_S,Liste_SCANNER

    if src_ip not in Liste_S:
        Liste_S[src_ip] = 1  # Start with neutral likelihood
        Liste_SCANNER[src_ip] = 0 # Start with 0

    # Sequential hypothesis update
    if ip_to_port > k or port_to_ip > k:
        Liste_S[src_ip] *= (1 - theta1) / (1 - theta0)  # Update for scanning behavior
    else:
        Liste_S[src_ip] *= (theta1 / theta0)  # Update for normal behavior

    # Decision thresholds
    if Liste_S[src_ip] > eta1:
        # print(f"Scanner detected: {src_ip}")
        Liste_SCANNER[src_ip] += 1  # Count how many times detected
        return("Scanner")
    elif Liste_S[src_ip] < eta0:
        return "Benign"
    return "Under Observation"

# Apply the function to each row
agg_data['status'] = agg_data.apply(
    lambda row: update_likelihood(row['Src IP Addr'], row['ip_to_port_ratio'], row['port_to_ip_ratio']), axis=1
)

fichier_csv = "result_9.csv"
fichier = open(fichier_csv, mode="w", newline="", encoding="utf-8")
writer = csv.writer(fichier)


print("Scanner Detection Counts:")
for ip, count in sorted(Liste_SCANNER.items(), key=lambda item: item[1], reverse=True):
    if count > 0:
        print(f"{ip}: {count} times")
        # Écrire les données (clés et valeurs)
        writer.writerow([ip, count])
    

fichier.close()
print(f"Le fichier {fichier_csv} a été créé avec succès !")