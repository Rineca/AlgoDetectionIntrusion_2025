from scapy.all import rdpcap
import pandas as pd
import csv

fichier_csv = "result_Scé3_eta1_25___eta0_0.05.csv"

# Liste pour stocker les correspondances

column_names = [
    "Date flow", "start", "Durat", "Prot", "Src IP Addr:Port", "Unknown",
    "Dst IP Addr:Port", "Flags", "Tos", "Packets", "Bytes", "Flows", "Label Labels","last"
]

# Charger le fichier en précisant les noms de colonnes
df = pd.read_csv("capture20110812.pcap.netflow.labeled", sep="\s+", names=column_names, skiprows=1, engine="python", header=None)

print("lecture terminée")
filtered_df = df

filtered_df[['Src IP Addr', 'Src Port']] = filtered_df['Src IP Addr:Port'].str.extract(r'([0-9.]+):([0-9]+)')
filtered_df[['Dst IP Addr', 'Dst Port']] = filtered_df['Dst IP Addr:Port'].str.extract(r'([0-9.]+):([0-9]+)')


ips_legitimes = filtered_df.loc[filtered_df["Label Labels"] == "LEGITIMATE", "Src IP Addr"] 
ips_botnet = filtered_df.loc[filtered_df["Label Labels"] == "Botnet", "Src IP Addr"]




# Convertir en liste

liste_ips_legitimate_uniques = list(set(ips_legitimes.tolist()))


liste_ips_botnets_uniques = list(set(ips_botnet.tolist()))



#ips_sources_uniques = df["Src IP Addr"].unique().tolist()

#print (liste_ips_botnets_uniques)





with open(fichier_csv, newline='', encoding='utf-8') as csvfile:
    spamreader = csv.reader(csvfile, delimiter=',', quotechar='"')  # ⚠️ Vérifie le bon délimiteur
        
    ip_alerte=[]
    faux_negatifs=[]
    vrais_negatifs=[]
    # Itérer sur les lignes du fichier
    for row in spamreader:
        if row:  # Vérifier que la ligne n'est pas vide
            ip = row[0]
            nombre = row[1]
            ip_alerte.append(ip)
        
faux_negatifs = [ip for ip in liste_ips_botnets_uniques if ip not in ip_alerte] #botnet qui ne renvoient pas d'alerte | 
faux_positifs = [ip for ip in liste_ips_legitimate_uniques if ip in ip_alerte] #legitimes qui renvoient une alerte
vrais_negatifs = [ip for ip in liste_ips_legitimate_uniques if ip not in ip_alerte] #legitimes qui ne renvoient pas d'alerte
vrais_positifs = [ip for ip in liste_ips_botnets_uniques if ip in ip_alerte] #botnet qui renvoient une alerte

        # Vérifier si l'adresse IP est dans la liste des IP botnets uniques

FN = len(faux_negatifs)  
FP = len(faux_positifs) 
VN = len(vrais_negatifs)
VP = len(vrais_positifs)



# Calcul des métriques
TVP = VP / (VP + FN) if (VP + FN) > 0 else 0  # Taux de Vrais Positifs (Recall)
TFP = FP / (FP + VN) if (FP + VN) > 0 else 0  # Taux de Faux Positifs
TFN = FN / (VP + FN) if (VP + FN) > 0 else 0  # Taux de Faux Négatifs
TVN = VN / (VN + FP) if (VN + FP) > 0 else 0  # Taux de Vrais Négatifs (Spécificité)

# Précision, rappel et F1-score
precision = VP / (VP + FP) if (VP + FP) > 0 else 0
recall = TVP  # Identique au taux de vrais positifs
f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
# Affichage des résultats   

print(f"✅ Taux de Vrais Positifs (Recall) : {TVP:.2%}")
print(f"❌ Taux de Faux Positifs : {TFP:.2%}")
print(f"⚠️ Taux de Faux Négatifs : {TFN:.2%}")
print(f"✅ Taux de Vrais Négatifs (Spécificité) : {TVN:.2%}")
print("------------------------------------------------")
print(f"🎯 Précision : {precision:.2%}")
print(f"🔄 Rappel (Recall) : {recall:.2%}")
print(f"📊 Score F1 : {f1_score:.2%}")
