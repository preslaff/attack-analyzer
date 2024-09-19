import pandas as pd
from sklearn.cluster import KMeans
import matplotlib.pyplot as plt
import requests

class LogAnalyzer:
    def __init__(self, fail2ban_log_path, ufw_log_path):
        self.fail2ban_log_path = fail2ban_log_path
        self.ufw_log_path = ufw_log_path

    import pandas as pd

    import pandas as pd

    def parse_fail2ban(self):
        data = []
        
        # Open the log file and read it line by line
        with open(self.fail2ban_log_path, 'r') as file:
            for line in file:
                # Look for relevant information: IP address and the type of action
                if "Found" in line or "Ban" in line or "Unban" in line:
                    parts = line.split()
                    date = str(parts[0])
                    time = str(parts[1])
                    status = parts[4]
                    ip = None
                    
                    # Extract the IP address from the line based on "Found", "Ban", or "Unban"
                    if "Found" in line:
                        ip = parts[7]
                    elif "Ban" in line or "Unban" in line:
                        ip = parts[6]
                    
                    # Append the parsed data to the list
                    if ip:
                        data.append([f"{date} {time}", ip, status])
        
        # Convert the collected data into a pandas DataFrame
        fail2ban_df = pd.DataFrame(data, columns=['datetime', 'ip', 'status'])
        
        # Convert the datetime string into a proper datetime object, handle errors
        fail2ban_df['datetime'] = pd.to_datetime(fail2ban_df['datetime'], errors='coerce')
        
        return fail2ban_df


   
    def parse_ufw(self):
        data = []
    
        with open(self.ufw_log_path, 'r') as file:
            for line in file:
                parts = line.split()
                if len(parts) >= 7:  # Ensure there are enough parts to process
                    date = str(parts[0])
                    time = str(parts[1])
                    action = parts[6]
                    ip = parts[7]
                    data.append([f"{date} {time}", ip, action])
        
        # Convert the data to a pandas DataFrame
        ufw_df = pd.DataFrame(data, columns=['datetime', 'ip', 'action'])
    
        # Convert datetime to pandas datetime format and handle any errors
        ufw_df['datetime'] = pd.to_datetime(ufw_df['datetime'], errors='coerce')
    
        return ufw_df



    def find_repeated_ips(self):
        fail2ban_df = self.parse_fail2ban()
        ufw_df = self.parse_ufw()
        common_ips = pd.merge(fail2ban_df, ufw_df, on='ip', how='inner')
        return common_ips

    def get_stats(self):
        fail2ban_df = self.parse_fail2ban()
        ufw_df = self.parse_ufw()
        fail2ban_ip_counts = fail2ban_df['ip'].value_counts()
        ufw_ip_counts = ufw_df['ip'].value_counts()
        return {'fail2ban_ip_counts': fail2ban_ip_counts, 'ufw_ip_counts': ufw_ip_counts}

    def geolocate_ip(self, ip):
        url = f"https://ipinfo.io/{ip}/json"
        response = requests.get(url)
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": "Could not retrieve geolocation"}

    def geolocate_ips(self, ip_list):
        geolocations = []
        for ip in ip_list:
            geo_info = self.geolocate_ip(ip)
            geolocations.append(geo_info)
        return geolocations


class ClusteringAnalyzer:
    def __init__(self, ip_data):
        self.ip_data = ip_data

    def ip_to_numeric(self):
        self.ip_data['ip_numeric'] = self.ip_data['ip'].apply(lambda ip: int(''.join(ip.split('.'))))

    def perform_clustering(self, n_clusters=3):
        self.ip_to_numeric()
        kmeans = KMeans(n_clusters=n_clusters)
        self.ip_data['cluster'] = kmeans.fit_predict(self.ip_data[['ip_numeric']])
        return self.ip_data

    def visualize_clusters(self):
        self.ip_data.plot(kind='scatter', x='datetime', y='ip_numeric', c='cluster', colormap='viridis')
        plt.show()
