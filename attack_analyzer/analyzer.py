import pandas as pd
from sklearn.cluster import KMeans
import matplotlib.pyplot as plt
import requests

class LogAnalyzer:
    def __init__(self, fail2ban_log_path, ufw_log_path):
        self.fail2ban_log_path = fail2ban_log_path
        self.ufw_log_path = ufw_log_path

    def parse_fail2ban(self):
        fail2ban_df = pd.read_csv(self.fail2ban_log_path, sep=' ', header=None, names=['date', 'time', 'ip', 'status'])
        fail2ban_df['datetime'] = pd.to_datetime(fail2ban_df['date'] + ' ' + fail2ban_df['time'])
        return fail2ban_df[['datetime', 'ip', 'status']]

    def parse_ufw(self):
        ufw_df = pd.read_csv(self.ufw_log_path, sep=' ', header=None, names=['date', 'time', 'ip', 'action'])
        ufw_df['datetime'] = pd.to_datetime(ufw_df['date'] + ' ' + ufw_df['time'])
        return ufw_df[['datetime', 'ip', 'action']]

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
