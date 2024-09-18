import inquirer
from attack.analyzer import LogAnalyzer, ClusteringAnalyzer
from my_package.geolocation import GeoLocator


class InteractiveSession:
    def __init__(self):
        self.fail2ban_log = None
        self.ufw_log = None
        self.log_analyzer = None

    def start(self):
        self.choose_files()
        self.show_menu()

    def choose_files(self):
        questions = [
            inquirer.Text('fail2ban_log', message="Enter the path to your Fail2Ban log file"),
            inquirer.Text('ufw_log', message="Enter the path to your UFW log file"),
        ]
        answers = inquirer.prompt(questions)
        self.fail2ban_log = answers['fail2ban_log']
        self.ufw_log = answers['ufw_log']
        self.log_analyzer = LogAnalyzer(self.fail2ban_log, self.ufw_log)

    def show_menu(self):
        while True:
            options = [
                "View statistics of blocked IPs",
                "Find repeated IPs between Fail2Ban and UFW logs",
                "Perform clustering analysis on repeated IPs",
                "Geolocate IPs and plot on a map",
                "Exit"
            ]
            question = [inquirer.List('option', message="Choose an option", choices=options)]
            answer = inquirer.prompt(question)

            if answer['option'] == "View statistics of blocked IPs":
                self.view_stats()
            elif answer['option'] == "Find repeated IPs between Fail2Ban and UFW logs":
                self.find_repeated_ips()
            elif answer['option'] == "Perform clustering analysis on repeated IPs":
                self.perform_clustering()
            elif answer['option'] == "Geolocate IPs and plot on a map":
                self.geolocate_and_map()
            elif answer['option'] == "Exit":
                break

    def view_stats(self):
        stats = self.log_analyzer.get_stats()
        print("Fail2Ban Blocked IPs:\n", stats['fail2ban_ip_counts'])
        print("UFW Blocked IPs:\n", stats['ufw_ip_counts'])

    def find_repeated_ips(self):
        repeated_ips = self.log_analyzer.find_repeated_ips()
        print("Repeated IPs between Fail2Ban and UFW:\n", repeated_ips)

    def perform_clustering(self):
        repeated_ips = self.log_analyzer.find_repeated_ips()
        clustering_analyzer = ClusteringAnalyzer(repeated_ips)
        clustered_data = clustering_analyzer.perform_clustering(n_clusters=3)
        print("Clustered Data:\n", clustered_data)
        clustering_analyzer.visualize_clusters()

    def geolocate_and_map(self):
        repeated_ips = self.log_analyzer.find_repeated_ips()
        unique_ips = repeated_ips['ip'].unique()
        geolocations = self.log_analyzer.geolocate_ips(unique_ips)
        geo_locator = GeoLocator(geolocations)
        geo_locator.create_map(output_file="geolocated_ips_map.html")
        

def main():
    session = InteractiveSession()
    session.start()

if __name__ == '__main__':
    main()

