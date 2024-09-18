import folium

class GeoLocator:
    def __init__(self, geolocations):
        self.geolocations = geolocations

    def create_map(self, output_file='geolocated_ips_map.html'):
        map_obj = folium.Map(location=[0, 0], zoom_start=2)

        for geo_info in self.geolocations:
            if 'loc' in geo_info:
                lat, lon = map(float, geo_info['loc'].split(','))
                popup_content = f"""
                IP: {geo_info.get('ip', 'N/A')}<br>
                City: {geo_info.get('city', 'N/A')}<br>
                Region: {geo_info.get('region', 'N/A')}<br>
                Country: {geo_info.get('country', 'N/A')}<br>
                Org: {geo_info.get('org', 'N/A')}
                """
                folium.Marker(
                    [lat, lon],
                    popup=folium.Popup(popup_content, max_width=300),
                    tooltip=f"IP: {geo_info.get('ip', 'N/A')}"
                ).add_to(map_obj)

        map_obj.save(output_file)
        print(f"Map with geolocated IPs saved to {output_file}")
