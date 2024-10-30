import shodan

# Function to perform Shodan lookup
def shodan_lookup(api_key, target_ip):
    try:
        #Initialize the Shodan API
        api = shodan.Shodan(api_key)

        #Perform a Shodan search on the target IP
        host_info = api.host(target_ip)

        # Prepare the result to return
        results = f"IP: {host_info['ip_str']}\n"
        results += f"Organization: {host_info.get('org', 'N/A')}\n"
        results += f"Operating System: {host_info.get('os', 'N/A')}\n\n"

        # Loop through all services on this IP
        for service in host_info['data']:
            results += f"Port: {service['port']}\n"
            results += f"Service: {service.get('product', 'N/A')}\n"
            results += f"Version: {service.get('version', 'N/A')}\n"
            results += f"Banner: {service.get('banner', 'N/A')}\n"
            results += '-' * 40 + '\n'

        return results

    except shodan.APIError as e:
        return f"Error: {str(e)}"
