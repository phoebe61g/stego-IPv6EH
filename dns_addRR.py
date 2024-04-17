# run bind9 to generate DNS answer, avg response time: 154.37 msec
base_domain = "pearl.org"
start_number = 1
end_number = 254
start_ip = "10.22.22.1"
end_ip = "10.22.22.254"

with open("/etc/bind/pearl.org", "a") as zone_file:
    for num in range(start_number, end_number + 1):
        ip_index = num
        ip = f"{start_ip[:-1]}{ip_index}"
        zone_file.write(f"*.{num}.{base_domain}. IN A {ip};\n")

'''
[DNS Configuration]
*To define zone: /etc/bind/named.conf.local
*zone file: /etc/bind/pearl.org
> named-checkzone pearl.org /etc/bind/pearl.org
> sudo rndc reload
'''
