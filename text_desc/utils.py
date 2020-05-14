
def call_api(endpoint, json_format=True, handle_errors=True):
    """Call to the ProtonVPN API."""

    # forward request to ProtonVPN API
    # return bytes or json? or just the bytes
    pass


def pull_server_data(force=False):
    """Pull current server data from the ProtonVPN API."""
    # Check if last server pull happened within the last 15 min (900 sec)
    # write servers to file
    pass

def get_servers():
    """Return a list of all servers for the users Tier."""
    # tier <= user_tier
    pass

def get_server_value(servername, key, servers):
    """Return the value of a key for a given server."""
    pass


def get_config_value(group, key):
    """Return specific value from CONFIG_FILE as string"""
    pass


def set_config_value(group, key, value):
    """Write a specific value to CONFIG_FILE"""
    pass

def get_ip_info():
    """Return the current public IP Address"""
    # ip_info = call_api("/vpn/location")
    # return ip, isp


def get_country_name(code):
    """Return the full name of a country from code"""
    # pass


def get_fastest_server(server_pool):
    """Return the fastest server from a list of servers"""

    # Sort servers by "speed" (Score) and select top n according to pool_size
    # if n_servers >= 50, pool=4 else 1
    # connect random from pool


def get_default_nic():
    """Find and return the default network interface"""
    # `ip show route | grep default | awk {print $5}`
    pass


def is_connected():
    """Check if a VPN connection already exists."""
    # pgrep -x openvpn
    pass


def wait_for_network(wait_time):
    """Check if internet access is working"""
    # ping api every 2 secs until connection
    # timeout supplied
    pass

def cidr_to_netmask(cidr):
    subnet = ipaddress.IPv4Network("0.0.0.0/{0}".format(cidr))
    return str(subnet.netmask)

def make_ovpn_template():
    """Create OpenVPN template file."""
    pull_server_data()

    with open(SERVER_INFO_FILE, "r") as f:
        server_data = json.load(f)

    # Get the ID of the first server from the API
    server_id = server_data["LogicalServers"][0]["ID"]

    config_file_response = call_api(
        "/vpn/config?Platform=linux&LogicalID={0}&Protocol=tcp".format(server_id),  # noqa
        json_format=False
    )

    with open(TEMPLATE_FILE, "wb") as f:
        for chunk in config_file_response.iter_content(100000):
            f.write(chunk)
            logger.debug("OpenVPN config file downloaded")

    # Write split tunneling config to OpenVPN Template
    try:
        if get_config_value("USER", "split_tunnel") == "1":
            split = True
        else:
            split = False
    except KeyError:
        split = False
    if split:
        logger.debug("Writing Split Tunnel config")
        with open(SPLIT_TUNNEL_FILE, "r") as f:
            content = f.readlines()

        with open(TEMPLATE_FILE, "a") as f:
            for line in content:
                line = line.rstrip("\n")
                netmask = None

                if not is_valid_ip(line):
                    logger.debug(
                        "[!] '{0}' is invalid. Skipped.".format(line)
                    )
                    continue

                if "/" in line:
                    ip, cidr = line.split("/")
                    netmask = cidr_to_netmask(int(cidr))
                else:
                    ip = line

                if netmask is None:
                    netmask = "255.255.255.255"

                if is_valid_ip(ip):
                    f.write(
                        "\nroute {0} {1} net_gateway".format(ip, netmask)
                    )

                else:
                    logger.debug(
                        "[!] '{0}' is invalid. Skipped.".format(line)
                    )

        logger.debug("Split Tunneling Written")

    # Remove all remote, proto, up, down and script-security lines
    # from template file
    remove_regex = re.compile(r"^(remote|proto|up|down|script-security) .*$")

    for line in fileinput.input(TEMPLATE_FILE, inplace=True):
        if not remove_regex.search(line):
            print(line, end="")

    logger.debug("remote and proto lines removed")

    change_file_owner(TEMPLATE_FILE)


def change_file_owner(path):
    """Change the owner of specific files to the sudo user."""
    uid = int(subprocess.run(["id", "-u", USER], stdout=subprocess.PIPE).stdout)
    gid = int(subprocess.run(["id", "-u", USER], stdout=subprocess.PIPE).stdout)
    current_owner = subprocess.run(["id", "-nu", str(os.stat(path).st_uid)], stdout=subprocess.PIPE).stdout
    current_owner = current_owner.decode().rstrip("\n")
    # Only change file owner if it not owned by USER.
    pass


def check_root():
    """Check if the program was executed as root and prompt the user."""
    # check root user
    # check deps installed: openvpn ip sysctl pgrep pkill
    pass

def check_update():
    """Return the download URL if an Update is available, False if otherwise"""
    # config check-interval
    # install update
    pass


def check_init():
    """Check if a profile has been initialized, quit otherwise."""
    # read config values and set defaults in file
    pass

def is_valid_ip(ipaddr):
    valid_ip_re = re.compile(
        r'^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.'
        r'(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.'
        r'(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.'
        r'(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)'
        r'(/(3[0-2]|[12][0-9]|[1-9]))?$'  # Matches CIDR
    )
     return True if valid_ip_re.match(ipaddr) else False

def get_transferred_data():
    """Reads and returns the amount of data transferred during a session
    from the /sys/ directory"""
    base_path = "/sys/class/net/{0}/statistics/{1}"
    # try 0 = proton0 or tun0
    # get rx_bytes and tx_bytes, convert, return
    pass
