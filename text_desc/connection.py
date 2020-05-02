def dialog():
    """Connect to a server with a dialog menu."""
    # pull_server_data // no force
    # ncurses dialog to select country, server, then protocol
    # connect
    pass


def random_c(protocol=None):
    """Connect to a random ProtonVPN Server."""
    # get protocol
    # get servers
    # choose random
    # openvpn connect
    pass

def fastest(protocol=None):
    """Connect to the fastest server available."""
    # get protocol
    # disconnect
    # pull server data
    # get servers
    # exclude secure-core and tor servers
    # connect fastest
    pass


def country_f(country_code, protocol=None):
    """Connect to the fastest server in a specific country."""
    # get protocol
    # disconnect
    # pull_server_data
    # get servers
    # filter by CC, exclude secure-core and tor servers
    # connect fastest
    pass


def feature_f(feature, protocol=None):
    """Connect to the fastest server in a specific country."""
    # get protocol
    # disconnect
    # pull_server_data
    # get servers
    # filter by feature
    # connect fastest
    pass


def direct(user_input, protocol=None):
    """Connect to a single given server directly"""
    # pull_server_data // no force
    # get protocol

    # validate input
    # For short format (UK-03/HK#5-Tor | Normal Servers/Tor Servers)
    re_short = re.compile(r"^((\w\w)(-|#)?(\d{1,3})-?(TOR)?)$")
    # For long format (IS-DE-01 | Secure-Core/Free/US Servers)
    re_long = re.compile(r"^(((\w\w)(-|#)?([A-Z]{2}|FREE))(-|#)?(\d{1,3})-?(TOR)?)$")

    # connect
    pass


def reconnect():
    """Reconnect to the last VPN Server."""
    # read data from config
    # connect
    pass


def disconnect(passed=False):
    """Disconnect VPN if a connection is present."""
    # if connected, SIGKILL openvpn
    # notify if kill fails

    # restore dns
    # restore ipv6
    # restore killswitch
    pass


def status():
    """
    Display the current VPN status

    Showing connection status (connected/disconnected),
    current IP, server name, country, server load
    """
    # check init
    # quit if not connected
    # pull_server_data // no force
    # read data from config
    # Check if the VPN Server is reachable (ping)

    # get servers
    # get ip info

    # get config and server values for output

    # ks status
    if os.path.isfile(os.path.join(CONFIG_DIR, "iptables.backup")):
        killswitch_on = True
    else:
        killswitch_on = False
    killswitch_status = "Enabled" if killswitch_on else "Disabled"

    # get_transferred_data

    # Print Status Output
    print(
        "Status:       Connected\n" +
        "Time:         {0}\n".format(connection_time) +
        "IP:           {0}\n".format(ip) +
        "Server:       {0}\n".format(connected_server) +
        "Features:     {0}\n".format(all_features[feature]) +
        "Protocol:     {0}\n".format(connected_protocol.upper()) +
        "Kill Switch:  {0}\n".format(killswitch_status) +
        "Country:      {0}\n".format(country) +
        "City:         {0}\n".format(city) +
        "Load:         {0}%\n".format(load) +
        "Received:     {0}\n".format(rx_amount) +
        "Sent:         {0}".format(tx_amount)
    )


def openvpn_connect(servername, protocol):
    """Connect to VPN Server."""

    # copy template to ovpn location
    # get servers // no froce
    # get sub servers

    # write config
    with open(OVPN_FILE, "a") as f:
        f.write("\n\n")
        f.write("proto {0}\n".format(protocol.lower()))
        for ip in ip_list:
            f.write("remote {0} {1}\n".format(ip, port[protocol.lower()]))
        logger.debug("IPs: {0}".format(ip_list))
        logger.debug("connect.ovpn written")

    # disconnect
    # remeber current (old) ip
    # write command to ovpn.log:
    ## openvpn --config OVPN_FILE --auth-user-pass PASSFILE --dev proton0 --dev-type tun

    # check log for successful connection and check ip change
    # Write connection info into configuration file
    # check_update


def manage_dns(mode, dns_server=False):
    """
    Manage resolv.conf to circumvent DNS Leaks.

    Has 2 modes (string): leak_protection / restore
    leak_protection: Replace the current resolv.conf entries with ProtonVPN DNS
    restore: Revert changes and restore original configuration
    """
    # if mode == "leak_protection":
        # Restore original resolv.conf if it exists
        # manage_dns("restore")
        # Check for custom DNS Server
        # Make sure DNS Server has been provided
        # copy resolvconf to backup
        # Remove previous nameservers
        # Add ProtonVPN managed DNS Server to resolv.conf
        # Write the hash of the edited file in the configuration
    # elif mode == "restore":
        # if backup matches config, restore
    pass

def manage_ipv6(mode):
    """
    Disable and Enable IPv6 to circumvent IPv6 leaks.

    Has 2 modes (string): disable / restore.
    disable: Disables IPv6 for the default interface.
    restore: Revert changes and restore original configuration.
    """

    ipv6_backupfile = os.path.join(CONFIG_DIR, "ipv6.backup")
    ip6tables_backupfile = os.path.join(CONFIG_DIR, "ip6tables.backup")

    if mode == "disable":

        logger.debug("Disabling IPv6")
        # Needs to be removed eventually. I'll leave it in for now
        # so it still properly restores the IPv6 address the old way
        if os.path.isfile(ipv6_backupfile):
            manage_ipv6("legacy_restore")

        if os.path.isfile(ip6tables_backupfile):
            logger.debug("IPv6 backup exists")
            manage_ipv6("restore")

        # Backing up ip6ables rules
        logger.debug("Backing up ip6tables rules")
        ip6tables_rules = subprocess.run(["ip6tables-save"],
                                         stdout=subprocess.PIPE)

        if "COMMIT" in ip6tables_rules.stdout.decode():
            with open(ip6tables_backupfile, "wb") as f:
                f.write(ip6tables_rules.stdout)
        else:
            with open(ip6tables_backupfile, "w") as f:
                f.write("*filter\n")
                f.write(":INPUT ACCEPT\n")
                f.write(":FORWARD ACCEPT\n")
                f.write(":OUTPUT ACCEPT\n")
                f.write("COMMIT\n")

        # Get the default nic from ip route show output
        default_nic = get_default_nic()

        ip6tables_commands = [
            "ip6tables -A INPUT -i {0} -j DROP".format(default_nic),
            "ip6tables -A OUTPUT -o {0} -j DROP".format(default_nic),
        ]
        for command in ip6tables_commands:
            command = command.split()
            subprocess.run(command)
        logger.debug("IPv6 disabled successfully")

    elif mode == "restore":
        logger.debug("Restoring ip6tables")
        # Same as above, remove eventually
        if os.path.isfile(ipv6_backupfile):
            logger.debug("legacy ipv6 backup found")
            manage_ipv6("legacy_restore")
        if os.path.isfile(ip6tables_backupfile):
            subprocess.run(
                "ip6tables-restore < {0}".format(
                                          ip6tables_backupfile
                ), shell=True, stdout=subprocess.PIPE
            )
            logger.debug("ip6tables restored")
            os.remove(ip6tables_backupfile)
            logger.debug("ip6tables.backup removed")
        else:
            logger.debug("No Backupfile found")
        return

    elif mode == "legacy_restore":
        logger.debug("Restoring IPv6")
        if not os.path.isfile(ipv6_backupfile):
            logger.debug("No Backupfile found")
            return

        with open(ipv6_backupfile, "r") as f:
            lines = f.readlines()
            default_nic = lines[0].strip()
            ipv6_addr = lines[1].strip()

        ipv6_info = subprocess.run(
            "ip addr show dev {0} | grep '\<inet6.*global\>'".format(default_nic), # noqa
            shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE
        )

        has_ipv6 = True if ipv6_info.returncode == 0 else False

        if has_ipv6:
            logger.debug("IPv6 address present")
            os.remove(ipv6_backupfile)
            return

        ipv6_enable = subprocess.run(
            "sysctl -w net.ipv6.conf.{0}.disable_ipv6=0".format(default_nic),
            shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE
        )

        if not ipv6_enable.returncode == 0:
            print(
                "[!] There was an error with restoring the IPv6 configuration"
            )
            logger.debug("IPv6 restoration error: sysctl")
            logger.debug("stdout: {0}".format(ipv6_enable.stdout))
            logger.debug("stderr: {0}".format(ipv6_enable.stderr))
            return

        ipv6_restore_address = subprocess.run(
            "ip addr add {0} dev {1}".format(ipv6_addr, default_nic),
            shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE
        )

        if not ipv6_restore_address.returncode == 0:
            print(
                "[!] There was an error with restoring the IPv6 configuration"
            )
            logger.debug("IPv6 restoration error: ip")
            logger.debug("stdout: {0}".format(ipv6_restore_address.stdout))
            logger.debug("stderr: {0}".format(ipv6_restore_address.stderr))
            return

        logger.debug("Removing IPv6 backup file")
        os.remove(ipv6_backupfile)
        logger.debug("IPv6 restored")

    else:
        raise Exception("Invalid argument provided. "
                        "Mode must be 'disable' or 'restore'")


def manage_killswitch(mode, proto=None, port=None):
    """
    Disable and enable the VPN Kill Switch.

    The Kill Switch creates IPTables rules that only allow connections to go
    through the OpenVPN device. If the OpenVPN process stops for some unknown
    reason this will completely block access to the internet.
    """
    # if mode == "restore":
        # restore backup
        # return

    # Stop if Kill Switch is disabled

    if mode == "enable":
        # restore backup if exists
        # get device from ovpn log
        # Back up IPTables rules

        # idk
        if "COMMIT" in iptables_rules.stdout.decode():
            with open(backupfile, "wb") as f:
                f.write(iptables_rules.stdout)
        else:
            with open(backupfile, "w") as f:
                f.write("*filter\n")
                f.write(":INPUT ACCEPT\n")
                f.write(":FORWARD ACCEPT\n")
                f.write(":OUTPUT ACCEPT\n")
                f.write("COMMIT\n")

        # Creating Kill Switch rules
        iptables_commands = [
            "iptables -F",
            "iptables -P INPUT DROP",
            "iptables -P OUTPUT DROP",
            "iptables -P FORWARD DROP",
            "iptables -A OUTPUT -o lo -j ACCEPT",
            "iptables -A INPUT -i lo -j ACCEPT",
            "iptables -A OUTPUT -o {0} -j ACCEPT".format(device),
            "iptables -A INPUT -i {0} -j ACCEPT".format(device),
            "iptables -A OUTPUT -o {0} -m state --state ESTABLISHED,RELATED -j ACCEPT".format(device), # noqa
            "iptables -A INPUT -i {0} -m state --state ESTABLISHED,RELATED -j ACCEPT".format(device), # noqa
            "iptables -A OUTPUT -p {0} -m {1} --dport {2} -j ACCEPT".format(proto.lower(), proto.lower(), port), # noqa
            "iptables -A INPUT -p {0} -m {1} --sport {2} -j ACCEPT".format(proto.lower(), proto.lower(), port), # noqa
        ]

        # idk
        if int(get_config_value("USER", "killswitch")) == 2:
            # Getting local network information
            default_nic = get_default_nic()
            local_network = subprocess.run(
                "ip addr show {0} | grep inet".format(default_nic),
                stdout=subprocess.PIPE, shell=True
            )
            local_network = local_network.stdout.decode().strip().split()[1]

            exclude_lan_commands = [
                "iptables -A OUTPUT -o {0} -d {1} -j ACCEPT".format(default_nic, local_network), # noqa
                "iptables -A INPUT -i {0} -s {1} -j ACCEPT".format(default_nic, local_network), # noqa
            ]

            for lan_command in exclude_lan_commands:
                iptables_commands.append(lan_command)

        for command in iptables_commands:
            command = command.split()
            subprocess.run(command)
        logger.debug("Kill Switch enabled")
