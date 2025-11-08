import re
from impacket.dcerpc.v5 import samr, tsch, transport
from impacket.dcerpc.v5 import tsts as TSTS
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from contextlib import suppress
import traceback
import socket
from nxc.helpers.misc import CATEGORY
# added for ldap enumeration with alternative credentials
from ldap3 import Server, Connection, ALL, NTLM, SUBTREE


class NXCModule:
    """
    Module to find Domain and Enterprise Admin presence on target systems over SMB.
    Made by @crosscutsaw, @NeffIsBack
    ###test code### modified to support alternative domain credentials
    """

    name = "presencetest"
    description = "Traces Domain and Enterprise Admin presence in the target over SMB"
    supported_protocols = ["smb"]
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        """Module options for alternative domain credentials."""
        # added module options for alternative domain enumeration
        context.log.debug(f"Raw module_options received: {module_options}")
        
        self.altuser = module_options.get("ALTUSER", None)
        self.altpass = module_options.get("ALTPASS", None)
        self.altdomain = module_options.get("ALTDOMAIN", None)
        # optional: manually specify dc ip if dns resolution fails
        self.altdc = module_options.get("ALTDC", None)
        
        # debug: log what we received
        context.log.debug(f"Module options parsed - altuser: {self.altuser}, altdomain: {self.altdomain}, altdc: {self.altdc}")
        
        # validate that all three are provided together
        alt_creds_provided = [self.altuser, self.altpass, self.altdomain]
        if any(alt_creds_provided) and not all(alt_creds_provided):
            context.log.fail("ALTUSER, ALTPASS, and ALTDOMAIN must all be specified together")
            raise ValueError("Incomplete alternative credentials")

    def on_admin_login(self, context, connection):
        try:
            # debug: check current state of variables
            context.log.debug(f"on_admin_login - altuser: {self.altuser}, altdomain: {self.altdomain}, altdc: {self.altdc}")
            
            # check if alternative credentials are provided
            if self.altuser and self.altpass and self.altdomain:
                context.log.info(f"Using alternative domain credentials: {self.altdomain}\\{self.altuser}")
                
                # use manually specified dc ip or resolve from domain
                if self.altdc:
                    context.log.info(f"Using manually specified DC IP: {self.altdc}")
                    self.alt_dc_ip = self.altdc
                else:
                    context.log.info("Attempting to resolve DC IP from domain...")
                    self.alt_dc_ip = self.get_dc_ip_from_domain(context, self.altdomain)
                
                admin_users = self.enumerate_admin_users_ldap(context)
            else:
                context.log.debug("No alternative credentials provided, using standard SAMR enumeration")
                # use standard samr enumeration
                self.alt_dc_ip = None
                admin_users = self.enumerate_admin_users(context, connection)
            
            if not admin_users:
                context.log.fail("No admin users found.")
                return

            # Update user objects to check if they are in tasklist, users directory or in scheduled tasks
            self.check_users_directory(context, connection, admin_users)
            self.check_tasklist(context, connection, admin_users)
            self.check_scheduled_tasks(context, connection, admin_users)

            # print grouped/logged results nicely
            self.print_grouped_results(context, admin_users)
        except Exception as e:
            context.log.fail(str(e))
            context.log.debug(traceback.format_exc())

    def enumerate_admin_users_ldap(self, context):
        # enumerate admin users using ldap with alternative credentials
        admin_users = []
        
        try:
            dc_ip = self.alt_dc_ip
            context.log.debug(f"Using DC IP for LDAP: {dc_ip}")
            
            # connect to ldap/ldaps
            context.log.debug(f"Connecting to LDAP at {dc_ip}")
            server = Server(dc_ip, get_info=ALL, use_ssl=False)
            
            # create connection with alternative credentials
            conn = Connection(
                server,
                user=f"{self.altdomain}\\{self.altuser}",
                password=self.altpass,
                authentication=NTLM,
                auto_bind=True
            )
            
            if not conn.bind():
                context.log.fail(f"LDAP bind failed: {conn.result}")
                return admin_users
            
            context.log.success(f"Successfully bound to LDAP as {self.altdomain}\\{self.altuser}")
            
            # get domain dn from domain fqdn
            domain_dn = ','.join([f"DC={part}" for part in self.altdomain.split('.')])
            context.log.debug(f"Using domain DN: {domain_dn}")
            
            # get domain sid from ldap
            conn.search(
                search_base=domain_dn,
                search_filter='(objectClass=domain)',
                attributes=['objectSid']
            )
            
            if conn.entries:
                self.domain_sid = str(conn.entries[0].objectSid)
                context.log.debug(f"Resolved domain SID: {self.domain_sid}")
            else:
                context.log.fail("Failed to retrieve domain SID from LDAP")
                return admin_users
            
            # define admin group rids
            admin_groups = {
                "Domain Admins": "512",
                "Enterprise Admins": "519",
            }
            
            # enumerate members of each admin group
            for group_name, group_rid in admin_groups.items():
                group_sid = f"{self.domain_sid}-{group_rid}"
                context.log.debug(f"Searching for group {group_name} with SID {group_sid}")
                
                # search for group by sid
                conn.search(
                    search_base=domain_dn,
                    search_filter=f'(objectSid={group_sid})',
                    attributes=['member']
                )
                
                if not conn.entries:
                    context.log.debug(f"Group {group_name} not found or has no members")
                    continue
                
                group_entry = conn.entries[0]
                members = group_entry.member if hasattr(group_entry, 'member') else []
                
                # enumerate each member
                for member_dn in members:
                    try:
                        # get user details
                        conn.search(
                            search_base=member_dn,
                            search_filter='(objectClass=user)',
                            search_scope=SUBTREE,
                            attributes=['sAMAccountName', 'objectSid']
                        )
                        
                        if conn.entries:
                            user_entry = conn.entries[0]
                            username = str(user_entry.sAMAccountName)
                            user_sid = str(user_entry.objectSid)
                            
                            # check if user already exists in list
                            if any(u["sid"] == user_sid for u in admin_users):
                                user = next(u for u in admin_users if u["sid"] == user_sid)
                                user["group"].append(group_name)
                            else:
                                admin_users.append({
                                    "username": username,
                                    "sid": user_sid,
                                    "domain": self.altdomain.split('.')[0].upper(),
                                    "group": [group_name],
                                    "in_tasks": False,
                                    "in_directory": False,
                                    "in_scheduled_tasks": False
                                })
                            context.log.debug(f"Found user: {username} with SID {user_sid} in group {group_name}")
                    except Exception as e:
                        context.log.debug(f"Failed to get user info for {member_dn}: {e}")
            
            conn.unbind()
            context.log.info(f"Enumerated {len(admin_users)} admin users via LDAP")
            
        except Exception as e:
            context.log.fail(f"LDAP enumeration failed: {e}")
            context.log.debug(traceback.format_exc())
        
        return admin_users

    def get_dce_rpc(self, target, string_binding, dce_binding, connection):
        # Create a DCE/RPC transport object with the specified string binding
        rpctransport = transport.DCERPCTransportFactory(string_binding)
        rpctransport.setRemoteHost(target)
        rpctransport.set_credentials(
            connection.username,
            connection.password,
            connection.domain,
            connection.lmhash,
            connection.nthash,
            aesKey=connection.aesKey,
        )
        rpctransport.set_kerberos(connection.kerberos, connection.kdcHost)

        # Connect to the DCE/RPC endpoint
        dce = rpctransport.get_dce_rpc()
        if connection.kerberos:
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        dce.set_credentials(*rpctransport.get_credentials())
        dce.connect()
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        dce.bind(dce_binding)
        return dce

    def enumerate_admin_users(self, context, connection):
        admin_users = []

        try:
            string_binding = fr"ncacn_np:{connection.kdcHost}[\pipe\samr]"
            dce = self.get_dce_rpc(connection.kdcHost, string_binding, samr.MSRPC_UUID_SAMR, connection)
        except Exception as e:
            context.log.fail(f"Failed to connect to SAMR: {e}")
            context.log.debug(traceback.format_exc())
            return admin_users

        try:
            server_handle = samr.hSamrConnect2(dce)["ServerHandle"]
            domain = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)["Buffer"]["Buffer"][0]["Name"]
            resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain)
            self.domain_sid = resp["DomainId"].formatCanonical()
            domain_handle = samr.hSamrOpenDomain(dce, server_handle, samr.DOMAIN_LOOKUP | samr.DOMAIN_LIST_ACCOUNTS, resp["DomainId"])["DomainHandle"]
            context.log.debug(f"Resolved domain SID for {domain}: {self.domain_sid}")
        except Exception as e:
            context.log.fail(f"Failed to open domain {domain}: {e!s}")
            context.log.debug(traceback.format_exc())
            return admin_users

        admin_rids = {
            "Domain Admins": 512,
            "Enterprise Admins": 519,
        }

        # Enumerate admin groups and their members
        for group_name, group_rid in admin_rids.items():
            context.log.debug(f"Looking up group: {group_name} with RID {group_rid}")

            try:
                group_handle = samr.hSamrOpenGroup(dce, domain_handle, samr.GROUP_LIST_MEMBERS, group_rid)["GroupHandle"]
                resp = samr.hSamrGetMembersInGroup(dce, group_handle)
                for member in resp["Members"]["Members"]:
                    rid = int.from_bytes(member.getData(), byteorder="little")
                    try:
                        user_handle = samr.hSamrOpenUser(dce, domain_handle, samr.MAXIMUM_ALLOWED, rid)["UserHandle"]
                        username = samr.hSamrQueryInformationUser2(dce, user_handle, samr.USER_INFORMATION_CLASS.UserAllInformation)["Buffer"]["All"]["UserName"]

                        # If user already exists, append group name
                        if any(u["sid"] == f"{self.domain_sid}-{rid}" for u in admin_users):
                            user = next(u for u in admin_users if u["sid"] == f"{self.domain_sid}-{rid}")
                            user["group"].append(group_name)
                        else:
                            admin_users.append({"username": username, "sid": f"{self.domain_sid}-{rid}", "domain": domain, "group": [group_name], "in_tasks": False, "in_directory": False, "in_scheduled_tasks": False})
                        context.log.debug(f"Found user: {username} with RID {rid} in group {group_name}")
                    except Exception as e:
                        context.log.debug(f"Failed to get user info for RID {rid}: {e!s}")
                    finally:
                        with suppress(Exception):
                            samr.hSamrCloseHandle(dce, user_handle)
            except Exception as e:
                context.log.debug(f"Failed to get members of group {group_name}: {e!s}")
            finally:
                with suppress(Exception):
                    samr.hSamrCloseHandle(dce, group_handle)

        return admin_users

    def check_users_directory(self, context, connection, admin_users):
        dirs_found = set()

        # try C$\Users first
        try:
            files = connection.conn.listPath("C$", "\\Users\\*")
        except Exception as e:
            context.log.debug(f"C$\\Users unavailable: {e}, trying Documents and Settings")
            try:
                files = connection.conn.listPath("C$", "\\Documents and Settings\\*")
            except Exception as e:
                context.log.fail(f"Error listing fallback directory: {e}")
                return
        else:
            context.log.debug("Successfully listed C$\\Users")

        # collect folder names (lowercase) ignoring "." and ".."
        dirs_found.update([f.get_shortname().lower() for f in files if f.get_shortname().lower() not in [".", "..", "administrator"]])

        # for admin users, check for folder presence
        for user in admin_users:
            # Look for administrator.domain to check if SID 500 Administrator is present (second check)
            if user["username"].lower() in dirs_found or \
                    (user["username"].lower() == "administrator" and f"{user['username'].lower()}.{user['domain']}" in dirs_found):
                user["in_directory"] = True
                context.log.info(f"Found user {user['username']} in directories")

    def check_tasklist(self, context, connection, admin_users):
        """Checks tasklist over rpc."""
        try:
            with TSTS.LegacyAPI(connection.conn, connection.remoteName, kerberos=connection.kerberos) as legacy:
                handle = legacy.hRpcWinStationOpenServer()
                processes = legacy.hRpcWinStationGetAllProcesses(handle)
        except Exception as e:
            context.log.fail(f"Error in check_tasklist RPC method: {e}")
            return []

        context.log.debug(f"Enumerated {len(processes)} processes on {connection.host}")

        for process in processes:
            context.log.debug(f"ImageName: {process['ImageName']}, UniqueProcessId: {process['SessionId']}, pSid: {process['pSid']}")
            # Check if process SID matches any admin user SID
            for user in admin_users:
                if process["pSid"] == user["sid"]:
                    user["in_tasks"] = True
                    context.log.info(f"Matched process {process['ImageName']} with user {user['username']}")

    def check_scheduled_tasks(self, context, connection, admin_users):
        """Checks scheduled tasks over rpc."""
        try:
            target = connection.remoteName if connection.kerberos else connection.host
            stringbinding = f"ncacn_np:{target}[\\pipe\\atsvc]"
            dce = self.get_dce_rpc(target, stringbinding, tsch.MSRPC_UUID_TSCHS, connection)

            # Also extract non admins where we can get the password
            self.non_admins = []
            non_admin_sids = set()

            tasks = tsch.hSchRpcEnumTasks(dce, "\\")["pNames"]
            for task in tasks:
                xml = tsch.hSchRpcRetrieveTask(dce, task["Data"])["pXml"]
                # Extract SID and LogonType from the XML, if LogonType is "Password" we should be able to extract the password
                sid = re.search(fr"<UserId>({self.domain_sid}-\d{{3,}})</UserId>", xml)
                logon_type = re.search(r"<LogonType>(\w+)</LogonType>", xml)

                # Check if SID and LogonType are found, then check if SID matches any admin user
                if sid and logon_type and logon_type.group(1) == "Password":
                    context.log.debug(f"Found scheduled task '{task['Data']}' with SID {sid} and LogonType {logon_type.group(1)}")
                    if any(user["sid"] == sid.group(1) for user in admin_users):
                        user = next(user for user in admin_users if user["sid"] == sid.group(1))
                        user["in_scheduled_tasks"] = True
                    else:
                        # If not an admin user, add to non_admin_sids for further processing
                        non_admin_sids.add(sid.group(1))

            if non_admin_sids:
                # use alt dc ip if available, otherwise use kdchost from connection
                samr_target = self.alt_dc_ip if self.alt_dc_ip else connection.kdcHost
                if not samr_target:
                    context.log.debug("No DC available for SAMR lookup of non-admin users")
                    return
                    
                string_binding = fr"ncacn_np:{samr_target}[\pipe\samr]"
                dce = self.get_dce_rpc(samr_target, string_binding, samr.MSRPC_UUID_SAMR, connection)

                # Get Domain Handle
                server_handle = samr.hSamrConnect2(dce)["ServerHandle"]
                domain = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)["Buffer"]["Buffer"][0]["Name"]
                domain_sid = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain)["DomainId"]
                domain_handle = samr.hSamrOpenDomain(dce, server_handle, samr.DOMAIN_LOOKUP | samr.DOMAIN_LIST_ACCOUNTS, domain_sid)["DomainHandle"]

                for sid in non_admin_sids:
                    user_handle = samr.hSamrOpenUser(dce, domain_handle, samr.MAXIMUM_ALLOWED, int(sid.split("-")[-1]))["UserHandle"]
                    username = samr.hSamrQueryInformationUser2(dce, user_handle, samr.USER_INFORMATION_CLASS.UserAllInformation)["Buffer"]["All"]["UserName"]
                    self.non_admins.append(username)

        except Exception as e:
            context.log.fail(f"Failed to enumerate scheduled tasks: {e}")
            context.log.debug(traceback.format_exc())

    def print_grouped_results(self, context, admin_users):
        """Logs all results grouped per host in order"""
        # Make less verbose for scanning large ranges
        context.log.info(f"Identified Admin Users: {', '.join([user['username'] for user in admin_users])}")

        # Print directory users
        dir_users = [user for user in admin_users if user["in_directory"]]
        if dir_users:
            context.log.success("Found admins in directories:")
            for user in dir_users:
                context.log.highlight(f"{user['username']} ({', '.join(user['group'])})")

        # Print tasklist users
        tasklist_users = [user for user in admin_users if user["in_tasks"]]
        if tasklist_users:
            context.log.success("Found admins in tasklist:")
            for user in tasklist_users:
                context.log.highlight(f"{user['username']} ({', '.join(user['group'])})")

        # Print scheduled tasks users
        scheduled_tasks_users = [user for user in admin_users if user["in_scheduled_tasks"]]
        if scheduled_tasks_users:
            context.log.success("Found admins in scheduled tasks:")
            for user in scheduled_tasks_users:
                context.log.highlight(f"{user['username']} ({', '.join(user['group'])})")
        if self.non_admins:
            context.log.info(f"Found {len(self.non_admins)} non-admin scheduled tasks:")
            for sid in self.non_admins:
                context.log.info(sid)

        # Making this less verbose to better scan large ranges
        if not dir_users and not tasklist_users:
            context.log.info("No matches found in users directory, tasklist or scheduled tasks.")