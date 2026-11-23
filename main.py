import ipaddress
from datetime import datetime
def load_data(filename):
    with open(filename, "r") as file:
        data = file.read()
        return data

def analyse_data(data):
    lines = data.splitlines()
    print("Total log lines" , len(lines))

    Allowed = 0
    Blocked = 0
    Other = 0
    Malformed = 0
    source_ips = []
    blocked_ips = []
    blocked_ip_counts = {}
    port_counts = {}

    for line in lines:
        try:
             parts = line.split()

             if len(parts) < 8:
                  Malformed +=1
                  continue

             event = parts[2]

             if event ==  "ALLOWED":
                  Allowed += 1

             elif event == "BLOCKED":
                  Blocked +=1

             else:
                  Other +=1
                  print("Unrecognised event:", line)

        except(ValueError,IndexError):
             Malformed += 1
        
      
           
        if "port=" in line:
            try:
                port =int(line.split("port=")[1].split()[0])

                if port in port_counts:
                     port_counts[port] +=1
                else:
                     port_counts[port] = 1

            except (ValueError , IndexError):
                pass

        if "src=" in line:
                     try:
                          source_ip = line.split("src=")[1].split()[0]
                          ipaddress.ip_address(source_ip)
                          source_ips.append(source_ip)

                          if "BLOCKED" in line:
                               blocked_ips.append(source_ip)

                     except (ValueError, IndexError):
                      continue

    for ip in blocked_ips:
       if ip in blocked_ip_counts:
                   blocked_ip_counts[ip] += 1
                  
       else:
                   blocked_ip_counts[ip] = 1
       
                   
    top_blocked_ips =sorted(blocked_ip_counts.items(), key=lambda item: item[1] ,reverse=True)[:5]
    top_ports = sorted(port_counts.items(), key=lambda item: item[1] ,reverse=True)[:5]
    print("Top 5 Targeted destination ports:",top_ports)
    print("Top 5 blocked IPs:",top_blocked_ips)
    print("Allowed events:" ,Allowed)
    print("Blocked events:" ,Blocked) 
    print("Other events:", Other) 
    print("Malformed lines",Malformed)  
    valid_events = Allowed + Blocked + Other
    unique_source_ips = set(source_ips)   
    print("Unique source IPs:", len(unique_source_ips))
    print("Blocked source IPs:", blocked_ip_counts)    

    return {
         "allowed": Allowed,
         "blocked": Blocked,
         "other": Other,
         "valid_events": valid_events,
         "malformed": Malformed,
         "unique_source_ips": len(unique_source_ips),
          "top_blocked_ips": top_blocked_ips,
          "top_ports": top_ports
    }                                                                                                                                                                                                                                                                                       
def calculate_risk(results, auth_result):
 failed_logins =auth_result["login_failed"]
 account_locked = auth_result["account_locked"]

 
 if failed_logins >=50 or account_locked >=5:
      risk = "High"
 elif failed_logins >=20:
      risk = "Medium"
 else:
      risk = "Low"
 return risk
def generate_report(results, auth_result, risk):
     with open("investigation_report.txt", "w") as file:
          file.write("SECURITY LOG INVESTIGATION REPORT\n")
          file.write("---------------------------------\n")
          file.write(f"Allowed events:{results['allowed']}\n")
          file.write(f"Blocked events:{results['blocked']}\n")
          file.write(f"Other events:{results['other']}\n")
          file.write(f"Valid firewall events:{results['valid_events']}\n")
          file.write(f"Malformed lines: {results['malformed']}\n")
          file.write(f"Unique source IPs: {results['unique_source_ips']}\n")
          file.write(f"Top blocked IPs: {results['top_blocked_ips']}\n")
          file.write(f"Top targeted ports: {results['top_ports']}\n")
          file.write(f"Successful logins:{auth_result['login_success']}\n")
          file.write(f"Failed logins:{auth_result['login_failed']}\n")
          file.write(f"Account lockouts:{auth_result['account_locked']}\n")
          file.write(f"Logout events:{auth_result['logout']}\n")
          file.write(f"Top failed login IPs:{auth_result['top_failed_ips']}\n")
          file.write(f"Top targeted username:{auth_result['top_failed_user']}\n")
          file.write(f"Authentication malformed lines:{auth_result['malformed']}\n")
          file.write(f"Unknown authentication events:{auth_result['unknown']}\n")
          file.write(f"Security Risk Level:{risk}\n")
          file.write("\nSECURITY OBSERVATIONS\n")
          file.write("---------------------\n")
          file.write("1. The ip address 198.51.100.23 recorded 46 failed login attempts, which may indicate a brute-force attack.\n")
          file.write("2. The ip address 203.0.113.55 generated 78 blocked firewall events, showing repeated traffic that was blocked by the firewall.\n")
def main():
     data = load_data("firewall.log")
     auth_data = load_data("authentication.log")
     auth_result = analyse_authentication(auth_data)
     results = analyse_data(data)
     print("Returned results:",results)
     risk = calculate_risk(results, auth_result)
     print("Security Risk Level:", risk)
     generate_report(results,auth_result,risk)

def analyse_authentication(data):
      lines = data.splitlines()
      login_success = 0
      login_failed = 0
      account_locked = 0
      logout = 0
      malformed = 0
      unknown = 0
      failed_ip_counts = {}
      failed_user_counts = {}

      for line in lines:
       parts = line.split()

       if len(parts) <5:
            malformed +=1
            continue
       
       try:
            datetime.strptime(parts[0]+ " "+ parts[1], "%Y-%m-%d %H:%M:%S")
       except ValueError:
         malformed+= 1
         continue



       
       
       if "LOGIN_SUCCESS" in line:
                   login_success += 1

       elif "LOGIN_FAILED" in line:
         login_failed += 1

         try:
          source_ip = line.split("src=")[1].split()[0]
          ipaddress.ip_address(source_ip)

          if source_ip in failed_ip_counts:
               failed_ip_counts[source_ip] += 1
          else:
               failed_ip_counts[source_ip] = 1

          if "user=" in line:
                    failed_user = line.split("user=",1)[1].split()[0]

                    if failed_user in failed_user_counts:
                         failed_user_counts[failed_user] +=1
                    else:
                         failed_user_counts[failed_user] = 1

         except (ValueError, IndexError):
          pass

       elif "ACCOUNT_LOCKED" in line:
            account_locked += 1

       elif "LOGOUT" in line:
            logout += 1

       else:
            unknown += 1

      top_failed_ips = sorted(failed_ip_counts.items(), key=lambda item: item[1], reverse=True)[:5]
      top_failed_user = sorted(failed_user_counts.items(), key=lambda item: item[1], reverse=True)[:5]

      print("Top 5 failed login IPs:",top_failed_ips)
      print("Top 5 targeted usernames:",top_failed_user)
      print("Successful logins:",login_success)
      print("Failed logins:",login_failed)
      print("Account lockouts:",account_locked)
      print("Logout events:",logout)

      return {
           "login_success": login_success,
           "login_failed": login_failed,
           "account_locked": account_locked,
           "logout": logout,
           "top_failed_ips": top_failed_ips,
           "top_failed_user": top_failed_user,
           "malformed": malformed,
           "unknown": unknown
          
           
      }


if __name__ == "__main__":
  main()


  