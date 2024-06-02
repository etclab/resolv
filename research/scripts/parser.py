import argparse
import analytics

DEFAULT_SCANFILE = '/opt/research/dnssd/random_scans/2024-05-22-random_scan_1.json'

def generate_plot_data(records):
    domains_by_service = analytics.domains_by_service(records)

    current_threshold = 1
    services_found = True

    while services_found:
        # count number of services advertised by at least current_threshold domains
        service_count = 0
        for service, domain_list in domains_by_service:
            if len(domain_list) > current_threshold:
                service_count += 1

        current_threshold += 1

        # this case is entered when we get to a threshold where threshold > domains advertising a service
        if service_count == 0:
            services_found = False


        print(str(current_threshold) + "," + str(service_count))


def generate_scan_data(records, threshold_start):
    domains_by_service = analytics.domains_by_service(records)

    current_threshold = threshold_start # so that we can cutoff values left of tail
    services_found = True

    distinct_services = set()

    while services_found:
        # count number of services advertised by at least current_threshold domains
        service_count = 0
        for service, domain_list in domains_by_service:
            if len(domain_list) > current_threshold:
                distinct_services.add(service)
                service_count += 1

        current_threshold += 1

        # this case is entered when we get to a threshold where threshold > domains advertising a service
        if service_count == 0:
            services_found = False


    for service in distinct_services:
        print(service)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scan-file", help="path to an sdscan output file")
    parser.add_argument("--mode", help="output mode either 'plot' or 'scan'")
    parser.add_argument("--threshold", help="threshold for scan mode")
    args = parser.parse_args()

    if not args.scan_file:
        args.scan_file = DEFAULT_SCANFILE

    records = analytics.read_scan_file(args.scan_file)
    records = analytics.sanitize(records)

    for record in records:
        #print(record["QName"])

        if record["DNSSDProbe"]:
            record_type = "DNSSDProbe"

            for service_instances in record[record_type]["Services"].values():

                for service_instance_list in service_instances:

                    if service_instance_list["Txt"]:
                        print(record["QName"])
                        print("Name:", service_instance_list["Name"], "Target:", service_instance_list["Target"])
                        print(service_instance_list["Txt"])





        if record["PTRProbe"]:
            record_type = "PTRProbe"

            for service_instances in record[record_type]["Services"].values():

                for service_instance_list in service_instances:

                    if service_instance_list["Txt"]:
                        print(record["QName"])
                        print("Name:", service_instance_list["Name"], "Target:", service_instance_list["Target"])
                        print(service_instance_list["Txt"])




        if record["SRVProbe"]:
            record_type = "SRVProbe"

            for service_instances in record[record_type]["Services"].values():

                for service_instance_list in service_instances:

                    if service_instance_list["Txt"]:
                        print(record["QName"])
                        print("Name:", service_instance_list["Name"], "Target:", service_instance_list["Target"])
                        print(service_instance_list["Txt"])


    if args.mode == "plot":
        generate_plot_data(records)
    elif args.mode == "scan":
        generate_scan_data(records, int(args.threshold)) # second parameter represents bar cutoff

    
if __name__ == '__main__':
    main()
