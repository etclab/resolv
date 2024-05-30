"""
Functions for reading the output of resolv's sdcan tool.

The output of sdscan is called a "scan file".  A scan file is a text file where
each line is a JSON object that contains the scan results for scanning a
specific domain.  Each line corresponds to a different domain.

The basic template for using this module is to first call:

    records = analytics.read_scan_file(scan_file)
    records = analytics.sanitize(records)

The read_scan_file function reads the scan file and parses each JSON object.
The return value of that function (records) is a list, where each entry is the
Python-version of that JSON object.  The next function, sanitize, cleans the
records of bogus values; that function either removes records altogether or
removes one or more their fields.
"""
import collections
import functools
import json

__builtin_filter = filter
__builtin_map = map

def filter(fn, records):
    """filter is like the builtin filter function, but returns a list rather than an
    iterator.
    """
    iterator = __builtin_filter(fn, records)
    return list(iterator)

def map(fn, *iterables):
    """map is like the builtin map function, but returns a list rather than an
    iterator.
    """
    iterator = __builtin_map(fn, *iterables)
    return list(iterator)

def collect(fn, records):
    """collect is similar to a combined map and filter operation.  collect
    applies the function fn to each record in records, and returns a new list
    with these modified records.  If fn returns a False value, the record is
    not included in the result list.  Otherwise, the output of fn is the value
    for that entry.  Note that the input records parameter is not affected.
    """
    results = []
    for record in records:
        result = fn(record)
        if result:
            results.append(result)
    return results

def set_extend(s, iterable):
    """set_extend is a helper function for adding all values in interable to
    the set s.
    """
    for x in iterable:
        s.add(x)

def _is_srv_valid(srv):
    """_is_srv_valid returns whether an SRV (a Python dictory holding the results
    of an SRV query) represents a real service.  Specifically, if the Target
    is . or an emtpy string, then the SRV record is not valid.
    """
    return (srv['Target'] != '.') and (srv['Target'].strip() != "")

def _sanitize_service_map(service_map):
    """_sanitize_service_map sanitizes a service map.  A service map is a Python
    dictionary where each key is a service (e.g., _ipp._tcp), and each value is
    a list of instances or replicas of that service.  This function simply
    checks whether the SRV data for each instance or replica.  This function
    returns a new dictory (a new service map) that contains only valid
    service; the input service_map is not affected.
    """
    new_map = collections.defaultdict(list)
    for service, instances in service_map.items():
        for instance in instances:
            if _is_srv_valid(instance):
                new_map[service].append(instance)
    return dict(new_map)

def _is_naptr_valid(naptr):
    """_is_naptr_valid returns whether an entry in the NAPTRProbe NAPTRs list is
    valid. For an entry to be valid, the Flag fields must contain an S (case
    insensitive), and the Replacement field contain non-whitespace characters,
    and the Services list must contain atleast one entry.
    """
    return ('s' in naptr['Flags'].lower()) \
            and naptr['Replacement'].strip() != "" \
            and naptr['Services'] != None \
            and len(naptr['Services'])

def _sanitize_naptrs(naptrs):
    """_sanitize_naptrs takes the NAPTRProbe's NAPTRs list and builds and
    returns a sanitized.  The function removes NAPTRS that are invalid or where
    all corresponding SRV records are invalid.  Furthermore, this function
    removes any invalid SRV records.  The original naptrs input parameter is
    not affected.
    """
    new_list = []
    for naptr in naptrs:
        if _is_naptr_valid(naptr):
            service_list = []
            for service in naptr['Services']:
                if _is_srv_valid(service):
                    service_list.append(service)
            if service_list:
                naptr['Services'] = service_list
                new_list.append(naptr)
    return new_list

def sanitize(records):
    """sanitize sanitizes the data of all SRV or NAPTR records that do not
    correspond to a real service.
    """
    def __sanitize(r):
        if r['DNSSDProbe']:
            service_map = _sanitize_service_map(r['DNSSDProbe']['Services'])
            if service_map:
                r['DNSSDProbe']['Services'] = service_map
            else:
                r['DNSSDProbe'] = None
        if r['PTRProbe']:
            service_map = _sanitize_service_map(r['PTRProbe']['Services'])
            if service_map:
                r['PTRProbe']['Services'] = service_map
            else:
                r['PTRProbe'] = None
        if r['SRVProbe']:
            service_map = _sanitize_service_map(r['SRVProbe']['Services'])
            if service_map:
                r['SRVProbe']['Services'] = service_map
            else:
                r['SRVProbe'] = None
        if r['NAPTRProbe']:
            naptrs = _sanitize_naptrs(r['NAPTRProbe']['NAPTRs'])
            if naptrs:
                r['NAPTRProbe']['NAPTRs'] = naptrs
            else:
                r['NAPTRProbe'] = None

        if r['DNSSDProbe'] or r['PTRProbe'] or r['SRVProbe'] or r['NAPTRProbe']:
            return r
        return None
        
    return collect(__sanitize, records)

def read_scan_file(path):
    """read_scan_file reads the sdscan scan file at path and JSON parses each
    line of the file.  The output is a list, where each entry
    corresponds to the scan results for a single domain.
    """
    records = []
    with open(path) as f:
        for line in f:
            record = json.loads(line)
            records.append(record)
    return records

def service_from_domain_name(name):
    """service_from_domain_name returns the service part of domain name.  For
    instance, if name is "_ipp._tcp.example.com", this function return
    "_ipp._tcp".  If this function cannot parse the service's name, it raises a
    ValueError.
    """
    labels = name.split('.')
    if len(labels) < 2:
        raise ValueError("cannot parse service from \"%s\"" % name)
    if not labels[0].startswith("_"):
        raise ValueError("cannot parse service from \"%s\": \
                service name label does not start with an underscore" % name)
    if not labels[1].startswith("_"):
        raise ValueError("cannot parse service from \"%s\": \
                protocol label does not start with an underscore" % name)
    return '%s.%s' % (labels[0], labels[1])


def distinct_services_for_record(record):
    """distinct_services_for_record returns a set of all unique service names
    (e.g., _ipp._tcp) across all probes in a record.
    """
    names = set()
    if record['DNSSDProbe']:
        set_extend(names, record['DNSSDProbe']['Services'].keys())
    if record['PTRProbe']:
        set_extend(names, record['PTRProbe']['Services'].keys())
    if record['SRVProbe']:
        set_extend(names, record['SRVProbe']['Services'].keys())
    if record['NAPTRProbe']:
        for naptr in record['NAPTRProbe']['NAPTRs']:
            service_name = service_from_domain_name(naptr['Replacement'])
            names.add(service_name)
    return names

def distinct_services(records):
    """distinct_services returns a set of all unique service names across
    all records.
    """
    name_sets = map(distinct_services_for_record, records)
    return functools.reduce(lambda x, y: x.union(y), name_sets, set())

def services_by_domain(records):
    """services_by_domain returns a list where each entry is a tuple: (n, s),
    where n is the domain name and s is a set of services at that domain.
    """
    def __fn(r):
        s = distinct_services_for_record(r)
        return (r['QName'], s)
    return map(__fn, records)

def domains_by_service(records):
    """domains_by_service returns a list where eachentry is a tupel (s, l),
    where s is a service (e.g., _ipp._tcp) and l is a set of domains.  The list
    is ordered by number of domains (the first entry has the most domains).
    """
    ds = services_by_domain(records)
    s2d = collections.defaultdict(set)
    for domain, service_set in ds:
        for service in service_set:
            s2d[service].add(domain)
    result = list(s2d.items())
    result.sort(key=lambda e: len(e[1]), reverse=True)
    return result
