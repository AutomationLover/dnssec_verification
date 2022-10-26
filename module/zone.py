import subprocess

g_zones = dict()  # {domain: class zone}
g_sent_queries = []


def get_sent_queries():
    return g_sent_queries


class Request:
    _request_func = None
    
    @classmethod
    def set_query_func(cls, query_func):  # enable test with local_show_file, avoid interact with ns.
        cls._request_func = query_func

    @classmethod
    def query(cls, *args, **kwargs):
        # before query record, to record command called in g_sent_queries.
        def log_before_query():
            items = []
            if args:
                parameters = ['domain', 'dns_record', 'query_to']
                for i,arg in enumerate(args):
                    item = f'{parameters[i]}={str(arg)}'
                    items.append(item)
            if kwargs:
                for k, v in kwargs.items():
                    item = f'{k}={str(v)}'
                    items.append(item)
            parameter_str = ','.join(items)
            log_string = f'query({parameter_str})'
            g_sent_queries.append(log_string)

        log_before_query()
        result = cls._request_func(*args, **kwargs)
        return result
        
    
class FailQueryNS(Exception):
    pass


def get_parent_domain(domain: str):
    if not domain or domain == '.':
        return None
    if '.' not in domain:
        return '.'
    if domain[-1] == '.':
        domain = domain[:-1]
    segments = domain.split('.')
    return '.'.join(segments[1:])+'.'


def get_record_from_line(line: str) -> str:
    segments = line.split()
    if len(segments) < 5:
        return ""
    return ' '.join(segments[4:])


def test_success_get_record_from_line():
    line = 'net.			172800	IN	NS	a.gtld-servers.net.'
    result = get_record_from_line(line)
    expect = 'a.gtld-servers.net.'
    assert result == expect
    
    
def retrieve_dns_records(lines: list, domain: str, record_type: str):
    result = {
        record_type: []
    }
    if not lines:
        return result
    if record_type == 'ns':
        result = retrieve_dns_records(lines, '*', 'a')
        result[record_type] = []
    for line in lines:
        if not line or len(line) < len(domain):
            continue
        if line[0] == ';':
            continue
        if domain != '*' and domain != line[:len(domain)]:
            continue
        segments = line.split()
        if 'RRSIG' in segments:
            record = get_record_from_line(line.strip())
            if not record:
                continue
            result['RRSIG'] = record
            continue
        if record_type.upper() in segments:
            record = get_record_from_line(line.strip())
            if not record:
                continue
            result[record_type].append(record)
            continue
    return result


class Zone:
    def __init__(self, domain):
        self._domain = domain
        self._parent_domain = get_parent_domain(domain)
        self._ns_from_parent = None  #
        self._ns_index = 0
        self._dnskeys = None
        self._query = Request()
    
    @property
    def ns(self):
        self._get_cur_ns()
    
    @property
    def ns_list(self):
        if self._ns_from_parent is None:
            self._init_ns()
        return self._ns_from_parent
    
    def _init_ns(self):
        # query parent for ns
        if self._domain == '.':
            parent_ns = None
        else:
            parent_zone = zone_of_domain(self._parent_domain)
            parent_ns = parent_zone.ns
        lines = self._query.query(self._domain, 'ns', parent_ns)
        result = retrieve_dns_records(lines, self._domain, 'ns')
        
        if 'a' in result:
            self._ns_from_parent = result['a'] + result['ns']
        else:
            self._ns_from_parent = result['ns']
    def _get_cur_ns(self):
        if self._ns_from_parent is None:
            self._init_ns()
        if len(self.ns_list) <= self._ns_index:
            raise FailQueryNS(f"failed reach ns: [{','.join(self.ns_list)}] for domain '{self._domain}. '.")
        return self.ns_list[self._ns_index]
        # TODO update ns_index, when ns not reply answer

def zone_of_domain(domain):
    if domain not in g_zones:
        g_zones[domain] = Zone(domain)
    return g_zones[domain]


 

