from module.zone import Request, Zone, zone_of_domain, \
    FailQueryNS, get_parent_domain, retrieve_dns_records, \
    g_sent_queries
from test import dummy_query


def test_success_parse_ns_record():
    domain = '.'
    record_type = 'ns'
    ns = None
    lines = dummy_query.dummy_check_dns_record(domain, record_type, ns)
    result = retrieve_dns_records(lines, domain, record_type)
    assert len(result[record_type]) > 12
    domain = 'net.'
    record_type = 'ns'
    ns = None
    lines = dummy_query.dummy_check_dns_record(domain, record_type, ns)
    result = retrieve_dns_records(lines, domain, record_type)
    assert len(result[record_type]) > 10
    assert len(result['a']) > 10
    print(g_sent_queries)
    
    
def test_dummy_check():
    domain = '.'
    record_type = 'ns'
    ns = None
    lines = dummy_query.dummy_check_dns_record(domain, record_type, ns)
    assert len(lines) > 0


def test_zone():
    Request.set_query_func(dummy_query.dummy_check_dns_record)
    domain = '.'
    zone = Zone(domain)
    
    print(zone.ns_list)
    domain = 'net.'
    zone = Zone(domain)

    print(zone.ns_list)
    print(g_sent_queries)


def test_success_get_parent_domain():
    assert get_parent_domain('') is None
    assert get_parent_domain('.') is None
    assert get_parent_domain('net') == '.'
    assert get_parent_domain('net.') == '.'
    assert get_parent_domain('a.b.c.com') == 'b.c.com.'
    assert get_parent_domain('a.b.c.com.') == 'b.c.com.'


def test_get_same_zone():
    domain = '.'
    zone_a = zone_of_domain(domain)
    zone_b = zone_of_domain(domain)
    assert zone_a is zone_b


def test_ns_fail_exception_message():
    domain = '.'
    zone = zone_of_domain(domain)
    zone._ns_from_parent = ['ns1', 'ns2']
    zone._ns_index = 2
    try:
        ns = zone.ns
        assert False
    except FailQueryNS as e:
        error_str = str(e)
        assert 'ns1' in error_str