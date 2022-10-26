PATH = 'local_show_files/'


def dummy_check_dns_record(domain, record_type, ns):
    file = PATH + '_'.join([domain, record_type])
    lines = []
    try:
        with open(file) as f:
            for line in f:
                lines.append(line)
    except:
        pass
    
    return lines


