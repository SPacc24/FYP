from project.enumeration import build_enumeration_intelligence


def test_enumeration_intelligence_groups_roles_and_relationships():
    services = [
        {'host': '10.10.10.5', 'port': 389, 'protocol': 'tcp', 'service': 'ldap', 'product': 'OpenLDAP'},
        {'host': '10.10.10.5', 'port': 88, 'protocol': 'tcp', 'service': 'kerberos'},
        {'host': '10.10.10.5', 'port': 445, 'protocol': 'tcp', 'service': 'microsoft-ds', 'product': 'Samba smbd'},
        {'host': '10.10.10.9', 'port': 111, 'protocol': 'tcp', 'service': 'rpcbind'},
        {'host': '10.10.10.9', 'port': 2049, 'protocol': 'tcp', 'service': 'nfs'},
    ]
    active = {
        'ldapsearch_rootdse': [{'host': '10.10.10.5', 'parsed': {'defaultNamingContext': 'DC=example,DC=local'}}],
        'kerberos_info': [{'host': '10.10.10.5'}],
        'budget': {'enabled': True},
    }
    result = build_enumeration_intelligence(services, modern_active_validation=active, passive_intelligence={}, web_inventory=[], smb_summary={})
    assert result['identity_correlation']
    assert any(r['relationship'] == 'LDAP to Kerberos relationship' for r in result['cross_service_relationships'])
    assert any(r['relationship'] == 'RPC to NFS relationship' for r in result['cross_service_relationships'])
    assert result['knowledge_graph']['nodes']
    assert result['detection_budget_summary']['authentication_attempts'] == 'None performed by recon module'
