from opensearchpy import OpenSearch, RequestsHttpConnection

# OpenSearch client setup
client = OpenSearch(
    hosts=[{'host': 'localhost', 'port': 9200}],
    http_auth=('admin', 'admin'),
    use_ssl=False,
    verify_certs=False,
    connection_class=RequestsHttpConnection
)

try:
    # Test connection
    health = client.cluster.health()
    print("Cluster Health:", health)
    
    # List indices
    indices = client.cat.indices(format='json')
    print("\nIndices:")
    for index in indices:
        print(f"Name: {index['index']}, Docs: {index['docs.count']}, Size: {index['store.size']}")
    
    # Get detailed stats
    stats = client.indices.stats()
    print("\nDetailed Stats:", stats)
    
except Exception as e:
    print("Error:", str(e)) 