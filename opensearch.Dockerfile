FROM opensearchproject/opensearch:2.11.1

ENV OPENSEARCH_JAVA_OPTS="-Xms512m -Xmx512m"
ENV discovery.type=single-node
ENV bootstrap.memory_lock=true
ENV path.data=/usr/share/opensearch/data

EXPOSE 9200 9300 9600

USER root
COPY opensearch.yml /usr/share/opensearch/config/
RUN chown opensearch:opensearch /usr/share/opensearch/config/opensearch.yml && \
    chmod 644 /usr/share/opensearch/config/opensearch.yml

USER opensearch 