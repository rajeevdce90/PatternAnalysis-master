import json
import logging
import pandas as pd
from datetime import datetime
from flask import current_app
from app.services.opensearch_service import OpenSearchService
import requests
import socket
import threading
import time
from typing import Dict, List, Optional, Union

logger = logging.getLogger(__name__)

class DataIngestionService:
    def __init__(self):
        self.opensearch = OpenSearchService()
        self.active_collectors = {}
        self.active_listeners = {}

    def process_file_upload(self, file_path: str, target_index: str, datatype: str) -> Dict:
        """Process an uploaded file and index its contents."""
        try:
            # Read file based on extension
            ext = file_path.split('.')[-1].lower()
            if ext == 'csv':
                df = pd.read_csv(file_path)
            elif ext == 'json':
                df = pd.read_json(file_path)
            elif ext == 'xlsx':
                df = pd.read_excel(file_path)
            else:
                raise ValueError(f"Unsupported file type: {ext}")

            # Convert DataFrame to list of dictionaries
            records = df.to_dict('records')

            # Add metadata to each record
            for record in records:
                record['datatype'] = datatype
                record['@timestamp'] = datetime.utcnow().isoformat()

            # Bulk index the records
            response = self.opensearch.bulk_index(target_index, records)

            # Process response
            success_count = len([item for item in response['items'] if 'index' in item and item['index'].get('status') == 201])
            total_count = len(records)

            return {
                'success': True,
                'message': f'Successfully indexed {success_count} out of {total_count} records',
                'total_records': total_count,
                'successful_records': success_count
            }

        except Exception as e:
            logger.error(f"Error processing file upload: {str(e)}")
            return {
                'success': False,
                'message': f'Error processing file: {str(e)}'
            }

    def start_rest_collector(self, config: Dict) -> Dict:
        """Start a REST API collector."""
        try:
            collector_id = f"rest_{int(time.time())}"
            
            # Create collector thread
            def collector_task():
                while collector_id in self.active_collectors:
                    try:
                        # Make API request
                        response = requests.request(
                            method=config['method'],
                            url=config['url'],
                            headers=config.get('headers', {}),
                            json=config.get('body') if config['method'] in ['POST', 'PUT'] else None,
                            timeout=30
                        )
                        response.raise_for_status()

                        # Process response
                        data = response.json()
                        if isinstance(data, dict):
                            data = [data]

                        # Add metadata
                        for record in data:
                            record['datatype'] = config['datatype']
                            record['@timestamp'] = datetime.utcnow().isoformat()
                            record['collector_id'] = collector_id

                        # Index data
                        self.opensearch.bulk_index(config['target_index'], data)

                        # Wait for next interval
                        time.sleep(config['interval'])

                    except Exception as e:
                        logger.error(f"Error in REST collector {collector_id}: {str(e)}")
                        time.sleep(config['interval'])

            # Start collector thread
            thread = threading.Thread(target=collector_task, daemon=True)
            thread.start()

            self.active_collectors[collector_id] = {
                'thread': thread,
                'config': config,
                'start_time': datetime.utcnow()
            }

            return {
                'success': True,
                'message': f'REST collector started successfully',
                'collector_id': collector_id
            }

        except Exception as e:
            logger.error(f"Error starting REST collector: {str(e)}")
            return {
                'success': False,
                'message': f'Error starting collector: {str(e)}'
            }

    def start_syslog_listener(self, config: Dict) -> Dict:
        """Start a Syslog listener."""
        try:
            listener_id = f"syslog_{int(time.time())}"
            
            # Create UDP server socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('0.0.0.0', config['port']))

            # Create listener thread
            def listener_task():
                while listener_id in self.active_listeners:
                    try:
                        data, addr = sock.recvfrom(8192)
                        message = data.decode('utf-8')

                        # Process and index the message
                        record = {
                            'message': message,
                            'source_ip': addr[0],
                            'source_port': addr[1],
                            'datatype': config['datatype'],
                            '@timestamp': datetime.utcnow().isoformat(),
                            'listener_id': listener_id
                        }

                        self.opensearch.index_document(
                            config['target_index'],
                            record
                        )

                    except Exception as e:
                        logger.error(f"Error in Syslog listener {listener_id}: {str(e)}")

            # Start listener thread
            thread = threading.Thread(target=listener_task, daemon=True)
            thread.start()

            self.active_listeners[listener_id] = {
                'thread': thread,
                'socket': sock,
                'config': config,
                'start_time': datetime.utcnow()
            }

            return {
                'success': True,
                'message': f'Syslog listener started successfully on port {config["port"]}',
                'listener_id': listener_id
            }

        except Exception as e:
            logger.error(f"Error starting Syslog listener: {str(e)}")
            return {
                'success': False,
                'message': f'Error starting listener: {str(e)}'
            }

    def stop_collector(self, collector_id: str) -> Dict:
        """Stop a running collector."""
        try:
            if collector_id in self.active_collectors:
                collector = self.active_collectors.pop(collector_id)
                # Thread will stop on next iteration
                return {
                    'success': True,
                    'message': f'Collector {collector_id} stopped successfully'
                }
            return {
                'success': False,
                'message': f'Collector {collector_id} not found'
            }
        except Exception as e:
            logger.error(f"Error stopping collector {collector_id}: {str(e)}")
            return {
                'success': False,
                'message': f'Error stopping collector: {str(e)}'
            }

    def stop_listener(self, listener_id: str) -> Dict:
        """Stop a running listener."""
        try:
            if listener_id in self.active_listeners:
                listener = self.active_listeners.pop(listener_id)
                listener['socket'].close()
                return {
                    'success': True,
                    'message': f'Listener {listener_id} stopped successfully'
                }
            return {
                'success': False,
                'message': f'Listener {listener_id} not found'
            }
        except Exception as e:
            logger.error(f"Error stopping listener {listener_id}: {str(e)}")
            return {
                'success': False,
                'message': f'Error stopping listener: {str(e)}'
            }

    def get_active_collectors(self) -> List[Dict]:
        """Get information about all active collectors."""
        return [{
            'id': collector_id,
            'type': 'REST',
            'url': info['config']['url'],
            'target_index': info['config']['target_index'],
            'interval': info['config']['interval'],
            'start_time': info['start_time'].isoformat()
        } for collector_id, info in self.active_collectors.items()]

    def get_active_listeners(self) -> List[Dict]:
        """Get information about all active listeners."""
        return [{
            'id': listener_id,
            'type': 'Syslog',
            'port': info['config']['port'],
            'target_index': info['config']['target_index'],
            'start_time': info['start_time'].isoformat()
        } for listener_id, info in self.active_listeners.items()] 